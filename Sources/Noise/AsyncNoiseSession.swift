/*
 * Copyright 2024 Edge Engineer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation

/// Sendable session statistics for monitoring
public struct SessionStatistics: Sendable {
    public let sentMessages: Int
    public let receivedMessages: Int
    public let timeSinceLastRekey: TimeInterval
    public let lastRekeyTime: Date?
    
    public init(
        sentMessages: Int,
        receivedMessages: Int,
        timeSinceLastRekey: TimeInterval,
        lastRekeyTime: Date?
    ) {
        self.sentMessages = sentMessages
        self.receivedMessages = receivedMessages
        self.timeSinceLastRekey = timeSinceLastRekey
        self.lastRekeyTime = lastRekeyTime
    }
}

/// Actor-based wrapper for NoiseSession providing enhanced thread safety
///
/// This actor encapsulates a NoiseSession and ensures all state mutations
/// are serialized, making it safe to use across multiple concurrent tasks
/// without external synchronization.
///
/// ## Usage
///
/// ```swift
/// // Create actor-wrapped session
/// let session = try await AsyncNoiseSession(
///     pattern: .XX,
///     initiator: true,
///     staticKeypair: keypair
/// )
///
/// // Safe concurrent access
/// let handshakeMessage = try await session.writeHandshakeMessage()
/// let response = try await session.readHandshakeMessage(receivedData)
///
/// // Multiple tasks can safely interact with the same session
/// async let sending = session.writeMessage(plaintext1)
/// async let receiving = session.readMessage(ciphertext2)
/// let (sent, received) = try await (sending, receiving)
/// ```
///
/// ## Thread Safety
///
/// Unlike the extension-based async methods which require external
/// synchronization when used across tasks, this actor provides
/// built-in mutual exclusion and is inherently thread-safe.
///
/// ## Performance Considerations
///
/// The actor approach adds slight overhead due to actor isolation
/// but provides stronger safety guarantees. For single-task usage,
/// the extension-based approach may be more efficient.
public actor AsyncNoiseSession {
    private var session: NoiseSession
    
    // MARK: - Initialization
    
    /// Creates a new async Noise session
    ///
    /// This initializer supports all the same parameters as the synchronous
    /// NoiseProtocol.handshake factory method.
    ///
    /// - Parameters:
    ///   - pattern: The handshake pattern to use
    ///   - initiator: Whether this party initiates the handshake
    ///   - prologue: Optional prologue data
    ///   - staticKeypair: Static keypair for authenticated patterns
    ///   - remoteStaticKey: Remote party's static public key
    ///   - psk: Pre-shared key for PSK patterns
    public init(
        pattern: HandshakePattern,
        initiator: Bool,
        prologue: Data = Data(),
        staticKeypair: KeyPair? = nil,
        remoteStaticKey: Data? = nil,
        psk: Data? = nil
    ) async throws {
        self.session = try NoiseProtocol.handshake(
            pattern: pattern,
            initiator: initiator,
            prologue: prologue,
            staticKeypair: staticKeypair,
            remoteStaticKey: remoteStaticKey,
            psk: psk
        )
    }
    
    // MARK: - Session State
    
    /// Whether the handshake is complete
    public var isHandshakeComplete: Bool {
        session.isHandshakeComplete
    }
    
    /// The handshake hash (available after handshake completion)
    public func getHandshakeHash() -> Data? {
        session.getHandshakeHash()
    }
    
    /// Get session statistics for monitoring
    public func getSessionStatistics() -> SessionStatistics {
        let stats = session.getSessionStatistics()
        return SessionStatistics(
            sentMessages: stats["sentMessages"] as? Int ?? 0,
            receivedMessages: stats["receivedMessages"] as? Int ?? 0,
            timeSinceLastRekey: stats["timeSinceLastRekey"] as? TimeInterval ?? 0,
            lastRekeyTime: stats["lastRekeyTime"] as? Date
        )
    }
    
    /// Check if rekeying is recommended
    public func shouldRekey() -> Bool {
        session.shouldRekey()
    }
    
    // MARK: - Handshake Operations
    
    /// Creates a handshake message with proper cancellation support
    ///
    /// - Parameter payload: Optional payload data
    /// - Returns: The handshake message to send
    /// - Throws: NoiseError or CancellationError if cancelled
    public func writeHandshakeMessage(payload: Data = Data()) async throws -> Data {
        try Task.checkCancellation()
        return try session.writeHandshakeMessage(payload: payload)
    }
    
    /// Processes a received handshake message with cancellation support
    ///
    /// - Parameter message: The received handshake message
    /// - Returns: Any payload data from the message
    /// - Throws: NoiseError or CancellationError if cancelled
    public func readHandshakeMessage(_ message: Data) async throws -> Data {
        try Task.checkCancellation()
        return try session.readHandshakeMessage(message)
    }
    
    // MARK: - Transport Operations
    
    /// Encrypts a message with cancellation support
    ///
    /// - Parameter plaintext: The message to encrypt
    /// - Returns: The encrypted message
    /// - Throws: NoiseError or CancellationError if cancelled
    public func writeMessage(_ plaintext: Data) async throws -> Data {
        try Task.checkCancellation()
        return try session.writeMessage(plaintext)
    }
    
    /// Decrypts a received message with cancellation support
    ///
    /// - Parameter ciphertext: The encrypted message
    /// - Returns: The decrypted plaintext
    /// - Throws: NoiseError or CancellationError if cancelled
    public func readMessage(_ ciphertext: Data) async throws -> Data {
        try Task.checkCancellation()
        return try session.readMessage(ciphertext)
    }
    
    // MARK: - Session Management
    
    /// Performs rekeying for forward secrecy with cancellation support
    ///
    /// - Throws: NoiseError or CancellationError if cancelled
    public func rekey() async throws {
        try Task.checkCancellation()
        try session.rekey()
    }
    
    /// Set automatic rekeying policy
    ///
    /// - Parameter policy: The rekeying policy to use
    public func setRekeyPolicy(_ policy: RekeyPolicy) {
        session.rekeyPolicy = policy
    }
    
    // MARK: - Batch Operations
    
    /// Process multiple messages in a batch for efficiency
    ///
    /// This method processes multiple messages while holding the actor
    /// isolation, which can be more efficient than individual calls.
    ///
    /// - Parameter plaintexts: Array of messages to encrypt
    /// - Returns: Array of encrypted messages
    /// - Throws: NoiseError or CancellationError if cancelled
    public func writeMessages(_ plaintexts: [Data]) async throws -> [Data] {
        try Task.checkCancellation()
        
        var results: [Data] = []
        results.reserveCapacity(plaintexts.count)
        
        for plaintext in plaintexts {
            try Task.checkCancellation() // Check between each operation
            let ciphertext = try session.writeMessage(plaintext)
            results.append(ciphertext)
        }
        
        return results
    }
    
    /// Decrypt multiple messages in a batch
    ///
    /// - Parameter ciphertexts: Array of encrypted messages
    /// - Returns: Array of decrypted messages
    /// - Throws: NoiseError or CancellationError if cancelled
    public func readMessages(_ ciphertexts: [Data]) async throws -> [Data] {
        try Task.checkCancellation()
        
        var results: [Data] = []
        results.reserveCapacity(ciphertexts.count)
        
        for ciphertext in ciphertexts {
            try Task.checkCancellation() // Check between each operation
            let plaintext = try session.readMessage(ciphertext)
            results.append(plaintext)
        }
        
        return results
    }
}

// MARK: - AsyncSequence Support for Actor

/// AsyncSequence wrapper that works with actor-isolated sessions
///
/// This provides the same streaming functionality as AsyncNoiseMessageStream
/// but works safely with actor-isolated sessions.
public struct ActorNoiseMessageStream: AsyncSequence {
    public typealias Element = Data
    
    private let session: AsyncNoiseSession
    private let transport: AsyncMessageTransport
    
    /// Creates a new actor-based async message stream
    ///
    /// - Parameters:
    ///   - session: The actor-wrapped Noise session
    ///   - transport: The underlying transport
    public init(session: AsyncNoiseSession, transport: AsyncMessageTransport) {
        self.session = session
        self.transport = transport
    }
    
    public func makeAsyncIterator() -> AsyncIterator {
        return AsyncIterator(session: session, transport: transport)
    }
    
    public struct AsyncIterator: AsyncIteratorProtocol {
        private let session: AsyncNoiseSession
        private let transport: AsyncMessageTransport
        
        init(session: AsyncNoiseSession, transport: AsyncMessageTransport) {
            self.session = session
            self.transport = transport
        }
        
        public mutating func next() async throws -> Data? {
            try Task.checkCancellation()
            
            guard let ciphertext = try await transport.receive() else {
                return nil // Stream ended
            }
            
            return try await session.readMessage(ciphertext)
        }
    }
}

// MARK: - Factory Methods

extension AsyncNoiseSession {
    /// Convenience factory for creating authenticated sessions
    ///
    /// - Parameters:
    ///   - pattern: The handshake pattern
    ///   - initiator: Whether this is the initiator
    ///   - staticKeypair: Static keypair for authentication
    /// - Returns: New async session
    public static func authenticated(
        pattern: HandshakePattern,
        initiator: Bool,
        staticKeypair: KeyPair
    ) async throws -> AsyncNoiseSession {
        return try await AsyncNoiseSession(
            pattern: pattern,
            initiator: initiator,
            staticKeypair: staticKeypair
        )
    }
    
    /// Convenience factory for PSK-based sessions
    ///
    /// - Parameters:
    ///   - pattern: The PSK handshake pattern
    ///   - initiator: Whether this is the initiator
    ///   - psk: Pre-shared key
    ///   - staticKeypair: Optional static keypair
    /// - Returns: New async session
    public static func withPSK(
        pattern: HandshakePattern,
        initiator: Bool,
        psk: Data,
        staticKeypair: KeyPair? = nil
    ) async throws -> AsyncNoiseSession {
        return try await AsyncNoiseSession(
            pattern: pattern,
            initiator: initiator,
            staticKeypair: staticKeypair,
            psk: psk
        )
    }
}