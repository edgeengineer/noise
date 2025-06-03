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

/// Async/await extensions for Noise protocol operations
///
/// This extension provides async versions of all Noise protocol operations,
/// making it easy to integrate with modern Swift concurrency patterns in
/// networking applications.
///
/// ## Usage with URLSession
///
/// ```swift
/// // Create Noise session
/// var session = try NoiseProtocol.handshake(pattern: .XX, initiator: true, staticKeypair: keypair)
///
/// // Async handshake over network
/// let handshakeMessage = try await session.writeHandshakeMessageAsync()
/// try await sendToServer(handshakeMessage) // Your network code
///
/// let response = try await receiveFromServer() // Your network code  
/// let _ = try await session.readHandshakeMessageAsync(response)
///
/// // Async encrypted messaging
/// let plaintext = Data("Hello, secure world!".utf8)
/// let ciphertext = try await session.writeMessageAsync(plaintext)
/// try await sendToServer(ciphertext)
/// ```
///
/// ## Thread Safety
///
/// All async methods maintain the same thread safety characteristics as their
/// synchronous counterparts. Each `NoiseSession` should be used from a single
/// task or properly synchronized across tasks.
///
/// ## Performance
///
/// The async methods provide the same cryptographic performance as synchronous
/// versions while enabling better integration with Swift's structured concurrency.
/// They're particularly beneficial for networking code that benefits from
/// cooperative cancellation and structured task management.
extension NoiseSession {
    
    // MARK: - Async Handshake Operations
    
    /// Asynchronously creates a handshake message to send to the remote party
    ///
    /// This async version of `writeHandshakeMessage` enables integration with
    /// Swift's structured concurrency for networking applications.
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Create handshake message
    /// let message = try await session.writeHandshakeMessageAsync()
    /// 
    /// // Send over network using URLSession
    /// let (_, response) = try await urlSession.upload(for: request, from: message)
    /// ```
    ///
    /// - Parameter payload: Optional payload data to include in the handshake message
    /// - Returns: The handshake message to send to the remote party
    /// - Throws: `NoiseError.handshakeAlreadyComplete` if the handshake is already complete,
    ///           or other `NoiseError` types for cryptographic failures
    public mutating func writeHandshakeMessageAsync(payload: Data = Data()) async throws -> Data {
        try Task.checkCancellation()
        return try writeHandshakeMessage(payload: payload)
    }
    
    /// Asynchronously processes a handshake message received from the remote party
    ///
    /// This async version of `readHandshakeMessage` enables integration with
    /// Swift's structured concurrency for networking applications.
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Receive handshake message from network
    /// let (data, _) = try await urlSession.data(from: url)
    /// 
    /// // Process handshake message
    /// let payload = try await session.readHandshakeMessageAsync(data)
    /// 
    /// // Check if handshake is complete
    /// if session.isHandshakeComplete {
    ///     print("Handshake complete!")
    /// }
    /// ```
    ///
    /// - Parameter message: The handshake message received from the remote party
    /// - Returns: Any payload data included in the handshake message
    /// - Throws: `NoiseError.handshakeAlreadyComplete` if the handshake is already complete,
    ///           `NoiseError.authenticationFailure` for invalid handshake messages,
    ///           or other `NoiseError` types for cryptographic failures
    public mutating func readHandshakeMessageAsync(_ message: Data) async throws -> Data {
        try Task.checkCancellation()
        return try readHandshakeMessage(message)
    }
    
    // MARK: - Async Transport Operations
    
    /// Asynchronously encrypts and authenticates a message for transmission
    ///
    /// This async version of `writeMessage` enables integration with Swift's
    /// structured concurrency for secure messaging applications.
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Encrypt message
    /// let plaintext = Data("Secret message".utf8)
    /// let ciphertext = try await session.writeMessageAsync(plaintext)
    /// 
    /// // Send over network
    /// try await webSocket.send(.data(ciphertext))
    /// ```
    ///
    /// - Parameter plaintext: The message data to encrypt and authenticate
    /// - Returns: The encrypted and authenticated message ready for transmission
    /// - Throws: `NoiseError.handshakeNotComplete` if called before handshake completion,
    ///           `NoiseError.invalidMessageLength` if the message is too large,
    ///           `NoiseError.nonceOverflow` if too many messages have been sent,
    ///           or other `NoiseError` types for cryptographic failures
    public mutating func writeMessageAsync(_ plaintext: Data) async throws -> Data {
        try Task.checkCancellation()
        return try writeMessage(plaintext)
    }
    
    /// Asynchronously decrypts and authenticates a received message
    ///
    /// This async version of `readMessage` enables integration with Swift's
    /// structured concurrency for secure messaging applications.
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Receive encrypted message
    /// let message = try await webSocket.receive()
    /// if case .data(let ciphertext) = message {
    ///     // Decrypt message
    ///     let plaintext = try await session.readMessageAsync(ciphertext)
    ///     let text = String(data: plaintext, encoding: .utf8)
    ///     print("Received: \(text ?? "Invalid UTF-8")")
    /// }
    /// ```
    ///
    /// - Parameter ciphertext: The encrypted message received from the remote party
    /// - Returns: The decrypted and authenticated plaintext message
    /// - Throws: `NoiseError.handshakeNotComplete` if called before handshake completion,
    ///           `NoiseError.authenticationFailure` if message authentication fails,
    ///           `NoiseError.invalidMessageLength` if the message format is invalid,
    ///           or other `NoiseError` types for cryptographic failures
    public mutating func readMessageAsync(_ ciphertext: Data) async throws -> Data {
        try Task.checkCancellation()
        return try readMessage(ciphertext)
    }
    
    // MARK: - Async Session Management
    
    /// Asynchronously performs rekeying for forward secrecy
    ///
    /// This async version of `rekey` enables integration with Swift's structured
    /// concurrency for long-lived secure sessions.
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Check if rekeying is needed
    /// if session.shouldRekey() {
    ///     // Coordinate rekeying with remote party
    ///     try await notifyRemotePartyOfRekey()
    ///     
    ///     // Perform local rekeying
    ///     try await session.rekeyAsync()
    ///     
    ///     // Wait for remote party confirmation
    ///     try await waitForRemoteRekeyConfirmation()
    /// }
    /// ```
    ///
    /// - Important: Both parties must coordinate rekeying to maintain session synchronization.
    ///              This method only performs local rekeying - coordination with the remote
    ///              party is the application's responsibility.
    ///
    /// - Throws: `NoiseError.handshakeNotComplete` if called before handshake completion,
    ///           or other `NoiseError` types for cryptographic failures
    public mutating func rekeyAsync() async throws {
        try Task.checkCancellation()
        try rekey()
    }
}

// MARK: - Async NoiseProtocol Factory

extension NoiseProtocol {
    
    /// Asynchronously creates a new Noise handshake session
    ///
    /// This async version of the handshake factory method enables integration
    /// with Swift's structured concurrency for session initialization that might
    /// involve key loading, hardware security modules, or other async operations.
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Load keys asynchronously (e.g., from keychain)
    /// let staticKeypair = try await loadStaticKeypairFromKeychain()
    /// let remoteKey = try await fetchRemotePublicKey()
    /// 
    /// // Create session
    /// var session = try await NoiseProtocol.handshakeAsync(
    ///     pattern: .XX,
    ///     initiator: true,
    ///     staticKeypair: staticKeypair,
    ///     remoteStaticKey: remoteKey
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - pattern: The handshake pattern to use (e.g., `.NN`, `.NK`, `.XX`)
    ///   - initiator: Whether this party is the handshake initiator (`true`) or responder (`false`)
    ///   - prologue: Optional prologue data to mix into the handshake hash
    ///   - staticKeypair: Static keypair for patterns requiring authentication
    ///   - remoteStaticKey: Remote party's static public key (for patterns that require it)
    ///   - psk: Pre-shared key for PSK patterns
    /// - Returns: A new `NoiseSession` ready to begin the handshake
    /// - Throws: `NoiseError.unsupportedPattern` for unsupported handshake patterns,
    ///           `NoiseError.missingStaticKey` if required keys are not provided,
    ///           `NoiseError.missingPSK` if PSK is required but not provided,
    ///           or other `NoiseError` types for initialization failures
    public static func handshakeAsync(
        pattern: HandshakePattern,
        initiator: Bool,
        prologue: Data = Data(),
        staticKeypair: KeyPair? = nil,
        remoteStaticKey: Data? = nil,
        psk: Data? = nil
    ) async throws -> NoiseSession {
        try Task.checkCancellation()
        return try handshake(
            pattern: pattern,
            initiator: initiator,
            prologue: prologue,
            staticKeypair: staticKeypair,
            remoteStaticKey: remoteStaticKey,
            psk: psk
        )
    }
}

// MARK: - Sendable Conformance

/// Ensure NoiseSession can be safely passed across async boundaries
///
/// NoiseSession contains only value types and manages its own synchronization,
/// making it safe to send across actor boundaries in structured concurrency.
extension NoiseSession: @unchecked Sendable {}

// MARK: - AsyncSequence Support

/// Async sequence wrapper for continuous message processing
///
/// This provides a convenient way to process a stream of incoming encrypted
/// messages using async/await and for-await-in loops.
///
/// ## Example
///
/// ```swift
/// // Create async stream for incoming messages
/// let messageStream = AsyncNoiseMessageStream(session: session, transport: webSocket)
/// 
/// // Process messages as they arrive
/// for try await plaintext in messageStream {
///     let message = String(data: plaintext, encoding: .utf8) ?? "Invalid UTF-8"
///     print("Received: \(message)")
/// }
/// ```
public struct AsyncNoiseMessageStream: AsyncSequence {
    public typealias Element = Data
    
    private let session: NoiseSession
    private let transport: AsyncMessageTransport
    
    /// Creates a new async message stream
    ///
    /// - Parameters:
    ///   - session: The Noise session for decryption (must be handshake complete)
    ///   - transport: The underlying transport for receiving messages
    public init(session: NoiseSession, transport: AsyncMessageTransport) {
        self.session = session
        self.transport = transport
    }
    
    public func makeAsyncIterator() -> AsyncIterator {
        return AsyncIterator(session: session, transport: transport)
    }
    
    public struct AsyncIterator: AsyncIteratorProtocol {
        private var session: NoiseSession
        private let transport: AsyncMessageTransport
        
        init(session: NoiseSession, transport: AsyncMessageTransport) {
            self.session = session
            self.transport = transport
        }
        
        public mutating func next() async throws -> Data? {
            try Task.checkCancellation()
            
            guard let ciphertext = try await transport.receive() else {
                return nil // Stream ended
            }
            
            return try await session.readMessageAsync(ciphertext)
        }
    }
}

/// Protocol for async message transport
///
/// Implement this protocol to integrate NoiseSession with your networking layer.
/// Common implementations include WebSocket, TCP, UDP, or custom protocols.
///
/// ## Example Implementation
///
/// ```swift
/// struct WebSocketTransport: AsyncMessageTransport {
///     let webSocket: URLSessionWebSocketTask
///     
///     func receive() async throws -> Data? {
///         let message = try await webSocket.receive()
///         switch message {
///         case .data(let data):
///             return data
///         case .string:
///             throw TransportError.unexpectedMessageType
///         @unknown default:
///             throw TransportError.unknownMessageType
///         }
///     }
/// }
/// ```
public protocol AsyncMessageTransport {
    /// Receives the next message from the transport
    ///
    /// - Returns: The received message data, or `nil` if the stream has ended
    /// - Throws: Transport-specific errors for network failures
    func receive() async throws -> Data?
}