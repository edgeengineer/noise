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

/// Policy for automatic rekeying in long-lived Noise sessions
///
/// Rekeying provides forward secrecy by periodically updating cipher keys,
/// ensuring that compromise of current keys cannot decrypt past messages.
///
/// ## Usage
///
/// ```swift
/// // Rekey after every 1000 messages
/// session.rekeyPolicy = .messageCount(1000)
///
/// // Rekey after 1 hour
/// session.rekeyPolicy = .timeInterval(3600)
///
/// // Manual rekeying only
/// session.rekeyPolicy = .manual
/// ```
public enum RekeyPolicy {
    /// No automatic rekeying - rekey() must be called manually
    case manual
    
    /// Rekey after sending/receiving a specified number of messages
    case messageCount(Int)
    
    /// Rekey after a specified time interval (in seconds)
    case timeInterval(TimeInterval)
    
    /// Rekey when nonce reaches a specified threshold (prevents nonce exhaustion)
    case nonceThreshold(UInt64)
}

/// A Swift implementation of the Noise Protocol Framework
///
/// The Noise Protocol Framework is a framework for building cryptographic protocols based on
/// Diffie-Hellman key agreement, symmetric encryption, and hash functions. It provides a simple
/// and flexible approach to building secure communication protocols.
///
/// ## Quick Start
///
/// ```swift
/// // Basic NN handshake (no authentication)
/// var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
/// var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
///
/// // Perform handshake
/// let message1 = try initiator.writeHandshakeMessage()
/// let _ = try responder.readHandshakeMessage(message1)
///
/// let message2 = try responder.writeHandshakeMessage()
/// let _ = try initiator.readHandshakeMessage(message2)
///
/// // Send encrypted messages
/// let plaintext = Data("Hello, Noise!".utf8)
/// let ciphertext = try initiator.writeMessage(plaintext)
/// let decrypted = try responder.readMessage(ciphertext)
/// ```
///
/// ## Supported Patterns
///
/// ### Basic Patterns
/// - **NN**: No authentication (anonymous)
/// - **NK**: Known responder key
/// - **XX**: Mutual authentication
///
/// ### One-way Patterns
/// - **N**: Anonymous initiator, known responder
/// - **K**: Known keys on both sides
/// - **X**: Mutual authentication, one message
///
/// ### Interactive Patterns
/// - **IX**: Immediate authentication
/// - **IK**: Known responder, authenticated initiator
///
/// ### PSK Patterns
/// - **NNpsk0, NNpsk2**: PSK variants of NN
/// - **NKpsk0, NKpsk2**: PSK variants of NK
/// - **XXpsk3**: PSK variant of XX
///
/// ## Security Features
///
/// - **Perfect Forward Secrecy**: Each session uses ephemeral keys
/// - **Mutual Authentication**: Verify identity of both parties (when using authenticated patterns)
/// - **Pre-shared Keys**: Additional security layer with PSK patterns
/// - **Replay Protection**: Built-in nonce management prevents replay attacks
/// - **Message Size Limits**: Enforces 65535-byte Noise protocol limits
public struct NoiseProtocol {
    
    /// Creates a new Noise handshake session
    ///
    /// This method initializes a new Noise protocol session with the specified handshake pattern
    /// and configuration. The returned `NoiseSession` can be used to perform the handshake and
    /// subsequent encrypted communication.
    ///
    /// - Parameters:
    ///   - pattern: The handshake pattern to use (e.g., `.NN`, `.NK`, `.XX`)
    ///   - initiator: Whether this party is the handshake initiator (`true`) or responder (`false`)
    ///   - prologue: Optional prologue data to mix into the handshake hash
    ///   - staticKeypair: Static keypair for patterns requiring authentication
    ///   - remoteStaticKey: Remote party's static public key (for patterns that require it)
    ///   - psk: Pre-shared key for PSK patterns
    ///
    /// - Returns: A configured `NoiseSession` ready to begin the handshake
    ///
    /// - Throws: 
    ///   - `NoiseError.missingStaticKey`: Required static key not provided
    ///   - `NoiseError.missingPSK`: Required PSK not provided for PSK patterns
    ///
    /// ## Examples
    ///
    /// ### Anonymous handshake (NN pattern)
    /// ```swift
    /// let initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
    /// let responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
    /// ```
    ///
    /// ### Authenticated handshake (XX pattern)
    /// ```swift
    /// let initiatorKeys = KeyPair.generate()
    /// let responderKeys = KeyPair.generate()
    ///
    /// let initiator = try NoiseProtocol.handshake(
    ///     pattern: .XX,
    ///     initiator: true,
    ///     staticKeypair: initiatorKeys
    /// )
    /// let responder = try NoiseProtocol.handshake(
    ///     pattern: .XX,
    ///     initiator: false,
    ///     staticKeypair: responderKeys
    /// )
    /// ```
    ///
    /// ### PSK handshake (NNpsk0 pattern)
    /// ```swift
    /// let psk = Data(repeating: 0x42, count: 32)
    /// let initiator = try NoiseProtocol.handshake(
    ///     pattern: .NNpsk0,
    ///     initiator: true,
    ///     psk: psk
    /// )
    /// let responder = try NoiseProtocol.handshake(
    ///     pattern: .NNpsk0,
    ///     initiator: false,
    ///     psk: psk
    /// )
    /// ```
    public static func handshake(
        pattern: HandshakePattern,
        initiator: Bool,
        prologue: Data = Data(),
        staticKeypair: KeyPair? = nil,
        remoteStaticKey: Data? = nil,
        psk: Data? = nil
    ) throws -> NoiseSession {
        let handshakeState = try HandshakeState(
            pattern: pattern,
            initiator: initiator,
            prologue: prologue,
            s: staticKeypair,
            rs: remoteStaticKey,
            psk: psk
        )
        
        return NoiseSession(handshakeState: handshakeState)
    }
}

/// A Noise protocol session for performing handshakes and encrypted communication
///
/// `NoiseSession` manages the state of a Noise protocol session, handling both the handshake
/// phase and the subsequent transport phase. During the handshake, it manages the exchange
/// of key material and authentication data. After handshake completion, it provides
/// authenticated encryption for application messages.
///
/// ## Usage Pattern
///
/// 1. **Create session**: Use `NoiseProtocol.handshake()` to create a session
/// 2. **Perform handshake**: Exchange handshake messages until `isHandshakeComplete` is `true`
/// 3. **Send/receive messages**: Use `writeMessage()` and `readMessage()` for encrypted communication
/// 4. **Optional rekeying**: Use `rekey()` for forward secrecy in long-lived sessions
///
/// ## Rekeying
///
/// For long-lived sessions, periodic rekeying provides forward secrecy:
///
/// ```swift
/// // Manual rekeying
/// try session.rekey()
///
/// // Automatic rekeying after 1000 messages
/// session.rekeyPolicy = .messageCount(1000)
/// ```
///
/// ## Example
///
/// ```swift
/// // Create sessions
/// var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
/// var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
///
/// // Handshake phase
/// let msg1 = try initiator.writeHandshakeMessage()
/// let _ = try responder.readHandshakeMessage(msg1)
///
/// let msg2 = try responder.writeHandshakeMessage()
/// let _ = try initiator.readHandshakeMessage(msg2)
///
/// assert(initiator.isHandshakeComplete && responder.isHandshakeComplete)
///
/// // Transport phase
/// let plaintext = Data("Hello, world!".utf8)
/// let ciphertext = try initiator.writeMessage(plaintext)
/// let decrypted = try responder.readMessage(ciphertext)
/// ```
///
/// ## Thread Safety
///
/// `NoiseSession` is not thread-safe. If you need to use it from multiple threads,
/// you must provide your own synchronization.
public struct NoiseSession {
    private var handshakeState: HandshakeState?
    private var sendCipher: CipherState<ChaChaPoly>?
    private var receiveCipher: CipherState<ChaChaPoly>?
    private var handshakeHash: Data?
    
    /// Policy for automatic rekeying
    public var rekeyPolicy: RekeyPolicy = .manual
    
    /// Counter for sent messages (used for message-based rekeying)
    private var sentMessageCount: Int = 0
    
    /// Counter for received messages (used for message-based rekeying)  
    private var receivedMessageCount: Int = 0
    
    /// Timestamp when session was created (used for time-based rekeying)
    private let sessionStartTime: Date = Date()
    
    /// Timestamp of last rekey operation
    private var lastRekeyTime: Date = Date()
    
    /// Whether the handshake phase has completed
    ///
    /// Returns `true` when all handshake messages have been exchanged and the session
    /// is ready for transport messages. When `true`, you can use `writeMessage()` and
    /// `readMessage()` for encrypted communication.
    public var isHandshakeComplete: Bool {
        return handshakeState == nil
    }
    
    internal init(handshakeState: HandshakeState) {
        self.handshakeState = handshakeState
    }
    
    /// Writes a handshake message
    ///
    /// Generates and returns the next handshake message according to the handshake pattern.
    /// The message contains cryptographic key material and, optionally, a payload that will
    /// be encrypted if the handshake state supports it.
    ///
    /// - Parameter payload: Optional payload data to include in the handshake message.
    ///                     Must be 65535 bytes or less.
    ///
    /// - Returns: The handshake message to send to the remote party
    ///
    /// - Throws:
    ///   - `NoiseError.handshakeAlreadyComplete`: Handshake is already finished
    ///   - `NoiseError.invalidMessageLength`: Payload exceeds 65535 bytes
    ///   - `NoiseError.missingStaticKey`: Required static key not available
    ///   - `NoiseError.missingPSK`: Required PSK not available
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Simple handshake message
    /// let message = try session.writeHandshakeMessage()
    ///
    /// // Handshake message with payload
    /// let payload = Data("Hello during handshake".utf8)
    /// let message = try session.writeHandshakeMessage(payload: payload)
    /// ```
    ///
    /// - Important: Call this method only when `isHandshakeComplete` is `false`.
    ///              The handshake pattern determines how many messages each party sends.
    public mutating func writeHandshakeMessage(payload: Data = Data()) throws -> Data {
        guard var hs = handshakeState else {
            throw NoiseError.handshakeAlreadyComplete
        }
        
        guard payload.count <= 65535 else {
            throw NoiseError.invalidMessageLength(length: payload.count)
        }
        
        let message = try hs.writeMessage(payload: payload)
        
        if hs.messageIndex == hs.messagePatterns.count {
            self.handshakeHash = hs.symmetricState.getHandshakeHash()
            let (cipher1, cipher2) = try hs.split()
            if hs.isInitiator {
                self.sendCipher = cipher1
                self.receiveCipher = cipher2
            } else {
                self.sendCipher = cipher2
                self.receiveCipher = cipher1
            }
            self.handshakeState = nil
        } else {
            self.handshakeState = hs
        }
        
        return message
    }
    
    /// Reads and processes a handshake message
    ///
    /// Processes a handshake message received from the remote party, extracting key material
    /// and any included payload. This method updates the internal handshake state and may
    /// complete the handshake if this was the final message.
    ///
    /// - Parameter message: The handshake message received from the remote party.
    ///                     Must be 65535 bytes or less.
    ///
    /// - Returns: Any payload data included in the handshake message
    ///
    /// - Throws:
    ///   - `NoiseError.handshakeAlreadyComplete`: Handshake is already finished
    ///   - `NoiseError.invalidMessageLength`: Message exceeds 65535 bytes
    ///   - `NoiseError.authenticationFailure`: Message authentication failed
    ///   - `NoiseError.malformedMessage`: Message format is invalid
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Process received handshake message
    /// let payload = try session.readHandshakeMessage(receivedMessage)
    /// 
    /// // Check if handshake is complete
    /// if session.isHandshakeComplete {
    ///     print("Handshake finished, ready for transport messages")
    /// }
    /// ```
    ///
    /// - Important: Call this method only when `isHandshakeComplete` is `false`.
    ///              Process messages in the order defined by the handshake pattern.
    public mutating func readHandshakeMessage(_ message: Data) throws -> Data {
        guard var hs = handshakeState else {
            throw NoiseError.handshakeAlreadyComplete
        }
        
        guard message.count <= 65535 else {
            throw NoiseError.invalidMessageLength(length: message.count)
        }
        
        let payload = try hs.readMessage(message)
        
        if hs.messageIndex == hs.messagePatterns.count {
            self.handshakeHash = hs.symmetricState.getHandshakeHash()
            let (cipher1, cipher2) = try hs.split()
            if hs.isInitiator {
                self.sendCipher = cipher1
                self.receiveCipher = cipher2
            } else {
                self.sendCipher = cipher2
                self.receiveCipher = cipher1
            }
            self.handshakeState = nil
        } else {
            self.handshakeState = hs
        }
        
        return payload
    }
    
    /// Encrypts and sends a transport message
    ///
    /// Encrypts application data using the established transport keys. This method can only
    /// be called after the handshake is complete. Each message is encrypted with a unique
    /// nonce to prevent replay attacks.
    ///
    /// - Parameter plaintext: The application data to encrypt. Must be 65535 bytes or less.
    ///
    /// - Returns: The encrypted message to send to the remote party
    ///
    /// - Throws:
    ///   - `NoiseError.handshakeNotComplete`: Handshake must be completed first
    ///   - `NoiseError.invalidMessageLength`: Plaintext exceeds 65535 bytes
    ///   - `NoiseError.nonceOverflow`: Too many messages sent (nonce exhausted)
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Encrypt application data
    /// let data = Data("Hello, secure world!".utf8)
    /// let ciphertext = try session.writeMessage(data)
    /// 
    /// // Send ciphertext to remote party...
    /// ```
    ///
    /// ## Security
    ///
    /// - Each message uses a unique nonce for replay protection
    /// - Messages are authenticated and cannot be tampered with
    /// - Forward secrecy is maintained through the handshake's ephemeral keys
    ///
    /// - Important: Only call after `isHandshakeComplete` returns `true`
    public mutating func writeMessage(_ plaintext: Data) throws -> Data {
        guard var cipher = sendCipher else {
            throw NoiseError.handshakeNotComplete
        }
        
        guard plaintext.count <= 65535 else {
            throw NoiseError.invalidMessageLength(length: plaintext.count)
        }
        
        // Check if automatic rekeying is needed before sending
        try checkAndPerformAutomaticRekey()
        
        let ciphertext = try cipher.encryptWithAd(ad: Data(), plaintext: plaintext)
        self.sendCipher = cipher
        sentMessageCount += 1
        return ciphertext
    }
    
    /// Decrypts and reads a transport message
    ///
    /// Decrypts and authenticates a transport message received from the remote party.
    /// This method can only be called after the handshake is complete. Messages must
    /// be processed in the order they were sent to maintain nonce synchronization.
    ///
    /// - Parameter ciphertext: The encrypted message received from the remote party.
    ///                        Must be 65535 bytes or less.
    ///
    /// - Returns: The decrypted application data
    ///
    /// - Throws:
    ///   - `NoiseError.handshakeNotComplete`: Handshake must be completed first
    ///   - `NoiseError.invalidMessageLength`: Ciphertext exceeds 65535 bytes
    ///   - `NoiseError.authenticationFailure`: Message authentication failed
    ///   - `NoiseError.nonceOverflow`: Too many messages received (nonce exhausted)
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Decrypt received message
    /// let plaintext = try session.readMessage(receivedCiphertext)
    /// let message = String(data: plaintext, encoding: .utf8)
    /// ```
    ///
    /// ## Security
    ///
    /// - Messages are authenticated and tampering will be detected
    /// - Replay attacks are prevented through nonce validation
    /// - Out-of-order messages will cause authentication failures
    ///
    /// - Important: Only call after `isHandshakeComplete` returns `true`.
    ///              Process messages in the order they were sent.
    public mutating func readMessage(_ ciphertext: Data) throws -> Data {
        guard var cipher = receiveCipher else {
            throw NoiseError.handshakeNotComplete
        }
        
        guard ciphertext.count <= 65535 else {
            throw NoiseError.invalidMessageLength(length: ciphertext.count)
        }
        
        let plaintext = try cipher.decryptWithAd(ad: Data(), ciphertext: ciphertext)
        self.receiveCipher = cipher
        receivedMessageCount += 1
        
        // Check if automatic rekeying is needed after receiving
        try checkAndPerformAutomaticRekey()
        
        return plaintext
    }
    
    /// Returns the handshake hash
    ///
    /// The handshake hash is a cryptographic digest of all handshake messages and can be
    /// used for channel binding or additional authentication. It's available both during
    /// and after the handshake.
    ///
    /// - Returns: The current handshake hash, or `nil` if not yet available
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Get handshake hash for channel binding
    /// if let hash = session.getHandshakeHash() {
    ///     // Use hash for additional verification
    ///     print("Handshake hash: \(hash.hexString)")
    /// }
    /// ```
    ///
    /// ## Channel Binding
    ///
    /// The handshake hash can be used to bind the Noise session to a higher-level
    /// protocol, ensuring that both parties completed the same handshake.
    public func getHandshakeHash() -> Data? {
        return handshakeHash ?? handshakeState?.symmetricState.getHandshakeHash()
    }
    
    // MARK: - Rekeying Functionality
    
    /// Manually performs rekeying for forward secrecy
    ///
    /// Rekeying updates both send and receive cipher keys, providing forward secrecy by
    /// ensuring that compromise of current keys cannot decrypt past messages. Both parties
    /// must call this method at the same time to maintain synchronization.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Manual rekeying for long-lived sessions
    /// try session.rekey()
    ///
    /// // Rekey after processing sensitive data
    /// if processedSensitiveData {
    ///     try session.rekey()
    /// }
    /// ```
    ///
    /// ## Security
    ///
    /// - Provides forward secrecy for long-lived sessions
    /// - Protects against key compromise attacks
    /// - Should be coordinated between both parties
    /// - Resets message counters after successful rekey
    ///
    /// - Throws: `NoiseError.handshakeNotComplete` if called before handshake completion
    ///
    /// - Important: Both parties must rekey at the exact same time to maintain session integrity
    public mutating func rekey() throws {
        guard sendCipher != nil && receiveCipher != nil else {
            throw NoiseError.handshakeNotComplete
        }
        
        // Perform rekeying on both cipher states
        sendCipher?.rekey()
        receiveCipher?.rekey()
        
        // Reset counters and update timestamps
        sentMessageCount = 0
        receivedMessageCount = 0
        lastRekeyTime = Date()
    }
    
    /// Checks if automatic rekeying should be performed based on the current policy
    ///
    /// This method is called internally by `writeMessage()` and `readMessage()` to
    /// automatically perform rekeying when the configured policy conditions are met.
    ///
    /// - Throws: `NoiseError.handshakeNotComplete` if automatic rekey is attempted before handshake completion
    private mutating func checkAndPerformAutomaticRekey() throws {
        guard isHandshakeComplete else { return }
        
        let shouldRekey: Bool
        
        switch rekeyPolicy {
        case .manual:
            shouldRekey = false
            
        case .messageCount(let threshold):
            shouldRekey = sentMessageCount >= threshold || receivedMessageCount >= threshold
            
        case .timeInterval(let interval):
            shouldRekey = Date().timeIntervalSince(lastRekeyTime) >= interval
            
        case .nonceThreshold(let threshold):
            // Check if either cipher is approaching nonce exhaustion
            // Note: This is a conservative check - actual nonce values aren't exposed
            shouldRekey = sentMessageCount >= threshold || receivedMessageCount >= threshold
        }
        
        if shouldRekey {
            try rekey()
        }
    }
    
    /// Returns statistics about the current session for monitoring rekeying behavior
    ///
    /// Provides information about message counts, timing, and rekeying status that can be
    /// used to monitor session health and rekeying behavior.
    ///
    /// - Returns: A dictionary containing session statistics
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let stats = session.getSessionStatistics()
    /// print("Sent messages: \(stats["sentMessages"] ?? 0)")
    /// print("Time since last rekey: \(stats["timeSinceLastRekey"] ?? 0)")
    /// ```
    public func getSessionStatistics() -> [String: Any] {
        return [
            "sentMessages": sentMessageCount,
            "receivedMessages": receivedMessageCount,
            "totalMessages": sentMessageCount + receivedMessageCount,
            "sessionDuration": Date().timeIntervalSince(sessionStartTime),
            "timeSinceLastRekey": Date().timeIntervalSince(lastRekeyTime),
            "rekeyPolicy": String(describing: rekeyPolicy),
            "handshakeComplete": isHandshakeComplete
        ]
    }
    
    /// Checks if the session should be rekeyed based on the current policy
    ///
    /// This method allows checking whether rekeying would be triggered without
    /// actually performing the rekey operation. Useful for monitoring and logging.
    ///
    /// - Returns: `true` if the session should be rekeyed according to the current policy
    ///
    /// ## Usage
    ///
    /// ```swift
    /// if session.shouldRekey() {
    ///     print("Session is ready for rekeying")
    ///     try session.rekey()
    /// }
    /// ```
    public func shouldRekey() -> Bool {
        guard isHandshakeComplete else { return false }
        
        switch rekeyPolicy {
        case .manual:
            return false
            
        case .messageCount(let threshold):
            return sentMessageCount >= threshold || receivedMessageCount >= threshold
            
        case .timeInterval(let interval):
            return Date().timeIntervalSince(lastRekeyTime) >= interval
            
        case .nonceThreshold(let threshold):
            return sentMessageCount >= threshold || receivedMessageCount >= threshold
        }
    }
}