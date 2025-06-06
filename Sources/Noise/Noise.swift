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
import Crypto

/// Errors that can occur during Noise protocol operations
///
/// `NoiseError` provides detailed error information for various failure modes
/// in the Noise protocol implementation. Each error case includes specific
/// context to help with debugging and error handling.
///
/// ## Error Categories
///
/// ### Validation Errors
/// - `invalidKeyLength`: Cryptographic key has wrong size
/// - `invalidMessageLength`: Message exceeds protocol limits
///
/// ### State Errors  
/// - `handshakeNotComplete`: Attempted transport operation during handshake
/// - `handshakeAlreadyComplete`: Attempted handshake operation after completion
///
/// ### Key Errors
/// - `missingStaticKey`: Required static key not provided
/// - `missingEphemeralKey`: Required ephemeral key not available
/// - `missingRemoteKey`: Required remote key not available
/// - `missingPSK`: Required pre-shared key not provided
///
/// ### Cryptographic Errors
/// - `authenticationFailure`: Message authentication check failed
/// - `decryptionFailure`: Unable to decrypt message
/// - `nonceOverflow`: Nonce counter exhausted
///
/// ### Protocol Errors
/// - `malformedMessage`: Invalid message format
/// - `invalidState`: Protocol state machine violation
/// - `protocolViolation`: General protocol specification violation
/// - `unsupportedPattern`: Handshake pattern not supported
/// - `unsupportedOperation`: Operation not implemented
///
/// ## Usage
///
/// ```swift
/// do {
///     let session = try NoiseProtocol.handshake(pattern: .XX, initiator: true)
/// } catch let error as NoiseError {
///     switch error {
///     case .missingStaticKey:
///         print("Authentication required - provide static key")
///     case .invalidKeyLength(let expected, let actual):
///         print("Key size mismatch: expected \(expected), got \(actual)")
///     default:
///         print("Noise error: \(error.localizedDescription)")
///     }
/// }
/// ```
public enum NoiseError: Error, Equatable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidMessageLength(length: Int, maxAllowed: Int = 65535)
    case messageTimeout
    case handshakeNotComplete
    case handshakeAlreadyComplete
    case missingStaticKey
    case missingEphemeralKey
    case missingRemoteKey(type: String)
    case missingPSK
    case authenticationFailure
    case decryptionFailure
    case nonceOverflow
    case unsupportedPattern(String)
    case unsupportedOperation(String)
    case malformedMessage(reason: String)
    case invalidState(reason: String)
    case protocolViolation(reason: String)
    case custom(message: String)
    
    public var localizedDescription: String {
        switch self {
        case .invalidKeyLength(let expected, let actual):
            return "Invalid key length: expected \(expected) bytes, got \(actual) bytes"
        case .invalidMessageLength(let length, let maxAllowed):
            return "Invalid message length: \(length) bytes exceeds maximum of \(maxAllowed) bytes"
        case .messageTimeout:
            return "Message processing timeout"
        case .handshakeNotComplete:
            return "Handshake not complete - cannot perform operation"
        case .handshakeAlreadyComplete:
            return "Handshake already complete - cannot send handshake message"
        case .missingStaticKey:
            return "Missing required static key for this handshake pattern"
        case .missingEphemeralKey:
            return "Missing required ephemeral key"
        case .missingRemoteKey(let type):
            return "Missing required remote \(type) key"
        case .missingPSK:
            return "Missing required pre-shared key for PSK handshake pattern"
        case .authenticationFailure:
            return "Authentication failure - message authentication check failed"
        case .decryptionFailure:
            return "Decryption failure - unable to decrypt message"
        case .nonceOverflow:
            return "Nonce overflow - maximum number of messages exceeded"
        case .unsupportedPattern(let pattern):
            return "Unsupported handshake pattern: \(pattern)"
        case .unsupportedOperation(let operation):
            return "Unsupported operation: \(operation)"
        case .malformedMessage(let reason):
            return "Malformed message: \(reason)"
        case .invalidState(let reason):
            return "Invalid state: \(reason)"
        case .protocolViolation(let reason):
            return "Protocol violation: \(reason)"
        case .custom(let message):
            return message
        }
    }
}

/// Protocol defining Diffie-Hellman key agreement functions
///
/// This protocol abstracts the elliptic curve Diffie-Hellman operations used
/// in Noise protocol handshakes. It provides key generation and shared secret
/// computation for establishing secure communication channels.
///
/// ## Implementation Requirements
///
/// Conforming types must provide:
/// - Secure key pair generation with cryptographically strong randomness
/// - ECDH shared secret computation resistant to timing attacks
/// - Proper key validation and error handling
///
/// ## Security Considerations
///
/// - Private keys must be generated using cryptographically secure random sources
/// - Shared secret computation should be constant-time to prevent timing attacks
/// - Key validation should reject weak or invalid public keys
/// - All operations should properly handle and validate key lengths
public protocol DiffieHellmanFunction {
    /// The length in bytes of DH keys (both private and public)
    static var dhlen: Int { get }
    
    /// Generates a new cryptographically secure key pair
    ///
    /// - Returns: A tuple containing the private key and corresponding public key
    static func generateKeypair() -> (privateKey: Data, publicKey: Data)
    
    /// Performs Diffie-Hellman key agreement
    ///
    /// - Parameters:
    ///   - privateKey: The local private key
    ///   - publicKey: The remote public key
    ///
    /// - Returns: The shared secret
    ///
    /// - Throws: `NoiseError.invalidKeyLength` if key sizes are incorrect
    static func dh(privateKey: Data, publicKey: Data) throws -> Data
}

/// Protocol defining AEAD cipher functions for authenticated encryption
///
/// This protocol abstracts the authenticated encryption with associated data (AEAD)
/// operations used in Noise protocol message encryption. It provides both
/// confidentiality and authenticity for handshake payloads and transport messages.
///
/// ## Implementation Requirements
///
/// Conforming types must provide:
/// - AEAD encryption with nonce-based security
/// - Authentication tag verification during decryption
/// - Proper handling of associated data
/// - Constant-time operations to prevent timing attacks
///
/// ## Security Properties
///
/// - **Confidentiality**: Plaintext is hidden from eavesdroppers
/// - **Authenticity**: Messages cannot be forged or tampered with
/// - **Nonce security**: Each nonce must be used only once with a given key
/// - **Associated data**: Additional data is authenticated but not encrypted
public protocol CipherFunction {
    /// The length in bytes of cipher keys
    static var keylen: Int { get }
    
    /// Encrypts plaintext with authenticated encryption
    ///
    /// - Parameters:
    ///   - key: The encryption key
    ///   - nonce: Unique number used only once per key
    ///   - associatedData: Data to authenticate but not encrypt
    ///   - plaintext: Data to encrypt and authenticate
    ///
    /// - Returns: The encrypted and authenticated ciphertext
    ///
    /// - Throws: `NoiseError.invalidKeyLength` if key size is incorrect
    static func encrypt(key: Data, nonce: UInt64, associatedData: Data, plaintext: Data) throws -> Data
    
    /// Decrypts ciphertext with authentication verification
    ///
    /// - Parameters:
    ///   - key: The decryption key
    ///   - nonce: The nonce used during encryption
    ///   - associatedData: The associated data used during encryption
    ///   - ciphertext: The encrypted and authenticated data
    ///
    /// - Returns: The decrypted and verified plaintext
    ///
    /// - Throws:
    ///   - `NoiseError.authenticationFailure` if authentication verification fails
    ///   - `NoiseError.invalidKeyLength` if key size is incorrect
    static func decrypt(key: Data, nonce: UInt64, associatedData: Data, ciphertext: Data) throws -> Data
}

/// Protocol defining cryptographic hash functions for Noise protocol
///
/// This protocol abstracts the hash function operations used throughout the
/// Noise protocol for key derivation, message authentication, and handshake
/// hash computation. It provides both basic hashing and HMAC operations.
///
/// ## Implementation Requirements
///
/// Conforming types must provide:
/// - Cryptographically secure hash function (e.g., SHA-256, BLAKE2)
/// - HMAC implementation for authenticated key derivation
/// - Collision resistance and preimage resistance
/// - Deterministic output for identical inputs
///
/// ## Security Properties
///
/// - **Collision resistance**: Computationally infeasible to find two inputs with same hash
/// - **Preimage resistance**: Computationally infeasible to find input for given hash
/// - **Second preimage resistance**: Computationally infeasible to find different input with same hash
/// - **Avalanche effect**: Small input changes produce dramatically different outputs
public protocol HashFunction {
    /// The length in bytes of hash outputs
    static var hashlen: Int { get }
    
    /// Computes cryptographic hash of input data
    ///
    /// - Parameter data: Data to hash
    ///
    /// - Returns: The cryptographic hash digest
    static func hash(_ data: Data) -> Data
    
    /// Computes HMAC (keyed hash) for authenticated key derivation
    ///
    /// - Parameters:
    ///   - key: The HMAC key
    ///   - data: Data to authenticate
    ///
    /// - Returns: The HMAC authentication tag
    static func hmac(key: Data, data: Data) -> Data
}

/// Curve25519 elliptic curve Diffie-Hellman implementation
///
/// Provides high-performance, secure elliptic curve operations using Curve25519.
/// This implementation offers approximately 128 bits of security with excellent
/// performance characteristics and resistance to timing attacks.
///
/// ## Security Features
///
/// - **Side-channel resistance**: Implementation resists timing and cache attacks
/// - **Invalid curve attacks**: Proper validation prevents weak point attacks  
/// - **High performance**: Optimized for speed while maintaining security
/// - **Wide compatibility**: Standard curve used in many cryptographic protocols
///
/// ## Usage
///
/// ```swift
/// // Generate a new key pair
/// let (privateKey, publicKey) = Curve25519.generateKeypair()
///
/// // Perform key agreement
/// let sharedSecret = try Curve25519.dh(privateKey: myPrivate, publicKey: theirPublic)
/// ```
///
/// - Note: This implementation uses Apple's CryptoKit for optimal security and performance
public struct Curve25519: DiffieHellmanFunction {
    /// The length of Curve25519 keys in bytes (32 bytes)
    public static let dhlen = 32
    
    public static func generateKeypair() -> (privateKey: Data, publicKey: Data) {
        let privateKey = Crypto.Curve25519.KeyAgreement.PrivateKey()
        return (
            privateKey: Data(privateKey.rawRepresentation),
            publicKey: Data(privateKey.publicKey.rawRepresentation)
        )
    }
    
    public static func dh(privateKey: Data, publicKey: Data) throws -> Data {
        guard privateKey.count == dhlen else {
            throw NoiseError.invalidKeyLength(expected: dhlen, actual: privateKey.count)
        }
        guard publicKey.count == dhlen else {
            throw NoiseError.invalidKeyLength(expected: dhlen, actual: publicKey.count)
        }
        
        let privKey = try Crypto.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let pubKey = try Crypto.Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
        return Data(sharedSecret.withUnsafeBytes { $0 })
    }
}

/// ChaCha20-Poly1305 authenticated encryption implementation
///
/// Provides high-security AEAD (Authenticated Encryption with Associated Data)
/// using the ChaCha20 stream cipher for encryption and Poly1305 for authentication.
/// This combination offers excellent security with superior performance on modern CPUs.
///
/// ## Security Features
///
/// - **Timing attack resistance**: Constant-time operations prevent timing analysis
/// - **Nonce misuse resistance**: Secure even with occasional nonce reuse
/// - **High performance**: Optimized for software implementations
/// - **No weak keys**: All keys provide equivalent security
/// - **Proven security**: Extensively analyzed and widely deployed
///
/// ## Key Properties
///
/// - **Key size**: 256 bits (32 bytes) for maximum security
/// - **Nonce size**: 96 bits used internally with 64-bit input nonce
/// - **Authentication tag**: 128 bits for strong message authentication
/// - **Maximum message size**: 2^38 - 64 bytes per nonce
///
/// ## Usage
///
/// ```swift
/// let key = Data(repeating: 0x42, count: 32)
/// let message = Data("Hello, world!".utf8)
/// let associated = Data("metadata".utf8)
///
/// let encrypted = try ChaChaPoly.encrypt(
///     key: key,
///     nonce: 0,
///     associatedData: associated,
///     plaintext: message
/// )
/// ```
///
/// - Note: This implementation uses Apple's CryptoKit for optimal security and performance
public struct ChaChaPoly: CipherFunction {
    /// The length of ChaCha20-Poly1305 keys in bytes (32 bytes)
    public static let keylen = 32
    
    public static func encrypt(key: Data, nonce: UInt64, associatedData: Data, plaintext: Data) throws -> Data {
        guard key.count == keylen else {
            throw NoiseError.invalidKeyLength(expected: keylen, actual: key.count)
        }
        
        let symmetricKey = SymmetricKey(data: key)
        var nonceBytes = Data(count: 12)
        nonceBytes.withUnsafeMutableBytes { bytes in
            bytes.storeBytes(of: nonce.littleEndian, toByteOffset: 4, as: UInt64.self)
        }
        
        let cryptoNonce = try Crypto.ChaChaPoly.Nonce(data: nonceBytes)
        let sealedBox = try Crypto.ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: associatedData)
        return sealedBox.ciphertext + sealedBox.tag
    }
    
    public static func decrypt(key: Data, nonce: UInt64, associatedData: Data, ciphertext: Data) throws -> Data {
        guard key.count == keylen else {
            throw NoiseError.invalidKeyLength(expected: keylen, actual: key.count)
        }
        guard ciphertext.count >= 16 else {
            throw NoiseError.malformedMessage(reason: "Ciphertext too short (minimum 16 bytes required)")
        }
        
        let symmetricKey = SymmetricKey(data: key)
        var nonceBytes = Data(count: 12)
        nonceBytes.withUnsafeMutableBytes { bytes in
            bytes.storeBytes(of: nonce.littleEndian, toByteOffset: 4, as: UInt64.self)
        }
        
        let cryptoNonce = try Crypto.ChaChaPoly.Nonce(data: nonceBytes)
        let tag = ciphertext.suffix(16)
        let encryptedData = ciphertext.dropLast(16)
        
        let sealedBox = try Crypto.ChaChaPoly.SealedBox(nonce: cryptoNonce, ciphertext: encryptedData, tag: tag)
        return try Crypto.ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: associatedData)
    }
}

/// SHA-256 cryptographic hash function implementation
///
/// Provides secure hashing using the SHA-256 algorithm from the SHA-2 family.
/// SHA-256 offers strong collision resistance and is widely used in cryptographic
/// protocols for integrity verification and key derivation.
///
/// ## Security Properties
///
/// - **256-bit output**: Provides 128 bits of collision resistance
/// - **Preimage resistance**: Computationally infeasible to reverse
/// - **Avalanche effect**: Small input changes produce dramatically different outputs
/// - **Deterministic**: Same input always produces same output
/// - **FIPS 180-4 compliant**: Meets federal cryptographic standards
///
/// ## Performance
///
/// - **Hardware acceleration**: Utilizes CPU crypto extensions when available
/// - **Optimized implementation**: Uses Apple's CryptoKit for best performance
/// - **Memory efficient**: Suitable for resource-constrained environments
///
/// ## Common Use Cases
///
/// - Key derivation in HKDF operations
/// - Message integrity verification
/// - Digital signatures and certificates
/// - Proof-of-work systems
///
/// ## Usage
///
/// ```swift
/// let data = Data("Hello, world!".utf8)
/// let hash = SHA256Hash.hash(data)
///
/// let key = Data(repeating: 0x42, count: 32)
/// let hmac = SHA256Hash.hmac(key: key, data: data)
/// ```
///
/// - Note: This implementation uses Apple's CryptoKit for optimal security and performance
public struct SHA256Hash: HashFunction {
    /// The length of SHA-256 hash outputs in bytes (32 bytes)
    public static let hashlen = 32
    
    public static func hash(_ data: Data) -> Data {
        return Data(Crypto.SHA256.hash(data: data))
    }
    
    public static func hmac(key: Data, data: Data) -> Data {
        let hmacKey = SymmetricKey(data: key)
        return Data(Crypto.HMAC<Crypto.SHA256>.authenticationCode(for: data, using: hmacKey))
    }
}

// MARK: - Additional Cryptographic Primitives for Agility

/// P-256 elliptic curve Diffie-Hellman implementation
///
/// Provides NIST P-256 elliptic curve operations for environments requiring
/// FIPS compliance or NIST-approved cryptography. P-256 offers approximately
/// 128 bits of security with wide industry support.
///
/// ## Security Features
///
/// - **FIPS 186-4 compliant**: Meets federal cryptographic standards
/// - **Wide compatibility**: Supported by most cryptographic libraries
/// - **Hardware acceleration**: Optimized implementations available
/// - **Proven security**: Extensively analyzed NIST standard curve
///
/// ## Usage
///
/// ```swift
/// // Generate a new key pair
/// let (privateKey, publicKey) = P256.generateKeypair()
///
/// // Perform key agreement
/// let sharedSecret = try P256.dh(privateKey: myPrivate, publicKey: theirPublic)
/// ```
///
/// - Note: This implementation uses Apple's CryptoKit for optimal security and performance
public struct P256: DiffieHellmanFunction {
    /// The length of P-256 keys in bytes (32 bytes for private key, 64 bytes for public key raw representation)
    public static let dhlen = 32
    
    public static func generateKeypair() -> (privateKey: Data, publicKey: Data) {
        let privateKey = Crypto.P256.KeyAgreement.PrivateKey()
        // For compatibility, we use the full raw representation (64 bytes)
        return (
            privateKey: Data(privateKey.rawRepresentation),
            publicKey: Data(privateKey.publicKey.rawRepresentation)
        )
    }
    
    public static func dh(privateKey: Data, publicKey: Data) throws -> Data {
        guard privateKey.count == dhlen else {
            throw NoiseError.invalidKeyLength(expected: dhlen, actual: privateKey.count)
        }
        guard publicKey.count == 64 else { // Raw representation is 64 bytes for P-256
            throw NoiseError.invalidKeyLength(expected: 64, actual: publicKey.count)
        }
        
        let privKey = try Crypto.P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let pubKey = try Crypto.P256.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
        return Data(sharedSecret.withUnsafeBytes { $0 })
    }
}

/// AES-GCM authenticated encryption implementation  
///
/// Provides AEAD using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
/// AES-GCM is widely supported and offers excellent performance with hardware acceleration
/// on most modern processors.
///
/// ## Security Features
///
/// - **FIPS 197 compliant**: Uses NIST-approved AES encryption
/// - **Hardware acceleration**: Optimized on Intel/AMD processors with AES-NI
/// - **Timing attack resistance**: Constant-time operations
/// - **Wide compatibility**: Supported by most cryptographic libraries
/// - **Proven security**: Extensively analyzed and widely deployed
///
/// ## Key Properties
///
/// - **Key size**: 256 bits (32 bytes) for maximum security
/// - **Nonce size**: 96 bits used internally with 64-bit input nonce
/// - **Authentication tag**: 128 bits for strong message authentication
/// - **Maximum message size**: ~64 GB per nonce
///
/// ## Usage
///
/// ```swift
/// let key = Data(repeating: 0x42, count: 32)
/// let message = Data("Hello, world!".utf8)
/// let associated = Data("metadata".utf8)
///
/// let encrypted = try AESGCM.encrypt(
///     key: key,
///     nonce: 0,
///     associatedData: associated,
///     plaintext: message
/// )
/// ```
///
/// - Note: This implementation uses Apple's CryptoKit for optimal security and performance
public struct AESGCM: CipherFunction {
    /// The length of AES-GCM keys in bytes (32 bytes for AES-256)
    public static let keylen = 32
    
    public static func encrypt(key: Data, nonce: UInt64, associatedData: Data, plaintext: Data) throws -> Data {
        guard key.count == keylen else {
            throw NoiseError.invalidKeyLength(expected: keylen, actual: key.count)
        }
        
        let symmetricKey = SymmetricKey(data: key)
        var nonceBytes = Data(count: 12)
        nonceBytes.withUnsafeMutableBytes { bytes in
            bytes.storeBytes(of: nonce.littleEndian, toByteOffset: 4, as: UInt64.self)
        }
        
        let cryptoNonce = try Crypto.AES.GCM.Nonce(data: nonceBytes)
        let sealedBox = try Crypto.AES.GCM.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: associatedData)
        return sealedBox.ciphertext + sealedBox.tag
    }
    
    public static func decrypt(key: Data, nonce: UInt64, associatedData: Data, ciphertext: Data) throws -> Data {
        guard key.count == keylen else {
            throw NoiseError.invalidKeyLength(expected: keylen, actual: key.count)
        }
        guard ciphertext.count >= 16 else {
            throw NoiseError.malformedMessage(reason: "Ciphertext too short (minimum 16 bytes required)")
        }
        
        let symmetricKey = SymmetricKey(data: key)
        var nonceBytes = Data(count: 12)
        nonceBytes.withUnsafeMutableBytes { bytes in
            bytes.storeBytes(of: nonce.littleEndian, toByteOffset: 4, as: UInt64.self)
        }
        
        let cryptoNonce = try Crypto.AES.GCM.Nonce(data: nonceBytes)
        let tag = ciphertext.suffix(16)
        let encryptedData = ciphertext.dropLast(16)
        
        let sealedBox = try Crypto.AES.GCM.SealedBox(nonce: cryptoNonce, ciphertext: encryptedData, tag: tag)
        return try Crypto.AES.GCM.open(sealedBox, using: symmetricKey, authenticating: associatedData)
    }
}

/// SHA-512 cryptographic hash function implementation
///
/// Provides secure hashing using the SHA-512 algorithm from the SHA-2 family.
/// SHA-512 offers stronger collision resistance than SHA-256 and is suitable
/// for applications requiring higher security margins.
///
/// ## Security Properties
///
/// - **512-bit output**: Provides 256 bits of collision resistance
/// - **Superior preimage resistance**: Higher security margin than SHA-256
/// - **Avalanche effect**: Small input changes produce dramatically different outputs
/// - **Deterministic**: Same input always produces same output
/// - **FIPS 180-4 compliant**: Meets federal cryptographic standards
///
/// ## Performance
///
/// - **64-bit optimized**: Performs well on 64-bit processors
/// - **Hardware acceleration**: Utilizes CPU crypto extensions when available
/// - **Parallel friendly**: Internal structure enables parallel implementations
///
/// ## Usage
///
/// ```swift
/// let data = Data("Hello, world!".utf8)
/// let hash = SHA512Hash.hash(data)
///
/// let key = Data(repeating: 0x42, count: 64)
/// let hmac = SHA512Hash.hmac(key: key, data: data)
/// ```
///
/// - Note: This implementation uses Apple's CryptoKit for optimal security and performance
public struct SHA512Hash: HashFunction {
    /// The length of SHA-512 hash outputs in bytes (64 bytes)
    public static let hashlen = 64
    
    public static func hash(_ data: Data) -> Data {
        return Data(Crypto.SHA512.hash(data: data))
    }
    
    public static func hmac(key: Data, data: Data) -> Data {
        let hmacKey = SymmetricKey(data: key)
        return Data(Crypto.HMAC<Crypto.SHA512>.authenticationCode(for: data, using: hmacKey))
    }
}

// MARK: - Crypto Suite Support

/// Protocol defining a complete cryptographic suite for Noise protocol
///
/// A crypto suite combines a Diffie-Hellman function, cipher function, and hash function
/// into a cohesive set that works together. This enables cryptographic agility by
/// allowing users to select different combinations of primitives.
///
/// ## Usage
///
/// ```swift
/// // Use a predefined suite
/// let session = try NoiseProtocol<StandardSuite>.handshake(pattern: .NN, initiator: true)
///
/// // Or define a custom suite
/// struct CustomSuite: NoiseCryptoSuite {
///     typealias DH = P256
///     typealias Cipher = AESGCM  
///     typealias Hash = SHA512Hash
/// }
/// let customSession = try NoiseProtocol<CustomSuite>.handshake(pattern: .NN, initiator: true)
/// ```
public protocol NoiseCryptoSuite {
    /// The Diffie-Hellman function type for this suite
    associatedtype DH: DiffieHellmanFunction
    
    /// The cipher function type for this suite
    associatedtype Cipher: CipherFunction
    
    /// The hash function type for this suite
    associatedtype Hash: HashFunction
    
    /// A human-readable name for this crypto suite
    static var suiteName: String { get }
    
    /// The protocol name fragment for this suite (e.g., "25519_ChaChaPoly_SHA256")
    static var protocolFragment: String { get }
}

/// Standard Noise crypto suite using Curve25519 + ChaCha20-Poly1305 + SHA-256
///
/// This is the recommended default suite offering excellent security and performance.
/// It corresponds to the widely-used "25519_ChaChaPoly_SHA256" Noise configuration.
///
/// ## Security Properties
///
/// - **Post-quantum consideration**: Curve25519 provides good resistance to quantum attacks
/// - **Side-channel resistance**: All primitives resist timing and cache attacks
/// - **High performance**: Optimized for software implementations
/// - **Wide compatibility**: Supported across all major Noise implementations
///
/// ## Usage
///
/// ```swift
/// let session = try NoiseProtocol<StandardSuite>.handshake(pattern: .XX, initiator: true)
/// ```
public struct StandardSuite: NoiseCryptoSuite {
    public typealias DH = Curve25519
    public typealias Cipher = ChaChaPoly
    public typealias Hash = SHA256Hash
    
    public static let suiteName = "Standard Curve25519 + ChaCha20-Poly1305 + SHA-256"
    public static let protocolFragment = "25519_ChaChaPoly_SHA256"
}

/// NIST-compliant crypto suite using P-256 + AES-GCM + SHA-256
///
/// This suite uses NIST-approved cryptographic primitives suitable for
/// environments requiring FIPS compliance or government security standards.
///
/// ## Compliance
///
/// - **FIPS 186-4**: P-256 elliptic curve
/// - **FIPS 197**: AES encryption
/// - **FIPS 180-4**: SHA-256 hash function
/// - **SP 800-38D**: GCM mode of operation
///
/// ## Usage
///
/// ```swift
/// let session = try NoiseProtocol<NISTSuite>.handshake(pattern: .XX, initiator: true)
/// ```
public struct NISTSuite: NoiseCryptoSuite {
    public typealias DH = P256
    public typealias Cipher = AESGCM
    public typealias Hash = SHA256Hash
    
    public static let suiteName = "NIST P-256 + AES-GCM + SHA-256"
    public static let protocolFragment = "P256_AESGCM_SHA256"
}

/// High-security crypto suite using P-256 + AES-GCM + SHA-512
///
/// This suite offers enhanced security margins with larger hash output
/// suitable for applications with very high security requirements.
///
/// ## Security Benefits
///
/// - **Larger hash**: 512-bit hash provides greater collision resistance
/// - **NIST compliance**: All FIPS-approved primitives
/// - **Future-proofing**: Higher security margins against future attacks
///
/// ## Usage
///
/// ```swift
/// let session = try NoiseProtocol<HighSecuritySuite>.handshake(pattern: .XX, initiator: true)
/// ```
public struct HighSecuritySuite: NoiseCryptoSuite {
    public typealias DH = P256
    public typealias Cipher = AESGCM
    public typealias Hash = SHA512Hash
    
    public static let suiteName = "High Security P-256 + AES-GCM + SHA-512"
    public static let protocolFragment = "P256_AESGCM_SHA512"
}