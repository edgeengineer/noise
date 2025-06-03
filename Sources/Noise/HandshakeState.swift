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

/// Noise protocol handshake patterns
///
/// Handshake patterns define the sequence of messages and cryptographic operations
/// performed during the Noise handshake. Each pattern provides different security
/// properties and authentication guarantees.
///
/// ## Pattern Naming
///
/// Pattern names use a systematic naming convention:
/// - First letter: Initiator's static key usage (`N` = none, `K` = known, `X` = transmitted, `I` = immediate)
/// - Second letter: Responder's static key usage (same meanings)
/// - Additional letters: Variations (`N` = interactive)
///
/// ## Security Properties
///
/// Different patterns provide different combinations of:
/// - **Authentication**: Verify the identity of the remote party
/// - **Forward secrecy**: Past messages remain secure even if long-term keys are compromised
/// - **Identity hiding**: Protect the identity of one or both parties
///
/// ## Pattern Categories
///
/// ### Anonymous Patterns
/// - **N**: One-way, anonymous initiator → known responder
/// - **NN**: Interactive, both parties anonymous
///
/// ### Pre-shared Key Patterns  
/// - **K**: One-way, both parties have pre-shared static keys
/// - **NK**: Interactive, initiator knows responder's static key
///
/// ### Mutual Authentication Patterns
/// - **X**: One-way, mutual authentication
/// - **XX**: Interactive, mutual authentication  
/// - **IX**: Interactive, immediate mutual authentication
/// - **IK**: Interactive, known responder + authenticated initiator
///
/// ### PSK Variants
/// PSK patterns add pre-shared symmetric keys for additional security:
/// - **NNpsk0**: NN with PSK at start of first message
/// - **NNpsk2**: NN with PSK at end of second message
/// - **NKpsk0, NKpsk2**: NK variants with PSK
/// - **XXpsk3**: XX with PSK at end of third message
public enum HandshakePattern: String, CaseIterable {
    case N, K, X, NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX
    // PSK variants - start with most common ones
    case NNpsk0, NNpsk2, NKpsk0, NKpsk2, XXpsk3
    
    var messagePatterns: [[Token]] {
        switch self {
        case .N:
            return [
                [.e, .es]
            ]
        case .K:
            return [
                [.e, .es, .ss]
            ]
        case .X:
            return [
                [.e, .es, .s, .ss]
            ]
        case .NN:
            return [
                [.e],
                [.e, .ee]
            ]
        case .NK:
            return [
                [.e, .es],
                [.e, .ee]
            ]
        case .NX:
            return [
                [.e],
                [.e, .ee, .s, .es]
            ]
        case .XN:
            return [
                [.e],
                [.e, .ee],
                [.s, .se]
            ]
        case .XK:
            return [
                [.e, .es],
                [.e, .ee],
                [.s, .se]
            ]
        case .XX:
            return [
                [.e],
                [.e, .ee, .s, .es],
                [.s, .se]
            ]
        case .KN:
            return [
                [.e],
                [.e, .ee, .se]
            ]
        case .KK:
            return [
                [.e, .es, .ss],
                [.e, .ee, .se]
            ]
        case .KX:
            return [
                [.e],
                [.e, .ee, .se, .s, .es]
            ]
        case .IN:
            return [
                [.e, .s],
                [.e, .ee, .se]
            ]
        case .IK:
            return [
                [.e, .es, .s, .ss],
                [.e, .ee, .se]
            ]
        case .IX:
            return [
                [.e, .s],
                [.e, .ee, .se, .s, .es]
            ]
        // PSK variants
        case .NNpsk0:
            return [
                [.psk, .e],
                [.e, .ee]
            ]
        case .NNpsk2:
            return [
                [.e],
                [.e, .ee, .psk]
            ]
        case .NKpsk0:
            return [
                [.psk, .e, .es],
                [.e, .ee]
            ]
        case .NKpsk2:
            return [
                [.e, .es],
                [.e, .ee, .psk]
            ]
        case .XXpsk3:
            return [
                [.e],
                [.e, .ee, .s, .es],
                [.s, .se, .psk]
            ]
        }
    }
    
    var isInitiator: Bool {
        return messagePatterns.count % 2 == 0
    }
    
    // Determine which static keys must be known during initialization
    var requiresInitiatorStaticForInit: Bool {
        switch self {
        case .K, .KN, .KK, .KX:
            return true // K patterns require both parties know initiator's static key
        default:
            return false
        }
    }
    
    var requiresResponderStaticForInit: Bool {
        switch self {
        case .N, .K, .X, .NK, .NX, .XK, .KN, .KK, .KX, .IK, .NKpsk0, .NKpsk2:
            return true // These patterns require initiator to know responder's static key beforehand
        default:
            return false // XX, NN, IN, IX patterns and their PSK variants discover keys during handshake
        }
    }
}

public enum Token {
    case e, s, ee, es, se, ss, psk
}

public struct HandshakeState {
    public var symmetricState: SymmetricState<ChaChaPoly, SHA256Hash>
    public let s: KeyPair?
    public var e: KeyPair?
    public var rs: Data?
    public var re: Data?
    public let messagePatterns: [[Token]]
    public let isInitiator: Bool
    public private(set) var messageIndex: Int = 0
    public let psk: Data?
    
    public init(
        pattern: HandshakePattern,
        initiator: Bool,
        prologue: Data = Data(),
        s: KeyPair? = nil,
        e: KeyPair? = nil,
        rs: Data? = nil,
        re: Data? = nil,
        psk: Data? = nil
    ) throws {
        let protocolName = "Noise_\(pattern.rawValue)_25519_ChaChaPoly_SHA256"
        self.symmetricState = SymmetricState<ChaChaPoly, SHA256Hash>(protocolName: protocolName)
        self.s = s
        self.e = e
        self.rs = rs
        self.re = re
        self.messagePatterns = pattern.messagePatterns
        self.isInitiator = initiator
        self.psk = psk
        
        self.symmetricState.mixHash(prologue)
        
        // Initialize patterns based on pre-shared knowledge requirements
        // Different patterns have different requirements for what keys must be known beforehand
        let requiresInitiatorStatic = pattern.requiresInitiatorStaticForInit
        let requiresResponderStatic = pattern.requiresResponderStaticForInit
        
        // Mix keys in the order specified by Noise: initiator static first, then responder static
        if requiresInitiatorStatic {
            if initiator {
                if let s = s {
                    self.symmetricState.mixHash(s.publicKey)
                }
            } else {
                if let rs = rs {
                    self.symmetricState.mixHash(rs)
                }
            }
        }
        
        if requiresResponderStatic {
            if initiator {
                if let rs = rs {
                    self.symmetricState.mixHash(rs)
                }
            } else {
                if let s = s {
                    self.symmetricState.mixHash(s.publicKey)
                }
            }
        }
    }
    
    public mutating func writeMessage(payload: Data = Data()) throws -> Data {
        guard messageIndex < messagePatterns.count else {
            throw NoiseError.invalidState(reason: "No more handshake messages to write")
        }
        
        let pattern = messagePatterns[messageIndex]
        var message = Data()
        
        for token in pattern {
            switch token {
            case .e:
                let keypair = Curve25519.generateKeypair()
                self.e = KeyPair(privateKey: keypair.privateKey, publicKey: keypair.publicKey)
                message.append(keypair.publicKey)
                symmetricState.mixHash(keypair.publicKey)
                if symmetricState.hasKey {
                    symmetricState.mixKey(keypair.publicKey)
                }
                
            case .s:
                if let s = s {
                    let encryptedS = try symmetricState.encryptAndHash(s.publicKey)
                    message.append(encryptedS)
                } else {
                    throw NoiseError.missingStaticKey
                }
                
            case .ee:
                if let e = e, let re = re {
                    let dh = try Curve25519.dh(privateKey: e.privateKey, publicKey: re)
                    symmetricState.mixKey(dh)
                } else {
                    throw NoiseError.missingEphemeralKey
                }
                
            case .es:
                if isInitiator {
                    if let e = e, let rs = rs {
                        let dh = try Curve25519.dh(privateKey: e.privateKey, publicKey: rs)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "static")
                    }
                } else {
                    if let s = s, let re = re {
                        let dh = try Curve25519.dh(privateKey: s.privateKey, publicKey: re)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "static")
                    }
                }
                
            case .se:
                if isInitiator {
                    if let s = s, let re = re {
                        let dh = try Curve25519.dh(privateKey: s.privateKey, publicKey: re)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "ephemeral")
                    }
                } else {
                    if let e = e, let rs = rs {
                        let dh = try Curve25519.dh(privateKey: e.privateKey, publicKey: rs)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "ephemeral")
                    }
                }
                
            case .ss:
                if let s = s, let rs = rs {
                    let dh = try Curve25519.dh(privateKey: s.privateKey, publicKey: rs)
                    symmetricState.mixKey(dh)
                } else {
                    throw NoiseError.missingStaticKey
                }
                
            case .psk:
                if let psk = psk {
                    symmetricState.mixKeyAndHash(psk)
                } else {
                    throw NoiseError.missingPSK
                }
            }
        }
        
        let encryptedPayload = try symmetricState.encryptAndHash(payload)
        message.append(encryptedPayload)
        
        messageIndex += 1
        return message
    }
    
    public mutating func readMessage(_ message: Data) throws -> Data {
        guard messageIndex < messagePatterns.count else {
            throw NoiseError.invalidState(reason: "No more handshake messages to read")
        }
        
        let pattern = messagePatterns[messageIndex]
        var messageOffset = 0
        
        for token in pattern {
            switch token {
            case .e:
                let publicKeySize = Curve25519.dhlen
                guard message.count >= messageOffset + publicKeySize else {
                    throw NoiseError.malformedMessage(reason: "Message too short for ephemeral key")
                }
                let reData = message.subdata(in: messageOffset..<messageOffset + publicKeySize)
                self.re = reData
                messageOffset += publicKeySize
                symmetricState.mixHash(reData)
                if symmetricState.hasKey {
                    symmetricState.mixKey(reData)
                }
                
            case .s:
                let expectedSize = symmetricState.hasKey ? Curve25519.dhlen + 16 : Curve25519.dhlen
                guard message.count >= messageOffset + expectedSize else {
                    throw NoiseError.malformedMessage(reason: "Message too short for static key")
                }
                let encryptedS = message.subdata(in: messageOffset..<messageOffset + expectedSize)
                messageOffset += expectedSize
                let decryptedS = try symmetricState.decryptAndHash(encryptedS)
                self.rs = decryptedS
                
            case .ee:
                if let e = e, let re = re {
                    let dh = try Curve25519.dh(privateKey: e.privateKey, publicKey: re)
                    symmetricState.mixKey(dh)
                } else {
                    throw NoiseError.missingEphemeralKey
                }
                
            case .es:
                if isInitiator {
                    if let e = e, let rs = rs {
                        let dh = try Curve25519.dh(privateKey: e.privateKey, publicKey: rs)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "static")
                    }
                } else {
                    if let s = s, let re = re {
                        let dh = try Curve25519.dh(privateKey: s.privateKey, publicKey: re)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "ephemeral")
                    }
                }
                
            case .se:
                if isInitiator {
                    if let s = s, let re = re {
                        let dh = try Curve25519.dh(privateKey: s.privateKey, publicKey: re)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "ephemeral")
                    }
                } else {
                    if let e = e, let rs = rs {
                        let dh = try Curve25519.dh(privateKey: e.privateKey, publicKey: rs)
                        symmetricState.mixKey(dh)
                    } else {
                        throw NoiseError.missingRemoteKey(type: "static")
                    }
                }
                
            case .ss:
                if let s = s, let rs = rs {
                    let dh = try Curve25519.dh(privateKey: s.privateKey, publicKey: rs)
                    symmetricState.mixKey(dh)
                } else {
                    throw NoiseError.missingStaticKey
                }
                
            case .psk:
                if let psk = psk {
                    symmetricState.mixKeyAndHash(psk)
                } else {
                    throw NoiseError.missingPSK
                }
            }
        }
        
        let remainingMessage = message.subdata(in: messageOffset..<message.count)
        let payload = try symmetricState.decryptAndHash(remainingMessage)
        
        messageIndex += 1
        return payload
    }
    
    public func split() throws -> (CipherState<ChaChaPoly>, CipherState<ChaChaPoly>) {
        guard messageIndex == messagePatterns.count else {
            throw NoiseError.handshakeNotComplete
        }
        return symmetricState.split()
    }
}

/// A Curve25519 key pair for Noise protocol handshakes
///
/// `KeyPair` represents a public/private key pair used for authentication and key
/// agreement in Noise protocol handshakes. It uses Curve25519 elliptic curve
/// cryptography for strong security with efficient performance.
///
/// ## Usage
///
/// ```swift
/// // Generate a new random key pair
/// let keyPair = KeyPair.generate()
///
/// // Use in authenticated handshake patterns
/// let session = try NoiseProtocol.handshake(
///     pattern: .XX,
///     initiator: true,
///     staticKeypair: keyPair
/// )
/// ```
///
/// ## Security
///
/// - Uses Curve25519 for elliptic curve Diffie-Hellman operations
/// - Private keys are 32 bytes of cryptographically secure random data
/// - Public keys are derived points on the Curve25519 elliptic curve
/// - Provides approximately 128 bits of security strength
///
/// ## Key Management
///
/// - Store private keys securely (e.g., in Keychain on iOS/macOS)
/// - Public keys can be shared freely for identity verification
/// - Generate new ephemeral keys for each session when possible
/// - Consider key rotation policies for long-term static keys
public struct KeyPair {
    /// The private key (32 bytes)
    public let privateKey: Data
    
    /// The public key (32 bytes)  
    public let publicKey: Data
    
    /// Creates a key pair from existing key material
    ///
    /// - Parameters:
    ///   - privateKey: The private key (must be 32 bytes)
    ///   - publicKey: The corresponding public key (must be 32 bytes)
    public init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
    
    /// Generates a new random key pair
    ///
    /// Creates a cryptographically secure random key pair suitable for use in
    /// Noise protocol handshakes. The private key is generated using the system's
    /// secure random number generator.
    ///
    /// - Returns: A new `KeyPair` with secure random keys
    ///
    /// ## Example
    ///
    /// ```swift
    /// let keyPair = KeyPair.generate()
    /// // keyPair.privateKey and keyPair.publicKey are ready to use
    /// ```
    ///
    /// - Important: Store the private key securely and never transmit it
    public static func generate() -> KeyPair {
        let (privateKey, publicKey) = Curve25519.generateKeypair()
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }
}