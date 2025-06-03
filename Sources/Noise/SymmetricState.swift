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

/// Manages the symmetric cryptographic state during Noise protocol handshakes
///
/// `SymmetricState` encapsulates the symmetric key state and handshake hash used during
/// the Noise protocol handshake phase. It provides operations for mixing key material,
/// hashing data, and encrypting/decrypting handshake payloads.
///
/// ## Core Operations
///
/// - **Key Mixing**: Derives new keys from Diffie-Hellman results and PSKs
/// - **Hash Accumulation**: Maintains a running hash of all handshake data
/// - **Encryption/Decryption**: Encrypts handshake payloads when keys are available
/// - **State Splitting**: Generates final transport keys at handshake completion
///
/// ## Usage
///
/// ```swift
/// var state = SymmetricState<ChaChaPoly, SHA256Hash>(protocolName: "Noise_XX_25519_ChaChaPoly_SHA256")
/// 
/// // Mix key material from DH operations
/// state.mixKey(dhResult)
/// 
/// // Hash handshake messages
/// state.mixHash(messageData)
/// 
/// // Encrypt payload when key is available
/// let ciphertext = try state.encryptAndHash(payload)
/// ```
///
/// - Note: This is an internal implementation detail of the Noise protocol.
///         Most users should interact with `NoiseSession` instead.
public struct SymmetricState<Cipher: CipherFunction, Hash: HashFunction> {
    private var cipherState: CipherState<Cipher>?
    private var ck: Data
    private var h: Data
    
    /// Whether the symmetric state has a cipher key available for encryption
    ///
    /// Returns `true` when key material has been mixed and encryption/decryption
    /// operations are available. Initially `false` until the first `mixKey()` call.
    public var hasKey: Bool {
        return cipherState != nil
    }
    
    /// Initializes a new symmetric state with the specified protocol name
    ///
    /// The protocol name is used to initialize the handshake hash according to the
    /// Noise specification. If the name is longer than the hash length, it's hashed;
    /// otherwise it's padded with zeros.
    ///
    /// - Parameter protocolName: The Noise protocol name (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
    ///
    /// ## Example
    ///
    /// ```swift
    /// let state = SymmetricState<ChaChaPoly, SHA256Hash>(
    ///     protocolName: "Noise_NN_25519_ChaChaPoly_SHA256"
    /// )
    /// ```
    public init(protocolName: String) {
        let protocolNameData = protocolName.data(using: .utf8) ?? Data()
        
        if protocolNameData.count <= Hash.hashlen {
            self.h = protocolNameData + Data(repeating: 0, count: Hash.hashlen - protocolNameData.count)
        } else {
            self.h = Hash.hash(protocolNameData)
        }
        
        self.ck = h
        self.cipherState = nil
    }
    
    /// Mixes new key material into the symmetric state
    ///
    /// Performs HKDF key derivation to generate a new chaining key and temporary key
    /// from the input key material. If a temporary key is produced, it initializes
    /// or updates the cipher state for encryption operations.
    ///
    /// - Parameter inputKeyMaterial: Key material to mix (typically from DH operations)
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Mix DH result into symmetric state
    /// let dhResult = try Curve25519.dh(privateKey: myPrivate, publicKey: theirPublic)
    /// symmetricState.mixKey(dhResult)
    /// ```
    ///
    /// - Note: This implements the `MixKey()` operation from the Noise specification
    public mutating func mixKey(_ inputKeyMaterial: Data) {
        let (newCk, tempK) = hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial)
        self.ck = newCk
        
        if tempK.count > 0 {
            self.cipherState = CipherState<Cipher>(key: tempK)
        }
    }
    
    /// Mixes data into the handshake hash
    ///
    /// Updates the running handshake hash by hashing the current hash concatenated
    /// with the new data. This operation accumulates all handshake messages and
    /// key material for authentication and channel binding.
    ///
    /// - Parameter data: Data to mix into the handshake hash
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Mix handshake message into hash
    /// symmetricState.mixHash(handshakeMessage)
    /// 
    /// // Mix public key into hash
    /// symmetricState.mixHash(publicKey)
    /// ```
    ///
    /// - Note: This implements the `MixHash()` operation from the Noise specification
    public mutating func mixHash(_ data: Data) {
        self.h = Hash.hash(h + data)
    }
    
    /// Mixes key material into both the chaining key and handshake hash
    ///
    /// Performs a 3-output HKDF operation to derive a new chaining key, hash input,
    /// and temporary encryption key from the input material. This operation is used
    /// for PSK mixing and other special key derivation scenarios.
    ///
    /// - Parameter inputKeyMaterial: Key material to mix (typically PSK data)
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Mix PSK into both key and hash chains
    /// symmetricState.mixKeyAndHash(preSharedKey)
    /// ```
    ///
    /// - Note: This implements the `MixKeyAndHash()` operation from the Noise specification,
    ///         primarily used for PSK operations
    public mutating func mixKeyAndHash(_ inputKeyMaterial: Data) {
        let (newCk, tempH, tempK) = hkdf3(chainingKey: ck, inputKeyMaterial: inputKeyMaterial)
        self.ck = newCk
        mixHash(tempH)
        
        if tempK.count > 0 {
            self.cipherState = CipherState<Cipher>(key: tempK)
        }
    }
    
    /// Returns the current handshake hash
    ///
    /// The handshake hash accumulates all handshake messages and key material,
    /// providing a cryptographic digest that can be used for channel binding
    /// and additional authentication.
    ///
    /// - Returns: The current handshake hash value
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let hash = symmetricState.getHandshakeHash()
    /// // Use hash for channel binding or verification
    /// ```
    ///
    /// - Note: Available throughout the handshake and used for final authentication
    public func getHandshakeHash() -> Data {
        return h
    }
    
    /// Encrypts plaintext and mixes the ciphertext into the handshake hash
    ///
    /// If a cipher key is available, encrypts the plaintext using the current handshake
    /// hash as associated data, then mixes the resulting ciphertext into the hash.
    /// If no key is available, simply mixes the plaintext and returns it unchanged.
    ///
    /// - Parameter plaintext: Data to encrypt and hash
    ///
    /// - Returns: Encrypted data (or plaintext if no key available)
    ///
    /// - Throws: `NoiseError.nonceOverflow` if nonce counter is exhausted
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let payload = Data("handshake payload".utf8)
    /// let encrypted = try symmetricState.encryptAndHash(payload)
    /// ```
    ///
    /// - Note: This implements the `EncryptAndHash()` operation from the Noise specification
    public mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        guard var cipher = cipherState else {
            mixHash(plaintext)
            return plaintext
        }
        
        let ciphertext = try cipher.encryptWithAd(ad: h, plaintext: plaintext)
        self.cipherState = cipher
        mixHash(ciphertext)
        return ciphertext
    }
    
    /// Decrypts ciphertext and mixes it into the handshake hash
    ///
    /// If a cipher key is available, decrypts the ciphertext using the current handshake
    /// hash as associated data, then mixes the ciphertext into the hash.
    /// If no key is available, simply mixes the ciphertext and returns it unchanged.
    ///
    /// - Parameter ciphertext: Data to decrypt and hash
    ///
    /// - Returns: Decrypted plaintext (or ciphertext if no key available)
    ///
    /// - Throws: 
    ///   - `NoiseError.authenticationFailure` if authentication tag verification fails
    ///   - `NoiseError.nonceOverflow` if nonce counter is exhausted
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let payload = try symmetricState.decryptAndHash(receivedCiphertext)
    /// ```
    ///
    /// - Note: This implements the `DecryptAndHash()` operation from the Noise specification
    public mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        guard var cipher = cipherState else {
            mixHash(ciphertext)
            return ciphertext
        }
        
        let plaintext = try cipher.decryptWithAd(ad: h, ciphertext: ciphertext)
        self.cipherState = cipher
        mixHash(ciphertext)
        return plaintext
    }
    
    /// Splits the symmetric state into two cipher states for transport phase
    ///
    /// Performs a final HKDF operation to derive two independent cipher keys from
    /// the final chaining key. These cipher states are used for sending and receiving
    /// transport messages after the handshake completes.
    ///
    /// - Returns: A tuple of two cipher states `(cipher1, cipher2)`
    ///           - For initiator: `(sendCipher, receiveCipher)`  
    ///           - For responder: `(receiveCipher, sendCipher)`
    ///
    /// ## Usage
    ///
    /// ```swift
    /// let (cipher1, cipher2) = symmetricState.split()
    /// // Assign ciphers based on initiator/responder role
    /// ```
    ///
    /// - Note: This implements the `Split()` operation from the Noise specification,
    ///         called at handshake completion to derive transport keys
    public func split() -> (CipherState<Cipher>, CipherState<Cipher>) {
        let (tempK1, tempK2) = hkdf2(chainingKey: ck, inputKeyMaterial: Data())
        return (
            CipherState<Cipher>(key: tempK1),
            CipherState<Cipher>(key: tempK2)
        )
    }
    
    private func hkdf(chainingKey: Data, inputKeyMaterial: Data) -> (Data, Data) {
        let tempKey = Hash.hmac(key: chainingKey, data: inputKeyMaterial)
        let output1 = Hash.hmac(key: tempKey, data: Data([0x01]))
        let output2 = Hash.hmac(key: tempKey, data: output1 + Data([0x02]))
        
        return (output1, Data(output2.prefix(Cipher.keylen)))
    }
    
    private func hkdf2(chainingKey: Data, inputKeyMaterial: Data) -> (Data, Data) {
        let tempKey = Hash.hmac(key: chainingKey, data: inputKeyMaterial)
        let output1 = Hash.hmac(key: tempKey, data: Data([0x01]))
        let output2 = Hash.hmac(key: tempKey, data: output1 + Data([0x02]))
        
        return (
            Data(output1.prefix(Cipher.keylen)),
            Data(output2.prefix(Cipher.keylen))
        )
    }
    
    private func hkdf3(chainingKey: Data, inputKeyMaterial: Data) -> (Data, Data, Data) {
        let tempKey = Hash.hmac(key: chainingKey, data: inputKeyMaterial)
        let output1 = Hash.hmac(key: tempKey, data: Data([0x01]))
        let output2 = Hash.hmac(key: tempKey, data: output1 + Data([0x02]))
        let output3 = Hash.hmac(key: tempKey, data: output2 + Data([0x03]))
        
        return (
            output1,
            output2,
            Data(output3.prefix(Cipher.keylen))
        )
    }
}

/// Manages AEAD encryption/decryption state with nonce tracking
///
/// `CipherState` encapsulates an AEAD cipher key and nonce counter for secure
/// message encryption and decryption. It automatically manages nonce increments
/// to prevent reuse and provides replay protection.
///
/// ## Features
///
/// - **Automatic nonce management**: Prevents nonce reuse vulnerabilities
/// - **AEAD encryption**: Provides both confidentiality and authenticity
/// - **Replay protection**: Sequential nonce validation prevents replay attacks
/// - **Key reuse prevention**: Nonce overflow detection for long-lived sessions
///
/// ## Usage
///
/// ```swift
/// var cipher = CipherState<ChaChaPoly>(key: derivedKey)
/// 
/// // Encrypt with associated data
/// let ciphertext = try cipher.encryptWithAd(ad: associatedData, plaintext: message)
/// 
/// // Decrypt and verify
/// let plaintext = try cipher.decryptWithAd(ad: associatedData, ciphertext: ciphertext)
/// ```
///
/// - Important: Each CipherState instance should only be used for either sending OR
///              receiving to maintain proper nonce synchronization.
public struct CipherState<Cipher: CipherFunction> {
    private let key: Data
    private var nonce: UInt64
    
    /// Creates a new cipher state with the specified key
    ///
    /// Initializes the cipher with a fresh nonce counter starting at 0.
    /// The key should be cryptographically secure and appropriate for the cipher.
    ///
    /// - Parameter key: The encryption key (typically 32 bytes for ChaCha20-Poly1305)
    public init(key: Data) {
        self.key = key
        self.nonce = 0
    }
    
    /// Encrypts plaintext with associated data and increments nonce
    ///
    /// Performs AEAD encryption using the current nonce, then automatically increments
    /// the nonce for the next operation. The associated data is authenticated but
    /// not encrypted.
    ///
    /// - Parameters:
    ///   - ad: Associated data to authenticate (not encrypted)
    ///   - plaintext: Data to encrypt and authenticate
    ///
    /// - Returns: The encrypted and authenticated ciphertext
    ///
    /// - Throws: 
    ///   - `NoiseError.nonceOverflow` if nonce counter reaches maximum value
    ///   - `NoiseError.invalidKeyLength` if key size is incorrect
    ///
    /// ## Example
    ///
    /// ```swift
    /// let message = Data("Hello, world!".utf8)
    /// let associated = Data("channel-id".utf8)
    /// let encrypted = try cipher.encryptWithAd(ad: associated, plaintext: message)
    /// ```
    public mutating func encryptWithAd(ad: Data, plaintext: Data) throws -> Data {
        guard nonce < UInt64.max else {
            throw NoiseError.nonceOverflow
        }
        
        let ciphertext = try Cipher.encrypt(key: key, nonce: nonce, associatedData: ad, plaintext: plaintext)
        nonce += 1
        return ciphertext
    }
    
    /// Decrypts ciphertext with associated data and increments nonce
    ///
    /// Performs AEAD decryption and authentication using the current nonce, then
    /// automatically increments the nonce for the next operation. Both the ciphertext
    /// and associated data are verified for authenticity.
    ///
    /// - Parameters:
    ///   - ad: Associated data to verify (was authenticated during encryption)
    ///   - ciphertext: Encrypted and authenticated data to decrypt
    ///
    /// - Returns: The decrypted and verified plaintext
    ///
    /// - Throws:
    ///   - `NoiseError.authenticationFailure` if authentication verification fails
    ///   - `NoiseError.nonceOverflow` if nonce counter reaches maximum value
    ///   - `NoiseError.invalidKeyLength` if key size is incorrect
    ///
    /// ## Example
    ///
    /// ```swift
    /// let associated = Data("channel-id".utf8)
    /// let plaintext = try cipher.decryptWithAd(ad: associated, ciphertext: received)
    /// ```
    ///
    /// - Important: The associated data must exactly match what was used during encryption
    public mutating func decryptWithAd(ad: Data, ciphertext: Data) throws -> Data {
        guard nonce < UInt64.max else {
            throw NoiseError.nonceOverflow
        }
        
        let plaintext = try Cipher.decrypt(key: key, nonce: nonce, associatedData: ad, ciphertext: ciphertext)
        nonce += 1
        return plaintext
    }
    
    /// Performs cipher rekeying for forward secrecy
    ///
    /// Updates the cipher key by encrypting zeros with the maximum nonce value.
    /// This operation provides forward secrecy by making past messages unrecoverable
    /// even if the current key is compromised.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// // Rekey after processing many messages
    /// if messageCount > rekeyThreshold {
    ///     cipher.rekey()
    ///     messageCount = 0
    /// }
    /// ```
    ///
    /// ## Security
    ///
    /// - Provides forward secrecy for long-lived sessions
    /// - Should be called periodically or after processing large amounts of data
    /// - Both parties must rekey at the same time to maintain synchronization
    ///
    /// - Note: This implements the `Rekey()` operation from the Noise specification
    public mutating func rekey() {
        let maxNonce = UInt64.max
        do {
            let newKey = try Cipher.encrypt(key: key, nonce: maxNonce, associatedData: Data(), plaintext: Data(repeating: 0, count: Cipher.keylen))
            self = CipherState(key: Data(newKey.prefix(Cipher.keylen)))
        } catch {
        }
    }
}