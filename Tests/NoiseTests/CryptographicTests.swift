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
import Testing
@testable import Noise

/// Tests for cryptographic primitives: Curve25519, ChaCha20-Poly1305, SHA-256
@Suite("Cryptographic Primitives")
struct CryptographicTests {
    
    @Test("Curve25519 key generation")
    func testCurve25519KeyGeneration() {
        let (privateKey, publicKey) = Curve25519.generateKeypair()
        #expect(privateKey.count == 32)
        #expect(publicKey.count == 32)
    }
    
    @Test("Curve25519 DH operation")
    func testCurve25519DH() throws {
        let alice = Curve25519.generateKeypair()
        let bob = Curve25519.generateKeypair()
        
        let sharedSecret1 = try Curve25519.dh(privateKey: alice.privateKey, publicKey: bob.publicKey)
        let sharedSecret2 = try Curve25519.dh(privateKey: bob.privateKey, publicKey: alice.publicKey)
        
        #expect(sharedSecret1.count == 32)
        #expect(sharedSecret2.count == 32)
        #expect(sharedSecret1 == sharedSecret2)
    }
    
    @Test("ChaChaPoly encryption/decryption")
    func testChaChaPoly() throws {
        let key = Data(repeating: 0x42, count: 32)
        let nonce: UInt64 = 0
        let ad = Data("additional data".utf8)
        let plaintext = Data("hello world".utf8)
        
        let ciphertext = try ChaChaPoly.encrypt(key: key, nonce: nonce, associatedData: ad, plaintext: plaintext)
        let decrypted = try ChaChaPoly.decrypt(key: key, nonce: nonce, associatedData: ad, ciphertext: ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("SHA256 hash")
    func testSHA256Hash() {
        let data = Data("hello world".utf8)
        let hash = SHA256Hash.hash(data)
        
        #expect(hash.count == 32)
        
        let expectedHash = Data([
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
            0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
            0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9
        ])
        #expect(hash == expectedHash)
    }
    
    @Test("SHA256 HMAC")
    func testSHA256HMAC() {
        let key = Data("key".utf8)
        let data = Data("data".utf8)
        let hmac = SHA256Hash.hmac(key: key, data: data)
        
        #expect(hmac.count == 32)
    }
    
    @Test("KeyPair generation")
    func testKeyPairGeneration() {
        let keypair = KeyPair.generate()
        #expect(keypair.privateKey.count == 32)
        #expect(keypair.publicKey.count == 32)
    }
    
    @Test("Symmetric state operations")
    func testSymmetricState() throws {
        var state1 = SymmetricState<ChaChaPoly, SHA256Hash>(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256")
        var state2 = SymmetricState<ChaChaPoly, SHA256Hash>(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256")
        
        let data1 = Data("test data 1".utf8)
        state1.mixHash(data1)
        state2.mixHash(data1)
        
        let keyMaterial = Data(repeating: 0x42, count: 32)
        state1.mixKey(keyMaterial)
        state2.mixKey(keyMaterial)
        
        let plaintext = Data("hello".utf8)
        let ciphertext = try state1.encryptAndHash(plaintext)
        #expect(ciphertext != plaintext)
        
        let decrypted = try state2.decryptAndHash(ciphertext)
        #expect(decrypted == plaintext)
    }
    
    @Test("Cipher state nonce increment")
    func testCipherStateNonceIncrement() throws {
        let key = Data(repeating: 0x42, count: 32)
        var cipher = CipherState<ChaChaPoly>(key: key)
        
        let plaintext = Data("message".utf8)
        let ad = Data()
        
        let ciphertext1 = try cipher.encryptWithAd(ad: ad, plaintext: plaintext)
        let ciphertext2 = try cipher.encryptWithAd(ad: ad, plaintext: plaintext)
        
        #expect(ciphertext1 != ciphertext2)
    }
    
    // MARK: - Additional Crypto Primitives Tests
    
    @Test("P-256 key generation")
    func testP256KeyGeneration() {
        let (privateKey, publicKey) = P256.generateKeypair()
        #expect(privateKey.count == 32)
        #expect(publicKey.count == 64) // Raw representation (x + y coordinates)
    }
    
    @Test("P-256 DH operation")
    func testP256DH() throws {
        let alice = P256.generateKeypair()
        let bob = P256.generateKeypair()
        
        let sharedSecret1 = try P256.dh(privateKey: alice.privateKey, publicKey: bob.publicKey)
        let sharedSecret2 = try P256.dh(privateKey: bob.privateKey, publicKey: alice.publicKey)
        
        #expect(sharedSecret1.count == 32)
        #expect(sharedSecret2.count == 32)
        #expect(sharedSecret1 == sharedSecret2)
    }
    
    @Test("AES-GCM encryption/decryption")
    func testAESGCM() throws {
        let key = Data(repeating: 0x42, count: 32)
        let nonce: UInt64 = 0
        let ad = Data("additional data".utf8)
        let plaintext = Data("hello world".utf8)
        
        let ciphertext = try AESGCM.encrypt(key: key, nonce: nonce, associatedData: ad, plaintext: plaintext)
        let decrypted = try AESGCM.decrypt(key: key, nonce: nonce, associatedData: ad, ciphertext: ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("SHA-512 hash")
    func testSHA512Hash() {
        let data = Data("hello world".utf8)
        let hash = SHA512Hash.hash(data)
        
        #expect(hash.count == 64)
        
        // Test against known hash
        let expectedHash = Data([
            0x30, 0x9e, 0xcc, 0x48, 0x9c, 0x12, 0xd6, 0xeb,
            0x4c, 0xc4, 0x0f, 0x50, 0xc9, 0x02, 0xf2, 0xb4,
            0xd0, 0xed, 0x77, 0xee, 0x51, 0x1a, 0x7c, 0x7a,
            0x9b, 0xcd, 0x3c, 0xa8, 0x6d, 0x4c, 0xd8, 0x6f,
            0x98, 0x9d, 0xd3, 0x5b, 0xc5, 0xff, 0x49, 0x96,
            0x70, 0xda, 0x34, 0x25, 0x5b, 0x45, 0xb0, 0xcf,
            0xd8, 0x30, 0xe8, 0x1f, 0x60, 0x5d, 0xcf, 0x7d,
            0xc5, 0x54, 0x2e, 0x93, 0xae, 0x9c, 0xd7, 0x6f
        ])
        #expect(hash == expectedHash)
    }
    
    @Test("SHA-512 HMAC")
    func testSHA512HMAC() {
        let key = Data("key".utf8)
        let data = Data("data".utf8)
        let hmac = SHA512Hash.hmac(key: key, data: data)
        
        #expect(hmac.count == 64)
    }
    
    @Test("Crypto suite functionality")
    func testCryptoSuites() {
        // Test suite names and fragments
        #expect(StandardSuite.suiteName.contains("Curve25519"))
        #expect(StandardSuite.protocolFragment == "25519_ChaChaPoly_SHA256")
        
        #expect(NISTSuite.suiteName.contains("P-256"))
        #expect(NISTSuite.protocolFragment == "P256_AESGCM_SHA256")
        
        #expect(HighSecuritySuite.suiteName.contains("SHA-512"))
        #expect(HighSecuritySuite.protocolFragment == "P256_AESGCM_SHA512")
    }
    
    @Test("Cross-crypto compatibility")
    func testCryptoPrimitiveCompatibility() throws {
        // Test that different primitives can work together
        
        // Test P-256 with different ciphers
        let p256Keys = P256.generateKeypair()
        #expect(p256Keys.privateKey.count == P256.dhlen)
        
        // Test AES-GCM with same interface as ChaCha20-Poly1305
        let key = Data(repeating: 0x01, count: 32)
        let plaintext = Data("test".utf8)
        let ad = Data("ad".utf8)
        
        let chacha_encrypted = try ChaChaPoly.encrypt(key: key, nonce: 1, associatedData: ad, plaintext: plaintext)
        let aes_encrypted = try AESGCM.encrypt(key: key, nonce: 1, associatedData: ad, plaintext: plaintext)
        
        // Different ciphers should produce different output
        #expect(chacha_encrypted != aes_encrypted)
        
        // But both should decrypt correctly
        let chacha_decrypted = try ChaChaPoly.decrypt(key: key, nonce: 1, associatedData: ad, ciphertext: chacha_encrypted)
        let aes_decrypted = try AESGCM.decrypt(key: key, nonce: 1, associatedData: ad, ciphertext: aes_encrypted)
        
        #expect(chacha_decrypted == plaintext)
        #expect(aes_decrypted == plaintext)
    }
}