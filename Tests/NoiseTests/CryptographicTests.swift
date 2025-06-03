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
}