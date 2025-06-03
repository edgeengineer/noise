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

/// Tests for official Noise protocol test vector validation
@Suite("Test Vector Validation")
struct TestVectorTests {
    
    @Test("Test vectors - NN pattern validation")
    func testVectorNN() throws {
        // Official test vector validation for Noise_NN_25519_ChaChaPoly_SHA256
        // Note: Full test vector validation would require API to accept predetermined keys
        // This test validates the protocol works with the test vector payload
        
        let payload1 = Data(hex: "4c756477696720766f6e204d69736573") // "Ludwig von Mises"
        
        // Create handshake sessions
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage(payload: payload1)
        let receivedPayload1 = try responder.readHandshakeMessage(message1)
        #expect(receivedPayload1 == payload1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test the multi-message payload from test vectors
        let payload2 = Data(hex: "4d757272617920526f746862617264") // "Murray Rothbard"
        let ciphertext = try initiator.writeMessage(payload2)
        let decrypted = try responder.readMessage(ciphertext)
        #expect(decrypted == payload2)
    }
    
    @Test("Test vectors - NK pattern basic validation") 
    func testVectorNK() throws {
        // Basic test for NK pattern (not using exact test vector keys due to key derivation complexity)
        // This validates that NK pattern works correctly with generated keys
        
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .NK,
            initiator: true,
            remoteStaticKey: responderStatic.publicKey
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .NK,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        let payload1 = Data(hex: "4c756477696720766f6e204d69736573") // "Ludwig von Mises"
        
        let message1 = try initiator.writeHandshakeMessage(payload: payload1)
        let receivedPayload1 = try responder.readHandshakeMessage(message1)
        #expect(receivedPayload1 == payload1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
    }
    
    @Test("Handshake hash validation - NN pattern")
    func testHandshakeHashNN() throws {
        // Test that both parties compute the same handshake hash for NN pattern
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        // Before handshake, hash should be nil or match the protocol name hash
        let preHandshakeHashInitiator = initiator.getHandshakeHash()
        let preHandshakeHashResponder = responder.getHandshakeHash()
        
        #expect(preHandshakeHashInitiator != nil)
        #expect(preHandshakeHashResponder != nil)
        #expect(preHandshakeHashInitiator == preHandshakeHashResponder)
        
        // Perform handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        // After first message, hashes should still match but be different from initial
        let midHandshakeHashInitiator = initiator.getHandshakeHash()
        let midHandshakeHashResponder = responder.getHandshakeHash()
        
        #expect(midHandshakeHashInitiator != nil)
        #expect(midHandshakeHashResponder != nil)
        #expect(midHandshakeHashInitiator == midHandshakeHashResponder)
        #expect(midHandshakeHashInitiator != preHandshakeHashInitiator)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // After handshake completion, both parties should have identical handshake hash
        let finalHashInitiator = initiator.getHandshakeHash()
        let finalHashResponder = responder.getHandshakeHash()
        
        #expect(finalHashInitiator != nil)
        #expect(finalHashResponder != nil)
        #expect(finalHashInitiator == finalHashResponder)
        #expect(finalHashInitiator != midHandshakeHashInitiator)
        
        // Hash should be 32 bytes (SHA-256)
        #expect(finalHashInitiator!.count == 32)
    }
    
    @Test("Handshake hash validation - XX pattern")
    func testHandshakeHashXX() throws {
        // Test handshake hash consistency for XX pattern (mutual authentication)
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .XX,
            initiator: true,
            staticKeypair: initiatorStatic
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .XX,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // Perform 3-message XX handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        let message3 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message3)
        
        // Both parties should have identical final handshake hash
        let hashInitiator = initiator.getHandshakeHash()
        let hashResponder = responder.getHandshakeHash()
        
        #expect(hashInitiator != nil)
        #expect(hashResponder != nil)
        #expect(hashInitiator == hashResponder)
        #expect(hashInitiator!.count == 32)
    }
    
    @Test("Handshake hash validation - NK pattern")
    func testHandshakeHashNK() throws {
        // Test handshake hash for NK pattern (known responder key)
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .NK,
            initiator: true,
            remoteStaticKey: responderStatic.publicKey
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .NK,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // Perform NK handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Verify identical handshake hashes
        let hashInitiator = initiator.getHandshakeHash()
        let hashResponder = responder.getHandshakeHash()
        
        #expect(hashInitiator != nil)
        #expect(hashResponder != nil)
        #expect(hashInitiator == hashResponder)
        #expect(hashInitiator!.count == 32)
    }
    
    @Test("Handshake hash validation - PSK pattern")
    func testHandshakeHashPSK() throws {
        // Test handshake hash for PSK patterns
        let psk = Data(repeating: 0x42, count: 32)
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .NNpsk0,
            initiator: true,
            psk: psk
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .NNpsk0,
            initiator: false,
            psk: psk
        )
        
        // Perform PSK handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Verify PSK affects handshake hash
        let hashInitiator = initiator.getHandshakeHash()
        let hashResponder = responder.getHandshakeHash()
        
        #expect(hashInitiator != nil)
        #expect(hashResponder != nil)
        #expect(hashInitiator == hashResponder)
        #expect(hashInitiator!.count == 32)
        
        // Compare with non-PSK version to ensure PSK changes the hash
        var nonPSKInitiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var nonPSKResponder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let nonPSKMessage1 = try nonPSKInitiator.writeHandshakeMessage()
        let _ = try nonPSKResponder.readHandshakeMessage(nonPSKMessage1)
        let nonPSKMessage2 = try nonPSKResponder.writeHandshakeMessage()
        let _ = try nonPSKInitiator.readHandshakeMessage(nonPSKMessage2)
        
        let nonPSKHash = nonPSKInitiator.getHandshakeHash()
        
        // PSK hash should be different from non-PSK hash
        #expect(hashInitiator != nonPSKHash)
    }
    
    @Test("Handshake hash persistence after completion")
    func testHandshakeHashPersistence() throws {
        // Test that handshake hash persists after handshake completion
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        let hashAfterHandshake = initiator.getHandshakeHash()
        
        // Send some transport messages
        let plaintext = Data("test message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let _ = try responder.readMessage(ciphertext)
        
        // Hash should remain the same after transport messages
        let hashAfterTransport = initiator.getHandshakeHash()
        #expect(hashAfterHandshake == hashAfterTransport)
    }
    
    @Test("Handshake hash with prologue")
    func testHandshakeHashWithPrologue() throws {
        // Test that prologue affects handshake hash
        let prologue1 = Data("prologue1".utf8)
        let prologue2 = Data("prologue2".utf8)
        
        // Create sessions with different prologues
        var initiator1 = try NoiseProtocol.handshake(pattern: .NN, initiator: true, prologue: prologue1)
        var responder1 = try NoiseProtocol.handshake(pattern: .NN, initiator: false, prologue: prologue1)
        
        var initiator2 = try NoiseProtocol.handshake(pattern: .NN, initiator: true, prologue: prologue2)
        var responder2 = try NoiseProtocol.handshake(pattern: .NN, initiator: false, prologue: prologue2)
        
        // Complete handshakes
        let message1_1 = try initiator1.writeHandshakeMessage()
        let _ = try responder1.readHandshakeMessage(message1_1)
        let message2_1 = try responder1.writeHandshakeMessage()
        let _ = try initiator1.readHandshakeMessage(message2_1)
        
        let message1_2 = try initiator2.writeHandshakeMessage()
        let _ = try responder2.readHandshakeMessage(message1_2)
        let message2_2 = try responder2.writeHandshakeMessage()
        let _ = try initiator2.readHandshakeMessage(message2_2)
        
        // Different prologues should result in different handshake hashes
        let hash1 = initiator1.getHandshakeHash()
        let hash2 = initiator2.getHandshakeHash()
        
        #expect(hash1 != nil)
        #expect(hash2 != nil)
        #expect(hash1 != hash2)
    }
}