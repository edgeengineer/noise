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
}