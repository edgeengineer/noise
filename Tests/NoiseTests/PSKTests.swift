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

/// Tests for Pre-Shared Key (PSK) handshake patterns
@Suite("PSK Patterns")
struct PSKTests {
    
    @Test("NNpsk0 handshake pattern (PSK at beginning)")
    func testNNpsk0Handshake() throws {
        let psk = Data(repeating: 0x42, count: 32) // 32-byte PSK
        
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
        
        // NNpsk0 has 2 messages: [psk, e] and [e, ee]
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("PSK secured message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("NNpsk2 handshake pattern (PSK at end)")
    func testNNpsk2Handshake() throws {
        let psk = Data(repeating: 0x33, count: 32) // Different PSK
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .NNpsk2,
            initiator: true,
            psk: psk
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .NNpsk2,
            initiator: false,
            psk: psk
        )
        
        // NNpsk2 has 2 messages: [e] and [e, ee, psk]
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("PSK2 secured message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("PSK error handling - missing PSK")
    func testMissingPSK() throws {
        // Try to create PSK pattern without providing PSK
        #expect(throws: NoiseError.missingPSK) {
            var initiator = try NoiseProtocol.handshake(
                pattern: .NNpsk0,
                initiator: true
                // psk: nil - missing PSK
            )
            let _ = try initiator.writeHandshakeMessage()
        }
    }
}