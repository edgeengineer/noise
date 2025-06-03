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

/// Tests for error conditions and edge cases
@Suite("Error Handling")
struct ErrorHandlingTests {
    
    @Test("Error handling - invalid key length")
    func testInvalidKeyLength() {
        let shortKey = Data(repeating: 0x42, count: 16)
        
        #expect(throws: NoiseError.self) {
            try ChaChaPoly.encrypt(
                key: shortKey,
                nonce: 0,
                associatedData: Data(),
                plaintext: Data("test".utf8)
            )
        }
    }
    
    @Test("Error handling - short ciphertext")
    func testShortCiphertext() {
        let key = Data(repeating: 0x42, count: 32)
        let shortCiphertext = Data(repeating: 0x00, count: 8)
        
        #expect(throws: NoiseError.self) {
            try ChaChaPoly.decrypt(
                key: key,
                nonce: 0,
                associatedData: Data(),
                ciphertext: shortCiphertext
            )
        }
    }
    
    @Test("Error handling - message size limits")
    func testMessageSizeLimits() throws {
        var session = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        
        // Test oversized handshake payload
        let oversizedPayload = Data(repeating: 0x42, count: 65536)
        #expect(throws: NoiseError.invalidMessageLength(length: 65536)) {
            try session.writeHandshakeMessage(payload: oversizedPayload)
        }
    }
    
    @Test("Error handling - handshake state violations")
    func testHandshakeStateViolations() throws {
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Try to send handshake message after completion
        #expect(throws: NoiseError.handshakeAlreadyComplete) {
            try initiator.writeHandshakeMessage()
        }
        
        // Try to send transport message before handshake on fresh session
        var newSession = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        #expect(throws: NoiseError.handshakeNotComplete) {
            try newSession.writeMessage(Data("test".utf8))
        }
    }
    
    @Test("Error handling - specific error types")
    func testSpecificErrorTypes() {
        // Test invalid key length error
        let shortKey = Data(repeating: 0x42, count: 16)
        do {
            let _ = try ChaChaPoly.encrypt(
                key: shortKey,
                nonce: 0,
                associatedData: Data(),
                plaintext: Data("test".utf8)
            )
            #expect(Bool(false), "Should have thrown an error")
        } catch let error as NoiseError {
            if case .invalidKeyLength(let expected, let actual) = error {
                #expect(expected == 32)
                #expect(actual == 16)
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        } catch {
            #expect(Bool(false), "Wrong error type: \(error)")
        }
    }
}