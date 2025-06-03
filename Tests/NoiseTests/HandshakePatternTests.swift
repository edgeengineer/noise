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

/// Tests for all supported handshake patterns
@Suite("Handshake Patterns")
struct HandshakePatternTests {
    
    @Test("Handshake pattern message patterns")
    func testHandshakePatterns() {
        #expect(HandshakePattern.NN.messagePatterns.count == 2)
        #expect(HandshakePattern.XX.messagePatterns.count == 3)
        #expect(HandshakePattern.NK.messagePatterns.count == 2)
    }
    
    @Test("NN handshake pattern")
    func testNNHandshake() throws {
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        let plaintext = Data("hello".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("XX handshake pattern")
    func testXXHandshake() throws {
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
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        let message3 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message3)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        let plaintext = Data("secure message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("NK handshake pattern with known responder key")
    func testNKHandshake() throws {
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
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
    }
    
    @Test("N handshake pattern (one-way, anonymous initiator)")
    func testNHandshake() throws {
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .N,
            initiator: true,
            remoteStaticKey: responderStatic.publicKey
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .N,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // Only one message in N pattern
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("N pattern message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("K handshake pattern (one-way, known keys)")
    func testKHandshake() throws {
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .K,
            initiator: true,
            staticKeypair: initiatorStatic,
            remoteStaticKey: responderStatic.publicKey
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .K,
            initiator: false,
            staticKeypair: responderStatic,
            remoteStaticKey: initiatorStatic.publicKey
        )
        
        // Only one message in K pattern
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("K pattern message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("X handshake pattern (one-way, mutual auth)")
    func testXHandshake() throws {
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .X,
            initiator: true,
            staticKeypair: initiatorStatic,
            remoteStaticKey: responderStatic.publicKey
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .X,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // Only one message in X pattern
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("X pattern message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("IX handshake pattern (interactive, immediate auth)")
    func testIXHandshake() throws {
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .IX,
            initiator: true,
            staticKeypair: initiatorStatic
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .IX,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // IX pattern has 2 messages
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("IX pattern message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("IK handshake pattern (interactive, known responder)")
    func testIKHandshake() throws {
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(
            pattern: .IK,
            initiator: true,
            staticKeypair: initiatorStatic,
            remoteStaticKey: responderStatic.publicKey
        )
        var responder = try NoiseProtocol.handshake(
            pattern: .IK,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // IK pattern has 2 messages
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test transport messages
        let plaintext = Data("IK pattern message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        let decrypted = try responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("Handshake with payload")
    func testHandshakeWithPayload() throws {
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let payload1 = Data("initiator payload".utf8)
        let message1 = try initiator.writeHandshakeMessage(payload: payload1)
        let receivedPayload1 = try responder.readHandshakeMessage(message1)
        #expect(receivedPayload1 == payload1)
        
        let payload2 = Data("responder payload".utf8)
        let message2 = try responder.writeHandshakeMessage(payload: payload2)
        let receivedPayload2 = try initiator.readHandshakeMessage(message2)
        #expect(receivedPayload2 == payload2)
    }
    
    @Test("Multiple message exchange")
    func testMultipleMessageExchange() throws {
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        for i in 0..<10 {
            let plaintext = Data("message \(i)".utf8)
            
            let ciphertext = try initiator.writeMessage(plaintext)
            let decrypted = try responder.readMessage(ciphertext)
            #expect(decrypted == plaintext)
            
            let response = Data("response \(i)".utf8)
            let responseCiphertext = try responder.writeMessage(response)
            let responseDecrypted = try initiator.readMessage(responseCiphertext)
            #expect(responseDecrypted == response)
        }
    }
}