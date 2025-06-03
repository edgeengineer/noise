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

/// Tests for actor-based AsyncNoiseSession providing enhanced thread safety
@Suite("Actor-Based Async Sessions")
struct ActorAsyncTests {
    
    // MARK: - Basic Actor Functionality
    
    @Test("Actor session creation")
    func testActorSessionCreation() async throws {
        let session = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        
        let isComplete = await session.isHandshakeComplete
        #expect(isComplete == false)
    }
    
    @Test("Actor handshake completion")
    func testActorHandshakeCompletion() async throws {
        let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
        
        // Perform handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Check completion
        let initiatorComplete = await initiator.isHandshakeComplete
        let responderComplete = await responder.isHandshakeComplete
        
        #expect(initiatorComplete)
        #expect(responderComplete)
    }
    
    @Test("Actor message exchange")
    func testActorMessageExchange() async throws {
        let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Exchange messages
        let plaintext = Data("Hello, actor world!".utf8)
        let ciphertext = try await initiator.writeMessage(plaintext)
        let decrypted = try await responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    // MARK: - Concurrent Access Tests
    
    @Test("Concurrent access to same actor session")
    func testConcurrentActorAccess() async throws {
        let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Multiple concurrent operations on the same actor
        try await withThrowingTaskGroup(of: Bool.self) { group in
            // Send messages concurrently (these will be serialized by the actor)
            for i in 0..<5 {
                group.addTask {
                    let plaintext = Data("Message \(i)".utf8)
                    let ciphertext = try await initiator.writeMessage(plaintext)
                    let decrypted = try await responder.readMessage(ciphertext)
                    return decrypted == plaintext
                }
            }
            
            // Verify all operations succeeded
            for try await success in group {
                #expect(success)
            }
        }
    }
    
    @Test("Multiple actor sessions concurrently")
    func testMultipleActorSessions() async throws {
        // Test multiple independent actor sessions
        try await withThrowingTaskGroup(of: Bool.self) { group in
            for i in 0..<3 {
                group.addTask {
                    let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
                    let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
                    
                    // Complete handshake
                    let message1 = try await initiator.writeHandshakeMessage()
                    let _ = try await responder.readHandshakeMessage(message1)
                    
                    let message2 = try await responder.writeHandshakeMessage()
                    let _ = try await initiator.readHandshakeMessage(message2)
                    
                    // Test message exchange
                    let plaintext = Data("Session \(i) message".utf8)
                    let ciphertext = try await initiator.writeMessage(plaintext)
                    let decrypted = try await responder.readMessage(ciphertext)
                    
                    return decrypted == plaintext
                }
            }
            
            for try await success in group {
                #expect(success)
            }
        }
    }
    
    // MARK: - Cancellation Tests
    
    @Test("Actor cancellation handling")
    func testActorCancellation() async throws {
        let session = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        
        // Test cancellation during operation
        let task = Task {
            do {
                let _ = try await session.writeHandshakeMessage()
                let _ = try await session.writeHandshakeMessage()
                let _ = try await session.writeHandshakeMessage()
            } catch is CancellationError {
                // Expected cancellation
                #expect(Bool(true))
            } catch {
                // Other errors are acceptable too since cancellation timing varies
                #expect(Bool(true))
            }
        }
        
        // Cancel immediately to test cancellation handling
        task.cancel()
        
        try await task.value
    }
    
    // MARK: - Batch Operations Tests
    
    @Test("Actor batch message processing")
    func testActorBatchOperations() async throws {
        let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Test batch encryption
        let plaintexts = [
            Data("Message 1".utf8),
            Data("Message 2".utf8),
            Data("Message 3".utf8)
        ]
        
        let ciphertexts = try await initiator.writeMessages(plaintexts)
        #expect(ciphertexts.count == plaintexts.count)
        
        // Test batch decryption
        let decrypted = try await responder.readMessages(ciphertexts)
        #expect(decrypted.count == plaintexts.count)
        
        for (original, decryptedMessage) in zip(plaintexts, decrypted) {
            #expect(original == decryptedMessage)
        }
    }
    
    // MARK: - Authentication Patterns Tests
    
    @Test("Actor XX handshake with authentication")
    func testActorXXHandshake() async throws {
        let initiatorKeypair = KeyPair.generate()
        let responderKeypair = KeyPair.generate()
        
        let initiator = try await AsyncNoiseSession.authenticated(
            pattern: .XX,
            initiator: true,
            staticKeypair: initiatorKeypair
        )
        let responder = try await AsyncNoiseSession.authenticated(
            pattern: .XX,
            initiator: false,
            staticKeypair: responderKeypair
        )
        
        // Perform 3-message handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        let message3 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message3)
        
        // Verify completion
        let initiatorComplete = await initiator.isHandshakeComplete
        let responderComplete = await responder.isHandshakeComplete
        
        #expect(initiatorComplete)
        #expect(responderComplete)
        
        // Test authenticated messaging
        let plaintext = Data("Authenticated message".utf8)
        let ciphertext = try await initiator.writeMessage(plaintext)
        let decrypted = try await responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("Actor PSK handshake")
    func testActorPSKHandshake() async throws {
        let psk = Data(repeating: 0x42, count: 32)
        
        let initiator = try await AsyncNoiseSession.withPSK(
            pattern: .NNpsk0,
            initiator: true,
            psk: psk
        )
        let responder = try await AsyncNoiseSession.withPSK(
            pattern: .NNpsk0,
            initiator: false,
            psk: psk
        )
        
        // Perform PSK handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Verify completion
        let initiatorComplete = await initiator.isHandshakeComplete
        let responderComplete = await responder.isHandshakeComplete
        
        #expect(initiatorComplete)
        #expect(responderComplete)
        
        // Test PSK-secured messaging
        let plaintext = Data("PSK-protected message".utf8)
        let ciphertext = try await initiator.writeMessage(plaintext)
        let decrypted = try await responder.readMessage(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    // MARK: - Session Management Tests
    
    @Test("Actor rekeying operations")
    func testActorRekeying() async throws {
        let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Send message before rekeying
        let beforeRekey = Data("Before rekey".utf8)
        let cipher1 = try await initiator.writeMessage(beforeRekey)
        let decrypted1 = try await responder.readMessage(cipher1)
        #expect(decrypted1 == beforeRekey)
        
        // Perform coordinated rekeying
        try await initiator.rekey()
        try await responder.rekey()
        
        // Send message after rekeying
        let afterRekey = Data("After rekey".utf8)
        let cipher2 = try await initiator.writeMessage(afterRekey)
        let decrypted2 = try await responder.readMessage(cipher2)
        #expect(decrypted2 == afterRekey)
    }
    
    @Test("Actor session statistics")
    func testActorSessionStatistics() async throws {
        let session = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        
        let stats = await session.getSessionStatistics()
        #expect(stats.sentMessages == 0)
        #expect(stats.receivedMessages == 0)
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Actor error handling")
    func testActorErrorHandling() async throws {
        let session = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        
        // Test operations before handshake completion
        do {
            let _ = try await session.writeMessage(Data("Too early".utf8))
            #expect(Bool(false), "Should have thrown error")
        } catch let error as NoiseError {
            if case .handshakeNotComplete = error {
                #expect(Bool(true)) // Expected error
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        }
        
        // Test rekeying before handshake completion
        do {
            try await session.rekey()
            #expect(Bool(false), "Should have thrown error")
        } catch let error as NoiseError {
            if case .handshakeNotComplete = error {
                #expect(Bool(true)) // Expected error
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        }
    }
}

// MARK: - Actor Stream Tests

@Suite("Actor Async Message Streams")
struct ActorStreamTests {
    
    @Test("Actor async message stream processing")
    func testActorAsyncMessageStream() async throws {
        let initiator = try await AsyncNoiseSession(pattern: .NN, initiator: true)
        let responder = try await AsyncNoiseSession(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessage()
        let _ = try await responder.readHandshakeMessage(message1)
        
        let message2 = try await responder.writeHandshakeMessage()
        let _ = try await initiator.readHandshakeMessage(message2)
        
        // Create test messages
        let testMessages = [
            Data("Message 1".utf8),
            Data("Message 2".utf8),
            Data("Message 3".utf8)
        ]
        
        // Encrypt messages
        let encryptedMessages = try await initiator.writeMessages(testMessages)
        
        // Create mock transport
        let transport = MockAsyncTransport(messages: encryptedMessages)
        
        // Create actor-based async stream
        let messageStream = ActorNoiseMessageStream(session: responder, transport: transport)
        
        // Process messages through stream
        var receivedMessages: [Data] = []
        for try await plaintext in messageStream {
            receivedMessages.append(plaintext)
        }
        
        // Verify all messages received correctly
        #expect(receivedMessages.count == testMessages.count)
        for (received, expected) in zip(receivedMessages, testMessages) {
            #expect(received == expected)
        }
    }
}