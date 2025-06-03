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

/// Tests for async/await concurrency support in Noise protocol
@Suite("Async/Await Concurrency")
struct AsyncTests {
    
    // MARK: - Async Handshake Tests
    
    @Test("Async NN handshake")
    func testAsyncNNHandshake() async throws {
        var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Perform async handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test async messaging
        let plaintext = Data("Hello, async world!".utf8)
        let ciphertext = try await initiator.writeMessageAsync(plaintext)
        let decrypted = try await responder.readMessageAsync(ciphertext)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("Async XX handshake with authentication")
    func testAsyncXXHandshake() async throws {
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try await NoiseProtocol.handshakeAsync(
            pattern: .XX,
            initiator: true,
            staticKeypair: initiatorStatic
        )
        var responder = try await NoiseProtocol.handshakeAsync(
            pattern: .XX,
            initiator: false,
            staticKeypair: responderStatic
        )
        
        // Perform 3-message async handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        let message3 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message3)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test bidirectional async messaging
        let message1_plain = Data("Message from initiator".utf8)
        let message1_cipher = try await initiator.writeMessageAsync(message1_plain)
        let message1_decrypted = try await responder.readMessageAsync(message1_cipher)
        #expect(message1_decrypted == message1_plain)
        
        let message2_plain = Data("Response from responder".utf8)
        let message2_cipher = try await responder.writeMessageAsync(message2_plain)
        let message2_decrypted = try await initiator.readMessageAsync(message2_cipher)
        #expect(message2_decrypted == message2_plain)
    }
    
    @Test("Async handshake with payload")
    func testAsyncHandshakeWithPayload() async throws {
        var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Send handshake message with payload
        let payload1 = Data("Initiator payload".utf8)
        let message1 = try await initiator.writeHandshakeMessageAsync(payload: payload1)
        let receivedPayload1 = try await responder.readHandshakeMessageAsync(message1)
        #expect(receivedPayload1 == payload1)
        
        // Send response with payload
        let payload2 = Data("Responder payload".utf8)
        let message2 = try await responder.writeHandshakeMessageAsync(payload: payload2)
        let receivedPayload2 = try await initiator.readHandshakeMessageAsync(message2)
        #expect(receivedPayload2 == payload2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
    }
    
    // MARK: - Async PSK Tests
    
    @Test("Async PSK handshake")
    func testAsyncPSKHandshake() async throws {
        let psk = Data(repeating: 0x42, count: 32)
        
        var initiator = try await NoiseProtocol.handshakeAsync(
            pattern: .NNpsk0,
            initiator: true,
            psk: psk
        )
        var responder = try await NoiseProtocol.handshakeAsync(
            pattern: .NNpsk0,
            initiator: false,
            psk: psk
        )
        
        // Perform PSK handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        
        // Test PSK-secured messaging
        let secretMessage = Data("PSK-protected message".utf8)
        let ciphertext = try await initiator.writeMessageAsync(secretMessage)
        let decrypted = try await responder.readMessageAsync(ciphertext)
        #expect(decrypted == secretMessage)
    }
    
    // MARK: - Async Rekeying Tests
    
    @Test("Async rekeying")
    func testAsyncRekeying() async throws {
        var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        // Send messages before rekeying
        let beforeRekey = Data("Before rekey".utf8)
        let cipher1 = try await initiator.writeMessageAsync(beforeRekey)
        let decrypted1 = try await responder.readMessageAsync(cipher1)
        #expect(decrypted1 == beforeRekey)
        
        // Perform coordinated async rekeying
        try await initiator.rekeyAsync()
        try await responder.rekeyAsync()
        
        // Send messages after rekeying
        let afterRekey = Data("After rekey".utf8)
        let cipher2 = try await initiator.writeMessageAsync(afterRekey)
        let decrypted2 = try await responder.readMessageAsync(cipher2)
        #expect(decrypted2 == afterRekey)
    }
    
    // MARK: - Concurrent Operations Tests
    
    @Test("Concurrent async sessions")
    func testConcurrentAsyncSessions() async throws {
        // Test multiple concurrent async sessions
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<5 {
                group.addTask {
                    var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
                    var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
                    
                    // Complete handshake
                    let message1 = try await initiator.writeHandshakeMessageAsync()
                    let _ = try await responder.readHandshakeMessageAsync(message1)
                    
                    let message2 = try await responder.writeHandshakeMessageAsync()
                    let _ = try await initiator.readHandshakeMessageAsync(message2)
                    
                    // Send test message
                    let testMessage = Data("Session \(i) message".utf8)
                    let ciphertext = try await initiator.writeMessageAsync(testMessage)
                    let decrypted = try await responder.readMessageAsync(ciphertext)
                    
                    #expect(decrypted == testMessage)
                }
            }
            
            try await group.waitForAll()
        }
    }
    
    @Test("Async message sequence")
    func testAsyncMessageSequence() async throws {
        var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        // Send sequence of async messages
        for i in 0..<10 {
            let plaintext = Data("Message \(i)".utf8)
            let ciphertext = try await initiator.writeMessageAsync(plaintext)
            let decrypted = try await responder.readMessageAsync(ciphertext)
            #expect(decrypted == plaintext)
        }
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Async error handling")
    func testAsyncErrorHandling() async throws {
        var session = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        
        // Test error before handshake completion
        do {
            let _ = try await session.writeMessageAsync(Data("Too early".utf8))
            #expect(Bool(false), "Should have thrown handshakeNotComplete error")
        } catch let error as NoiseError {
            if case .handshakeNotComplete = error {
                #expect(true) // Expected error
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        }
        
        // Test rekey error before handshake completion
        do {
            try await session.rekeyAsync()
            #expect(Bool(false), "Should have thrown handshakeNotComplete error")
        } catch let error as NoiseError {
            if case .handshakeNotComplete = error {
                #expect(true) // Expected error
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        }
    }
    
    @Test("Async message size limits")
    func testAsyncMessageSizeLimits() async throws {
        var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        // Test oversized message
        let oversizedMessage = Data(repeating: 0x42, count: 65536) // 1 byte over limit
        
        do {
            let _ = try await initiator.writeMessageAsync(oversizedMessage)
            #expect(Bool(false), "Should have thrown invalidMessageLength error")
        } catch let error as NoiseError {
            if case .invalidMessageLength = error {
                #expect(true) // Expected error
            } else {
                #expect(Bool(false), "Wrong error type: \(error)")
            }
        }
    }
    
    // MARK: - Performance Tests
    
    @Test("Async performance comparison")
    func testAsyncPerformanceComparison() async throws {
        var initiatorSync = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responderSync = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        var initiatorAsync = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responderAsync = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Complete both handshakes
        let sync1 = try initiatorSync.writeHandshakeMessage()
        let _ = try responderSync.readHandshakeMessage(sync1)
        let sync2 = try responderSync.writeHandshakeMessage()
        let _ = try initiatorSync.readHandshakeMessage(sync2)
        
        let async1 = try await initiatorAsync.writeHandshakeMessageAsync()
        let _ = try await responderAsync.readHandshakeMessageAsync(async1)
        let async2 = try await responderAsync.writeHandshakeMessageAsync()
        let _ = try await initiatorAsync.readHandshakeMessageAsync(async2)
        
        // Test message processing performance
        let testMessage = Data("Performance test message".utf8)
        
        // Sync version
        let syncCiphertext = try initiatorSync.writeMessage(testMessage)
        let syncDecrypted = try responderSync.readMessage(syncCiphertext)
        #expect(syncDecrypted == testMessage)
        
        // Async version
        let asyncCiphertext = try await initiatorAsync.writeMessageAsync(testMessage)
        let asyncDecrypted = try await responderAsync.readMessageAsync(asyncCiphertext)
        #expect(asyncDecrypted == testMessage)
        
        // Both should produce equivalent results
        #expect(syncCiphertext.count == asyncCiphertext.count)
    }
    
    // MARK: - Sendable Conformance Tests
    
    @Test("NoiseSession Sendable conformance")
    func testSendableConformance() async throws {
        let session = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        
        // Test that sessions can be passed across actor boundaries
        let result = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                // Session should be sendable across task boundaries
                return session.isHandshakeComplete == false
            }
            
            var results: [Bool] = []
            for await result in group {
                results.append(result)
            }
            return results.first ?? false
        }
        
        #expect(result == true)
    }
}

// MARK: - Mock Transport for Testing

/// Mock async transport for testing purposes
class MockAsyncTransport: AsyncMessageTransport {
    private let messages: [Data]
    private var currentIndex: Int = 0
    
    init(messages: [Data]) {
        self.messages = messages
    }
    
    func receive() async throws -> Data? {
        guard currentIndex < messages.count else {
            return nil
        }
        
        let message = messages[currentIndex]
        currentIndex += 1
        
        // Return immediately for deterministic test behavior
        
        return message
    }
}

// MARK: - AsyncSequence Tests

@Suite("Async Message Streams")
struct AsyncStreamTests {
    
    @Test("Async message stream processing")
    func testAsyncMessageStream() async throws {
        var initiator = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: true)
        var responder = try await NoiseProtocol.handshakeAsync(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try await initiator.writeHandshakeMessageAsync()
        let _ = try await responder.readHandshakeMessageAsync(message1)
        
        let message2 = try await responder.writeHandshakeMessageAsync()
        let _ = try await initiator.readHandshakeMessageAsync(message2)
        
        // Create test messages
        let testMessages = [
            Data("Message 1".utf8),
            Data("Message 2".utf8),
            Data("Message 3".utf8)
        ]
        
        // Encrypt messages
        let encryptedMessages = try await testMessages.asyncMap { plaintext in
            try await initiator.writeMessageAsync(plaintext)
        }
        
        // Create mock transport
        let transport = MockAsyncTransport(messages: encryptedMessages)
        
        // Create async stream
        let messageStream = AsyncNoiseMessageStream(session: responder, transport: transport)
        
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

// MARK: - Helper Extensions

extension Array {
    /// Async map function for transforming array elements
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var results: [T] = []
        for element in self {
            let transformed = try await transform(element)
            results.append(transformed)
        }
        return results
    }
}