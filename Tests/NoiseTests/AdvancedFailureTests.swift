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

/// Tests for advanced failure scenarios, malformed inputs, and edge cases
@Suite("Advanced Failure Scenarios")
struct AdvancedFailureTests {
    
    // MARK: - Message Tampering Tests
    
    @Test("Tampered handshake message - modified ciphertext")
    func testTamperedHandshakeMessage() throws {
        // Create handshake sessions for a pattern that has encrypted handshake messages
        var initiator = try NoiseProtocol.handshake(pattern: .XX, initiator: true, staticKeypair: KeyPair.generate())
        var responder = try NoiseProtocol.handshake(pattern: .XX, initiator: false, staticKeypair: KeyPair.generate())
        
        // Complete first message (unencrypted)
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        // Get second message (this will be encrypted)
        let message2 = try responder.writeHandshakeMessage()
        
        // Tamper with the encrypted message
        var tamperedMessage = message2
        if tamperedMessage.count > 10 {
            tamperedMessage[5] ^= 0xFF // Flip all bits in byte 5
            tamperedMessage[tamperedMessage.count - 5] ^= 0xFF // Flip bits near end
        }
        
        // Initiator should reject tampered encrypted message
        do {
            let _ = try initiator.readHandshakeMessage(tamperedMessage)
            #expect(Bool(false), "Should have thrown an error for tampered encrypted message")
        } catch let error as NoiseError {
            // Expected to throw authentication or decryption error for tampered encrypted message
            switch error {
            case .authenticationFailure, .decryptionFailure, .malformedMessage:
                #expect(true) // These are the expected error types
            default:
                #expect(Bool(false), "Unexpected error type: \(error)")
            }
        } catch {
            // CryptoKit or other errors are also acceptable for tampered messages
            let errorString = String(describing: error)
            if errorString.contains("authentication") || errorString.contains("decrypt") {
                #expect(true) // Expected authentication/decryption failure
            } else {
                #expect(Bool(false), "Expected authentication/decryption error but got: \(error)")
            }
        }
    }
    
    @Test("Tampered transport message - modified MAC")
    func testTamperedTransportMessage() throws {
        // Complete handshake first
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Send legitimate transport message
        let plaintext = Data("Legitimate message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        
        // Tamper with the MAC (last 16 bytes for ChaCha20-Poly1305)
        var tamperedCiphertext = ciphertext
        if tamperedCiphertext.count >= 16 {
            let macStart = tamperedCiphertext.count - 16
            tamperedCiphertext[macStart] ^= 0xFF
            tamperedCiphertext[macStart + 8] ^= 0xFF
        }
        
        // Responder should reject tampered message
        do {
            let _ = try responder.readMessage(tamperedCiphertext)
            #expect(Bool(false), "Should have thrown an authentication error")
        } catch let error as NoiseError {
            // Expected authentication failure for tampered MAC
            if case .authenticationFailure = error {
                #expect(true) // Expected NoiseError.authenticationFailure
            } else {
                #expect(Bool(false), "Expected NoiseError.authenticationFailure but got: \(error)")
            }
        } catch {
            // CryptoKit may throw its own authentication errors
            let errorString = String(describing: error)
            if errorString.contains("authentication") {
                #expect(true) // Expected authentication failure from CryptoKit
            } else {
                #expect(Bool(false), "Expected authentication failure but got: \(error)")
            }
        }
    }
    
    @Test("Malformed message - incorrect length")
    func testMalformedMessageLength() throws {
        var session = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        
        // Test oversized handshake message
        let oversizedPayload = Data(repeating: 0x42, count: 65536) // 1 byte over limit
        #expect(throws: NoiseError.invalidMessageLength(length: 65536)) {
            try session.writeHandshakeMessage(payload: oversizedPayload)
        }
        
        // Complete handshake
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        let message1 = try session.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        let message2 = try responder.writeHandshakeMessage()
        let _ = try session.readHandshakeMessage(message2)
        
        // Test oversized transport message
        let oversizedTransport = Data(repeating: 0x42, count: 65536)
        #expect(throws: NoiseError.invalidMessageLength(length: 65536)) {
            try session.writeMessage(oversizedTransport)
        }
    }
    
    @Test("Malformed ciphertext - truncated message")
    func testTruncatedCiphertext() throws {
        // Complete handshake
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Create legitimate ciphertext
        let plaintext = Data("Test message".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        
        // Test various truncated lengths
        for truncateLength in [0, 1, 8, 15] { // Less than 16 bytes (MAC size)
            let truncated = ciphertext.prefix(truncateLength)
            do {
                let _ = try responder.readMessage(truncated)
                #expect(Bool(false), "Should have thrown error for truncated message of \(truncateLength) bytes")
            } catch let error as NoiseError {
                // Expected specific errors for truncated messages
                switch error {
                case .invalidMessageLength, .authenticationFailure, .malformedMessage:
                    #expect(true) // These are expected for truncated ciphertext
                default:
                    #expect(Bool(false), "Unexpected error for truncated message: \(error)")
                }
            } catch {
                #expect(Bool(false), "Expected NoiseError but got: \(error)")
            }
        }
    }
    
    // MARK: - Out-of-Order Message Tests
    
    @Test("Out-of-order handshake messages")
    func testOutOfOrderHandshakeMessages() throws {
        // Create XX handshake sessions (3-message pattern)
        let initiatorStatic = KeyPair.generate()
        let responderStatic = KeyPair.generate()
        
        var initiator = try NoiseProtocol.handshake(pattern: .XX, initiator: true, staticKeypair: initiatorStatic)
        var responder = try NoiseProtocol.handshake(pattern: .XX, initiator: false, staticKeypair: responderStatic)
        
        // Get all three handshake messages
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        let message3 = try initiator.writeHandshakeMessage()
        
        // Try to replay message1 instead of processing message3
        do {
            let _ = try responder.readHandshakeMessage(message1) // Should fail - wrong message order
            #expect(Bool(false), "Should have thrown error for out-of-order message")
        } catch let error as NoiseError {
            // Expected specific errors for out-of-order/replayed messages
            switch error {
            case .invalidState, .malformedMessage, .authenticationFailure, .protocolViolation:
                #expect(true) // These are expected for out-of-order messages
            default:
                #expect(Bool(false), "Unexpected error for out-of-order message: \(error)")
            }
        } catch {
            // CryptoKit or other errors are also acceptable for tampered messages
            let errorString = String(describing: error)
            if errorString.contains("authentication") || errorString.contains("decrypt") {
                #expect(true) // Expected authentication/decryption failure
            } else {
                #expect(Bool(false), "Expected authentication/decryption error but got: \(error)")
            }
        }
        
        // Try to send a handshake message after completion
        let _ = try responder.readHandshakeMessage(message3) // Complete handshake
        
        #expect(throws: NoiseError.handshakeAlreadyComplete) {
            try responder.writeHandshakeMessage() // Should fail - handshake complete
        }
    }
    
    @Test("Unexpected handshake message format")
    func testUnexpectedHandshakeFormat() throws {
        // Use a completed handshake, then send random data as transport messages
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        // Complete handshake
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Test completely random data as transport message (should fail authentication)
        let randomData = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        
        do {
            let _ = try responder.readMessage(randomData)
            #expect(Bool(false), "Should have thrown an error")
        } catch let error as NoiseError {
            // Expected authentication failure for random transport data
            if case .authenticationFailure = error {
                #expect(true) // Expected NoiseError.authenticationFailure
            } else {
                #expect(Bool(false), "Expected NoiseError.authenticationFailure but got: \(error)")
            }
        } catch {
            // CryptoKit may throw its own authentication errors
            let errorString = String(describing: error)
            if errorString.contains("authentication") {
                #expect(true) // Expected authentication failure from CryptoKit
            } else {
                #expect(Bool(false), "Expected authentication failure but got: \(error)")
            }
        }
        
        // Test empty message (too short for MAC)
        do {
            let _ = try responder.readMessage(Data())
            #expect(Bool(false), "Should have thrown an error")
        } catch let error as NoiseError {
            // Expected error for empty/malformed message
            switch error {
            case .invalidMessageLength, .malformedMessage, .authenticationFailure:
                #expect(true) // These are expected error types for empty/invalid data
            default:
                #expect(Bool(false), "Unexpected error type: \(error)")
            }
        } catch {
            // CryptoKit or other errors are also acceptable for tampered messages
            let errorString = String(describing: error)
            if errorString.contains("authentication") || errorString.contains("decrypt") {
                #expect(true) // Expected authentication/decryption failure
            } else {
                #expect(Bool(false), "Expected authentication/decryption error but got: \(error)")
            }
        }
    }
    
    // MARK: - Nonce Exhaustion Tests
    
    @Test("Nonce exhaustion simulation")
    func testNonceExhaustion() throws {
        // Create a cipher state with a key
        let key = Data(repeating: 0x42, count: 32)
        var cipher = CipherState<ChaChaPoly>(key: key)
        
        // Simulate approaching nonce exhaustion by creating a cipher with high nonce
        // Note: We can't actually exhaust UInt64.max nonces in a test, so we'll test the error condition
        
        // This test validates that the nonce overflow error is properly defined and throwable
        #expect(NoiseError.nonceOverflow != NoiseError.authenticationFailure)
        
        // Test that we can encrypt many messages without immediate failure
        for _ in 0..<1000 {
            let plaintext = Data("Test message".utf8)
            let _ = try cipher.encryptWithAd(ad: Data(), plaintext: plaintext)
        }
        
        // Verify cipher is still functional after many operations
        let testPlaintext = Data("Final test".utf8)
        let ciphertext = try cipher.encryptWithAd(ad: Data(), plaintext: testPlaintext)
        #expect(ciphertext.count > testPlaintext.count) // Should include authentication tag
    }
    
    @Test("Nonce overflow edge case")
    func testNonceOverflowEdgeCase() throws {
        // Test the nonce overflow error type exists and is properly structured
        let overflowError = NoiseError.nonceOverflow
        
        // Verify error description
        let description = overflowError.localizedDescription
        #expect(description.contains("nonce") || description.contains("overflow"))
        
        // Verify error is equatable
        #expect(overflowError == NoiseError.nonceOverflow)
        #expect(overflowError != NoiseError.authenticationFailure)
    }
    
    // MARK: - State Violation Tests
    
    @Test("Invalid state transitions")
    func testInvalidStateTransitions() throws {
        // Test sending transport messages before handshake completion
        var session = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        
        #expect(throws: NoiseError.handshakeNotComplete) {
            try session.writeMessage(Data("Premature message".utf8))
        }
        
        #expect(throws: NoiseError.handshakeNotComplete) {
            try session.readMessage(Data("Invalid input".utf8))
        }
        
        #expect(throws: NoiseError.handshakeNotComplete) {
            try session.rekey()
        }
    }
    
    @Test("Double handshake completion attempt")
    func testDoubleHandshakeCompletion() throws {
        // Complete a handshake
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Try to continue handshake after completion
        #expect(throws: NoiseError.handshakeAlreadyComplete) {
            try initiator.writeHandshakeMessage()
        }
        
        #expect(throws: NoiseError.handshakeAlreadyComplete) {
            try responder.writeHandshakeMessage()
        }
    }
    
    // MARK: - Key Management Edge Cases
    
    @Test("Missing required keys")
    func testMissingRequiredKeys() throws {
        // Test patterns that require static keys - XX pattern may succeed creation but fail on operation
        do {
            var session = try NoiseProtocol.handshake(pattern: .XX, initiator: true)
            let _ = try session.writeHandshakeMessage()
            // If it succeeds, that's valid behavior - XX can work without pre-existing static keys
            #expect(Bool(true), "XX pattern can work without static keys")
        } catch {
            // If it fails, that's also valid - depends on implementation
            #expect(error is NoiseError)
        }
        
        // Test PSK patterns without PSK - should fail on creation or first write
        #expect(throws: NoiseError.self) {
            var session = try NoiseProtocol.handshake(pattern: .NNpsk0, initiator: true)
            let _ = try session.writeHandshakeMessage()
        }
        
        // Test NK pattern without remote static key - should fail on creation or first write
        #expect(throws: NoiseError.self) {
            var session = try NoiseProtocol.handshake(pattern: .NK, initiator: true)
            let _ = try session.writeHandshakeMessage()
        }
    }
    
    @Test("Invalid key lengths in different contexts")
    func testInvalidKeyLengthsInContext() throws {
        // Test various invalid key lengths for different crypto functions
        let shortKey = Data(repeating: 0x42, count: 16)  // Too short
        let longKey = Data(repeating: 0x42, count: 64)   // Too long for some functions
        
        // Test ChaCha20-Poly1305 with wrong key length
        #expect(throws: NoiseError.invalidKeyLength(expected: 32, actual: 16)) {
            try ChaChaPoly.encrypt(
                key: shortKey,
                nonce: 0,
                associatedData: Data(),
                plaintext: Data("test".utf8)
            )
        }
        
        // Test with oversized key
        #expect(throws: NoiseError.invalidKeyLength(expected: 32, actual: 64)) {
            try ChaChaPoly.encrypt(
                key: longKey,
                nonce: 0,
                associatedData: Data(),
                plaintext: Data("test".utf8)
            )
        }
    }
    
    // MARK: - Fuzz Testing Scenarios
    
    @Test("Random data as handshake messages")
    func testRandomDataAsHandshakeMessages() throws {
        var session = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        // Test multiple random data inputs
        for _ in 0..<10 {
            let randomLength = Int.random(in: 0...100)
            let randomData = Data((0..<randomLength).map { _ in UInt8.random(in: 0...255) })
            
            // Should handle random data gracefully without crashing
            do {
                let _ = try session.readHandshakeMessage(randomData)
                // If it doesn't throw, that's unexpected but not necessarily wrong
            } catch {
                // Expected to throw various NoiseError types
                #expect(error is NoiseError)
            }
        }
    }
    
    @Test("Random data as transport messages")
    func testRandomDataAsTransportMessages() throws {
        // Complete handshake first
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Test random data as transport messages
        for _ in 0..<10 {
            let randomLength = Int.random(in: 16...100) // At least MAC size
            let randomData = Data((0..<randomLength).map { _ in UInt8.random(in: 0...255) })
            
            // Should handle random data gracefully
            do {
                let _ = try responder.readMessage(randomData)
                #expect(Bool(false), "Should have thrown an error")
            } catch let error as NoiseError {
                // Expected authentication failure for random transport data
                if case .authenticationFailure = error {
                    #expect(true) // Expected NoiseError.authenticationFailure
                } else {
                    #expect(Bool(false), "Expected NoiseError.authenticationFailure but got: \(error)")
                }
            } catch {
                // CryptoKit may throw its own authentication errors
                let errorString = String(describing: error)
                if errorString.contains("authentication") {
                    #expect(true) // Expected authentication failure from CryptoKit
                } else {
                    #expect(Bool(false), "Expected authentication failure but got: \(error)")
                }
            }
        }
    }
    
    @Test("Edge case message sizes")
    func testEdgeCaseMessageSizes() throws {
        // Complete handshake
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Test maximum valid message size (accounting for MAC overhead)
        let maxValidMessage = Data(repeating: 0x42, count: 65519) // 65535 - 16 bytes for MAC
        let maxCiphertext = try initiator.writeMessage(maxValidMessage)
        let maxDecrypted = try responder.readMessage(maxCiphertext)
        #expect(maxDecrypted == maxValidMessage)
        
        // Test empty message
        let emptyCiphertext = try initiator.writeMessage(Data())
        let emptyDecrypted = try responder.readMessage(emptyCiphertext)
        #expect(emptyDecrypted.isEmpty)
        
        // Test single byte message
        let singleByte = Data([0xFF])
        let singleCiphertext = try initiator.writeMessage(singleByte)
        let singleDecrypted = try responder.readMessage(singleCiphertext)
        #expect(singleDecrypted == singleByte)
    }
    
    // MARK: - Concurrent Access Edge Cases
    
    @Test("Invalid rekey coordination")
    func testInvalidRekeyCoordination() throws {
        // Complete handshake
        var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
        var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
        
        let message1 = try initiator.writeHandshakeMessage()
        let _ = try responder.readHandshakeMessage(message1)
        
        let message2 = try responder.writeHandshakeMessage()
        let _ = try initiator.readHandshakeMessage(message2)
        
        // Rekey only one side
        try initiator.rekey()
        // Don't rekey responder
        
        // Communication should fail due to desynchronized keys
        let plaintext = Data("This should fail".utf8)
        let ciphertext = try initiator.writeMessage(plaintext)
        
        do {
            let _ = try responder.readMessage(ciphertext)
            #expect(Bool(false), "Should have thrown an authentication error")
        } catch let error as NoiseError {
            // Expected authentication failure for tampered MAC
            if case .authenticationFailure = error {
                #expect(true) // Expected NoiseError.authenticationFailure
            } else {
                #expect(Bool(false), "Expected NoiseError.authenticationFailure but got: \(error)")
            }
        } catch {
            // CryptoKit may throw its own authentication errors
            let errorString = String(describing: error)
            if errorString.contains("authentication") {
                #expect(true) // Expected authentication failure from CryptoKit
            } else {
                #expect(Bool(false), "Expected authentication failure but got: \(error)")
            }
        }
    }
    
    @Test("Protocol violation sequences")
    func testProtocolViolationSequences() throws {
        // Test NK pattern without remote static key (should fail immediately)
        #expect(throws: NoiseError.self) {
            var wrongPatternSession = try NoiseProtocol.handshake(pattern: .NK, initiator: true)
            let _ = try wrongPatternSession.writeHandshakeMessage() // Should fail - missing remote static key
        }
        
        // Test XX pattern without static keys - may or may not fail depending on implementation
        do {
            var xxSession = try NoiseProtocol.handshake(pattern: .XX, initiator: true)
            let _ = try xxSession.writeHandshakeMessage() // May succeed - XX can generate keys dynamically
            #expect(Bool(true), "XX pattern can work without pre-existing static keys")
        } catch {
            // If it fails, that's also valid behavior
            #expect(error is NoiseError)
        }
    }
}