import Foundation
import Testing
@testable import Noise

extension Data {
    init(hex: String) {
        let cleanHex = hex.replacingOccurrences(of: " ", with: "")
        var data = Data()
        var index = cleanHex.startIndex
        while index < cleanHex.endIndex {
            let nextIndex = cleanHex.index(index, offsetBy: 2)
            let byteString = String(cleanHex[index..<nextIndex])
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            }
            index = nextIndex
        }
        self = data
    }
}

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

@Test("Test vectors - NN pattern basic validation")
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