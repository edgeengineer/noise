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
import Noise

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Example demonstrating secure WebSocket communication using Noise protocol with async/await
///
/// This example shows how to establish a Noise-encrypted WebSocket connection between
/// a client and server using Swift's modern concurrency features.

// MARK: - WebSocket Transport Implementation

/// WebSocket transport adapter for Noise protocol
class WebSocketNoiseTransport: AsyncMessageTransport {
    private let webSocket: URLSessionWebSocketTask
    
    init(webSocket: URLSessionWebSocketTask) {
        self.webSocket = webSocket
    }
    
    func receive() async throws -> Data? {
        let message = try await webSocket.receive()
        switch message {
        case .data(let data):
            return data
        case .string(let string):
            // Convert string to data if needed
            return string.data(using: .utf8)
        @unknown default:
            throw NoiseError.authenticationFailure
        }
    }
    
    func send(_ data: Data) async throws {
        try await webSocket.send(.data(data))
    }
}

// MARK: - Secure WebSocket Client

/// Secure WebSocket client using Noise protocol
class SecureWebSocketClient {
    private var session: URLSession
    private var noiseSession: NoiseSession?
    private var webSocket: URLSessionWebSocketTask?
    private var transport: WebSocketNoiseTransport?
    
    init() {
        self.session = URLSession(configuration: .default)
    }
    
    /// Connect to a secure WebSocket server
    func connect(to url: URL, staticKeypair: KeyPair? = nil) async throws {
        // Create WebSocket connection
        webSocket = session.webSocketTask(with: url)
        guard let webSocket = webSocket else {
            throw NoiseError.authenticationFailure
        }
        
        // Start WebSocket connection
        webSocket.resume()
        
        // Create Noise session
        noiseSession = try await NoiseProtocol.handshakeAsync(
            pattern: staticKeypair != nil ? .XX : .NN,
            initiator: true,
            staticKeypair: staticKeypair
        )
        
        // Create transport adapter
        transport = WebSocketNoiseTransport(webSocket: webSocket)
        
        // Perform Noise handshake over WebSocket
        try await performHandshake()
        
        print("✅ Secure WebSocket connection established")
    }
    
    /// Perform Noise protocol handshake over WebSocket
    private func performHandshake() async throws {
        guard var session = noiseSession,
              let transport = transport else {
            throw NoiseError.handshakeNotComplete
        }
        
        // Send initial handshake message
        let message1 = try await session.writeHandshakeMessageAsync()
        try await transport.send(message1)
        
        // Receive and process response
        guard let response1 = try await transport.receive() else {
            throw NoiseError.authenticationFailure
        }
        let _ = try await session.readHandshakeMessageAsync(response1)
        
        // Continue handshake if needed (for XX pattern)
        if !session.isHandshakeComplete {
            let message2 = try await session.writeHandshakeMessageAsync()
            try await transport.send(message2)
        }
        
        // Update stored session
        noiseSession = session
    }
    
    /// Send encrypted message
    func sendMessage(_ text: String) async throws {
        guard var session = noiseSession,
              let transport = transport else {
            throw NoiseError.handshakeNotComplete
        }
        
        let plaintext = Data(text.utf8)
        let ciphertext = try await session.writeMessageAsync(plaintext)
        try await transport.send(ciphertext)
        
        // Update stored session
        noiseSession = session
    }
    
    /// Receive and decrypt message
    func receiveMessage() async throws -> String? {
        guard var session = noiseSession,
              let transport = transport else {
            throw NoiseError.handshakeNotComplete
        }
        
        guard let ciphertext = try await transport.receive() else {
            return nil
        }
        
        let plaintext = try await session.readMessageAsync(ciphertext)
        noiseSession = session
        
        return String(data: plaintext, encoding: .utf8)
    }
    
    /// Start listening for messages
    func startListening() async throws {
        while true {
            do {
                if let message = try await receiveMessage() {
                    print("📨 Received: \(message)")
                } else {
                    print("🔚 Connection ended")
                    break
                }
            } catch {
                print("❌ Error receiving message: \(error)")
                break
            }
        }
    }
    
    /// Disconnect from server
    func disconnect() {
        webSocket?.cancel(with: .normalClosure, reason: nil)
        webSocket = nil
        noiseSession = nil
        transport = nil
    }
}

// MARK: - Example Usage

/// Example demonstrating secure WebSocket communication
func runWebSocketExample() async {
    print("🚀 Starting Secure WebSocket Example")
    
    // Generate client keypair for authentication
    let clientKeypair = KeyPair.generate()
    print("🔑 Generated client keypair")
    
    do {
        // Create secure WebSocket client
        let client = SecureWebSocketClient()
        
        // Connect to WebSocket server (replace with actual server URL)
        let serverURL = URL(string: "ws://localhost:8080/noise")!
        try await client.connect(to: serverURL, staticKeypair: clientKeypair)
        
        // Start concurrent message handling
        async let listening: Void = client.startListening()
        
        // Send some test messages
        try await client.sendMessage("Hello from Noise client!")
        try await client.sendMessage("This message is encrypted with Noise protocol")
        
        // Simulate some delay
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Send final message
        try await client.sendMessage("Goodbye!")
        
        // Wait for listening to complete or timeout
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await listening
            }
            
            group.addTask {
                try await Task.sleep(nanoseconds: 5_000_000_000) // 5 second timeout
                throw CancellationError()
            }
            
            try await group.next()
            group.cancelAll()
        }
        
        // Disconnect
        client.disconnect()
        print("✅ WebSocket example completed successfully")
        
    } catch {
        print("❌ WebSocket example failed: \(error)")
    }
}

// MARK: - Server Implementation (Simplified)

/// Simple WebSocket server for testing (would typically run separately)
class SecureWebSocketServer {
    private var noiseSession: NoiseSession?
    private let serverKeypair: KeyPair
    
    init() {
        self.serverKeypair = KeyPair.generate()
    }
    
    /// Handle incoming WebSocket connection
    func handleConnection(_ webSocket: URLSessionWebSocketTask) async throws {
        // Create responder session
        noiseSession = try await NoiseProtocol.handshakeAsync(
            pattern: .XX,
            initiator: false,
            staticKeypair: serverKeypair
        )
        
        let transport = WebSocketNoiseTransport(webSocket: webSocket)
        
        // Perform handshake
        try await performServerHandshake(transport: transport)
        
        // Handle messages
        try await handleMessages(transport: transport)
    }
    
    private func performServerHandshake(transport: WebSocketNoiseTransport) async throws {
        guard var session = noiseSession else {
            throw NoiseError.handshakeNotComplete
        }
        
        // Receive initial message
        guard let message1 = try await transport.receive() else {
            throw NoiseError.authenticationFailure
        }
        let _ = try await session.readHandshakeMessageAsync(message1)
        
        // Send response
        let response1 = try await session.writeHandshakeMessageAsync()
        try await transport.send(response1)
        
        // Continue handshake if needed
        if !session.isHandshakeComplete {
            guard let message2 = try await transport.receive() else {
                throw NoiseError.authenticationFailure
            }
            let _ = try await session.readHandshakeMessageAsync(message2)
        }
        
        noiseSession = session
    }
    
    private func handleMessages(transport: WebSocketNoiseTransport) async throws {
        while true {
            guard var session = noiseSession else { break }
            
            guard let ciphertext = try await transport.receive() else {
                break // Connection ended
            }
            
            let plaintext = try await session.readMessageAsync(ciphertext)
            let message = String(data: plaintext, encoding: .utf8) ?? "Invalid UTF-8"
            
            print("🖥️ Server received: \(message)")
            
            // Echo message back
            let echoText = "Echo: \(message)"
            let echoData = Data(echoText.utf8)
            let echoCiphertext = try await session.writeMessageAsync(echoData)
            try await transport.send(echoCiphertext)
            
            noiseSession = session
            
            // Break on goodbye message
            if message.lowercased().contains("goodbye") {
                break
            }
        }
    }
}

// MARK: - Main Example Runner

/// Run the WebSocket example
@main
struct WebSocketExample {
    static func main() async {
        await runWebSocketExample()
    }
}