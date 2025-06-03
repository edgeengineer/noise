import Foundation
import Noise

print("🔐 NK (Known Key) Example")
print("=========================")

do {
    // Server generates a static key pair
    print("🖥️  Server generating static key pair...")
    let serverStatic = KeyPair.generate()
    print("📤 Server publishes public key: \(serverStatic.publicKey.prefix(8).map { String(format: "%02x", $0) }.joined())...")
    
    // Client knows server's public key in advance
    print("📱 Client obtains server's public key through trusted channel")
    
    // Create NK handshake sessions
    print("\n🤝 Starting NK handshake...")
    var client = try NoiseProtocol.handshake(
        pattern: .NK,
        initiator: true,
        remoteStaticKey: serverStatic.publicKey  // Client knows server's key
    )
    
    var server = try NoiseProtocol.handshake(
        pattern: .NK,
        initiator: false,
        staticKeypair: serverStatic  // Server uses its static key
    )
    
    // Message 1: Client -> Server
    print("1️⃣  Client sends ephemeral key + encrypted data to known server...")
    let payload1 = Data("Client connecting to verified server".utf8)
    let message1 = try client.writeHandshakeMessage(payload: payload1)
    let receivedPayload1 = try server.readHandshakeMessage(message1)
    print("   ✅ Server received: \"\(String(data: receivedPayload1, encoding: .utf8)!)\"")
    
    // Message 2: Server -> Client
    print("2️⃣  Server responds with ephemeral key...")
    let payload2 = Data("Server confirmed - secure channel ready".utf8)
    let message2 = try server.writeHandshakeMessage(payload: payload2)
    let receivedPayload2 = try client.readHandshakeMessage(message2)
    print("   ✅ Client received: \"\(String(data: receivedPayload2, encoding: .utf8)!)\"")
    
    print("\n🎉 NK handshake complete!")
    print("🔒 Secure channel established")
    print("✅ Server is authenticated (client verified server's identity)")
    print("👻 Client remains anonymous")
    
    // Exchange messages
    print("\n💬 Secure communication...")
    
    let clientRequest = Data("GET /api/data - anonymous request".utf8)
    print("📤 Anonymous client: \"\(String(data: clientRequest, encoding: .utf8)!)\"")
    let encrypted1 = try client.writeMessage(clientRequest)
    let decrypted1 = try server.readMessage(encrypted1)
    print("📥 Verified server: \"\(String(data: decrypted1, encoding: .utf8)!)\"")
    
    let serverResponse = Data("200 OK - Data from authenticated server".utf8)
    print("📤 Verified server: \"\(String(data: serverResponse, encoding: .utf8)!)\"")
    let encrypted2 = try server.writeMessage(serverResponse)
    let decrypted2 = try client.readMessage(encrypted2)
    print("📥 Anonymous client: \"\(String(data: decrypted2, encoding: .utf8)!)\"")
    
    print("\n✨ NK example completed!")
    print("🛡️  Client successfully connected to verified server while staying anonymous")
    print("🌐 Perfect for web-like scenarios with server verification")
    
} catch {
    print("❌ Error: \(error)")
}