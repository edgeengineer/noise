import Foundation
import Noise

print("🔐 Noise Protocol Client-Server Example")
print("=======================================")

do {
    // Generate static key pairs for client and server
    print("📱 Generating client static key pair...")
    let clientStatic = KeyPair.generate()
    
    print("🖥️  Generating server static key pair...")
    let serverStatic = KeyPair.generate()
    
    // Create handshake sessions
    print("\n🤝 Starting XX handshake...")
    var client = try NoiseProtocol.handshake(
        pattern: .XX,
        initiator: true,
        staticKeypair: clientStatic
    )
    
    var server = try NoiseProtocol.handshake(
        pattern: .XX,
        initiator: false,
        staticKeypair: serverStatic
    )
    
    // Message 1: Client -> Server
    print("1️⃣  Client sends initial message...")
    let message1 = try client.writeHandshakeMessage()
    let _ = try server.readHandshakeMessage(message1)
    print("   ✅ Server received and processed message 1")
    
    // Message 2: Server -> Client
    print("2️⃣  Server responds...")
    let message2 = try server.writeHandshakeMessage()
    let _ = try client.readHandshakeMessage(message2)
    print("   ✅ Client received and processed message 2")
    
    // Message 3: Client -> Server
    print("3️⃣  Client sends final handshake message...")
    let message3 = try client.writeHandshakeMessage()
    let _ = try server.readHandshakeMessage(message3)
    print("   ✅ Server received and processed message 3")
    
    print("\n🎉 Handshake complete! Both parties are authenticated.")
    print("🔒 Secure channel established.")
    
    // Now exchange secure messages
    print("\n💬 Exchanging secure messages...")
    
    // Client sends a message
    let clientMessage = Data("Hello from client! 👋".utf8)
    print("📤 Client sending: \"\(String(data: clientMessage, encoding: .utf8)!)\"")
    let encryptedToServer = try client.writeMessage(clientMessage)
    let decryptedAtServer = try server.readMessage(encryptedToServer)
    print("📥 Server received: \"\(String(data: decryptedAtServer, encoding: .utf8)!)\"")
    
    // Server responds
    let serverMessage = Data("Hello from server! Welcome! 🚀".utf8)
    print("📤 Server sending: \"\(String(data: serverMessage, encoding: .utf8)!)\"")
    let encryptedToClient = try server.writeMessage(serverMessage)
    let decryptedAtClient = try client.readMessage(encryptedToClient)
    print("📥 Client received: \"\(String(data: decryptedAtClient, encoding: .utf8)!)\"")
    
    // More back and forth
    let clientMessage2 = Data("Can you handle file transfers? 📁".utf8)
    print("📤 Client sending: \"\(String(data: clientMessage2, encoding: .utf8)!)\"")
    let encrypted2 = try client.writeMessage(clientMessage2)
    let decrypted2 = try server.readMessage(encrypted2)
    print("📥 Server received: \"\(String(data: decrypted2, encoding: .utf8)!)\"")
    
    let serverMessage2 = Data("Yes! I can handle any data securely! 🛡️".utf8)
    print("📤 Server sending: \"\(String(data: serverMessage2, encoding: .utf8)!)\"")
    let encrypted3 = try server.writeMessage(serverMessage2)
    let decrypted3 = try client.readMessage(encrypted3)
    print("📥 Client received: \"\(String(data: decrypted3, encoding: .utf8)!)\"")
    
    print("\n✨ Example completed successfully!")
    print("🔐 All messages were encrypted and authenticated using the Noise Protocol.")
    
} catch {
    print("❌ Error: \(error)")
}