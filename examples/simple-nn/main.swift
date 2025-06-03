import Foundation
import Noise

print("🔐 Simple NN (No Authentication) Example")
print("========================================")

do {
    // Create NN handshake sessions (no static keys needed)
    print("🚀 Creating anonymous sessions...")
    var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
    var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)
    
    print("🤝 Performing NN handshake...")
    
    // Message 1: Initiator -> Responder
    print("1️⃣  Initiator sends ephemeral key...")
    let message1 = try initiator.writeHandshakeMessage()
    let _ = try responder.readHandshakeMessage(message1)
    print("   ✅ Responder received ephemeral key")
    
    // Message 2: Responder -> Initiator  
    print("2️⃣  Responder sends ephemeral key...")
    let message2 = try responder.writeHandshakeMessage()
    let _ = try initiator.readHandshakeMessage(message2)
    print("   ✅ Initiator received ephemeral key")
    
    print("\n🎉 NN handshake complete!")
    print("🔒 Anonymous secure channel established")
    print("⚠️  Note: No authentication - identities are anonymous")
    
    // Exchange messages
    print("\n💬 Exchanging anonymous encrypted messages...")
    
    let message1_payload = Data("Hello from anonymous sender! 👻".utf8)
    print("📤 Sender: \"\(String(data: message1_payload, encoding: .utf8)!)\"")
    let encrypted1 = try initiator.writeMessage(message1_payload)
    let decrypted1 = try responder.readMessage(encrypted1)
    print("📥 Receiver: \"\(String(data: decrypted1, encoding: .utf8)!)\"")
    
    let message2_payload = Data("Anonymous reply received! 🔍".utf8)
    print("📤 Replier: \"\(String(data: message2_payload, encoding: .utf8)!)\"")
    let encrypted2 = try responder.writeMessage(message2_payload)
    let decrypted2 = try initiator.readMessage(encrypted2)
    print("📥 Original sender: \"\(String(data: decrypted2, encoding: .utf8)!)\"")
    
    print("\n✨ NN example completed!")
    print("🔐 Messages were encrypted but parties remain anonymous")
    print("🚀 Perfect for scenarios where privacy is needed without identity verification")
    
} catch {
    print("❌ Error: \(error)")
}