# Noise

[![Swift](https://github.com/edgeengineer/noise/actions/workflows/swift.yml/badge.svg)](https://github.com/edgeengineer/noise/actions/workflows/swift.yml)
[![Swift 6.0+](https://img.shields.io/badge/Swift-6.0+-blue.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20iOS%20%7C%20visionOS%20%7C%20tvOS%20%7C%20WASM%20%7C%20Android-lightgrey.svg)](https://swift.org)

A Swift implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html), providing modern cryptographic protocols for secure communication.

## Features

- 🔒 **Secure**: Implements the Noise Protocol Framework specification
- 🚀 **Modern**: Built with Swift 6.0 and latest cryptographic practices
- 🔧 **Flexible**: Cryptographic agility with multiple cipher suites
- 🏛️ **Compliant**: FIPS-approved crypto options for enterprise environments
- 🔄 **Forward Secrecy**: Automatic and manual rekeying for long-lived sessions
- 🛡️ **Robust**: Comprehensive error handling and test vector validation
- 🌍 **Cross-platform**: Support for macOS, Linux, iOS, visionOS, tvOS, WASM, and Android
- 🧪 **Tested**: Comprehensive test suite using Swift Testing (51/51 tests passing)
- 📚 **Well-documented**: Full API documentation with examples

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/edgeengineer/noise.git", from: "0.0.3")
]
```

Then add `Noise` to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "Noise", package: "noise")
    ]
)
```

## Quick Start

### Basic NN Handshake

```swift
import Noise

// Create initiator and responder
var initiator = try NoiseProtocol.handshake(pattern: .NN, initiator: true)
var responder = try NoiseProtocol.handshake(pattern: .NN, initiator: false)

// Perform handshake
let message1 = try initiator.writeHandshakeMessage()
let _ = try responder.readHandshakeMessage(message1)

let message2 = try responder.writeHandshakeMessage()
let _ = try initiator.readHandshakeMessage(message2)

// Both sides now have secure channels
let plaintext = Data("Hello, Noise!".utf8)
let ciphertext = try initiator.writeMessage(plaintext)
let decrypted = try responder.readMessage(ciphertext)

print(String(data: decrypted, encoding: .utf8)!) // "Hello, Noise!"
```

### XX Handshake with Authentication

```swift
import Noise

// Generate static key pairs
let initiatorStatic = KeyPair.generate()
let responderStatic = KeyPair.generate()

// Create sessions with static keys
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

// Perform 3-message handshake
let message1 = try initiator.writeHandshakeMessage()
let _ = try responder.readHandshakeMessage(message1)

let message2 = try responder.writeHandshakeMessage()
let _ = try initiator.readHandshakeMessage(message2)

let message3 = try initiator.writeHandshakeMessage()
let _ = try responder.readHandshakeMessage(message3)

// Now both sides are authenticated and have secure channels
```

## Supported Handshake Patterns

### Core Patterns (8 supported)
- **N**: One-way, anonymous initiator to known responder
- **K**: One-way, known keys (mutual authentication)  
- **X**: One-way, mutual authentication with key exchange
- **NN**: No authentication (anonymous)
- **NK**: Known responder static key
- **XX**: Mutual authentication with key discovery
- **IX**: Interactive, immediate initiator authentication
- **IK**: Interactive, known responder key

### PSK Patterns (5 supported)
- **NNpsk0, NNpsk2**: Pre-shared key variants of NN
- **NKpsk0, NKpsk2**: Pre-shared key variants of NK  
- **XXpsk3**: Pre-shared key variant of XX

All patterns include comprehensive test coverage and follow the official Noise Protocol Framework specification.

## Cryptographic Suites

### StandardSuite (Default)
- **DH**: Curve25519
- **Cipher**: ChaCha20-Poly1305  
- **Hash**: SHA-256
- **Use case**: High performance, modern cryptography

### NISTSuite (FIPS Compliant)
- **DH**: P-256
- **Cipher**: AES-GCM
- **Hash**: SHA-256
- **Use case**: Government/enterprise compliance

### HighSecuritySuite
- **DH**: P-256
- **Cipher**: AES-GCM
- **Hash**: SHA-512
- **Use case**: Enhanced security margins

### Custom Suites
Define your own combinations of cryptographic primitives for specific requirements.

## Cryptographic Agility

Choose the cipher suite that best fits your requirements:

```swift
// High-performance default (same as v0.0.1)
let session = try NoiseProtocol.handshake(pattern: .XX, initiator: true)

// FIPS-compliant for enterprise
let session = try NoiseProtocol<NISTSuite>.handshake(pattern: .XX, initiator: true)

// Enhanced security
let session = try NoiseProtocol<HighSecuritySuite>.handshake(pattern: .XX, initiator: true)

// Custom suite
struct MyCustomSuite: NoiseCryptoSuite {
    typealias DH = P256
    typealias Cipher = AESGCM  
    typealias Hash = SHA512Hash
}
let customSession = try NoiseProtocol<MyCustomSuite>.handshake(pattern: .XX, initiator: true)
```

## Rekeying for Forward Secrecy

For long-lived sessions, rekeying provides forward secrecy by periodically updating cipher keys:

```swift
// Manual rekeying (both parties must coordinate)
try initiatorSession.rekey()
try responderSession.rekey()

// Automatic rekeying policies
session.rekeyPolicy = .messageCount(1000)    // Rekey after 1000 messages
session.rekeyPolicy = .timeInterval(3600)    // Rekey every hour  
session.rekeyPolicy = .nonceThreshold(50000) // Rekey before nonce exhaustion

// Monitor session health
let stats = session.getSessionStatistics()
print("Messages sent: \(stats["sentMessages"]!)")
print("Time since last rekey: \(stats["timeSinceLastRekey"]!)")

// Check if rekeying is needed
if session.shouldRekey() {
    try session.rekey()
}
```

### Security Benefits

- **Forward secrecy**: Past messages remain secure even if current keys are compromised
- **Nonce exhaustion protection**: Automatic rekeying prevents nonce overflow
- **Long-lived session support**: Maintain security over extended periods
- **Flexible policies**: Choose rekeying strategy based on your security requirements

## Examples

See the [examples](./examples) directory for more detailed usage examples:

- [Basic Client-Server](./examples/client-server)
- [File Transfer](./examples/file-transfer)
- [Streaming Data](./examples/streaming)

## Requirements

- Swift 6.0 or later
- Platforms: macOS 10.15+, iOS 13+, tvOS 13+, visionOS 1+, watchOS 6+

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [Noise Protocol Framework Specification](https://noiseprotocol.org/noise.html)
- [Swift Crypto](https://github.com/apple/swift-crypto)