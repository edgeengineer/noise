# Noise

[![Swift](https://github.com/edgeengineer/noise/actions/workflows/swift.yml/badge.svg)](https://github.com/edgeengineer/noise/actions/workflows/swift.yml)
[![Swift 6.0+](https://img.shields.io/badge/Swift-6.0+-blue.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20iOS%20%7C%20visionOS%20%7C%20tvOS%20%7C%20WASM%20%7C%20Android-lightgrey.svg)](https://swift.org)

A Swift implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html), providing modern cryptographic protocols for secure communication.

## Features

- 🔒 **Secure**: Implements the Noise Protocol Framework specification
- 🚀 **Modern**: Built with Swift 6.0 and latest cryptographic practices
- 🌍 **Cross-platform**: Support for macOS, Linux, iOS, visionOS, tvOS, WASM, and Android
- 🧪 **Tested**: Comprehensive test suite using Swift Testing
- 📚 **Well-documented**: Full API documentation with examples

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/edgeengineer/noise.git", from: "0.0.1")
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

- **NN**: No authentication
- **NK**: Known responder static key
- **NX**: Unknown responder static key
- **XN, XK, XX**: Unknown/known initiator and responder keys
- **KN, KK, KX**: Known initiator static key patterns
- **IN, IK, IX**: Immediate initiator static key patterns

## Cryptographic Primitives

- **DH**: Curve25519
- **Cipher**: ChaCha20-Poly1305
- **Hash**: SHA-256

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