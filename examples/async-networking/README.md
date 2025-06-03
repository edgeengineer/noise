# Async/Await Networking Examples

This directory contains examples demonstrating how to use the Noise Protocol Framework with Swift's async/await concurrency features for networking applications.

## Examples

### 1. WebSocket Client-Server
- **File**: `websocket-example.swift`
- **Description**: Secure WebSocket communication using Noise protocol with async/await
- **Features**: Real-time messaging, connection management, error handling

### 2. TCP Client-Server
- **File**: `tcp-example.swift` 
- **Description**: TCP socket communication with Noise encryption using async/await
- **Features**: Stream-based communication, connection pooling, graceful shutdown

### 3. HTTP Client with Noise
- **File**: `http-client-example.swift`
- **Description**: HTTP client with Noise-encrypted payloads using URLSession
- **Features**: Request/response patterns, authentication, retry logic

### 4. Streaming Data Processing
- **File**: `streaming-example.swift`
- **Description**: Continuous data stream processing with Noise protocol
- **Features**: AsyncSequence integration, backpressure handling, flow control

## Key Concepts

### Async/Await Integration

The Noise Protocol Framework provides async versions of all major operations:

```swift
// Async handshake
let message = try await session.writeHandshakeMessageAsync()
let response = try await session.readHandshakeMessageAsync(receivedData)

// Async messaging
let ciphertext = try await session.writeMessageAsync(plaintext)
let decrypted = try await session.readMessageAsync(ciphertext)

// Async rekeying
try await session.rekeyAsync()
```

### Structured Concurrency

Examples demonstrate proper use of Swift's structured concurrency:

- Task groups for concurrent operations
- Async sequences for streaming data
- Proper cancellation handling
- Resource cleanup with defer blocks

### Error Handling

Comprehensive error handling patterns:

- NoiseError propagation in async contexts
- Network error recovery strategies
- Graceful degradation techniques
- Timeout and cancellation handling

### Performance Considerations

- Zero-copy data handling where possible
- Efficient buffer management
- Concurrent session handling
- Memory pressure management

## Building and Running

Each example is self-contained and can be built with:

```bash
swift build
swift run example-name
```

Or include in your own project by copying the relevant code and adapting to your networking layer.

## Security Notes

These examples demonstrate secure patterns:

- Proper key management
- Secure random number generation
- Memory cleanup for sensitive data
- Forward secrecy through rekeying

Always review security implications for your specific use case and consider professional security auditing for production applications.