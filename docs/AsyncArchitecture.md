# Async/Await Architecture in Noise Protocol Framework

This document explains the async/await implementation approach and architectural decisions in the Noise Protocol Framework for Swift.

## Implementation Approaches

### 1. Extension-Based Async Wrappers (NoiseAsync.swift)

The primary async support is provided through extensions that wrap synchronous cryptographic operations:

```swift
public mutating func writeMessageAsync(_ plaintext: Data) async throws -> Data {
    try Task.checkCancellation()
    return try writeMessage(plaintext)
}
```

**Characteristics:**
- **True Asynchronicity**: No - wraps synchronous crypto operations
- **Cancellation Support**: Yes - checks `Task.isCancelled` before operations
- **Thread Safety**: Requires external synchronization for concurrent access
- **Performance**: Minimal overhead, direct passthrough to sync operations
- **Use Case**: Best for single-task usage or when external synchronization is available

**Rationale:**
For a pure cryptographic library, the core operations (encryption, decryption, key exchange) are CPU-bound and inherently synchronous. The async keyword primarily serves to:
1. Allow callers to await these methods without blocking threads
2. Enable integration with networking APIs (URLSession, WebSocket)
3. Support cooperative cancellation in structured concurrency

### 2. Actor-Based Encapsulation (AsyncNoiseSession.swift)

An actor wrapper provides enhanced thread safety for concurrent scenarios:

```swift
public actor AsyncNoiseSession {
    private var session: NoiseSession
    
    public func writeMessage(_ plaintext: Data) async throws -> Data {
        try Task.checkCancellation()
        return try session.writeMessage(plaintext)
    }
}
```

**Characteristics:**
- **True Asynchronicity**: No - still wraps synchronous operations
- **Cancellation Support**: Yes - comprehensive cancellation checks
- **Thread Safety**: Yes - actor isolation provides mutual exclusion
- **Performance**: Slight overhead due to actor serialization
- **Use Case**: Best for multi-task concurrent access scenarios

**Benefits:**
- Automatic serialization of all session state mutations
- No external synchronization required
- Safe to pass across task boundaries
- Built-in protection against data races

## Cancellation Handling

Both implementations include comprehensive cancellation support:

```swift
// Check before potentially long-running operations
try Task.checkCancellation()

// Operations throw CancellationError when cancelled
let result = try await session.writeMessageAsync(data)
```

**Cancellation Points:**
- Before each cryptographic operation
- In AsyncSequence iteration
- In batch operations (between each message)

**Rationale:**
While individual crypto operations are fast and difficult to cancel mid-operation, cancellation checks allow:
- Responsive cancellation in batch operations
- Early termination of networking workflows
- Proper resource cleanup in structured concurrency

## When to Use Each Approach

### Extension-Based (NoiseAsync.swift)
**Recommended for:**
- Single-task usage patterns
- High-performance scenarios requiring minimal overhead
- Integration with existing synchronization mechanisms
- Direct replacement for synchronous APIs

**Example:**
```swift
// Single task managing session state
var session = try await NoiseProtocol.handshakeAsync(pattern: .XX, initiator: true)
let message = try await session.writeHandshakeMessageAsync()
```

### Actor-Based (AsyncNoiseSession.swift)
**Recommended for:**
- Multi-task concurrent access
- Server applications handling multiple connections
- Long-lived sessions shared across tasks
- Scenarios requiring guaranteed thread safety

**Example:**
```swift
// Multiple tasks safely accessing same session
let session = try AsyncNoiseSession(pattern: .XX, initiator: true)

// Safe concurrent access from multiple tasks
async let sending = session.writeMessage(plaintext1)
async let receiving = session.readMessage(ciphertext2)
let (sent, received) = try await (sending, receiving)
```

## Network Integration Patterns

### URLSession Integration
```swift
// Async handshake over HTTP
let handshakeMessage = try await session.writeHandshakeMessageAsync()
let (responseData, _) = try await urlSession.data(for: request)
let response = try await session.readHandshakeMessageAsync(responseData)
```

### WebSocket Integration
```swift
// Async messaging over WebSocket
let ciphertext = try await session.writeMessageAsync(plaintext)
try await webSocket.send(.data(ciphertext))

let message = try await webSocket.receive()
if case .data(let data) = message {
    let decrypted = try await session.readMessageAsync(data)
}
```

### Streaming with AsyncSequence
```swift
// Continuous message processing
let messageStream = AsyncNoiseMessageStream(session: session, transport: webSocket)
for try await plaintext in messageStream {
    // Process each decrypted message
    handleMessage(plaintext)
}
```

## Performance Considerations

### CPU-Bound Operations
The cryptographic operations (ChaCha20-Poly1305, Curve25519, SHA-256) are:
- Computationally intensive but fast (microseconds)
- Not suitable for mid-operation cancellation
- Don't benefit from true asynchronicity

### Network-Bound Integration
The async wrappers enable:
- Non-blocking integration with network I/O
- Structured concurrency with proper cancellation
- Cooperative task scheduling in concurrent applications

### Memory and Threading
- Extension approach: Zero additional memory overhead
- Actor approach: Minimal overhead for actor state management
- Both approaches avoid thread creation/destruction costs

## Future Considerations

### Potential True Async Operations
If future versions involve truly async operations (e.g., hardware security modules, key derivation services), the current architecture can be extended:

```swift
public mutating func writeMessageAsync(_ plaintext: Data) async throws -> Data {
    try Task.checkCancellation()
    
    // Hypothetical async key loading
    let key = await loadKeyFromSecureEnclave()
    
    // Async cryptographic operation
    return try await performAsyncEncryption(plaintext, key: key)
}
```

### Progressive Enhancement
The current wrapper approach provides a foundation that can be enhanced with true asynchronicity while maintaining API compatibility.

## Conclusion

The current async implementation balances:
- **Practical utility**: Enables modern Swift concurrency patterns
- **Performance**: Minimal overhead for CPU-bound operations
- **Safety**: Comprehensive cancellation and thread safety options
- **Flexibility**: Both lightweight and actor-based approaches available

This architecture provides excellent integration with Swift's async/await ecosystem while acknowledging the synchronous nature of cryptographic primitives.