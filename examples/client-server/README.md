# Client-Server Example

This example demonstrates a basic client-server communication using the XX handshake pattern with mutual authentication.

## Running the Example

```bash
swift run ClientServer
```

## How it Works

1. **Key Generation**: Both client and server generate static key pairs
2. **Handshake**: They perform a 3-message XX handshake for mutual authentication
3. **Secure Communication**: Exchange encrypted messages over the secure channel
4. **Bidirectional**: Both sides can send and receive messages

## Code Structure

- `main.swift`: Complete client-server example
- Shows key generation, handshake, and message exchange
- Demonstrates error handling and proper session management