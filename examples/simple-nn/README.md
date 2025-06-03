# Simple NN Example

This example demonstrates the simplest Noise protocol handshake pattern: NN (No authentication).

## What is NN?

The NN pattern provides:
- ✅ Confidentiality (encryption)
- ✅ Forward secrecy
- ❌ No authentication (anonymous)

Perfect for cases where you need encryption but don't need to verify identities.

## Running the Example

```bash
swift run SimpleNN
```

## Use Cases

- Anonymous file sharing
- Public chat rooms
- Any scenario where encryption is needed but identity verification is not required