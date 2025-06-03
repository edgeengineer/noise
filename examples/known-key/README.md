# Known Key (NK) Example

This example demonstrates the NK handshake pattern where the initiator knows the responder's static public key in advance.

## What is NK?

The NK pattern provides:
- ✅ Confidentiality (encryption)
- ✅ Forward secrecy  
- ✅ Server authentication (responder is authenticated)
- ❌ Client authentication (initiator remains anonymous)

Perfect for client-server scenarios where clients need to verify the server's identity but can remain anonymous.

## Running the Example

```bash
swift run KnownKey
```

## Use Cases

- Web browsing (client verifies server, stays anonymous)
- API access with server verification
- Anonymous file downloads from trusted servers