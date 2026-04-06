# P2P Secure File Sharing Protocol

## Transport

- Peer discovery uses mDNS with service type `_p2pfs._tcp.local.`
- Peers communicate over TCP
- Each TCP message is length-prefixed with a 4-byte big-endian unsigned integer
- Payloads are UTF-8 JSON objects

## Cryptography

- Long-term identity keys: `Ed25519`
- Ephemeral key agreement: `X25519`
- Session key derivation: `HKDF-SHA256`, 32-byte output, `info = "session key"`
- Session encryption: `AES-256-GCM`
- File hashing: `SHA-256`
- Local encrypted storage: `AES-256-GCM` with storage key from `PBKDF2-HMAC-SHA256`

## Handshake

### 1. Ephemeral key exchange

Each peer sends:

```json
{
  "type": "key_exchange",
  "pub": "<hex-encoded X25519 public key>"
}
```

### 2. Identity exchange

Each peer sends:

```json
{
  "type": "hello",
  "name": "Alice1",
  "identity_pub": "<hex-encoded Ed25519 public key>",
  "fingerprint": "<sha256(identity_pub)>",
  "signature": "<hex-encoded Ed25519 signature over hello metadata and both X25519 public keys>"
}
```

Rules:

- The `hello.signature` must verify against the advertised `identity_pub`
- The signed payload must bind the peer identity to the current X25519 exchange
- If a contact already exists in the trust store, the fingerprint must match
- If the fingerprint is new, the user must confirm it out-of-band before trusting the peer
- A fingerprint mismatch must abort the connection

### 3. Encrypted session messages

After the handshake, all application messages are sent inside:

```json
{
  "type": "data",
  "nonce": "<hex-encoded 12-byte nonce>",
  "payload": "<hex-encoded AES-GCM ciphertext>"
}
```

The decrypted plaintext is a JSON message encoded with sorted keys and compact separators.

## Encrypted Application Messages

### Request file list

```json
{
  "type": "file_list_request"
}
```

### File list response

```json
{
  "type": "file_list_response",
  "files": [
    {
      "owner": "Alice1",
      "owner_pub": "<hex>",
      "filename": "hello.txt",
      "sha256": "<hex>",
      "size": 123,
      "signature": "<hex>"
    }
  ]
}
```

### Request file

```json
{
  "type": "file_request",
  "filename": "hello.txt"
}
```

### Offer file

```json
{
  "type": "file_offer",
  "filename": "hello.txt",
  "record": {
    "owner": "Alice1",
    "owner_pub": "<hex>",
    "filename": "hello.txt",
    "sha256": "<hex>",
    "size": 123,
    "signature": "<hex>"
  }
}
```

### Offer response

```json
{
  "type": "file_offer_response",
  "filename": "hello.txt",
  "accepted": true,
  "message": ""
}
```

### File data

```json
{
  "type": "file_chunk",
  "filename": "hello.txt",
  "data": "<hex-encoded file bytes>",
  "record": {
    "owner": "Alice1",
    "owner_pub": "<hex>",
    "filename": "hello.txt",
    "sha256": "<hex>",
    "size": 123,
    "signature": "<hex>"
  },
  "done": true
}
```

The receiver must:

- verify the SHA-256 hash
- verify the Ed25519 signature over the metadata record
- reject the file if verification fails

This allows an offline peer to fetch a cached copy from another peer while still verifying the original owner’s signed metadata.

### Key migration

```json
{
  "type": "key_migration",
  "new_pub": "<hex-encoded new Ed25519 public key>",
  "old_sig": "<hex-encoded signature by old key over new_pub bytes>",
  "new_sig": "<hex-encoded signature by new key over old_pub bytes>"
}
```

The receiver must verify both signatures before updating the trusted fingerprint.

### Error

```json
{
  "type": "error",
  "message": "human-readable error"
}
```

## Consent Rules

- `file_list_request`: no consent required
- `file_request`: receiver consent required before sending file bytes
- `file_offer`: receiver consent required before accepting file bytes

## Local Storage

- Shared plaintext files live in `data/<peer-name>/shared/`
- Received files are also stored encrypted in `data/<peer-name>/store/`
- Identity keys and trust stores are persisted under `data/<peer-name>/`
