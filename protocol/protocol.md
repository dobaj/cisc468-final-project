# P2P Secure File Sharing — Protocol Specification

**Version:** 1  
**Authors:** Nick, Alice, Matt

This is the shared contract between all three clients (Java, Python, Go). If your client follows this spec exactly, it will interoperate with the others. If something is ambiguous, bring it up with the group before guessing.

---

## 1. The Big Picture

Here's what happens when two peers communicate:

1. **Discovery** — Peers find each other on the local network using mDNS (like how your laptop finds a printer).
2. **TCP Connection** — One peer connects to the other over TCP.
3. **Handshake** — They exchange identity keys and ephemeral keys, verify each other's signatures, and derive a shared session key. This is the mutual authentication step.
4. **Encrypted Channel** — From here on, every message is encrypted with AES-256-GCM using the session key. Nobody on the network can read the traffic.
5. **Do Stuff** — List files, request files, send files, migrate keys, etc.
6. **Disconnect** — Either side can close the connection whenever.

Every new connection does a fresh handshake with fresh ephemeral keys, so even if someone's long-term key is compromised later, past sessions stay private. That's perfect forward secrecy.

### Crypto Stack

| What | Algorithm | Why |
|------|-----------|-----|
| Identity keys | Ed25519 | Fast, 32-byte keys, well-supported everywhere |
| Key exchange | X25519 | Ephemeral Diffie-Hellman for PFS |
| Key derivation | HKDF-SHA256 | Turns the raw DH shared secret into a proper key |
| Session encryption | AES-256-GCM | Authenticated encryption — confidentiality + integrity in one shot |
| File integrity | SHA-256 | Detects tampered files |
| Encoding | Base64 (standard) | Binary data in JSON needs to be a string |

---

## 2. Transport: How Messages Get Sent Over TCP

TCP is a stream — it doesn't have built-in message boundaries. So we use **length-prefixed framing**: every message starts with 4 bytes that tell the receiver how long the JSON payload is.

```
┌──────────────────────────┬─────────────────────────────┐
│ 4 bytes: payload length  │ N bytes: UTF-8 JSON payload │
│ (big-endian uint32)      │                             │
└──────────────────────────┴─────────────────────────────┘
```

**Important details:**
- The 4-byte length is the size of the JSON in bytes, NOT including the 4 bytes themselves.
- Max payload: **10 MiB** (10,485,760 bytes). If you receive a length bigger than this, close the connection.
- Everything is UTF-8 encoded.

This is the #1 source of interop bugs. Make sure your length prefix is **big-endian** (most significant byte first). Java's `DataOutputStream.writeInt()` and Python's `struct.pack('>I', length)` both default to big-endian, but double-check your Go implementation.

---

## 3. Message Format

Every message is a JSON object with a `"type"` field:

```json
{
  "type": "MESSAGE_TYPE",
  ...other fields...
}
```

Rules:
- Field names are `snake_case` (e.g., `identity_pub`, `chunk_index`).
- All binary data (keys, signatures, nonces, IVs, ciphertext, file chunks) is Base64-encoded using the **standard** alphabet (A-Z, a-z, 0-9, +, /). No line breaks, no URL-safe variant.
- Hashes are **lowercase hex** strings (e.g., `"a3b2c4d5..."`).

---

## 4. The Handshake (Mutual Authentication + Key Exchange)

This is the most important part to get right. It happens in three messages:

```
Initiator (the one who opened the TCP connection)
    ──── AUTH_REQUEST ────>
                            Responder (the one listening)
    <── AUTH_RESPONSE ──────
    ──── AUTH_SUCCESS ────>
                            [both sides now have the session key]
```

If the trust check fails on either side, an `AUTH_FAIL` is sent and the connection closes.

### Step 1: AUTH_REQUEST (Initiator → Responder)

The initiator sends their identity public key, a fresh ephemeral X25519 public key, and a random 32-byte nonce.

```json
{
  "type": "AUTH_REQUEST",
  "version": 1,
  "identity_pub": "<base64, 32 bytes>",
  "ephemeral_pub": "<base64, 32 bytes>",
  "nonce": "<base64, 32 bytes>"
}
```

### Step 2: AUTH_RESPONSE (Responder → Initiator)

The responder sends the same fields, plus a signature that proves they own their identity key.

```json
{
  "type": "AUTH_RESPONSE",
  "version": 1,
  "identity_pub": "<base64, 32 bytes>",
  "ephemeral_pub": "<base64, 32 bytes>",
  "nonce": "<base64, 32 bytes>",
  "signature": "<base64>"
}
```

**How to compute the signature:**

Take these three values as raw bytes (decode them from Base64 first), concatenate them in this exact order, and sign the result with the responder's Ed25519 private key:

```
bytes_to_sign = initiator_nonce + initiator_ephemeral_pub + responder_ephemeral_pub
signature = Ed25519_Sign(responder_private_key, bytes_to_sign)
```

The order matters. If you get it wrong, the other client won't be able to verify your signature, and the handshake will fail silently. This is another common interop bug.

### Step 3: AUTH_SUCCESS (Initiator → Responder)

The initiator sends their own signature to prove they own their identity key.

```json
{
  "type": "AUTH_SUCCESS",
  "signature": "<base64>"
}
```

**Signature computation (note the order is swapped compared to AUTH_RESPONSE):**

```
bytes_to_sign = responder_nonce + responder_ephemeral_pub + initiator_ephemeral_pub
signature = Ed25519_Sign(initiator_private_key, bytes_to_sign)
```

### AUTH_FAIL (either side → the other)

Sent whenever authentication cannot proceed — trust rejected, signature bad, etc. Connection closes immediately after.

```json
{
  "type": "AUTH_FAIL",
  "reason": "Peer not trusted"
}
```

### After the Handshake: Deriving the Session Key

Both sides now independently compute the same session key:

```
shared_secret = X25519(my_ephemeral_private_key, their_ephemeral_public_key)
salt = initiator_nonce + responder_nonce
info = "p2p-session"    (as UTF-8 bytes)
session_key = HKDF-SHA256(ikm=shared_secret, salt=salt, info=info, output_length=32)
```

`initiator_nonce` is **always** the nonce from `AUTH_REQUEST`. `responder_nonce` is **always** the nonce from `AUTH_RESPONSE`. Both sides must use the same order regardless of which role they played.

### Trust Verification

After verifying the signature, each side checks the remote peer's identity key against their local trust store:

- **Already trusted:** Proceed normally.
- **Unknown key:** Show the fingerprint to the user and ask them to verify it out-of-band. If they accept, save it to the trust store. If they reject, send `AUTH_FAIL` and close.
- **Key mismatch (known contact, different key):** This could be an attack. Warn the user and reject.

---

## 5. Encrypted Messages

After the handshake, **every single message** gets wrapped in an encrypted envelope before sending:

```json
{
  "type": "ENCRYPTED",
  "iv": "<base64, 12 bytes>",
  "ciphertext": "<base64>"
}
```

- Generate a random 12-byte IV for each message.
- Encrypt the inner JSON message (as UTF-8 bytes) with AES-256-GCM using the session key and the IV.
- The `ciphertext` field contains both the encrypted data and the GCM authentication tag (most crypto libraries append the tag automatically).
- No AAD (additional authenticated data) is used.

The receiving side does the reverse: decode the Base64, decrypt with AES-256-GCM, and parse the inner JSON to figure out the actual message type.

---

## 6. Application Messages

These are the messages that go inside the encrypted envelope. They handle the actual file sharing functionality.

### FILE_LIST_REQUEST / FILE_LIST_RESPONSE

Request a peer's shared files. **No consent required** — the remote peer just responds immediately.

```json
{ "type": "FILE_LIST_REQUEST" }
```

```json
{
  "type": "FILE_LIST_RESPONSE",
  "files": [
    {
      "name": "photo.jpg",
      "size": 102400,
      "hash": "a3b2c4d5e6f7...",
      "origin": "<base64 public key of original owner>"
    }
  ]
}
```

The `origin` field is important: it tells you who originally shared this file. If Alice shares a file, Bob downloads it, and then you get it from Bob, the `origin` is still Alice's public key. This is how you verify the file hasn't been tampered with when fetching from a third party (requirement #5).

### FILE_REQUEST / FILE_ACCEPT / FILE_DENY

Ask a peer for a specific file. **Requires their consent** — they see a prompt and choose to accept or reject.

```json
{ "type": "FILE_REQUEST", "hash": "a3b2c4...", "name": "photo.jpg" }
```

If accepted, the peer sends `FILE_ACCEPT` and immediately starts sending `FILE_TRANSFER` chunks:

```json
{ "type": "FILE_ACCEPT", "hash": "a3b2c4..." }
```

If rejected:

```json
{ "type": "FILE_DENY", "hash": "a3b2c4...", "reason": "Request denied" }
```

### FILE_OFFER / FILE_OFFER_ACCEPT / FILE_OFFER_DENY

Push a file to a peer (the reverse direction — sender initiates). Also **requires consent**.

```json
{ "type": "FILE_OFFER", "name": "doc.pdf", "size": 51200, "hash": "b4c5d6..." }
```

If the receiver accepts:

```json
{ "type": "FILE_OFFER_ACCEPT", "hash": "b4c5d6..." }
```

If the receiver declines:

```json
{ "type": "FILE_OFFER_DENY", "hash": "b4c5d6..." }
```

### FILE_TRANSFER / FILE_COMPLETE

Files are sent in chunks. Each chunk is its own `FILE_TRANSFER` message. After the last chunk, a `FILE_COMPLETE` signals end-of-file.

```json
{
  "type": "FILE_TRANSFER",
  "hash": "a3b2c4...",
  "chunk_index": 0,
  "total_chunks": 3,
  "data": "<base64-encoded chunk>"
}
```

```json
{ "type": "FILE_COMPLETE", "hash": "a3b2c4..." }
```

- Max chunk size: **1 MiB** (before Base64 encoding).
- Chunks must be sent in order: 0, 1, 2, etc.
- The receiver reassembles on `FILE_COMPLETE` and computes SHA-256. If it doesn't match `hash`, the file was tampered with — discard it and warn the user.

### KEY_MIGRATION

When someone needs to switch to a new identity key (e.g., old key got compromised):

```json
{
  "type": "KEY_MIGRATION",
  "new_identity_pub": "<base64>",
  "signature_old": "<base64>",
  "signature_new": "<base64>"
}
```

How the signatures work:
- `signature_old` = the **old** private key signs the **new** public key's raw bytes. This proves the real owner authorized the switch.
- `signature_new` = the **new** private key signs the **old** public key's raw bytes. This proves the sender actually holds the new key.

The receiver verifies both signatures. If both check out, they update their trust store to use the new key. If either fails, they reject and warn the user.

The current session stays valid after migration. The new key takes effect on the next connection.

### ERROR

```json
{ "type": "ERROR", "code": "UNTRUSTED_KEY", "message": "Peer not in trust store" }
```

Standard error codes:

| Code | When to use it |
|------|---------------|
| `UNTRUSTED_KEY` | User rejected an unknown peer's fingerprint |
| `HANDSHAKE_FAILED` | Signature didn't verify during handshake |
| `INVALID_MESSAGE` | Received malformed or unexpected JSON |
| `FILE_NOT_FOUND` | Peer asked for a file hash we don't have |
| `TRANSFER_FAILED` | Something went wrong during file transfer |
| `HASH_MISMATCH` | File failed integrity check after transfer |
| `MIGRATION_FAILED` | Key migration signatures didn't verify |
| `VERSION_MISMATCH` | Protocol version not supported |

---

## 7. Peer Discovery (mDNS)

Each client advertises itself on the local network using mDNS so other peers can find it automatically.

**TCP port:** The group-agreed default is **6767**. mDNS advertises the actual port each peer is listening on, so discovery works correctly even if a peer can't bind to 6767 (e.g., two instances on the same machine — the second one falls back to a random port). Always trust the mDNS-advertised port, not an assumed constant.

**What to register:**
- Service type: `_p2pfs._tcp.local.`
- Instance name: whatever the user picked as their peer name
- Port: the TCP port you're listening on (ideally 6767, see above)
- TXT records: `fingerprint=<first 32 hex chars of your SHA-256 fingerprint>` and `version=1`

**What to browse for:**
- Continuously listen for other `_p2pfs._tcp.local.` services. When one appears, show the user the peer's name, IP, port, and fingerprint.

When a peer shuts down, it should unregister its service. Other peers will also notice the departure through mDNS TTL expiry.

> **Note:** mDNS uses the standard multicast address (224.0.0.251 / port 5353) internally — you don't need to manage this yourself. The "discovery port 6868" mentioned in early group notes referred to a different approach and is **not used**; mDNS handles everything automatically.

---

## 8. Trust Model

### How identity works

Each peer has a long-term **Ed25519 keypair**. The public key is your identity. It gets generated once (on first run) and reused across sessions.

### Fingerprints

A fingerprint is just the SHA-256 hash of your public key, displayed as hex. We group it in chunks of 4 for readability:

```
27A6 B5F6 6C62 8275 1455 269A 9555 2D49 ...
```

You verify fingerprints **out-of-band** — tell your teammate your fingerprint over text or in person, and they check it matches what their client shows during the handshake. This is the same model Signal uses for its "safety numbers."

### Trust store

Each client keeps a JSON file mapping trusted contacts to their public keys. Once you've verified someone's fingerprint and accepted them, their key is saved and you won't be prompted again on future connections.

---

## 9. File List Caching (Offline Peer Lookup)

This is for requirement #5: fetching a file from a third party when the original owner is offline.

Whenever you receive a `FILE_LIST_RESPONSE` from a peer, **save it to disk**. Cache it by the peer's identity public key. That way, if they go offline later, you still know what files they had and what the hashes were.

**The flow:**

1. You previously ran `list alice` and cached her file list (including `secret.txt` with hash `abc123...`).
2. Alice goes offline.
3. You want `secret.txt`. Your client checks the cache, finds the hash.
4. Your client queries connected peers' file lists for anyone who has a file with `origin = alice's key` and `hash = abc123...`.
5. If Bob has it (because he downloaded it from Alice earlier), you request it from Bob.
6. After transfer, you verify the SHA-256 matches `abc123...` from Alice's original list. If it does, the file is legit. If not, it was tampered with.

---

## 10. Encrypted Local Storage

All files stored on disk must be encrypted so that stealing the device doesn't expose them.

**How it works:**

1. On startup, the user enters a passphrase.
2. Derive a 256-bit storage key: `PBKDF2-HMAC-SHA256(passphrase, salt, 600000 iterations)`. The salt is random 16 bytes generated once and saved alongside the encrypted data. Argon2id is also fine if your language supports it easily.
3. Each file is encrypted with AES-256-GCM using a random 12-byte IV. Stored as `[IV || ciphertext || tag]`.
4. A metadata index (mapping hashes to encrypted file paths) is also encrypted with the same scheme.

---

## 11. Key Migration

When a user's key is compromised, they need to switch to a new one and let their contacts know.

1. Generate a new Ed25519 keypair.
2. Sign the new public key with the old private key (proves the real owner authorized this).
3. Sign the old public key with the new private key (proves you actually hold the new key).
4. Connect to each online contact using the **old** key, perform the handshake normally, then send a `KEY_MIGRATION` message.
5. Contacts verify both signatures and update their trust stores.
6. Save the new keypair locally, replacing the old one.

Contacts who were offline during migration won't get the message. When they try to connect later, the old key won't match your new one, and they'll have to re-verify your fingerprint manually. That's expected.

---

## 12. Common Interop Pitfalls

Things that tend to break when three different languages try to talk to each other:

1. **Byte order in the length prefix.** Must be big-endian. Java and Python default to this, but verify your Go implementation.
2. **Signature byte concatenation order.** The order is different for `AUTH_RESPONSE` vs `AUTH_SUCCESS`. Re-read Section 4 carefully.
3. **Base64 variant.** Use standard Base64 (not URL-safe, not unpadded). Java's `Base64.getEncoder()`, Python's `base64.b64encode()`, and Go's `base64.StdEncoding` all use the standard variant.
4. **HKDF salt order.** Always `AUTH_REQUEST nonce + AUTH_RESPONSE nonce` (i.e., initiator's nonce first), regardless of which side you are.
5. **Hash encoding.** File hashes are lowercase hex. Key fingerprints are also lowercase hex. Don't mix these up with Base64.
6. **GCM tag.** Most libraries append the tag to the ciphertext automatically. Don't try to separate them — just send `ciphertext + tag` together as the `ciphertext` field and let the decryption function handle it.
