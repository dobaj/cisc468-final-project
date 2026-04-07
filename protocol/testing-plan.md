# Testing Plan

This is our checklist for making sure everything works — both within each client and across all three languages. Each test maps to a specific assignment requirement so we know we're not missing anything.

The plan is split into two parts:
- **Automated tests** — unit and integration tests you run locally before we meet (`mvn test`, `pytest`, `go test`). These catch bugs in your own code.
- **Manual tests** — things we do together on the same LAN to verify the clients actually talk to each other correctly.

**Before our group testing session, everyone should have their automated tests passing.** That way we're not debugging basic crypto bugs while sitting together — we can focus on the cross-language stuff.

---

## Requirement 1: Peer Discovery

> *"Support peer discovery on a local network."*

We use mDNS for this. Each client broadcasts its presence, and the others pick it up automatically.

### Automated

| # | What to test | What should happen |
|---|---|---|
| 1.1 | Start two instances of your client on the same machine | They discover each other via mDNS within a few seconds |

### Manual (all three clients)

| # | What to test | What should happen |
|---|---|---|
| 1.2 | Start Java, Python, and Go on the same Wi-Fi | Running `peers` on any client shows the other two (name, IP, port, fingerprint) |
| 1.3 | Kill one of the clients | The other two notice (peer disappears from the `peers` list) |

---

## Requirement 2: Mutual Authentication

> *"After key verification, each user should be assured of the identity of the user they are communicating with."*

This is the handshake. Both sides prove they own their identity key by signing the other side's nonce.

### Automated

| # | What to test | What should happen |
|---|---|---|
| 2.1 | Two peers that already trust each other do a handshake | Completes successfully, both sides report authenticated |
| 2.2 | Connect to an unknown peer, user types `n` to reject | Handshake fails, connection closes, error message shown |
| 2.3 | Connect to an unknown peer, user types a name to accept | Fingerprint displayed, contact saved to trust store, handshake completes |
| 2.4 | Try to verify a signature with the wrong key | Verification returns false |
| 2.5 | Try to verify a signature over a tampered message | Verification returns false |

### Manual (cross-language)

| # | What to test | What should happen |
|---|---|---|
| 2.6 | Java connects to Python for the first time | Both sides see the fingerprint prompt. Verify the fingerprints match what each client printed at startup. Accept, and the handshake completes. |
| 2.7 | Java connects to Go (already trusted from a previous session) | Handshake completes instantly, no prompt |

---

## Requirement 3: File Request and Send (with Consent)

> *"Peers should be able to request files from each other, or send a file to another peer; the peer receiving a request or receiving a file should consent before the request is processed."*

Both directions (pull and push) need a consent prompt on the receiving end.

### Automated

| # | What to test | What should happen |
|---|---|---|
| 3.1 | Peer A requests a file, Peer B accepts | B sends `accepted: true`, then the file data |
| 3.2 | Peer A requests a file, Peer B rejects | B sends `accepted: false`, no data follows |
| 3.3 | Peer A offers to send a file, Peer B accepts | B sends `accepted: true`, A sends the data |
| 3.4 | Peer A offers to send a file, Peer B rejects | B sends `accepted: false`, nothing happens |

### Manual (cross-language)

| # | What to test | What should happen |
|---|---|---|
| 3.5 | Java: `request python-peer testfile.txt` — Python user types `y` | File transfers, Java confirms hash verified and file saved |
| 3.6 | Java: `request python-peer testfile.txt` — Python user types `n` | Java shows "rejected", no file transferred |
| 3.7 | Go: `send java-peer doc.pdf` — Java user types `y` | File arrives at Java, hash verified |
| 3.8 | Go: `send java-peer doc.pdf` — Java user types `n` | Go shows "rejected", no file transferred |

---

## Requirement 4: File Listing (No Consent)

> *"Peers should be able to request a list of files available to be shared by each other (consent is not required)."*

Unlike file transfers, listing files should just work — no prompt on the other side.

### Automated

| # | What to test | What should happen |
|---|---|---|
| 4.1 | Send FILE_LIST_REQUEST to a peer | Get back FILE_LIST_RESPONSE with file names, sizes, hashes, and origins |
| 4.2 | Check that no consent prompt appeared on the responding peer | The response was automatic — no user interaction needed |

### Manual (cross-language)

| # | What to test | What should happen |
|---|---|---|
| 4.3 | Java runs `list python-peer` | Python's files show up immediately. Python's terminal shows no prompt. |
| 4.4 | After downloading a file from one peer, check that `list` on another peer shows the `origin` correctly | A file originally from Alice should still show Alice's key as the origin, even when listed by Bob |

---

## Requirement 5: Offline Peer — Fetch from Third Party

> *"If peer A is offline, but peer B already had peer A's list of available files, peer B may find another peer C that had previously downloaded the file from peer A, and request the file from them instead."*

This is the trickiest requirement. It needs all three of us online for setup, then one person goes offline.

### Manual (all three clients — this is the big one)

| # | What to test | Steps | What should happen |
|---|---|---|---|
| 5.1 | Fetch from third party, hash verified | 1. **Alice** (Python) has `secret.txt` in her shared folder<br>2. **Nick** (Java) runs `list alice` — this caches Alice's file list<br>3. **Matt** (Go) runs `request alice secret.txt` and downloads it<br>4. **Alice shuts down her client**<br>5. **Nick** runs `request alice secret.txt` | Nick can't reach Alice. His client checks the cache, finds the hash, searches Matt's file list, finds the file (with `origin = alice`), downloads it from Matt, and verifies the SHA-256 matches Alice's original hash. |
| 5.2 | Tampered file is caught | Same setup as 5.1, but before step 5, Matt manually edits the file on his disk to corrupt it | Nick downloads from Matt, hash check fails, file is rejected with a tamper warning |

---

## Requirement 6: Key Migration

> *"Allow users to migrate to a new key if their old one is compromised. Existing contacts should be notified."*

### Automated

| # | What to test | What should happen |
|---|---|---|
| 6.1 | Create a KEY_MIGRATION message, verify both signatures | Old key's signature over new key verifies. New key's signature over old key verifies. |
| 6.2 | Verify KEY_MIGRATION with the wrong "current" key | Verification fails — migration rejected |
| 6.3 | Apply a valid migration to the trust store | The contact's key gets updated to the new one |

### Manual (cross-language)

| # | What to test | What should happen |
|---|---|---|
| 6.4 | Nick (Java) runs `migrate` while connected to Alice and Matt | Both Alice and Matt see a confirmation that Nick migrated. Their trust stores update. |
| 6.5 | After migrating, Nick disconnects and reconnects to Alice | Handshake works with the new key, no fingerprint prompt (Alice's trust store already has the new key) |
| 6.6 | Matt was offline during Nick's migration. Matt comes back and tries to connect to Nick. | Connection fails because Matt still has Nick's old key. Nick and Matt have to re-verify fingerprints manually. |

---

## Requirement 7: Confidentiality and Integrity

> *"Guarantee the confidentiality and integrity of any files that are sent between users."*

### Automated

| # | What to test | What should happen |
|---|---|---|
| 7.1 | Encrypt then decrypt a message with AES-256-GCM | Decrypted output matches the original |
| 7.2 | Encrypt the same plaintext twice | Different ciphertexts (because the IV is random each time) |
| 7.3 | Flip a byte in the ciphertext, try to decrypt | Decryption fails (GCM tag check catches the tampering) |
| 7.4 | Try to decrypt with a different key | Decryption fails |
| 7.5 | Transfer a file, check the hash | SHA-256 of received file matches the hash from the file list |
| 7.6 | Modify file data before hashing | SHA-256 doesn't match, file gets rejected |

### Manual (cross-language)

| # | What to test | What should happen |
|---|---|---|
| 7.7 | Transfer a file between Java and Python | File arrives intact, hash verified, `diff` the two files and they're identical |

---

## Requirement 8: Perfect Forward Secrecy

> *"Compromise of a long-term secret should not allow an attacker to decrypt all past communication."*

### Automated

| # | What to test | What should happen |
|---|---|---|
| 8.1 | Create two KeyExchange instances | They produce different ephemeral public keys (each one is random) |
| 8.2 | Connect to the same peer twice | The two sessions have different session keys (because the ephemeral keys are different) |

### For the report

PFS is guaranteed by design: every TCP connection uses a fresh X25519 ephemeral keypair. The session key comes from the ephemeral shared secret, not the long-term Ed25519 key. If the Ed25519 key leaks, an attacker can impersonate you going forward but **cannot** decrypt any past sessions — the ephemeral private keys are never saved to disk.

---

## Requirement 9: Encrypted Local Storage

> *"Securely store files on the local client device, so that an attacker who steals the device should not be able to read them."*

### Automated

| # | What to test | What should happen |
|---|---|---|
| 9.1 | Store a file with passphrase A, retrieve it with passphrase A | Decrypted file matches the original |
| 9.2 | Store a file with passphrase A, try to retrieve with passphrase B | Decryption fails |
| 9.3 | Read the raw `.enc` file from disk | It's gibberish — not the original plaintext |

### Manual

| # | What to test | What should happen |
|---|---|---|
| 9.4 | After receiving a file, look in `data/<name>/store/` | You see `.enc` files with UUID names, not readable as plaintext |
| 9.5 | Restart the app with the same passphrase | Your previously stored files are still accessible |
| 9.6 | Restart the app with a different passphrase | Can't read the old encrypted index — stored files are inaccessible |

---

## Requirement 10: Error Handling

> *"Display an appropriate message to the user if any error occurs or a security check fails."*

### Automated

| # | What to test | What should happen |
|---|---|---|
| 10.1 | Request a file hash that doesn't exist | User sees a `FILE_NOT_FOUND` error |
| 10.2 | Reject an unknown peer during handshake | User sees an `UNTRUSTED_KEY` error, connection closes |
| 10.3 | Handshake with a bad signature | User sees a `HANDSHAKE_FAILED` error |
| 10.4 | Receive a file whose hash doesn't match | User sees a tamper warning, file is discarded |

### Manual (cross-language)

| # | What to test | What should happen |
|---|---|---|
| 10.5 | Java requests a file that Python doesn't have | Java shows "FILE_NOT_FOUND" error message |
| 10.6 | Kill a peer mid-transfer (Ctrl+C) | The other peer shows "connection lost" message, doesn't crash |

---

## Requirement 11: Cross-Language Interoperability

> *"Clients should be able to communicate with each other despite being implemented with different cryptographic APIs in different languages."*

This is what the whole project comes down to. Run the full interop matrix.

### Manual (all three clients)

| # | What to test | What should happen |
|---|---|---|
| 11.1 | Java <-> Python handshake | Mutual auth completes |
| 11.2 | Java <-> Go handshake | Mutual auth completes |
| 11.3 | Python <-> Go handshake | Mutual auth completes |
| 11.4 | Java sends a file to Python | File received, hash verified |
| 11.5 | Python sends a file to Go | File received, hash verified |
| 11.6 | Go sends a file to Java | File received, hash verified |
| 11.7 | All three online, check file lists with origin tracking | `list` shows files with correct `origin` keys regardless of who currently holds the file |

---

## Checklist: Run Through This in Order

### Before we meet

Everyone runs their automated tests solo. Don't show up with failing tests.

- [ ] **Nick (Java):** `cd java-nick && mvn test` — all 37 tests pass
- [ ] **Alice (Python):** `cd python-alice && pytest` — all tests pass
- [ ] **Matt (Go):** `cd go-matt && go test ./...` — all tests pass

### Group session (same Wi-Fi)

Work through these in order. If something breaks, fix it before moving on — later tests depend on earlier ones working.

1. [ ] **Discovery** (1.2, 1.3) — can we see each other?
2. [ ] **Authentication** (2.6, 2.7) — can we handshake across languages?
3. [ ] **File listing** (4.3, 4.4) — can we list each other's files?
4. [ ] **File transfer with consent** (3.5–3.8) — request, send, accept, reject
5. [ ] **File integrity** (7.7) — does the file arrive intact across languages?
6. [ ] **Offline peer fetch** (5.1, 5.2) — the three-peer scenario with hash verification
7. [ ] **Key migration** (6.4–6.6) — migrate, reconnect, offline peer re-verify
8. [ ] **Error scenarios** (10.5, 10.6) — missing files, killed connections
9. [ ] **Full interop matrix** (11.1–11.7) — every pair, both directions
