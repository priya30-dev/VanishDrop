# Module 3 · Socket programming and cryptography

Everything in this module is real code in the project, not a separate toy program.

## 1. Where each requirement lives

| Syllabus item | File | What to show |
|---|---|---|
| UDP client-server | `vd/discovery.py` | `socket(AF_INET, SOCK_DGRAM)`, `SO_BROADCAST`, `sendto()` beacons every 3 s, `recvfrom()` listener thread; signed delivery alerts |
| TCP client-server | `vd/transfer.py`, `vd/protocol.py` | `socket(AF_INET, SOCK_STREAM)`, `bind/listen/accept` server with a thread per connection; `create_connection` client; our own length-prefixed framing |
| Symmetric key (AES) | `vd/crypto_lan.py` `Channel`; `static/js/common.js` | AES-256-GCM, counter nonces per direction; browser Web Crypto for links |
| Asymmetric key (RSA) | `vd/identity.py`; `static/js/common.js` | RSA-2048 device keys, RSA-PSS signatures; RSA-OAEP key wrapping for upload requests |
| Key exchange (Diffie-Hellman) | `vd/crypto_lan.py` `DHKeyPair` | RFC 3526 2048-bit group, generator 2, public-value validation, HKDF to session keys |

## 2. The protocol (VD1)

```
Frame:  | length (4 bytes, big-endian) | type (1 byte) | payload (≤ 1 MB) |

 1 HELLO        client → server   JSON  {proto, name, pub, dh, nonce, sig}
 2 HELLO_REPLY  server → client   JSON  {proto, name, pub, dh, nonce, sig}
 3 CONFIRM      client → server   AES   {sig over transcript hash}
 4 REQUEST      client → server   AES   {"op":"pair"}, {"op":"offer", tid, name, size, sha, plain, sig, udp}
                                        or {"op":"chat", mid, text, ttl, at, sig}
 5 REPLY        server → client   AES   {"ok":true, "resume":offset} or {"ok":false, "reason":…}
 6 CHUNK        client → server   AES   256 KB of the file
 7 CHUNK_PLAIN  client → server   raw   256 KB (Lab demo mode only, receiver must allow it)
 8 END          client → server   AES   {}
 9 ERROR        either            JSON  {reason}
```

### Handshake step by step
1. Client picks a DH private value `a`, sends `A = 2^a mod p`, a 32-byte nonce, its RSA public key,
   and an RSA signature over `A|nonce`.
2. Server checks the signature, picks `b`, sends `B = 2^b mod p`, its nonce and key, and signs
   **both** sides' values (`B|nonce_s|A|nonce_c`), so the reply can't be replayed to someone else.
3. Both compute `s = B^a = A^b mod p`, then
   `HKDF-SHA256(s, salt = nonce_c‖nonce_s, info = fingerprints) → 64 bytes`
   = two AES-256 keys (client→server and server→client).
4. Client sends CONFIRM: encrypted, with an RSA signature over the hash of the whole handshake.
   This proves it holds the session key *and* its private key.
5. Both screens show the **safety code**: 6 digits from SHA-256 of both public-key fingerprints.

### Why each piece is there
| Piece | Stops |
|---|---|
| RSA signature on DH values | Man in the middle swapping DH values |
| Both nonces in the signature and HKDF | Replaying an old handshake |
| Separate key per direction + counter nonce | Nonce reuse, replayed/reordered/dropped frames |
| GCM tag on every frame | Bit-flips and tampering (decryption fails) |
| SHA-256 of whole file + RSA signature in the offer | Swapped or corrupted files, fake sender |
| Checking `2 ≤ B ≤ p−2` and `B^((p−1)/2) = 1` | Degenerate or small-subgroup DH values |
| Frame cap 1 MB, 8 parallel connections, timeouts | Memory exhaustion and slow-client attacks |

### Resume
The receiver keeps `inbox/.partial/<hash>.part`. If the same sender offers the same file
(same SHA-256 and size) again, it replies `resume = bytes already received` (rounded down to a
whole chunk) and the sender seeks there. The final SHA-256 check covers the whole file.

## 3. Demonstrations
1. **Two devices, one laptop:** see README. Pair → compare the safety codes → send a file.
2. **Resume:** start sending a large file, stop the receiver (Ctrl+C) halfway, start it again,
   click **Retry** on the sender: it continues from where it stopped.
3. **Tamper/attack tests:** `python tests/test_lan.py` runs 27 checks, including forged
   signatures, bit-flipped chunks, replayed frames, bad DH values, a spoofed beacon, a fake
   alert, oversized frames and path-traversal file names.

## 4. Viva questions
- *Why HKDF instead of using the DH secret directly?* The DH output isn't uniformly random and is
  the wrong length; HKDF turns it into independent keys bound to this session's nonces.
- *Why GCM?* It encrypts and authenticates in one step; a changed byte makes decryption fail.
- *What if someone records the traffic and steals a device key later?* Each session uses fresh
  DH values, so old sessions can't be decrypted from the RSA key alone (forward secrecy).
- *Why is the safety code needed if handshakes are signed?* The first time you meet a device you
  don't know its key yet; comparing the code is how you confirm it's really your friend's.

## 5. Secure chat
Each chat message is one VD1 connection: a fresh Diffie-Hellman handshake (forward secrecy per
message), then an encrypted REQUEST `{"op":"chat", mid, text, ttl, at, sig}`. The RSA signature
covers `mid | time | ttl | SHA-256(text)`, so changing a single character is detected. Only paired
friends are accepted (strangers can't spam you), and a repeated message id is stored once (replay
protection). Messages with a timer are deleted on both devices when it runs out.
