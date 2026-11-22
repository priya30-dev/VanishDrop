# Module 5 · Threat model and security measures

## 1. What we protect
| Asset | Why it matters |
|---|---|
| File and note contents | Aadhaar, marksheets, bank details, passwords, OTPs |
| File names | "Aadhaar_Rahul.pdf" alone reveals personal information |
| Who sent a file | Fake documents from a "friend" are a common scam |
| Device keys | Whoever holds them can impersonate the device |
| The owner's VanishDrop | Others on the Wi-Fi shouldn't be able to use it |

## 2. Who might attack
| Attacker | Can do |
|---|---|
| **Eavesdropper on the Wi-Fi** (hostel, café) | Capture every packet |
| **Active attacker on the Wi-Fi** | Send fake UDP beacons, intercept and change packets (man in the middle) |
| **Someone who gets the link ID** (shoulder surfing, forwarded chat) | Request the file from the server |
| **Curious or hacked server** | Read everything stored on disk |
| **Malicious website** the owner visits | Make the owner's browser send requests to localhost |
| **Malicious nearby device** | Send garbage, huge frames, evil file names, spam offers |

## 3. Threats and defences (STRIDE)

| Type | Threat | Defence in VanishDrop | Tested by |
|---|---|---|---|
| **S**poofing | Fake device announces itself as "Priya" | Beacons aren't trusted; the TCP handshake must be signed by the key we picked; friends are stored by key | test_lan: spoofed beacon, impostor name |
| Spoofing | Man in the middle during first pairing | Safety code from both public keys, compared out loud | test_web: both screens show same code |
| Spoofing | Fake upload-request page | Check code (SHA-256 of the request's public key) shared by the owner | test_web: uploader sees same check code |
| **T**ampering | Change bytes in transit | AES-GCM tag per frame; SHA-256 + RSA signature for the whole file | test_lan: bit-flip, tampered content, forged signature |
| Tampering | Replay or reorder frames | Counter nonces, separate key per direction | test_lan: replay, reorder |
| Tampering | Server swaps a link's file | AES-GCM in the browser: decryption fails | download page error message |
| **R**epudiation | "I never sent that" | Files are signed with the sender's RSA key | inbox shows "signature checked" |
| **I**nformation disclosure | Read files on the Wi-Fi | AES-256 everywhere; HTTPS for pages | wireshark/2_ vs 3_ captures |
| Information disclosure | Server reads files | Keys never reach the server: link key after `#`, password-derived keys, RSA private key in the browser only | Server view page; wireshark/5_ capture |
| Information disclosure | Offline password guessing | No verifier is public; the server only answers after an auth token derived by PBKDF2 (600k rounds) | test_web: info leaks no name/check data |
| Information disclosure | Old sessions decrypted later | Fresh Diffie-Hellman per session (forward secrecy) | design |
| **D**enial of service | Guessing link passwords | 5 wrong attempts → file wiped | test_web: lockout |
| Denial of service | Huge frames, many connections, slow clients | 1 MB frame cap, 8 parallel connections, 30 s timeouts, upload size limits, 5 GB storage cap | test_lan: oversized frame, garbage hello |
| Denial of service | Spam file offers | Strangers' files always need manual Accept; 2-minute timeout | test_lan: decline |
| **E**levation of privilege | Others on the Wi-Fi use your VanishDrop | Owner features only from 127.0.0.1 | test_web: visitor blocked |
| Elevation of privilege | Malicious website controls VanishDrop (CSRF) | Custom `X-VD` header + Origin check on every change | test_web: CSRF tests |
| Elevation of privilege | DNS rebinding | Only known Host names accepted | test_web: Host header test |
| Elevation of privilege | Script injection (XSS) | Text inserted with `textContent` only; CSP `script-src 'self'` | test_web: CSP header |
| Elevation of privilege | `../../` file names | Names cleaned, Windows reserved names renamed | test_lan: path traversal |
| Elevation of privilege | Command injection on the Network page | Fixed programs, no shell, strict host-name check | manual: `; rm -rf /` refused |
| Spoofing | Strangers sending chat messages | Chat accepts only paired friends, checked by RSA key | test_chat: non-friends refused |
| Tampering | Changing a chat message | RSA signature over the message hash | test_chat: changed text rejected |
| Tampering | Replaying an old chat message | Unique message id stored once | test_chat: replay stored once |
| Information disclosure | Photos revealing home or hostel location | Photo cleaner removes GPS, camera and date before encryption | test_web: received photo has no GPS |
| Spoofing | Scam links (fake bank / KYC pages) in chats and notes | Link checker flags look-alike brands, IP hosts, risky endings, short links | test_web: scam link flagged |
| Downgrade | Force an unencrypted transfer | Receiver must enable Lab demo mode itself and still clicks Accept | test_lan: downgrade refused |

## 4. Security measures summary
- **Confidentiality:** AES-256-GCM (files, notes, Nearby), RSA-OAEP (upload requests), HTTPS.
- **Integrity:** GCM tags, SHA-256 file hashes, RSA-PSS signatures.
- **Authentication:** RSA device keys, signed DH handshake, safety codes, auth tokens for links.
- **Key exchange:** Diffie-Hellman (RFC 3526, 2048-bit) → HKDF-SHA256.
- **Availability:** limits, timeouts, lockout, storage cap.
- **Data minimisation:** files wiped after use (overwritten, then deleted); file names encrypted.

## 5. Residual risks (what we don't protect against)
| Risk | Why | Possible improvement |
|---|---|---|
| Malware on the sender's or receiver's laptop | It sees files before encryption / after decryption | Out of scope |
| Device key stored unencrypted in `data/` | Simplicity | Protect with an OS keystore or a passphrase |
| 6-digit safety code | Short codes are a convenience trade-off, like Bluetooth | Longer codes or QR-code comparison |
| Traffic analysis | Sizes, timing and IP addresses stay visible | Padding, cover traffic |
| Self-signed HTTPS certificate | No certificate authority on a hotspot | Local CA installed on devices |
| Anyone with the full link can download | The link *is* the key | Use a password and send it separately |
| Browser memory limits (links ≤ 200 MB) | Web Crypto encrypts the whole file at once | Chunked streaming encryption |
