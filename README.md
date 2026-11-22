# VanishDrop

Share private files with self-destructing, end-to-end encrypted links. Send files straight to
nearby laptops over your own Wi-Fi. Collect documents that only you can open.

Computer Network Lab (24B15CS313) PBL project · Kirti Mishra, Priya Singh

---

## 1. Run it (Windows + VS Code)

1. Install **Python 3.10 or newer** from python.org (tick **Add python.exe to PATH**).
2. Open this folder in VS Code, then open a terminal (**Terminal → New Terminal**).
3. Install the two libraries:
   ```
   pip install -r requirements.txt
   ```
4. Start VanishDrop:
   ```
   python app.py
   ```
5. Open **http://localhost:5000**.

On Windows, if `python` opens the Microsoft Store instead, use **`py`** in every command
(`py app.py`, `py tests/test_lan.py`). If port 5000 is busy, add `--port 8080` and open
http://localhost:8080. Without `--https`, links use `localhost`, so they work on this computer only.

The first time, Windows asks whether Python may use the network. Tick **Private networks** and
click **Allow**. Also set your Wi-Fi or hotspot to **Private** (Settings → Network → your Wi-Fi →
Network profile type), or other devices can't connect.

### Let phones and other laptops open your links

Browsers only allow encryption on `localhost` or `https`. So for anyone else to open your links:
```
python app.py --https
```
The link VanishDrop gives you then starts with `https://<your-ip>:5000`. The other device shows a
certificate warning the first time (the certificate is self-signed): tap **Advanced → Proceed**.

### Optional: real packet capture on the Monitor page

```
py -m pip install scapy
```
On Windows this also needs Npcap, which you installed with Wireshark. Restart VanishDrop, open
**Monitor** and turn on **Capture packets**.

### Share with anyone, on any network (Cloudflare Tunnel)

1. Install the tunnel tool once: `winget install --id Cloudflare.cloudflared` (then close and reopen VS Code).
2. Terminal 1: `py app.py --port 8080`
3. Terminal 2: `cloudflared tunnel --url http://localhost:8080`
   It prints an address like `https://random-words.trycloudflare.com`.
4. Terminal 1: Ctrl+C, then `py app.py --port 8080 --public-url https://random-words.trycloudflare.com`
5. Use VanishDrop at **http://localhost:8080** as usual. Links now use the public address and
   open on any phone or laptop, anywhere, with real HTTPS.

Your laptop must stay on with both terminals running. Each `cloudflared` start gives a new address,
so repeat step 4 with the new one. Visitors through the tunnel can only open links and upload to
requests: they can never use your Share, Nearby, Network or settings pages.

### Try Nearby with two "devices" on one laptop

Open a second terminal and run a second copy with its own ports and folder:
```
python app.py --name "Priya's laptop" --port 5001 --udp 50506 --tcp 50606 --data data-priya
```
Open http://localhost:5000 and http://localhost:5001 side by side. Each sees the other on the
**Nearby** page within a few seconds.

On two real laptops, just run `python app.py` on both, on the same Wi-Fi or hotspot.

| Option | Default | Meaning |
|---|---|---|
| `--port` | 5000 | Web page port |
| `--udp` | 50505 | Discovery port (must be 50505–50510) |
| `--tcp` | 50605 | Device-to-device transfer port |
| `--data` | `data` | Folder for this device's keys, database and files |
| `--name` | computer name | Name nearby devices see |
| `--https` | off | Serve HTTPS so other devices on your Wi-Fi can decrypt |
| `--public-url` | none | Public address from a tunnel; links use it |

---

## 2. Features

| # | Feature | Where | How it works |
|---|---|---|---|
| 1 | **Nearby send** | Nearby | UDP broadcast finds devices; files go over our own TCP protocol, encrypted, with resume |
| 2 | **Send to a friend** | Nearby → Pair | Authenticated Diffie-Hellman; friends are remembered by their RSA key |
| 3 | **Verified sender** | Nearby | Every handshake and file is signed with RSA-PSS and checked |
| 4 | **Safety code** | Nearby | Six digits from both keys; same on both screens only if no one is in the middle |
| 5 | **Lab demo mode** | Nearby → This device | Sends file bytes unencrypted so Wireshark shows the difference |
| 6 | **Lockout on guessing** | Links | 5 wrong passwords and the server wipes the file |
| 7 | **Secret notes** | Notes | Text that burns after one read |
| 8 | **Upload requests** | Requests | RSA-OAEP + AES hybrid encryption; only your browser holds the private key |
| 9 | **Delivery alerts** | Everywhere | Toasts and desktop notifications; nearby receivers send a signed UDP alert |

| — | **Network check** | Network | Runs ipconfig, ping, tracert, nslookup, netstat, arp and route, and explains the output |
| 10 | **Secure chat** | Chat | End-to-end encrypted, RSA-signed messages with paired friends over the VD1 protocol; disappearing messages; friends only |
| 11 | **Scam link warnings** | Chat, Notes | Flags fake bank/KYC links: look-alike brands, IP addresses, risky endings, short links, scam words |
| 12 | **Live traffic monitor** | Monitor | Every UDP beacon, VD1 TCP frame and HTTP request, live chart, click a packet for an explanation; optional real capture with Scapy |
| 13 | **Photo privacy cleaner** | Share, Nearby, Requests | Finds GPS location, camera and date in JPEG/PNG photos and removes them in the browser, without losing quality |

Plus: self-destructing links (1–10 downloads, 10 min–7 days), QR codes, WhatsApp share,
My files dashboard with "Destroy now", and **Server view**, which shows that the server only
holds scrambled bytes.

---

## 3. How the security works

### Links and notes (browser ↔ server)
- The browser makes a random 256-bit secret. From it, HKDF derives **two** keys: an AES-256-GCM
  key that encrypts the file and its name, and an **auth token** that proves you hold the link.
- The secret goes after the `#` in the link. Browsers never send that part to the server, and
  the download page removes it from the address bar as soon as it's read.
- With a password, the secret is derived with PBKDF2-SHA256 (600,000 rounds) and a random salt.
- The server stores only the SHA-256 of the auth token. Each wrong token counts toward the
  lockout, so nobody can guess passwords offline or online.
- After the last download, on expiry, or on "Destroy now", the encrypted file is overwritten
  with random bytes and deleted.

### Nearby transfers (device ↔ device, our own protocol over TCP)
```
frame = [4-byte length][1-byte type][payload]      (max 1 MB per frame)

client → HELLO        name, RSA public key, DH value, nonce, RSA signature
server → HELLO_REPLY  same, signed over BOTH sides' DH values and nonces
both:   shared secret = DH (RFC 3526 2048-bit group)  →  HKDF  →  2 AES-256 keys (one per direction)
client → CONFIRM      encrypted RSA signature over the whole handshake
client → REQUEST      encrypted: pair, or offer {name, size, SHA-256, RSA signature}
server → REPLY        accept (+ resume offset) or decline
client → CHUNK × n    AES-256-GCM, counter nonces (replay/reorder fails)
client → END          receiver checks size + SHA-256, saves, replies, sends signed UDP alert
```

### Threat model

| Threat | Defence |
|---|---|
| Someone sniffing the Wi-Fi | AES-256-GCM on everything; HTTPS for the web pages |
| The server is hacked or curious | Server never has keys, passwords or file names |
| File changed in transit | GCM tags on every chunk, SHA-256 of the whole file, RSA signature |
| Man in the middle on Nearby | Signed DH handshake + safety code comparison + stored friend keys |
| Fake device announcing itself (spoofed UDP beacon) | Handshake checks the key matches the device you picked |
| Someone using a friend's name | Flagged in red: "Not your saved Priya: different key" |
| Replayed or reordered packets | Counter nonces; any change fails decryption |
| Password guessing | PBKDF2 600k rounds + 5-attempt lockout that wipes the file |
| Downgrade to unencrypted | Receiver refuses demo transfers unless *it* turned demo mode on, and still asks |
| Malicious file names (`../../evil.bat`, `CON`) | Names are cleaned before saving |
| Other people on the Wi-Fi using your VanishDrop | Sharing, settings, inbox and Nearby work only on the computer running it |
| Malicious websites (CSRF) | Every change needs a custom header and a matching Origin |
| DNS rebinding | Unknown `Host` names are refused |
| Script injection (XSS) | Text is never inserted as HTML; strict Content-Security-Policy |
| Huge or garbage packets | Frame size cap, JSON validation, 8 parallel connections max, timeouts |
| Disk filling up | 200 MB per link, 100 MB per upload, 5 GB total |

### Known limits (good viva points)
- Six-digit safety codes are like Bluetooth pairing codes: fine when you compare them, not a
  replacement for comparing them.
- The browser holds the file in memory while encrypting, so links are capped at 200 MB.
  Nearby send streams from disk and goes up to 4 GB.
- The device key is stored unencrypted in the `data` folder. Anyone with access to your laptop
  account could copy it.
- The `--https` certificate is self-signed, so browsers warn once.
- The `cryptography` library now prefers X25519 over classic Diffie-Hellman; we use classic DH
  because the syllabus asks for it.

---

## 4. Every module of the course

| Module | What's in the project | Guide |
|---|---|---|
| 1. Devices & commands | **Network** page runs ipconfig, ping, tracert, nslookup, netstat, arp, route with explanations | [docs/module1_network_commands.md](docs/module1_network_commands.md) |
| 2. Wireshark | Six real captures in `wireshark/`: UDP discovery, encrypted vs plain transfer, TLS, HTTP, DNS + ICMP | [docs/module2_wireshark.md](docs/module2_wireshark.md) |
| 3. Socket programming | UDP discovery/alerts, TCP protocol, AES-GCM, RSA, Diffie-Hellman in `vd/` | [docs/module3_socket_programming.md](docs/module3_socket_programming.md) |
| 4. NS2 | `ns2/vanishdrop.tcl`, AWK scripts, `run_all.sh`, `plot.py`, results and graphs in `ns2/results/` | [docs/module4_ns2.md](docs/module4_ns2.md) |
| 5. Secure application | The whole app + STRIDE threat model | [docs/module5_threat_model.md](docs/module5_threat_model.md) |

## 5. Tests

```
python tests/test_lan.py      # 27 checks: two devices, pairing, transfer, resume and attacks
python tests/test_chat.py     # 8 checks: chat delivery, friends only, replay and tampering
python tests/test_web.py      # 52 browser checks      # 43 browser checks (needs Playwright; start two devices first)
```
`test_web.py` expects device A at `https://localhost:5001` (`--https --port 5001 --data /tmp/vdA`)
and device B at `http://localhost:5002` (`--port 5002 --udp 50506 --tcp 50606 --data /tmp/vdB`).

## 6. Files

```
app.py                Web server, links, notes, requests, security headers
vd/discovery.py       UDP beacons and alerts
vd/protocol.py        TCP frame format
vd/transfer.py        Handshake, pairing, file transfer, resume
vd/crypto_lan.py      Diffie-Hellman, HKDF, AES-GCM channel
vd/identity.py        RSA device key, signatures, safety codes
vd/db.py              SQLite storage
vd/util.py            Safe file names, secure wipe
vd/monitor.py         Live traffic log and optional Scapy packet capture
templates/, static/   Pages, Noir design, browser-side encryption (static/js/common.js),
                      photo cleaner (static/js/photo.js)
tests/                Automated tests
docs/                 One guide per syllabus module
wireshark/            Real .pcap captures of VanishDrop traffic (module 2)
ns2/                  NS2 simulation, AWK analysis, graphs (module 4)
```
