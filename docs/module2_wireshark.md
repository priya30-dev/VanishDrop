# Module 2 · Wireshark analysis

The `wireshark/` folder has **six real capture files** recorded from VanishDrop. Open them in
Wireshark (File → Open), apply the filter, and take the screenshots listed. Then repeat a few of
them live on your own laptop (section 3).

## 1. The capture files

| File | Filter to apply | What it shows |
|---|---|---|
| `1_discovery_udp.pcap` | `udp.port == 50505 \|\| udp.port == 50506` | VanishDrop's discovery beacons: small UDP datagrams every 3 s, JSON with device name, key fingerprint and ports. Destination 255.255.255.255 = broadcast |
| `2_nearby_transfer_encrypted.pcap` | `tcp.port == 50606` | A Nearby send: TCP 3-way handshake, our HELLO/HELLO_REPLY (public keys and Diffie-Hellman values, readable JSON), then only ciphertext |
| `3_nearby_transfer_plain_demo.pcap` | `tcp.port == 50606` | The same file sent in **Lab demo mode**: the Aadhaar number and bank details are readable |
| `4_web_https_tls.pcap` | `tls` | Sharing and downloading over HTTPS: TLS Client Hello, Server Hello, certificate, then Application Data only |
| `5_web_http_plain.pcap` | `http` | The same over plain HTTP: request lines and headers are visible, **but the file and its name are still unreadable** because the browser encrypted them first |
| `6_dns_ping_icmp.pcap` | `dns \|\| icmp` | DNS queries/answers (UDP 53) for google.com and wikipedia.org; ICMP Echo Request/Reply (ping); ICMP time-exceeded (traceroute) |

## 2. What to look at, layer by layer

### Application layer
- **HTTP** (`5_…`, filter `http`): `POST /api/links` (upload), `GET /api/links/<id>`,
  `GET /api/links/<id>/blob` (download). Right-click → Follow → HTTP Stream: the body is random
  bytes. The link's key (after `#`) never appears: browsers never send the fragment.
  The `X-VD-Auth` header carries a token *derived* from the key, which can't be turned back into it.
- **DNS** (`6_…`, filter `dns`): Query (A record), Response with the IP. Note the Transaction ID
  matching, and that DNS is unencrypted: anyone on the Wi-Fi can see which sites you look up.
- **VanishDrop discovery** (`1_…`): select a packet → the bottom pane shows the JSON beacon.

### Transport layer
- **TCP** (`2_…`): packets 1–3 are SYN, SYN-ACK, ACK. Check sequence and acknowledgment numbers,
  window size, and the FIN/ACK at the end. Statistics → Flow Graph shows the whole exchange.
  Statistics → TCP Stream Graphs → Throughput shows the transfer speed.
- **UDP** (`1_…`): no handshake, no ACKs, 8-byte header (source port, destination port, length,
  checksum). That's why our delivery alert over UDP is "best effort".

### Network layer
- Any packet → expand **Internet Protocol Version 4**: version, header length, TTL, protocol
  (6 = TCP, 17 = UDP, 1 = ICMP), source/destination addresses, checksum.
- ICMP time-exceeded messages in `6_…` come from routers whose TTL hit 0: that's how traceroute
  discovers each hop.

### Security handshakes
- **TLS** (`4_…`, filter `tls.handshake`): Client Hello (cipher suites, SNI, key share),
  Server Hello (chosen cipher suite, e.g. TLS_AES_128_GCM_SHA256 / TLS 1.3), then everything is
  "Application Data". The certificate is self-signed (that's why the browser warns).
- **VanishDrop's own handshake** (`2_…`): Follow → TCP Stream. The first two messages are JSON:
  `"pub"` (RSA public key), `"dh"` (Diffie-Hellman public value), `"nonce"` and `"sig"`
  (RSA-PSS signature). Public values are safe to send in the open: that's the point of
  Diffie-Hellman. After CONFIRM, every frame is AES-256-GCM ciphertext.

### The key comparison: plain vs encrypted
Open `2_…` and `3_…` side by side → Follow → TCP Stream on each.
- `3_…` (demo mode): "Aadhaar: 1234 5678 9012" is visible. Screenshot this.
- `2_…` (normal): the same file is random bytes. Edit → Find Packet → String "Aadhaar": not found.

## 3. Capture live on your own laptop (Windows)

1. Install Wireshark; tick **Npcap** and **Support loopback traffic capture**.
2. Start two VanishDrop devices (see README) or use two laptops on a hotspot.
3. In Wireshark pick the adapter:
   - two copies on one laptop → **Adapter for loopback traffic capture**
   - two laptops → your **Wi-Fi** adapter
4. Start capture, do the action, stop, then filter:

| Action in VanishDrop | Filter |
|---|---|
| Open the Nearby page | `udp.port == 50505` |
| Send a file to a nearby device | `tcp.port == 50605` |
| Turn on Lab demo mode (receiver) and send a .txt file | `tcp.port == 50605` → Follow TCP Stream |
| Share and download a link | `tcp.port == 5000` (`http`) or `tls` with `--https` |
| Network page → nslookup / ping / tracert | `dns`, `icmp` |

## 4. Questions this answers for your report
- *Why is UDP used for discovery and TCP for files?* Discovery is small, periodic and fine to lose;
  files must arrive complete and in order.
- *What can an attacker on the same Wi-Fi learn?* Who talks to whom (IP addresses, ports, sizes,
  timing) and DNS lookups, but not file names or contents.
- *Why is the Diffie-Hellman value visible but still safe?* Computing the shared secret from the
  public values needs a discrete logarithm in a 2048-bit group, which is infeasible.

## 5. Inside the app: the Monitor page
VanishDrop's **Monitor** page is a small Wireshark for its own traffic. It lists every UDP beacon,
every VD1 TCP frame (HELLO, HELLO_REPLY, CONFIRM, REQUEST, REPLY, CHUNK, END) and every HTTP
request, marks which ones are encrypted, draws bytes per second, and explains each packet when you
click it. With Scapy installed (`py -m pip install scapy`) its **Capture packets** switch shows raw
TCP segments too: the SYN → SYN-ACK → ACK handshake, sequence numbers and FIN. Compare it with
Wireshark side by side for your report: both should show the same packets.

Notice that each beacon arrives more than once: VanishDrop sends it to 255.255.255.255, to the
subnet broadcast address (e.g. 192.168.1.255) and to localhost, and the receiver hears every copy.
