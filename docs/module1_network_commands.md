# Module 1 · Network devices and networking commands

VanishDrop has a **Network** page (http://localhost:5000/network) that runs each command and
explains the output. You can also type the same commands in a terminal. Run them with
VanishDrop open so you can see its own ports and the devices it talks to.

## 1. The devices between two laptops

| Device | Layer | What it does | Where you see it in VanishDrop |
|---|---|---|---|
| **Hub** | 1 (physical) | Repeats every bit to every port. Everyone receives everyone's traffic. | Why encryption matters: on a shared medium (like Wi-Fi) anyone nearby can capture packets |
| **Switch** | 2 (data link) | Learns MAC address → port, forwards each frame only to the right port | Nearby send between two laptops on the same Wi-Fi goes through the router's built-in switch only |
| **Router** | 3 (network) | Forwards packets between networks by IP address, decrements TTL | `tracert` shows routers; NS2 model has r1, r2, r3 |
| **Gateway** | 3 | The router your laptop sends traffic to when the destination isn't on its own subnet | `ipconfig` "Default Gateway", `route print` 0.0.0.0 entry |

A home or hostel Wi-Fi router is all of these in one box: an access point, a switch, a router
and the gateway to the internet.

## 2. Commands (Windows / Linux)

| Purpose | Windows | Linux | What to note for your report |
|---|---|---|---|
| IP configuration | `ipconfig /all` | `ip addr` / `ifconfig` | IPv4 address, subnet mask, default gateway, DNS servers, MAC (Physical Address) |
| Reachability + RTT | `ping 192.168.1.1` | `ping -c 4 192.168.1.1` | time= (RTT), TTL, % loss. Ping the gateway, the other laptop, and google.com |
| Path to a host | `tracert -d google.com` | `traceroute -n google.com` | Hop 1 is the gateway; count the hops; `* * *` = router not answering |
| DNS lookup | `nslookup google.com` | `nslookup google.com` | DNS server used, "Non-authoritative answer", IPv4/IPv6 addresses |
| Open ports | `netstat -ano` | `ss -tulpn` / `netstat -tulpn` | VanishDrop's ports: TCP 5000 (web), UDP 50505 (discovery), TCP 50605 (transfers) |
| MAC table (ARP) | `arp -a` | `ip neigh` | The gateway's MAC; after a Nearby send, the other laptop's IP + MAC appears |
| Routing table | `route print -4` | `ip route` | 0.0.0.0/0 → gateway (default route); your subnet is "On-link" |

Windows tip: Windows Firewall blocks incoming ping by default, so pinging a Windows laptop may
time out even when VanishDrop works. That's the firewall, not the network.

## 3. A short experiment for the report

1. Start VanishDrop on two laptops on the same hotspot.
2. On laptop A: `ipconfig` → note IP, mask, gateway.
3. `ping <laptop B's IP>` → RTT should be a few ms (same subnet, through the switch only).
4. `tracert <laptop B's IP>` → **one hop**: B is on the same network, no router in between.
5. `tracert google.com` → many hops: your gateway first, then your ISP's routers.
6. `arp -a` → laptop B's MAC now appears (ARP resolved it before the first packet).
7. `netstat -ano | findstr 5060` → during a Nearby send you'll see an ESTABLISHED TCP connection
   between A's random port and B's port 50605.

Conclusion to write: Nearby send works without internet because both laptops are in the same
subnet, so packets are switched (layer 2), never routed. Links shared outside need the router.
