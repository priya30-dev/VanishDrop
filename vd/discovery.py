"""UDP: find other VanishDrop devices on the same Wi-Fi, and receive delivery alerts.

Every few seconds each device broadcasts a small "beacon" datagram. Listeners keep a
table of devices seen recently. Beacons are NOT trusted for identity: anyone can send
one. Identity is proved later in the signed TCP handshake.
"""
import json
import socket
import threading
import time

from .monitor import MON

DISCOVERY_PORTS = range(50505, 50511)   # up to 6 devices on one computer for testing
BEACON_EVERY = 3.0
PEER_TTL = 12.0
MAX_DATAGRAM = 4096


class Discovery:
    def __init__(self, identity, udp_port, tcp_port, http_port, name_getter, on_alert, lan_ip_getter):
        self.identity = identity
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.http_port = http_port
        self.name_getter = name_getter
        self.on_alert = on_alert
        self.lan_ip_getter = lan_ip_getter
        self.peers = {}
        self.lock = threading.Lock()
        self.sock = None
        self.running = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("0.0.0.0", self.udp_port))
        self.running = True
        threading.Thread(target=self._listen, daemon=True, name="udp-listen").start()
        threading.Thread(target=self._beacon_loop, daemon=True, name="udp-beacon").start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------ sending ---
    def _targets(self):
        ip = self.lan_ip_getter()
        hosts = ["255.255.255.255", "127.0.0.1"]
        if ip and not ip.startswith("127."):
            hosts.append(".".join(ip.split(".")[:3] + ["255"]))
        return [(h, p) for h in hosts for p in DISCOVERY_PORTS]

    def _beacon_loop(self):
        while self.running:
            msg = json.dumps({
                "app": "vanishdrop", "v": 1, "t": "beacon",
                "name": self.name_getter(), "fp": self.identity.fp,
                "tcp": self.tcp_port, "udp": self.udp_port, "http": self.http_port,
            }).encode()
            targets = self._targets()
            for target in targets:
                try:
                    self.sock.sendto(msg, target)
                except OSError:
                    pass  # no route for that address on this network; others still work
            MON.log("udp", "out", "beacon", "broadcast", len(msg), note=f"sent to {len(targets)} addresses", head=msg)
            time.sleep(BEACON_EVERY)

    def send_alert(self, ip: str, port: int, payload: dict) -> None:
        payload = dict(payload, app="vanishdrop", v=1, t="alert")
        data = json.dumps(payload).encode()
        MON.log("udp", "out", "alert", f"{ip}:{port}", len(data), note="signed delivery receipt", head=data)
        try:
            self.sock.sendto(data, (ip, int(port)))
        except OSError:
            pass  # UDP is best effort: the TCP reply already told the sender it worked

    # ---------------------------------------------------------- receiving ---
    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                if not self.running:
                    return
                continue
            if len(data) > MAX_DATAGRAM:
                continue
            try:
                msg = json.loads(data.decode())
            except (UnicodeDecodeError, ValueError):
                continue
            if not isinstance(msg, dict) or msg.get("app") != "vanishdrop" or msg.get("v") != 1:
                continue
            if msg.get("t") == "beacon":
                if msg.get("fp") != self.identity.fp:
                    MON.log("udp", "in", "beacon", f"{addr[0]}:{addr[1]}", len(data), note=str(msg.get("name", ""))[:40], head=data)
                self._on_beacon(msg, addr)
            elif msg.get("t") == "alert":
                MON.log("udp", "in", "alert", f"{addr[0]}:{addr[1]}", len(data), note="delivery receipt", head=data)
                try:
                    self.on_alert(msg, addr)
                except Exception as exc:  # never let one bad datagram stop the listener
                    print("alert error:", exc)

    def _on_beacon(self, msg, addr):
        fp, name = msg.get("fp"), msg.get("name")
        if not isinstance(fp, str) or len(fp) != 64 or fp == self.identity.fp:
            return
        try:
            tcp, udp = int(msg.get("tcp")), int(msg.get("udp"))
        except (TypeError, ValueError):
            return
        if not (1 <= tcp <= 65535 and 1 <= udp <= 65535):
            return
        name = name if isinstance(name, str) else "Unknown device"
        with self.lock:
            prev = self.peers.get(fp)
            ip = addr[0]
            # Prefer a real network address over loopback when both are heard.
            if prev and prev["ip"] != "127.0.0.1" and ip == "127.0.0.1" and time.time() - prev["seen"] < PEER_TTL:
                ip = prev["ip"]
            self.peers[fp] = {"fp": fp, "name": name[:40], "ip": ip, "tcp": tcp, "udp": udp, "seen": time.time()}

    def list_peers(self):
        now = time.time()
        with self.lock:
            return [dict(p) for p in self.peers.values() if now - p["seen"] <= PEER_TTL]

    def peer(self, fp):
        with self.lock:
            p = self.peers.get(fp)
            return dict(p) if p and time.time() - p["seen"] <= PEER_TTL else None
