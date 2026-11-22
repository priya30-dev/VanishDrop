"""Live traffic monitor: a record of every packet and frame VanishDrop sends and receives.

Two sources feed it:
  1. The app itself logs each UDP datagram, each TCP frame of our VD1 protocol and each
     HTTP request. This always works, needs no special rights, and knows what each frame *means*.
  2. Optional real packet capture with Scapy + Npcap/libpcap (see Sniffer below), which shows
     raw TCP/UDP packets: SYN, ACK, FIN flags, sequence numbers and sizes, like Wireshark.
"""
import collections
import threading
import time

ENCRYPTED_FRAMES = {"CONFIRM", "REQUEST", "REPLY", "CHUNK", "END"}


class TrafficMonitor:
    def __init__(self, max_events=3000, window=120):
        self.lock = threading.Lock()
        self.events = collections.deque(maxlen=max_events)
        self.seq = 0
        self.window = window
        self.buckets = collections.OrderedDict()   # second -> {key: bytes}
        self.totals = collections.Counter()
        self.counts = collections.Counter()
        self.started = time.time()

    def log(self, proto, direction, kind, peer="", size=0, encrypted=False, note="", head=b"", source="app"):
        now = time.time()
        with self.lock:
            self.seq += 1
            self.events.append({
                "n": self.seq, "t": now, "proto": proto, "dir": direction, "kind": kind, "peer": peer,
                "size": int(size), "enc": bool(encrypted), "note": note, "head": head[:32].hex(), "src": source,
            })
            sec = int(now)
            bucket = self.buckets.setdefault(sec, collections.Counter())
            bucket[f"{proto}_{direction}"] += int(size)
            while self.buckets and next(iter(self.buckets)) < sec - self.window:
                self.buckets.popitem(last=False)
            self.totals[f"{proto}_{direction}"] += int(size)
            self.counts[proto] += 1

    def snapshot(self, after=0, limit=300, seconds=60):
        now = int(time.time())
        with self.lock:
            events = [e for e in self.events if e["n"] > after][-limit:]
            series = []
            for sec in range(now - seconds + 1, now + 1):
                b = self.buckets.get(sec, {})
                series.append({"t": sec, **{k: b.get(k, 0) for k in
                               ("udp_in", "udp_out", "tcp_in", "tcp_out", "http_in", "http_out")}})
            return {"seq": self.seq, "events": events, "series": series,
                    "totals": dict(self.totals), "counts": dict(self.counts), "since": self.started}

    def clear(self):
        with self.lock:
            self.events.clear()
            self.buckets.clear()
            self.totals.clear()
            self.counts.clear()
            self.started = time.time()


MON = TrafficMonitor()


def peer_of(sock):
    try:
        host, port = sock.getpeername()[:2]
        return f"{host}:{port}"
    except OSError:
        return ""


class Sniffer:
    """Real packet capture of VanishDrop's ports with Scapy (optional).

    Windows: needs Npcap (installed with Wireshark). Linux/macOS: needs root.
    """

    def __init__(self, ports_getter):
        self.ports_getter = ports_getter
        self.sniffer = None
        self.error = None

    @staticmethod
    def available():
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            return False

    @property
    def running(self):
        return bool(self.sniffer and getattr(self.sniffer, "running", False))

    def start(self):
        if self.running:
            return True
        self.error = None
        try:
            from scapy.all import AsyncSniffer, conf
        except Exception:
            self.error = "Scapy isn't installed. Run: py -m pip install scapy"
            return False
        web, udp, tcp = self.ports_getter()
        bpf = f"tcp port {web} or tcp port {tcp} or udp port {udp}"
        ifaces = []
        for name in (getattr(conf, "iface", None), getattr(conf, "loopback_name", None)):
            if name and str(name) not in [str(i) for i in ifaces]:
                ifaces.append(name)
        try:
            self.sniffer = AsyncSniffer(iface=ifaces or None, filter=bpf, store=False, prn=self._on_packet)
            self.sniffer.start()
            time.sleep(0.6)
            if not self.sniffer.running:
                raise RuntimeError(getattr(self.sniffer, "exception", None) or "capture didn't start")
            return True
        except Exception as exc:
            self.sniffer = None
            msg = str(exc)
            if "ermission" in msg or "Operation not permitted" in msg:
                msg = "Capture needs permission. On Windows, install Npcap (comes with Wireshark); on Linux, run as root."
            elif "pcap" in msg.lower() or "winpcap" in msg.lower():
                msg = "Npcap isn't installed. Install Wireshark (tick Npcap) and restart VanishDrop."
            self.error = msg
            return False

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.sniffer = None

    def _on_packet(self, pkt):
        try:
            from scapy.all import IP, IPv6, TCP, UDP
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                return
            web, udp_port, tcp_port = self.ports_getter()
            if TCP in pkt:
                t = pkt[TCP]
                payload = bytes(t.payload)
                flags = str(t.flags)
                ours = {web, tcp_port}
                direction = "in" if t.dport in ours else "out"
                MON.log("pcap", direction, f"TCP {flags}", f"{ip.src}:{t.sport} → {ip.dst}:{t.dport}", len(payload),
                        note=f"seq={t.seq} ack={t.ack} win={t.window}", head=payload, source="pcap")
            elif UDP in pkt:
                u = pkt[UDP]
                payload = bytes(u.payload)
                direction = "in" if u.dport == udp_port else "out"
                MON.log("pcap", direction, "UDP", f"{ip.src}:{u.sport} → {ip.dst}:{u.dport}", len(payload),
                        note=f"len={u.len}", head=payload, source="pcap")
        except Exception:
            pass
