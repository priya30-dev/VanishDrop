"""Two VanishDrop devices in one process: pairing, transfers, resume and attack cases.

Run:  python -m pytest tests/test_lan.py -q     (or: python tests/test_lan.py)
"""
import hashlib
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidTag  # noqa: E402

from vd import protocol as P  # noqa: E402
from vd.crypto_lan import Channel, DHKeyPair  # noqa: E402
from vd.db import DB  # noqa: E402
from vd.discovery import Discovery  # noqa: E402
from vd.identity import Identity, safety_code  # noqa: E402
from vd.transfer import Node, handshake_client, file_signature_payload  # noqa: E402
from vd.util import b64e, safe_filename  # noqa: E402


class Device:
    def __init__(self, name, udp, tcp):
        self.dir = tempfile.mkdtemp(prefix=f"vd-{name}-")
        self.name = name
        self.db = DB(os.path.join(self.dir, "db.sqlite"))
        self.id = Identity(os.path.join(self.dir, "id.pem"))
        self.node = Node(self.id, self.db, self.dir, tcp, lambda: self.disc, lambda: self.name)
        self.disc = Discovery(self.id, udp, tcp, 0, lambda: self.name, self.node.on_alert, lambda: "127.0.0.1")
        self.node.start()
        self.disc.start()

    def stop(self):
        self.disc.stop()
        self.node.stop()


def q(db, sql):
    with db.conn() as c:
        return c.execute(sql).fetchone()


def wait(cond, timeout=15, msg="timed out"):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    raise AssertionError(msg)


def auto_decide(dev, accept=True, stop=None):
    def loop():
        while not stop.is_set():
            for p in dev.node.snapshot()["pending"]:
                dev.node.decide(p["id"], accept)
            time.sleep(0.05)
    threading.Thread(target=loop, daemon=True).start()


def stage(dev, data, name="report.pdf"):
    path = os.path.join(dev.node.outbox_dir, secrets.token_hex(6))
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def main():
    a = Device("Kirti", 50509, 50609)
    b = Device("Priya", 50510, 50610)
    results = []

    def check(label, cond):
        results.append((label, bool(cond)))
        print(("PASS " if cond else "FAIL ") + label)

    try:
        wait(lambda: a.disc.peer(b.id.fp) and b.disc.peer(a.id.fp), msg="discovery failed")
        check("UDP discovery finds both devices", True)

        # Safety codes match on both sides
        check("safety code is the same on both devices",
              safety_code(a.id.pub_der, b.id.pub_der) == safety_code(b.id.pub_der, a.id.pub_der))

        # Pairing: B accepts
        stop = threading.Event()
        auto_decide(b, True, stop)
        pid = a.node.pair(b.id.fp)
        wait(lambda: a.node.pairings[pid]["status"] in ("paired", "failed", "declined"))
        check("pairing succeeds", a.node.pairings[pid]["status"] == "paired")
        check("both store each other as friends", a.node.friend(b.id.fp) and b.node.friend(a.id.fp))
        stop.set()

        # Friend transfer: auto-accepted, encrypted
        data = os.urandom(3 * 1024 * 1024 + 123)
        jid = a.node.send_file(b.id.fp, stage(a, data), "Marksheet sem4.pdf", plain=False)
        job = wait(lambda: a.node.jobs[jid] if a.node.jobs[jid]["status"] in ("delivered", "failed", "declined") else None)
        check("friend transfer delivered without asking: " + str(job.get("error")), job["status"] == "delivered")
        with b.db.conn() as c:
            row = c.execute("SELECT * FROM inbox ORDER BY received DESC").fetchone()
        check("received file is byte-for-byte identical", open(row["path"], "rb").read() == data)
        check("staged copy wiped from sender after delivery", not os.path.exists(job.get("path", "")) if "path" in job else True)
        wait(lambda: q(a.db, "SELECT 1 FROM events WHERE kind='delivered'"), 5,
             "no UDP delivery alert")
        check("sender got signed UDP delivery alert", True)

        # Path traversal in file name
        jid = a.node.send_file(b.id.fp, stage(a, b"evil"), "../../../Windows/System32/evil.bat", plain=False)
        wait(lambda: a.node.jobs[jid]["status"] in ("delivered", "failed"))
        with b.db.conn() as c:
            row = c.execute("SELECT * FROM inbox ORDER BY received DESC").fetchone()
        check("path traversal name is neutralised", os.path.dirname(row["path"]) == b.node.inbox_dir and row["name"] == "evil.bat")
        check("Windows reserved name is renamed", safe_filename("CON.txt") == "_CON.txt" and safe_filename("..") == "file")

        # Plain demo mode refused unless receiver allows it
        jid = a.node.send_file(b.id.fp, stage(a, b"hello plain"), "plain.txt", plain=True)
        wait(lambda: a.node.jobs[jid]["status"] in ("delivered", "failed", "declined"))
        check("unencrypted demo refused by default (no downgrade)", a.node.jobs[jid]["status"] == "declined")
        b.db.set_setting("allow_plain", "1")
        stop = threading.Event()
        auto_decide(b, True, stop)
        jid = a.node.send_file(b.id.fp, stage(a, b"hello plain"), "plain.txt", plain=True)
        wait(lambda: a.node.jobs[jid]["status"] in ("delivered", "failed", "declined"))
        stop.set()
        check("demo transfer works once receiver opts in (and still asks)", a.node.jobs[jid]["status"] == "delivered")
        b.db.set_setting("allow_plain", "0")

        # Stranger (not a friend) must be accepted manually; decline works
        c_dev = Device("Stranger", 50508, 50608)
        wait(lambda: c_dev.disc.peer(b.id.fp))
        stop = threading.Event()
        auto_decide(b, False, stop)
        jid = c_dev.node.send_file(b.id.fp, stage(c_dev, b"spam"), "spam.exe", plain=False)
        wait(lambda: c_dev.node.jobs[jid]["status"] in ("delivered", "failed", "declined"))
        stop.set()
        check("stranger's file is declined when user says no", c_dev.node.jobs[jid]["status"] == "declined")

        # Impostor: stranger renames itself to a friend's name
        c_dev.name = "Kirti"
        seen = {}
        def watch():
            while "x" not in seen:
                for p in b.node.snapshot()["pending"]:
                    seen["x"] = p
                    b.node.decide(p["id"], False)
                time.sleep(0.05)
        threading.Thread(target=watch, daemon=True).start()
        jid = c_dev.node.send_file(b.id.fp, stage(c_dev, b"fake"), "fake.pdf", plain=False)
        wait(lambda: c_dev.node.jobs[jid]["status"] in ("delivered", "failed", "declined"))
        check("impostor using a friend's name is flagged and not auto-accepted",
              seen.get("x", {}).get("impostor") and not seen["x"]["friend"])

        # Resume: interrupt a transfer midway, then retry
        big = os.urandom(5 * P.CHUNK_SIZE + 999)
        path = stage(a, big)
        orig_send = a.node.jobs  # noqa
        state = {"n": 0}
        real = P.send_frame
        def flaky(sock, t, payload):
            if t == P.CHUNK:
                state["n"] += 1
                if state["n"] == 3:
                    sock.close()
                    raise ConnectionError("simulated drop")
            return real(sock, t, payload)
        P.send_frame = flaky
        jid = a.node.send_file(b.id.fp, path, "big.bin", plain=False)
        wait(lambda: a.node.jobs[jid]["status"] in ("delivered", "failed"))
        P.send_frame = real
        check("dropped transfer fails cleanly with a retry message", a.node.jobs[jid]["status"] == "failed")
        time.sleep(0.3)
        a.node.retry(jid)
        wait(lambda: a.node.jobs[jid]["status"] in ("delivered", "failed"))
        check("retry resumes from where it stopped: " + str(a.node.jobs[jid].get("error")),
              a.node.jobs[jid]["status"] == "delivered" and a.node.jobs[jid].get("resumed_from", 0) >= 2 * P.CHUNK_SIZE)
        with b.db.conn() as c:
            row = c.execute("SELECT * FROM inbox WHERE name='big.bin'").fetchone()
        check("resumed file is identical", open(row["path"], "rb").read() == big)

        # Forged file signature (attacker changes the name after signing)
        s = handshake_client(socket.create_connection(("127.0.0.1", 50610)), c_dev.id, "Stranger")
        tid = secrets.token_hex(16)
        sha = hashlib.sha256(b"x").hexdigest()
        sig = c_dev.id.sign(file_signature_payload(tid, "a.txt", 1, sha))
        s.send_enc_json(P.REQUEST, {"op": "offer", "tid": tid, "name": "b.txt", "size": 1, "sha": sha, "sig": b64e(sig)})
        t, payload = P.recv_frame(s.sock)
        check("forged file signature is rejected", t == P.ERROR and "signature" in json.loads(payload)["reason"])
        s.sock.close()

        # Tampered data: hash mismatch is discarded
        b.db.set_setting("auto_accept", "1")
        s = handshake_client(socket.create_connection(("127.0.0.1", 50610)), a.id, "Kirti")
        tid = secrets.token_hex(16)
        sha = hashlib.sha256(b"original").hexdigest()
        sig = a.id.sign(file_signature_payload(tid, "t.txt", 8, sha))
        s.send_enc_json(P.REQUEST, {"op": "offer", "tid": tid, "name": "t.txt", "size": 8, "sha": sha, "sig": b64e(sig)})
        s.recv_enc_json(P.REPLY)
        s.send_enc(P.CHUNK, b"tampered")
        s.send_enc_json(P.END, {})
        t, payload = P.recv_frame(s.sock)
        check("tampered content is detected and discarded", t == P.ERROR and "damaged" in json.loads(payload)["reason"])
        s.sock.close()

        # Bit-flip on the wire: AES-GCM catches it
        s = handshake_client(socket.create_connection(("127.0.0.1", 50610)), a.id, "Kirti")
        tid = secrets.token_hex(16)
        sha = hashlib.sha256(b"12345678").hexdigest()
        sig = a.id.sign(file_signature_payload(tid, "f.txt", 8, sha))
        s.send_enc_json(P.REQUEST, {"op": "offer", "tid": tid, "name": "f.txt", "size": 8, "sha": sha, "sig": b64e(sig)})
        s.recv_enc_json(P.REPLY)
        ct = bytearray(s.channel.seal(P.CHUNK, b"12345678"))
        ct[3] ^= 1
        P.send_frame(s.sock, P.CHUNK, bytes(ct))
        t, payload = P.recv_frame(s.sock)
        check("bit-flipped encrypted chunk is rejected", t == P.ERROR)
        s.sock.close()

        # Replay / reorder: counter nonces
        k1, k2 = os.urandom(32), os.urandom(32)
        tx, rx = Channel(k1, k2), Channel(k2, k1)
        f1, f2 = tx.seal(6, b"one"), tx.seal(6, b"two")
        try:
            rx.open(6, f2)
            reordered = False
        except InvalidTag:
            reordered = True
        rx2 = Channel(k2, k1)
        rx2.open(6, f1)
        try:
            rx2.open(6, f1)
            replayed = False
        except InvalidTag:
            replayed = True
        check("reordered frames are rejected", reordered)
        check("replayed frames are rejected", replayed)

        # Bad DH values (small-subgroup / degenerate)
        dh = DHKeyPair()
        bad = 0
        from vd.crypto_lan import P as prime
        for v in (0, 1, prime - 1, prime, prime + 5):
            try:
                dh.shared_secret(v)
            except ValueError:
                bad += 1
        check("degenerate Diffie-Hellman values are rejected", bad == 5)

        # Oversized frame header
        raw = socket.create_connection(("127.0.0.1", 50610))
        raw.sendall(P.HEADER.pack(50 * 1024 * 1024, P.HELLO))
        raw.settimeout(5)
        try:
            t, payload = P.recv_frame(raw)
            check("oversized frame is refused", t == P.ERROR)
        except ConnectionError:
            check("oversized frame is refused", True)
        raw.close()

        # Garbage hello
        raw = socket.create_connection(("127.0.0.1", 50610))
        P.send_frame(raw, P.HELLO, b"not json at all")
        raw.settimeout(5)
        t, _ = P.recv_frame(raw)
        check("garbage handshake is refused", t == P.ERROR)
        raw.close()

        # Spoofed beacon: attacker announces Priya's fingerprint with its own TCP port
        c_dev.disc.sock.sendto(json.dumps({"app": "vanishdrop", "v": 1, "t": "beacon", "name": "Priya",
                                           "fp": b.id.fp, "tcp": 50608, "udp": 50508, "http": 0}).encode(),
                               ("127.0.0.1", 50509))
        time.sleep(0.2)
        jid = a.node.send_file(b.id.fp, stage(a, b"secret"), "secret.txt", plain=False)
        wait(lambda: a.node.jobs[jid]["status"] in ("delivered", "failed", "declined"))
        job = a.node.jobs[jid]
        check("spoofed beacon can't steal a file (identity mismatch detected)",
              job["status"] == "failed" and "pretending" in (job["error"] or ""))

        # Forged UDP alert (wrong signer)
        before = q(a.db, "SELECT COUNT(*) FROM events WHERE kind='delivered'")[0]
        a.node.sent_tids["f" * 32] = {"der": b.id.pub_der, "sha": "0" * 64, "peer_name": "Priya", "name": "x"}
        c_dev.disc.send_alert("127.0.0.1", 50509, {"tid": "f" * 32, "sha": "0" * 64, "fp": b.id.fp,
                                                   "sig": b64e(c_dev.id.sign(b"VD1|ALERT|" + b"f" * 32))})
        time.sleep(0.5)
        after = q(a.db, "SELECT COUNT(*) FROM events WHERE kind='delivered'")[0]
        check("forged UDP alert is ignored", before == after)
        c_dev.stop()
    finally:
        a.stop()
        b.stop()

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


def test_lan():
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
