"""Device-to-device transfers over TCP.

Handshake (authenticated Diffie-Hellman):
  1. client -> HELLO        {name, rsa_pub, dh, nonce, sig(dh|nonce)}
  2. server -> HELLO_REPLY  {name, rsa_pub, dh, nonce, sig(dh_s|nonce_s|dh_c|nonce_c)}
  3. both derive two AES-256 keys from the DH secret with HKDF
  4. client -> CONFIRM      encrypted {sig(transcript)}  proves the client holds the key
After that every frame is AES-256-GCM with counter nonces.
"""
import hashlib
import json
import os
import secrets
import shutil
import socket
import threading
import time

from cryptography.exceptions import InvalidTag

from . import protocol as P
from .crypto_lan import Channel, DHKeyPair, session_keys
from .identity import fingerprint, safety_code, verify
from .util import b64d, b64e, safe_filename, unique_path, wipe_file

LAN_MAX_BYTES = 4 * 1024 * 1024 * 1024   # 4 GB per transfer
DECISION_TIMEOUT = 120                   # seconds the receiver has to accept
IO_TIMEOUT = 30
MAX_PARALLEL_INCOMING = 8
PROTO = "VD1"
CHAT_TTLS = {0, 60, 3600, 86400, 604800}   # 0 = keep until deleted
CHAT_MAX_CHARS = 4000


class TransferError(Exception):
    pass


# --------------------------------------------------------------- session ---
class Session:
    def __init__(self, sock, channel, peer_name, peer_der, transcript):
        self.sock = sock
        self.channel = channel
        self.peer_name = peer_name
        self.peer_der = peer_der
        self.peer_fp = fingerprint(peer_der)
        self.transcript = transcript

    def send_enc(self, frame_type, data: bytes):
        P.send_frame(self.sock, frame_type, self.channel.seal(frame_type, data))

    def send_enc_json(self, frame_type, obj):
        self.send_enc(frame_type, json.dumps(obj, separators=(",", ":")).encode())

    def recv_enc_json(self, expected):
        t, payload = P.recv_frame(self.sock)
        if t == P.ERROR:
            raise TransferError(P.parse_json(payload).get("reason", "The other device stopped."))
        if t != expected:
            raise P.ProtocolError(f"expected frame {expected}, got {t}")
        return P.parse_json(self.channel.open(t, payload))


def _hello_fields(msg):
    name, pub, dh_hex, nonce, sig = (msg.get(k) for k in ("name", "pub", "dh", "nonce", "sig"))
    if msg.get("proto") != PROTO or not all(isinstance(x, str) for x in (name, pub, dh_hex, nonce, sig)):
        raise P.ProtocolError("bad hello")
    if len(dh_hex) > 600 or len(pub) > 1200:
        raise P.ProtocolError("hello too large")
    try:
        der, nonce_b, sig_b, dh_int = b64d(pub), b64d(nonce), b64d(sig), int(dh_hex, 16)
    except ValueError as exc:
        raise P.ProtocolError("bad hello encoding") from exc
    if len(nonce_b) != 32:
        raise P.ProtocolError("bad nonce")
    return name.strip()[:40] or "Unknown device", der, dh_int, nonce_b, sig_b


def handshake_client(sock, identity, my_name):
    dh = DHKeyPair()
    nonce_c = secrets.token_bytes(32)
    dh_c = format(dh.public_int, "x")
    P.send_json(sock, P.HELLO, {
        "proto": PROTO, "name": my_name, "pub": b64e(identity.pub_der), "dh": dh_c,
        "nonce": b64e(nonce_c), "sig": b64e(identity.sign(f"{PROTO}|HELLO|{dh_c}|{b64e(nonce_c)}".encode())),
    })
    t, payload = P.recv_frame(sock)
    if t == P.ERROR:
        raise TransferError(P.parse_json(payload).get("reason", "Refused"))
    if t != P.HELLO_REPLY:
        raise P.ProtocolError("expected hello reply")
    name, der, dh_s_int, nonce_s, sig = _hello_fields(P.parse_json(payload))
    dh_s = format(dh_s_int, "x")
    signed = f"{PROTO}|HELLO_REPLY|{dh_s}|{b64e(nonce_s)}|{dh_c}|{b64e(nonce_c)}".encode()
    if not verify(der, sig, signed):
        raise TransferError("The other device's signature is invalid.")
    shared = dh.shared_secret(dh_s_int)
    k_c2s, k_s2c = session_keys(shared, nonce_c, nonce_s, identity.fp, fingerprint(der))
    channel = Channel(send_key=k_c2s, recv_key=k_s2c)
    transcript = hashlib.sha256(signed + identity.pub_der + der).hexdigest()
    session = Session(sock, channel, name, der, transcript)
    session.send_enc_json(P.CONFIRM, {"sig": b64e(identity.sign(f"{PROTO}|CONFIRM|{transcript}".encode()))})
    return session


def handshake_server(sock, identity, my_name):
    t, payload = P.recv_frame(sock)
    if t != P.HELLO:
        raise P.ProtocolError("expected hello")
    name, der, dh_c_int, nonce_c, sig = _hello_fields(P.parse_json(payload))
    dh_c = format(dh_c_int, "x")
    if not verify(der, sig, f"{PROTO}|HELLO|{dh_c}|{b64e(nonce_c)}".encode()):
        raise TransferError("Invalid signature on hello")
    if fingerprint(der) == identity.fp:
        raise TransferError("A device can't connect to itself")
    dh = DHKeyPair()
    nonce_s = secrets.token_bytes(32)
    dh_s = format(dh.public_int, "x")
    signed = f"{PROTO}|HELLO_REPLY|{dh_s}|{b64e(nonce_s)}|{dh_c}|{b64e(nonce_c)}".encode()
    P.send_json(sock, P.HELLO_REPLY, {
        "proto": PROTO, "name": my_name, "pub": b64e(identity.pub_der), "dh": dh_s,
        "nonce": b64e(nonce_s), "sig": b64e(identity.sign(signed)),
    })
    shared = dh.shared_secret(dh_c_int)
    k_c2s, k_s2c = session_keys(shared, nonce_c, nonce_s, fingerprint(der), identity.fp)
    channel = Channel(send_key=k_s2c, recv_key=k_c2s)
    transcript = hashlib.sha256(signed + der + identity.pub_der).hexdigest()
    session = Session(sock, channel, name, der, transcript)
    confirm = session.recv_enc_json(P.CONFIRM)
    try:
        csig = b64d(confirm.get("sig", ""))
    except ValueError as exc:
        raise P.ProtocolError("bad confirm") from exc
    if not verify(der, csig, f"{PROTO}|CONFIRM|{transcript}".encode()):
        raise TransferError("Handshake confirmation failed")
    return session


def file_signature_payload(tid, name, size, sha):
    return f"{PROTO}|FILE|{tid}|{name}|{size}|{sha}".encode()


def chat_signature_payload(mid, at, ttl, text):
    digest = hashlib.sha256(text.encode()).hexdigest()
    return f"{PROTO}|CHAT|{mid}|{at!r}|{ttl}|{digest}".encode()


def sha256_file(path, progress=None):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            h.update(block)
            if progress:
                progress(len(block))
    return h.hexdigest()


# ------------------------------------------------------------------ node ---
class Node:
    def __init__(self, identity, db, data_dir, tcp_port, discovery_getter, name_getter, max_bytes=LAN_MAX_BYTES):
        self.identity = identity
        self.db = db
        self.tcp_port = tcp_port
        self.discovery_getter = discovery_getter
        self.name_getter = name_getter
        self.max_bytes = max_bytes
        self.inbox_dir = os.path.join(data_dir, "inbox")
        self.partial_dir = os.path.join(data_dir, "inbox", ".partial")
        self.outbox_dir = os.path.join(data_dir, "outbox")
        for d in (self.inbox_dir, self.partial_dir, self.outbox_dir):
            os.makedirs(d, exist_ok=True)
        self.lock = threading.Lock()
        self.pending = {}    # decisions waiting for the user: id -> dict
        self.receiving = {}  # live incoming progress: id -> dict
        self.jobs = {}       # outgoing files: id -> dict
        self.pairings = {}   # outgoing pair requests: id -> dict
        self.sent_tids = {}  # tid -> receiver public key, to verify UDP alerts
        self.slots = threading.BoundedSemaphore(MAX_PARALLEL_INCOMING)
        self.server = None

    # ---------- settings / friends
    def setting_bool(self, key, default):
        return self.db.setting(key, "1" if default else "0") == "1"

    def friend(self, fp):
        with self.db.conn() as c:
            row = c.execute("SELECT * FROM friends WHERE fp=?", (fp,)).fetchone()
        return dict(row) if row else None

    def friends(self):
        with self.db.conn() as c:
            return [dict(r) for r in c.execute("SELECT fp, name, added FROM friends ORDER BY name")]

    def save_friend(self, fp, name, der):
        with self.db.conn() as c:
            c.execute("INSERT INTO friends (fp, name, pub, added) VALUES (?,?,?,?) "
                      "ON CONFLICT(fp) DO UPDATE SET name=excluded.name",
                      (fp, name, b64e(der), time.time()))

    def remove_friend(self, fp):
        with self.db.conn() as c:
            c.execute("DELETE FROM friends WHERE fp=?", (fp,))

    def impostor_warning(self, fp, name):
        """True if someone uses a friend's name with a different key."""
        with self.db.conn() as c:
            row = c.execute("SELECT fp FROM friends WHERE lower(name)=lower(?) AND fp<>?", (name, fp)).fetchone()
        return row is not None

    # ---------- TCP server
    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            # On Windows, SO_REUSEADDR would let another program steal the port.
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.tcp_port))
        self.server.listen(16)
        threading.Thread(target=self._accept_loop, daemon=True, name="tcp-accept").start()

    def stop(self):
        try:
            self.server.close()
        except OSError:
            pass

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self.server.accept()
            except OSError:
                return
            if not self.slots.acquire(blocking=False):
                try:
                    P.send_json(conn, P.ERROR, {"reason": "This device is busy. Try again in a moment."})
                finally:
                    conn.close()
                continue
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        conn.settimeout(IO_TIMEOUT)
        try:
            s = handshake_server(conn, self.identity, self.name_getter())
            req = s.recv_enc_json(P.REQUEST)
            op = req.get("op")
            if op == "pair":
                self._incoming_pair(s)
            elif op == "offer":
                self._incoming_offer(s, req, addr)
            elif op == "chat":
                self._incoming_chat(s, req)
            else:
                raise P.ProtocolError("unknown request")
        except (P.ProtocolError, TransferError, InvalidTag, ValueError, ConnectionError, OSError) as exc:
            try:
                P.send_json(conn, P.ERROR, {"reason": str(exc)[:200] or "Transfer failed"})
            except OSError:
                pass
        finally:
            conn.close()
            self.slots.release()

    def _wait_for_user(self, s, kind, extra):
        pid = secrets.token_hex(8)
        item = {
            "id": pid, "kind": kind, "peer_name": s.peer_name, "peer_fp": s.peer_fp,
            "code": safety_code(self.identity.pub_der, s.peer_der),
            "friend": self.friend(s.peer_fp) is not None,
            "impostor": self.impostor_warning(s.peer_fp, s.peer_name),
            "created": time.time(), "expires": time.time() + DECISION_TIMEOUT,
            "event": threading.Event(), "decision": None, **extra,
        }
        with self.lock:
            self.pending[pid] = item
        item["event"].wait(DECISION_TIMEOUT)
        with self.lock:
            self.pending.pop(pid, None)
        return bool(item["decision"])

    def decide(self, pid, accept):
        with self.lock:
            item = self.pending.get(pid)
        if not item:
            return False
        item["decision"] = bool(accept)
        item["event"].set()
        return True

    def _incoming_pair(self, s):
        if self.friend(s.peer_fp):
            ok = True
        else:
            ok = self._wait_for_user(s, "pair", {})
        if ok:
            self.save_friend(s.peer_fp, s.peer_name, s.peer_der)
            self.db.event("paired", s.peer_fp, f"You're now friends with {s.peer_name}.")
        s.send_enc_json(P.REPLY, {"ok": ok, "reason": None if ok else "They declined."})

    def _incoming_offer(self, s, req, addr):
        tid, name, size, sha = req.get("tid"), req.get("name"), req.get("size"), req.get("sha")
        plain, udp_port = bool(req.get("plain")), req.get("udp")
        if not (isinstance(tid, str) and len(tid) == 32 and all(c in "0123456789abcdef" for c in tid)):
            raise P.ProtocolError("bad transfer id")
        if not (isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
            raise P.ProtocolError("bad hash")
        if not isinstance(name, str) or not 0 < len(name) <= 255:
            raise P.ProtocolError("bad name")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= self.max_bytes:
            s.send_enc_json(P.REPLY, {"ok": False, "reason": "The file is too large for this device."})
            return
        try:
            sig = b64d(req.get("sig", ""))
        except ValueError:
            raise P.ProtocolError("bad signature encoding")
        if not verify(s.peer_der, sig, file_signature_payload(tid, name, size, sha)):
            raise TransferError("The file's signature doesn't match the sender.")
        if plain and not self.setting_bool("allow_plain", False):
            s.send_enc_json(P.REPLY, {"ok": False, "reason": "This device doesn't accept unencrypted demo transfers. Turn on Lab demo mode on the receiving device first."})
            return

        friend = self.friend(s.peer_fp) is not None
        auto = friend and not plain and self.setting_bool("auto_accept", True)
        if not auto:
            if not self._wait_for_user(s, "file", {"name": name, "size": size, "plain": plain}):
                s.send_enc_json(P.REPLY, {"ok": False, "reason": "They declined the file, or didn't answer in time."})
                return

        part_key = hashlib.sha256(f"{s.peer_fp}|{sha}|{size}".encode()).hexdigest()[:40]
        part_path = os.path.join(self.partial_dir, part_key + ".part")
        offset = os.path.getsize(part_path) if os.path.exists(part_path) else 0
        offset = (offset // P.CHUNK_SIZE) * P.CHUNK_SIZE
        if offset >= size:
            offset = 0
        with open(part_path, "ab") as fh:
            fh.truncate(offset)
        s.send_enc_json(P.REPLY, {"ok": True, "resume": offset})

        rid = tid
        with self.lock:
            self.receiving[rid] = {"id": rid, "name": name, "size": size, "got": offset,
                                   "peer_name": s.peer_name, "plain": plain, "status": "receiving"}
        received = offset
        try:
            with open(part_path, "ab") as fh:
                while True:
                    t, payload = P.recv_frame(s.sock)
                    if t == P.CHUNK:
                        data = s.channel.open(t, payload)
                    elif t == P.CHUNK_PLAIN and plain:
                        data = payload
                    elif t == P.END:
                        s.channel.open(t, payload)
                        break
                    elif t == P.ERROR:
                        raise TransferError("The sender stopped the transfer.")
                    else:
                        raise P.ProtocolError("unexpected frame during transfer")
                    received += len(data)
                    if received > size:
                        raise TransferError("The sender sent more data than it announced.")
                    fh.write(data)
                    with self.lock:
                        self.receiving[rid]["got"] = received
            if received != size:
                raise TransferError("The file arrived incomplete.")
            if sha256_file(part_path) != sha:
                wipe_file(part_path)
                raise TransferError("The file was damaged or changed in transit, so it was discarded.")
            final = unique_path(self.inbox_dir, safe_filename(name))
            shutil.move(part_path, final)
            iid = secrets.token_hex(8)
            with self.db.conn() as c:
                c.execute("INSERT INTO inbox (id, name, path, size, sha, from_name, from_fp, friend, plain, received) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (iid, os.path.basename(final), final, size, sha, s.peer_name, s.peer_fp,
                           int(friend), int(plain), time.time()))
            self.db.event("received", iid, f"Received {os.path.basename(final)} from {s.peer_name}.")
            s.send_enc_json(P.REPLY, {"ok": True})
            with self.lock:
                self.receiving[rid]["status"] = "done"
            self._send_alert(addr[0], udp_port, s.peer_fp, tid, sha)
        except Exception:
            with self.lock:
                if rid in self.receiving:
                    self.receiving[rid]["status"] = "interrupted"
            raise

    # ---------- chat
    def _incoming_chat(self, s, req):
        """A friend's message. Only paired friends may chat, so strangers can't spam you."""
        mid, text, ttl, at = req.get("mid"), req.get("text"), req.get("ttl"), req.get("at")
        if not self.friend(s.peer_fp):
            s.send_enc_json(P.REPLY, {"ok": False, "reason": "You're not friends on this device. Pair first on the Nearby page."})
            return
        if not (isinstance(mid, str) and len(mid) == 32 and all(c in "0123456789abcdef" for c in mid)):
            raise P.ProtocolError("bad message id")
        if not isinstance(text, str) or not 1 <= len(text) <= CHAT_MAX_CHARS:
            raise P.ProtocolError("bad message text")
        if ttl not in CHAT_TTLS or isinstance(ttl, bool) or not isinstance(at, (int, float)):
            raise P.ProtocolError("bad message settings")
        try:
            sig = b64d(req.get("sig", ""))
        except ValueError:
            raise P.ProtocolError("bad signature encoding")
        if not verify(s.peer_der, sig, chat_signature_payload(mid, at, ttl, text)):
            raise TransferError("The message's signature doesn't match the sender.")
        now = time.time()
        with self.db.conn() as c:
            # The same message id twice is a replay (or a retry): store it once.
            fresh = c.execute("SELECT 1 FROM chats WHERE mid=?", (mid,)).fetchone() is None
            if fresh:
                c.execute("INSERT INTO chats (mid, peer_fp, peer_name, direction, text, at, ttl, expires, status) "
                          "VALUES (?,?,?,?,?,?,?,?,?)",
                          (mid, s.peer_fp, s.peer_name, "in", text, now, ttl, now + ttl if ttl else None, "received"))
        if fresh:
            self.db.event("chat", s.peer_fp, f"New message from {s.peer_name}.")
        s.send_enc_json(P.REPLY, {"ok": True})

    def send_chat(self, fp, text, ttl):
        mid = secrets.token_hex(16)
        friend = self.friend(fp)
        now = time.time()
        with self.db.conn() as c:
            c.execute("INSERT INTO chats (mid, peer_fp, peer_name, direction, text, at, ttl, expires, status, read) "
                      "VALUES (?,?,?,?,?,?,?,?,?,1)",
                      (mid, fp, friend["name"] if friend else "?", "out", text, now, ttl, now + ttl if ttl else None, "sending"))
        threading.Thread(target=self._run_chat, args=(mid,), daemon=True).start()
        return mid

    def retry_chat(self, mid):
        with self.db.conn() as c:
            row = c.execute("SELECT status FROM chats WHERE mid=? AND direction='out'", (mid,)).fetchone()
            if not row or row["status"] != "failed":
                return False
            c.execute("UPDATE chats SET status='sending', error=NULL WHERE mid=?", (mid,))
        threading.Thread(target=self._run_chat, args=(mid,), daemon=True).start()
        return True

    def _run_chat(self, mid):
        with self.db.conn() as c:
            row = dict(c.execute("SELECT * FROM chats WHERE mid=?", (mid,)).fetchone())
        s = None
        status, error = "failed", None
        try:
            s = self._connect(row["peer_fp"])
            at = row["at"]
            sig = self.identity.sign(chat_signature_payload(mid, at, row["ttl"], row["text"]))
            s.send_enc_json(P.REQUEST, {"op": "chat", "mid": mid, "text": row["text"], "ttl": row["ttl"],
                                        "at": at, "sig": b64e(sig)})
            reply = s.recv_enc_json(P.REPLY)
            if reply.get("ok"):
                status = "delivered"
            else:
                error = reply.get("reason") or "Not delivered."
        except Exception as exc:
            error = _friendly(exc)
        finally:
            if s:
                s.sock.close()
        with self.db.conn() as c:
            c.execute("UPDATE chats SET status=?, error=? WHERE mid=?", (status, error, mid))

    def _send_alert(self, ip, udp_port, peer_fp, tid, sha):
        disc = self.discovery_getter()
        if not disc:
            return
        peer = disc.peer(peer_fp)
        port = peer["udp"] if peer else udp_port
        if not isinstance(port, int) or not 1 <= port <= 65535:
            return
        sig = self.identity.sign(f"{PROTO}|ALERT|{tid}|{sha}".encode())
        disc.send_alert(ip, port, {"tid": tid, "sha": sha, "fp": self.identity.fp,
                                   "name": self.name_getter(), "sig": b64e(sig)})

    def on_alert(self, msg, addr):
        """A receiver told us over UDP that it saved our file. Check it really was them."""
        tid, sha, sig = msg.get("tid"), msg.get("sha"), msg.get("sig")
        with self.lock:
            known = self.sent_tids.pop(tid, None) if isinstance(tid, str) else None
        if not known or known["sha"] != sha:
            return
        try:
            ok = verify(known["der"], b64d(sig), f"{PROTO}|ALERT|{tid}|{sha}".encode())
        except ValueError:
            ok = False
        if ok:
            self.db.event("delivered", tid, f"{known['peer_name']} saved {known['name']}.")

    # ---------- outgoing
    def _connect(self, fp):
        disc = self.discovery_getter()
        peer = disc.peer(fp) if disc else None
        if not peer:
            raise TransferError("That device isn't nearby any more. Check it's on the same Wi-Fi and VanishDrop is open.")
        sock = socket.create_connection((peer["ip"], peer["tcp"]), timeout=10)
        sock.settimeout(IO_TIMEOUT)
        s = handshake_client(sock, self.identity, self.name_getter())
        if s.peer_fp != fp:
            sock.close()
            raise TransferError("The device that answered isn't the one you picked. Someone may be pretending to be it.")
        return s

    def pair(self, fp):
        pid = secrets.token_hex(8)
        item = {"id": pid, "peer_fp": fp, "peer_name": "", "code": None, "status": "connecting", "error": None}
        with self.lock:
            self.pairings[pid] = item
        threading.Thread(target=self._run_pair, args=(item,), daemon=True).start()
        return pid

    def _run_pair(self, item):
        s = None
        try:
            s = self._connect(item["peer_fp"])
            item.update(peer_name=s.peer_name, code=safety_code(self.identity.pub_der, s.peer_der), status="waiting")
            s.send_enc_json(P.REQUEST, {"op": "pair"})
            s.sock.settimeout(DECISION_TIMEOUT + 15)
            reply = s.recv_enc_json(P.REPLY)
            if reply.get("ok"):
                self.save_friend(s.peer_fp, s.peer_name, s.peer_der)
                self.db.event("paired", s.peer_fp, f"You're now friends with {s.peer_name}.")
                item["status"] = "paired"
            else:
                item.update(status="declined", error=reply.get("reason") or "They declined.")
        except Exception as exc:
            item.update(status="failed", error=_friendly(exc))
        finally:
            if s:
                s.sock.close()

    def send_file(self, fp, staged_path, name, plain):
        jid = secrets.token_hex(8)
        job = {"id": jid, "tid": secrets.token_hex(16), "peer_fp": fp, "peer_name": "", "name": name,
               "path": staged_path, "size": os.path.getsize(staged_path), "sent": 0, "sha": None,
               "plain": bool(plain), "status": "queued", "error": None, "code": None, "friend": False,
               "created": time.time()}
        with self.lock:
            self.jobs[jid] = job
        threading.Thread(target=self._run_job, args=(job,), daemon=True).start()
        return jid

    def retry(self, jid):
        with self.lock:
            job = self.jobs.get(jid)
        if not job or job["status"] not in ("failed", "declined") or not os.path.exists(job["path"]):
            return False
        job.update(status="queued", error=None)
        threading.Thread(target=self._run_job, args=(job,), daemon=True).start()
        return True

    def cancel(self, jid):
        with self.lock:
            job = self.jobs.get(jid)
        if not job or job["status"] in ("sending", "waiting", "hashing", "connecting"):
            return False
        wipe_file(job["path"])
        with self.lock:
            self.jobs.pop(jid, None)
        return True

    def _run_job(self, job):
        s = None
        try:
            if not job["sha"]:
                job["status"] = "hashing"
                job["sha"] = sha256_file(job["path"])
            job["status"] = "connecting"
            s = self._connect(job["peer_fp"])
            job.update(peer_name=s.peer_name, code=safety_code(self.identity.pub_der, s.peer_der),
                       friend=self.friend(s.peer_fp) is not None)
            sig = self.identity.sign(file_signature_payload(job["tid"], job["name"], job["size"], job["sha"]))
            disc = self.discovery_getter()
            s.send_enc_json(P.REQUEST, {"op": "offer", "tid": job["tid"], "name": job["name"], "size": job["size"],
                                        "sha": job["sha"], "plain": job["plain"], "sig": b64e(sig),
                                        "udp": disc.udp_port if disc else None})
            job["status"] = "waiting"
            s.sock.settimeout(DECISION_TIMEOUT + 15)
            reply = s.recv_enc_json(P.REPLY)
            s.sock.settimeout(IO_TIMEOUT)
            if not reply.get("ok"):
                job.update(status="declined", error=reply.get("reason") or "They declined.")
                return
            offset = reply.get("resume", 0)
            if not isinstance(offset, int) or not 0 <= offset < job["size"] or offset % P.CHUNK_SIZE:
                raise P.ProtocolError("bad resume offset")
            job.update(status="sending", sent=offset, resumed_from=offset)
            with open(job["path"], "rb") as fh:
                fh.seek(offset)
                while True:
                    block = fh.read(P.CHUNK_SIZE)
                    if not block:
                        break
                    if job["plain"]:
                        P.send_frame(s.sock, P.CHUNK_PLAIN, block)
                    else:
                        s.send_enc(P.CHUNK, block)
                    job["sent"] += len(block)
            with self.lock:
                self.sent_tids[job["tid"]] = {"der": s.peer_der, "sha": job["sha"],
                                              "peer_name": s.peer_name, "name": job["name"]}
            s.send_enc_json(P.END, {"done": True})
            s.sock.settimeout(120)  # the receiver checks the hash before answering
            result = s.recv_enc_json(P.REPLY)
            if result.get("ok"):
                job["status"] = "delivered"
                self.db.event("sent", job["tid"], f"Sent {job['name']} to {s.peer_name}.")
                wipe_file(job["path"])
            else:
                job.update(status="failed", error=result.get("reason") or "The receiver rejected the file.")
        except Exception as exc:
            job.update(status="failed", error=_friendly(exc))
        finally:
            if s:
                s.sock.close()

    # ---------- snapshot for the UI
    def snapshot(self):
        now = time.time()
        with self.lock:
            pending = [{k: v for k, v in p.items() if k != "event"} | {"seconds_left": max(0, int(p["expires"] - now))}
                       for p in self.pending.values()]
            jobs = [{k: v for k, v in j.items() if k != "path"} for j in self.jobs.values()]
            receiving = [dict(r) for r in self.receiving.values()]
            pairings = [dict(p) for p in self.pairings.values()]
        return {"pending": pending, "jobs": sorted(jobs, key=lambda j: -j["created"]),
                "receiving": receiving, "pairings": pairings}


def _friendly(exc):
    if isinstance(exc, TransferError):
        return str(exc)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "The other device stopped responding. You can retry: it continues where it left off."
    if isinstance(exc, ConnectionRefusedError):
        return "The other device refused the connection. Is VanishDrop running there?"
    if isinstance(exc, (ConnectionError, OSError)):
        return "The connection dropped. You can retry: it continues where it left off."
    if isinstance(exc, InvalidTag):
        return "A message failed its integrity check, so the transfer was stopped."
    if isinstance(exc, P.ProtocolError):
        return f"The other device sent something unexpected ({exc})."
    return f"Something went wrong: {exc}"
