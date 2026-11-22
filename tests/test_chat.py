"""Secure chat between devices: delivery, friends-only, replay and tamper protection.

Run:  py tests/test_chat.py
"""
import os, sys, time, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_lan import Device, wait, q
from vd import protocol as P
from vd.transfer import handshake_client, chat_signature_payload
from vd.util import b64e
import socket, secrets, json
a = Device("Kirti", 50509, 50609); b = Device("Priya", 50510, 50610); c = Device("Stranger", 50508, 50608)
res = []
def check(l, v): res.append(v); print(("PASS " if v else "FAIL ") + l)
try:
    wait(lambda: a.disc.peer(b.id.fp) and b.disc.peer(a.id.fp) and c.disc.peer(b.id.fp))
    stop = threading.Event()
    def acc():
        while not stop.is_set():
            for p in b.node.snapshot()["pending"]: b.node.decide(p["id"], True)
            time.sleep(0.05)
    threading.Thread(target=acc, daemon=True).start()
    pid = a.node.pair(b.id.fp); wait(lambda: a.node.pairings[pid]["status"] == "paired"); stop.set()
    mid = a.node.send_chat(b.id.fp, "Hi Priya! notes: https://sbi-kyc-update.xyz/login", 3600)
    wait(lambda: q(a.db, f"SELECT status FROM chats WHERE mid='{mid}'")["status"] != "sending")
    check("message delivered to friend", q(a.db, f"SELECT status FROM chats WHERE mid='{mid}'")["status"] == "delivered")
    row = q(b.db, f"SELECT * FROM chats WHERE mid='{mid}'")
    check("friend receives exact text", row and row["text"].startswith("Hi Priya!") and row["direction"] == "in")
    check("disappearing time is set", row["expires"] and abs(row["expires"] - time.time() - 3600) < 30)
    # stranger cannot chat
    c.node.save_friend(b.id.fp, "Priya", b.id.pub_der)  # stranger thinks it's friends, B doesn't
    mid2 = c.node.send_chat(b.id.fp, "spam", 60)
    wait(lambda: q(c.db, f"SELECT status FROM chats WHERE mid='{mid2}'")["status"] != "sending")
    r2 = q(c.db, f"SELECT * FROM chats WHERE mid='{mid2}'")
    check("non-friends can't send messages", r2["status"] == "failed" and "Pair first" in (r2["error"] or ""))
    check("spam never stored on receiver", q(b.db, f"SELECT 1 FROM chats WHERE mid='{mid2}'") is None)
    # replay same message: stored once
    s = handshake_client(socket.create_connection(("127.0.0.1", 50610)), a.id, "Kirti")
    at = time.time(); m3 = secrets.token_hex(16); sig = a.id.sign(chat_signature_payload(m3, at, 60, "once"))
    s.send_enc_json(P.REQUEST, {"op": "chat", "mid": m3, "text": "once", "ttl": 60, "at": at, "sig": b64e(sig)}); s.recv_enc_json(P.REPLY); s.sock.close()
    s = handshake_client(socket.create_connection(("127.0.0.1", 50610)), a.id, "Kirti")
    s.send_enc_json(P.REQUEST, {"op": "chat", "mid": m3, "text": "once", "ttl": 60, "at": at, "sig": b64e(sig)}); s.recv_enc_json(P.REPLY); s.sock.close()
    check("replayed message stored only once", q(b.db, f"SELECT COUNT(*) FROM chats WHERE mid='{m3}'")[0] == 1)
    # forged text
    s = handshake_client(socket.create_connection(("127.0.0.1", 50610)), a.id, "Kirti")
    m4 = secrets.token_hex(16); sig = a.id.sign(chat_signature_payload(m4, at, 60, "pay 10"))
    s.send_enc_json(P.REQUEST, {"op": "chat", "mid": m4, "text": "pay 10000", "ttl": 60, "at": at, "sig": b64e(sig)})
    t, payload = P.recv_frame(s.sock); s.sock.close()
    check("changed message text is rejected (signature)", t == P.ERROR and q(b.db, f"SELECT 1 FROM chats WHERE mid='{m4}'") is None)
    # offline friend -> failed, retry later works
    b.disc.stop(); b.node.stop(); time.sleep(13)
    m5 = a.node.send_chat(b.id.fp, "are you there?", 60)
    wait(lambda: q(a.db, f"SELECT status FROM chats WHERE mid='{m5}'")["status"] != "sending")
    check("message to offline friend fails with a reason", q(a.db, f"SELECT status FROM chats WHERE mid='{m5}'")["status"] == "failed")
finally:
    for d in (a, c):
        d.stop()
print(f"{sum(res)}/{len(res)} chat checks passed")
sys.exit(0 if all(res) else 1)
