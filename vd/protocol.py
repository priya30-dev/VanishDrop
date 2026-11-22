"""VanishDrop's TCP wire format.

Every message is a frame:  [4-byte length][1-byte type][payload]
Lengths are capped so a bad peer can't make us allocate huge buffers.
"""
import json
import struct

HEADER = struct.Struct(">IB")
MAX_FRAME = 1024 * 1024 + 1024
CHUNK_SIZE = 256 * 1024

HELLO = 1         # client -> server, plain JSON: identity, DH value, nonce, signature
HELLO_REPLY = 2   # server -> client, plain JSON: same, signed over both sides
CONFIRM = 3       # client -> server, encrypted: client's signature over the whole handshake
REQUEST = 4       # client -> server, encrypted JSON: pair or offer a file
REPLY = 5         # server -> client, encrypted JSON: decision / result
CHUNK = 6         # client -> server, encrypted file bytes
CHUNK_PLAIN = 7   # client -> server, UNENCRYPTED file bytes (lab demo mode only)
END = 8           # client -> server, encrypted JSON: end of file
ERROR = 9         # either side, plain JSON: a reason before closing

NAMES = {v: k for k, v in globals().items() if isinstance(v, int) and k.isupper() and k not in
         ("MAX_FRAME", "CHUNK_SIZE")}


class ProtocolError(Exception):
    pass


def _log(direction, sock, frame_type, payload):
    from .monitor import ENCRYPTED_FRAMES, MON, peer_of
    name = NAMES.get(frame_type, f"TYPE {frame_type}")
    MON.log("tcp", direction, name, peer_of(sock), len(payload) + HEADER.size,
            encrypted=name in ENCRYPTED_FRAMES, head=payload)


def send_frame(sock, frame_type: int, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise ProtocolError("frame too large")
    sock.sendall(HEADER.pack(len(payload), frame_type) + payload)
    _log("out", sock, frame_type, payload)


def send_json(sock, frame_type: int, obj) -> None:
    send_frame(sock, frame_type, json.dumps(obj, separators=(",", ":")).encode())


def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(min(n - len(buf), 65536))
        if not part:
            raise ConnectionError("connection closed")
        buf += part
    return bytes(buf)


def recv_frame(sock):
    length, frame_type = HEADER.unpack(_recv_exact(sock, HEADER.size))
    if length > MAX_FRAME:
        raise ProtocolError("frame too large")
    payload = _recv_exact(sock, length)
    _log("in", sock, frame_type, payload)
    return frame_type, payload


def parse_json(payload: bytes) -> dict:
    try:
        obj = json.loads(payload.decode())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("bad JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("expected a JSON object")
    return obj
