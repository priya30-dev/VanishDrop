"""Small helpers shared by the server and the LAN code."""
import base64
import os
import re
import secrets
import socket
import unicodedata

B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    if not isinstance(text, str) or not B64URL_RE.match(text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def wipe_file(path: str) -> None:
    """Overwrite a file with random bytes, then delete it."""
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            remaining = size
            while remaining > 0:
                n = min(remaining, 1024 * 1024)
                fh.write(secrets.token_bytes(n))
                remaining -= n
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


def safe_filename(name: str, fallback: str = "file") -> str:
    """Turn a name chosen by someone else into a safe file name for this computer.

    Blocks path tricks like ../../ and C:\\, control characters and Windows
    reserved names such as CON or NUL.
    """
    if not isinstance(name, str):
        name = ""
    name = unicodedata.normalize("NFC", name)
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*')
    name = name.strip().strip(".")
    if not name:
        name = fallback
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    if stem.upper() in WINDOWS_RESERVED or name.upper() in WINDOWS_RESERVED:
        stem = "_" + (stem or name)
    stem = stem[:120]
    ext = ext[:16]
    return f"{stem}.{ext}" if ext else stem


def unique_path(folder: str, name: str) -> str:
    base = safe_filename(name)
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    candidate = os.path.join(folder, base)
    n = 1
    while os.path.exists(candidate):
        candidate = os.path.join(folder, f"{stem} ({n})" + (f".{ext}" if ext else ""))
        n += 1
    return candidate


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
