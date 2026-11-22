"""Device identity: an RSA-2048 key pair used to sign handshakes, files and alerts."""
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class Identity:
    def __init__(self, path: str):
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self.key = serialization.load_pem_private_key(fh.read(), password=None)
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        self.pub_der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.fp = fingerprint(self.pub_der)

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data, PSS, hashes.SHA256())


def fingerprint(pub_der: bytes) -> str:
    return hashlib.sha256(pub_der).hexdigest()


def load_public(pub_der: bytes):
    key = serialization.load_der_public_key(pub_der)
    if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 4096:
        raise ValueError("expected an RSA key of 2048 to 4096 bits")
    return key


def verify(pub_der: bytes, signature: bytes, data: bytes) -> bool:
    try:
        load_public(pub_der).verify(signature, data, PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def safety_code(der_a: bytes, der_b: bytes) -> str:
    """Six digits both people see. Same on both screens only if nobody is in the middle."""
    a, b = sorted([fingerprint(der_a), fingerprint(der_b)])
    digest = hashlib.sha256(f"vanishdrop-safety|{a}|{b}".encode()).digest()
    n = int.from_bytes(digest[:8], "big") % 1_000_000
    s = f"{n:06d}"
    return f"{s[:3]} {s[3:]}"
