"""Diffie-Hellman key exchange and the encrypted channel used for device-to-device transfers."""
import warnings

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The cryptography library now prefers X25519, but the syllabus asks for classic
# Diffie-Hellman, so we use the standard RFC 3526 group and silence the notice.
warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")

# RFC 3526 group 14: a 2048-bit safe prime, generator 2.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
PARAMS = dh.DHParameterNumbers(P, G).parameters()


class DHKeyPair:
    def __init__(self):
        self.private = PARAMS.generate_private_key()
        self.public_int = self.private.public_key().public_numbers().y

    def shared_secret(self, peer_public_int: int) -> bytes:
        # Reject 0, 1, p-1 and anything out of range: these force a guessable secret.
        if not isinstance(peer_public_int, int) or not 2 <= peer_public_int <= P - 2:
            raise ValueError("invalid Diffie-Hellman public value")
        # Safe prime: the value must be in the large prime-order subgroup.
        if pow(peer_public_int, (P - 1) // 2, P) != 1:
            raise ValueError("Diffie-Hellman value is outside the safe subgroup")
        peer = dh.DHPublicNumbers(peer_public_int, PARAMS.parameter_numbers()).public_key()
        return self.private.exchange(peer)


def session_keys(shared: bytes, nonce_c: bytes, nonce_s: bytes, fp_c: str, fp_s: str):
    """Two AES-256 keys: one for each direction, so nonces can never collide."""
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=nonce_c + nonce_s,
        info=f"vanishdrop v1 session|{fp_c}|{fp_s}".encode(),
    ).derive(shared)
    return material[:32], material[32:]


class Channel:
    """AES-256-GCM with counter nonces. A replayed, dropped or reordered frame fails to decrypt."""

    def __init__(self, send_key: bytes, recv_key: bytes):
        self._tx = AESGCM(send_key)
        self._rx = AESGCM(recv_key)
        self._tx_n = 0
        self._rx_n = 0

    @staticmethod
    def _nonce(n: int) -> bytes:
        return b"\x00\x00\x00\x00" + n.to_bytes(8, "big")

    def seal(self, frame_type: int, data: bytes) -> bytes:
        out = self._tx.encrypt(self._nonce(self._tx_n), data, bytes([frame_type]))
        self._tx_n += 1
        return out

    def open(self, frame_type: int, data: bytes) -> bytes:
        out = self._rx.decrypt(self._nonce(self._rx_n), data, bytes([frame_type]))
        self._rx_n += 1
        return out
