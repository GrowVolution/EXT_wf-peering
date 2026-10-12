from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import base64, hashlib, re

from .canonical import canonical

KEY_LENGTH = 32
SIGNATURE_LENGTH = 64

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(text: str) -> bytes:
    if not isinstance(text, str) or not _BASE64URL.match(text) or len(text) % 4 == 1:
        raise ValueError("INVALID_ENCODING")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint(public_key: str) -> str:
    return b64encode(hashlib.sha256(b64decode(public_key)).digest()[:16])


def ed25519_key(text: str) -> Ed25519PublicKey:
    raw = b64decode(text)
    if len(raw) != KEY_LENGTH: raise ValueError("INVALID_KEY")
    return Ed25519PublicKey.from_public_bytes(raw)


def x25519_key(text: str) -> X25519PublicKey:
    raw = b64decode(text)
    if len(raw) != KEY_LENGTH: raise ValueError("INVALID_KEY")
    key = X25519PublicKey.from_public_bytes(raw)
    X25519PrivateKey.generate().exchange(key)
    return key


def valid_ed25519(text) -> bool:
    try:
        ed25519_key(text)
        return True
    except (ValueError, TypeError): return False


def valid_x25519(text) -> bool:
    try:
        x25519_key(text)
        return True
    except (ValueError, TypeError): return False


def message(context: str, payload) -> bytes:
    body = payload if isinstance(payload, bytes) else canonical(payload)
    return context.encode("utf-8") + b"\n" + body


def verify(public_key: str, context: str, payload, signature: str) -> bool:
    try:
        raw = b64decode(signature)
        if len(raw) != SIGNATURE_LENGTH: return False
        ed25519_key(public_key).verify(raw, message(context, payload))
        return True
    except (ValueError, TypeError, InvalidSignature): return False


class Signer:
    def __init__(self, seed: bytes):
        if len(seed) != KEY_LENGTH: raise ValueError("INVALID_SEED")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = b64encode(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.fingerprint = fingerprint(self.public_key)

    @classmethod
    def generate(cls) -> "Signer":
        key = Ed25519PrivateKey.generate()
        return cls(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    def sign(self, context: str, payload) -> str:
        return b64encode(self._key.sign(message(context, payload)))
