from pathlib import Path
import os, secrets, time

from ..protocol.signing import Signer, b64decode, b64encode
from ..protocol.entries import utc_now
from .settings import settings, PROTOCOL_VERSION, SCHEMA_VERSION

NODE_CONTEXT = "wf-peering-node-v1"


class NodeIdentity:
    signer: Signer | None = None
    boot_id: str = ""
    started_at: str = ""
    started_monotonic: float = 0.0

    @classmethod
    def setup(cls):
        cls.signer = Signer(cls._seed())
        cls.boot_id = b64encode(secrets.token_bytes(12))
        cls.started_at = utc_now()
        cls.started_monotonic = time.monotonic()

    @staticmethod
    def _seed() -> bytes:
        if settings.node_key:
            seed = b64decode(settings.node_key.strip())
            if len(seed) != 32: raise ValueError("PEERING_NODE_KEY must be 32 bytes, base64url.")
            return seed

        path: Path = settings.key_file
        if path.is_file():
            seed = b64decode(path.read_text(encoding="ascii").strip())
            if len(seed) != 32: raise ValueError(f"The node key in {path} is corrupt.")
            return seed

        path.parent.mkdir(parents=True, exist_ok=True)
        seed = secrets.token_bytes(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(b64encode(seed))
        return seed

    @classmethod
    def node_id(cls) -> str:
        return cls.signer.fingerprint

    @classmethod
    def public_key(cls) -> str:
        return cls.signer.public_key

    @classmethod
    def sign(cls, context: str, payload) -> str:
        return cls.signer.sign(context, payload)

    @classmethod
    def uptime(cls) -> int:
        return int(time.monotonic() - cls.started_monotonic)

    @classmethod
    def statement(cls) -> dict:
        from .role import current
        return {
            "node": cls.node_id(),
            "key": cls.public_key(),
            "role": settings.role,
            "url": settings.origin,
            "host": settings.assessed,
            "protocol": PROTOCOL_VERSION,
            "schema": SCHEMA_VERSION,
            "software": current().software,
            "boot": cls.boot_id,
            "started_at": cls.started_at,
            "ts": utc_now()
        }

    @classmethod
    def signed_statement(cls) -> dict:
        statement = cls.statement()
        return { "statement": statement, "signature": cls.sign(NODE_CONTEXT, statement) }
