from dataclasses import dataclass, field
from pathlib import Path
import os

from webfluid.core.constants import DEBUG

PROTOCOL_VERSION = 1
SCHEMA_VERSION = 1

HOST_API = "/peering/api/v1"
PEER_API = "/api/v1"
HOST_SOCKET = "/peering/ws/peer"
ROLES = ("host", "peer")


@dataclass
class Settings:
    role: str = "host"
    origin: str = "http://localhost:8000"
    host: str | None = None
    host_key: str | None = None
    key_file: Path | None = None
    node_key: str | None = None
    peers: list = field(default_factory=list)
    references: dict = field(default_factory=dict)
    reference_hosts: list = field(default_factory=list)
    allow_insecure: bool = False
    debug: bool = False
    max_peers: int = 64
    registrations_per_hour: int = 20
    max_response_bytes: int = 2 * 1024 * 1024
    timeout: int = 10
    schedule: bool = True
    sync_time: tuple = (23, 59)
    checkpoint_time: tuple = (0, 0)
    checkpoint_grace: int = 300
    sync_attempts: int = 3
    integrity_interval: int = 900
    probe_interval: int = 300
    trust_interval: int = 600
    heartbeat_interval: int = 30
    probe_retention_days: int = 30
    peer_inactive_days: int = 30
    ledger_page: int = 500

    @property
    def is_host(self) -> bool:
        return self.role == "host"

    @property
    def is_peer(self) -> bool:
        return self.role == "peer"

    @property
    def assessed(self) -> str | None:
        return self.host if self.is_peer else self.origin

    def api_of(self, url: str | None) -> str:
        return HOST_API if url is not None and url == self.assessed else PEER_API


settings = Settings()


def _origin(value: str | None) -> str | None:
    if not value: return None
    value = value.strip()
    while value.endswith("/"): value = value[:-1]
    return value.lower()


def configure(config, role: str, root: Path) -> Settings:
    if role not in ROLES: raise ValueError(f"The peering role must be 'host' or 'peer', not {role!r}.")

    key_file = Path(config.get("PEERING_KEY_FILE") or "keys/node.key")
    if not key_file.is_absolute(): key_file = root / key_file

    settings.role = role
    settings.origin = _origin(config.get("PEERING_PUBLIC_URL") or config.get("BASE_URL")) or settings.origin
    settings.host = _origin(config.get("PEERING_HOST")) if role == "peer" else None
    settings.host_key = config.get("PEERING_HOST_KEY")
    settings.key_file = key_file
    settings.node_key = config.get("PEERING_NODE_KEY") or os.getenv("PEERING_NODE_KEY")
    settings.peers = [_origin(url) for url in config.get("PEERING_PEERS") or [] if url]
    settings.references = dict(config.get("PEERING_TRUSTED_REFERENCES") or {})
    settings.reference_hosts = list(config.get("PEERING_REFERENCE_HOSTS") or ["raw.githubusercontent.com"])
    settings.debug = DEBUG
    settings.allow_insecure = bool(config.get("PEERING_ALLOW_INSECURE")) or DEBUG
    settings.max_peers = int(config.get("PEERING_MAX_PEERS") or 64)
    settings.registrations_per_hour = int(config.get("PEERING_REGISTRATIONS_PER_HOUR") or 20)
    settings.max_response_bytes = int(config.get("PEERING_MAX_RESPONSE_BYTES") or 2 * 1024 * 1024)
    settings.timeout = int(config.get("PEERING_REQUEST_TIMEOUT") or 10)
    settings.schedule = config.get("PEERING_SCHEDULE", True) not in (False, 0, "0", "false", "False")
    settings.sync_time = tuple(config.get("PEERING_SYNC_TIME") or (23, 59))
    settings.checkpoint_time = tuple(config.get("PEERING_CHECKPOINT_TIME") or (0, 0))
    settings.checkpoint_grace = int(config.get("PEERING_CHECKPOINT_GRACE") or 300)
    settings.sync_attempts = max(1, int(config.get("PEERING_SYNC_ATTEMPTS") or 3))
    settings.integrity_interval = int(config.get("PEERING_INTEGRITY_INTERVAL") or 900)
    settings.probe_interval = int(config.get("PEERING_PROBE_INTERVAL") or 300)
    settings.trust_interval = int(config.get("PEERING_TRUST_INTERVAL") or 600)
    settings.heartbeat_interval = int(config.get("PEERING_HEARTBEAT_INTERVAL") or 30)
    settings.probe_retention_days = int(config.get("PEERING_PROBE_RETENTION_DAYS") or 30)
    inactive_days = config.get("PEERING_PEER_INACTIVE_DAYS")
    settings.peer_inactive_days = 30 if inactive_days is None else max(0, int(inactive_days))
    settings.ledger_page = max(10, min(int(config.get("PEERING_LEDGER_PAGE") or 500), 2000))

    if role == "peer" and not settings.host:
        raise ValueError("PEERING_HOST is required on a peer.")
    return settings
