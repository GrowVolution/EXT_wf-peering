from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from webfluid.core.ext import db
from typing import Optional

from . import TABLE_PREFIX


def _unique_name(name: str) -> str:
    return f"{TABLE_PREFIX}{name}"


class Peer(db.Model):
    __tablename__ = _unique_name("peers")

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[Optional[str]] = mapped_column(String(32), unique=True)
    public_key: Mapped[Optional[str]] = mapped_column(String(64))
    url: Mapped[str] = mapped_column(String(512), unique=True)
    sources: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[str] = mapped_column(String(20))
    last_seen: Mapped[Optional[str]] = mapped_column(String(20))
    connected: Mapped[bool] = mapped_column(default=False)
    last_connected_at: Mapped[Optional[str]] = mapped_column(String(20))
    last_disconnected_at: Mapped[Optional[str]] = mapped_column(String(20))
    last_heartbeat_at: Mapped[Optional[str]] = mapped_column(String(20))
    head_seq: Mapped[Optional[int]]
    head_hash: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="active")
    failures: Mapped[int] = mapped_column(default=0)
    last_error: Mapped[Optional[str]] = mapped_column(String(256))
    key_changed_at: Mapped[Optional[str]] = mapped_column(String(20))
    check: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, url: str, first_seen: str, sources: str = "[]",
                 node_id: Optional[str] = None, public_key: Optional[str] = None):
        self.url = url
        self.first_seen = first_seen
        self.sources = sources
        self.node_id = node_id
        self.public_key = public_key
        self.connected = False
        self.status = "active"
        self.failures = 0


class PeerConnection(db.Model):
    __tablename__ = _unique_name("connections")

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    opened_at: Mapped[str] = mapped_column(String(20), index=True)
    closed_at: Mapped[Optional[str]] = mapped_column(String(20))
    authenticated: Mapped[bool] = mapped_column(default=False)
    reason: Mapped[Optional[str]] = mapped_column(String(128))
    address: Mapped[Optional[str]] = mapped_column(String(64))

    def __init__(self, opened_at: str, address: Optional[str] = None):
        self.opened_at = opened_at
        self.address = address
        self.authenticated = False


class Probe(db.Model):
    __tablename__ = _unique_name("probes")

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    ts: Mapped[str] = mapped_column(String(20), index=True)
    ok: Mapped[bool]
    latency_ms: Mapped[Optional[int]]
    error: Mapped[Optional[str]] = mapped_column(String(128))
    detail: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, target: str, ts: str, ok: bool, latency_ms: Optional[int] = None,
                 error: Optional[str] = None, detail: Optional[str] = None):
        self.target = target
        self.ts = ts
        self.ok = ok
        self.latency_ms = latency_ms
        self.error = error
        self.detail = detail
