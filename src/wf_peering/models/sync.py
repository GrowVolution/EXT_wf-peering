from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from webfluid.core.ext import db
from typing import Optional

from . import TABLE_PREFIX


def _unique_name(name: str) -> str:
    return f"{TABLE_PREFIX}{name}"


class SyncRun(db.Model):
    __tablename__ = _unique_name("sync_runs")

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    day: Mapped[Optional[str]] = mapped_column(String(10), index=True)
    started_at: Mapped[str] = mapped_column(String(20), index=True)
    finished_at: Mapped[Optional[str]] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(16))
    attempts: Mapped[int] = mapped_column(default=0)
    from_seq: Mapped[Optional[int]]
    to_seq: Mapped[Optional[int]]
    head_hash: Mapped[Optional[str]] = mapped_column(String(64))
    host_root: Mapped[Optional[str]] = mapped_column(String(64))
    local_root: Mapped[Optional[str]] = mapped_column(String(64))
    error: Mapped[Optional[str]] = mapped_column(String(256))
    detail: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, id: str, kind: str, started_at: str, day: Optional[str] = None):
        self.id = id
        self.kind = kind
        self.started_at = started_at
        self.day = day
        self.status = "running"
        self.attempts = 0


class Checkpoint(db.Model):
    __tablename__ = _unique_name("checkpoints")

    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))
    hash: Mapped[Optional[str]] = mapped_column(String(64))
    content: Mapped[Optional[str]] = mapped_column(Text)
    signature: Mapped[Optional[str]] = mapped_column(String(128))
    computed_at: Mapped[str] = mapped_column(String(20))

    def __init__(self, day: str, status: str, computed_at: str, hash: Optional[str] = None,
                 content: Optional[str] = None, signature: Optional[str] = None):
        self.day = day
        self.status = status
        self.computed_at = computed_at
        self.hash = hash
        self.content = content
        self.signature = signature


class RemoteCheckpoint(db.Model):
    __tablename__ = _unique_name("remote_checkpoints")

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[str] = mapped_column(String(32), index=True)
    day: Mapped[str] = mapped_column(String(10), index=True)
    hash: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(String(128))
    verified: Mapped[bool] = mapped_column(default=False)
    via: Mapped[str] = mapped_column(String(16))
    received_at: Mapped[str] = mapped_column(String(20))

    __table_args__ = (UniqueConstraint("node_id", "day", "hash"),)

    def __init__(self, node_id: str, day: str, hash: str, content: str, signature: str,
                 verified: bool, via: str, received_at: str):
        self.node_id = node_id
        self.day = day
        self.hash = hash
        self.content = content
        self.signature = signature
        self.verified = verified
        self.via = via
        self.received_at = received_at
