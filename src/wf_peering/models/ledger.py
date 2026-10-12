from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from webfluid.core.ext import db
from typing import Optional

from . import TABLE_PREFIX


def _unique_name(name: str) -> str:
    return f"{TABLE_PREFIX}{name}"


class LedgerEntry(db.Model):
    __tablename__ = _unique_name("ledger")

    seq: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    leaf: Mapped[str] = mapped_column(String(64))
    prev: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(160), index=True)
    source: Mapped[str] = mapped_column(String(64))
    subject: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    ref: Mapped[Optional[str]] = mapped_column(String(256), unique=True)
    ts: Mapped[str] = mapped_column(String(20), index=True)
    content: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(String(128))
    received_at: Mapped[str] = mapped_column(String(20))
    flags: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, seq: int, hash: str, leaf: str, prev: str, kind: str, source: str,
                 subject: Optional[str], ref: Optional[str], ts: str, content: str,
                 signature: str, received_at: str, flags: Optional[str] = None):
        self.seq = seq
        self.hash = hash
        self.leaf = leaf
        self.prev = prev
        self.kind = kind
        self.source = source
        self.subject = subject
        self.ref = ref
        self.ts = ts
        self.content = content
        self.signature = signature
        self.received_at = received_at
        self.flags = flags


class JournalEntry(db.Model):
    __tablename__ = _unique_name("journal")

    seq: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    hash: Mapped[str] = mapped_column(String(64), unique=True)
    leaf: Mapped[str] = mapped_column(String(64))
    prev: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(160), index=True)
    ts: Mapped[str] = mapped_column(String(20), index=True)
    content: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(String(128))

    def __init__(self, seq: int, hash: str, leaf: str, prev: str, kind: str, ts: str,
                 content: str, signature: str):
        self.seq = seq
        self.hash = hash
        self.leaf = leaf
        self.prev = prev
        self.kind = kind
        self.ts = ts
        self.content = content
        self.signature = signature
