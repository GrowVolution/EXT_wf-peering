from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from webfluid.core.ext import db
from typing import Optional

from . import TABLE_PREFIX


def _unique_name(name: str) -> str:
    return f"{TABLE_PREFIX}{name}"


class NodeState(db.Model):
    __tablename__ = _unique_name("state")

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)

    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value


class Conflict(db.Model):
    __tablename__ = _unique_name("conflicts")

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    subject: Mapped[Optional[str]] = mapped_column(String(256))
    summary: Mapped[str] = mapped_column(String(512))
    evidence: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    detected_at: Mapped[str] = mapped_column(String(20), index=True)
    resolved_at: Mapped[Optional[str]] = mapped_column(String(20))

    def __init__(self, kind: str, severity: str, summary: str, evidence: str,
                 fingerprint: str, detected_at: str, subject: Optional[str] = None):
        self.kind = kind
        self.severity = severity
        self.summary = summary
        self.evidence = evidence
        self.fingerprint = fingerprint
        self.detected_at = detected_at
        self.subject = subject


class TrustSnapshot(db.Model):
    __tablename__ = _unique_name("trust")

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    computed_at: Mapped[str] = mapped_column(String(20), index=True)
    score: Mapped[Optional[int]]
    level: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)

    def __init__(self, target: str, computed_at: str, score: Optional[int], level: str, content: str):
        self.target = target
        self.computed_at = computed_at
        self.score = score
        self.level = level
        self.content = content


class AccountView(db.Model):
    __tablename__ = _unique_name("accounts")

    handle: Mapped[str] = mapped_column(String(32), primary_key=True)
    keys: Mapped[str] = mapped_column(Text)
    actions: Mapped[str] = mapped_column(Text)
    flags: Mapped[str] = mapped_column(Text, default="[]")
    ledger_seq: Mapped[int]
    updated_at: Mapped[str] = mapped_column(String(20))

    def __init__(self, handle: str, keys: str, actions: str, flags: str, ledger_seq: int, updated_at: str):
        self.handle = handle
        self.keys = keys
        self.actions = actions
        self.flags = flags
        self.ledger_seq = ledger_seq
        self.updated_at = updated_at
