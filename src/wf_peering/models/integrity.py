from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from webfluid.core.ext import db
from typing import Optional

from . import TABLE_PREFIX


def _unique_name(name: str) -> str:
    return f"{TABLE_PREFIX}{name}"


class IntegrityRun(db.Model):
    __tablename__ = _unique_name("integrity_runs")

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    started_at: Mapped[str] = mapped_column(String(20), index=True)
    finished_at: Mapped[Optional[str]] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(16))
    groups: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, id: str, started_at: str):
        self.id = id
        self.started_at = started_at
        self.status = "running"


class IntegrityRecord(db.Model):
    __tablename__ = _unique_name("integrity")

    id: Mapped[int] = mapped_column(primary_key=True)
    artifact: Mapped[str] = mapped_column(String(128), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64))
    previous: Mapped[Optional[str]] = mapped_column(String(64))
    record: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[str] = mapped_column(String(20), index=True)
    run_id: Mapped[str] = mapped_column(String(32))
    ledger_seq: Mapped[Optional[int]]
    context: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, artifact: str, provider: str, fingerprint: str, previous: Optional[str],
                 record: str, observed_at: str, run_id: str, context: Optional[str] = None):
        self.artifact = artifact
        self.provider = provider
        self.fingerprint = fingerprint
        self.previous = previous
        self.record = record
        self.observed_at = observed_at
        self.run_id = run_id
        self.context = context


class IntegrityCurrent(db.Model):
    __tablename__ = _unique_name("integrity_current")

    artifact: Mapped[str] = mapped_column(String(128), primary_key=True)
    record_id: Mapped[int]
    confirmed_at: Mapped[str] = mapped_column(String(20))
    run_id: Mapped[str] = mapped_column(String(32))
    missing_since: Mapped[Optional[str]] = mapped_column(String(20))

    def __init__(self, artifact: str, record_id: int, confirmed_at: str, run_id: str):
        self.artifact = artifact
        self.record_id = record_id
        self.confirmed_at = confirmed_at
        self.run_id = run_id


class Observation(db.Model):
    __tablename__ = _unique_name("observations")

    id: Mapped[int] = mapped_column(primary_key=True)
    artifact: Mapped[str] = mapped_column(String(128), index=True)
    ts: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(32))
    claimed_hash: Mapped[Optional[str]] = mapped_column(String(128))
    observed_hash: Mapped[Optional[str]] = mapped_column(String(128))
    reference_hash: Mapped[Optional[str]] = mapped_column(String(128))
    served_version: Mapped[Optional[str]] = mapped_column(String(64))
    latest_version: Mapped[Optional[str]] = mapped_column(String(64))
    detail: Mapped[Optional[str]] = mapped_column(Text)

    def __init__(self, artifact: str, ts: str, status: str, claimed_hash: Optional[str] = None,
                 observed_hash: Optional[str] = None, reference_hash: Optional[str] = None,
                 served_version: Optional[str] = None, latest_version: Optional[str] = None,
                 detail: Optional[str] = None):
        self.artifact = artifact
        self.ts = ts
        self.status = status
        self.claimed_hash = claimed_hash
        self.observed_hash = observed_hash
        self.reference_hash = reference_hash
        self.served_version = served_version
        self.latest_version = latest_version
        self.detail = detail
