from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select
import asyncio, json

from ..models.integrity import IntegrityRun, IntegrityRecord, IntegrityCurrent, Observation
from ..protocol import integrity as spec
from ..protocol.canonical import canonical_text
from ..protocol.entries import utc_now
from .identity import NodeIdentity
from .store import dumps, loads

PUSH = "push:"


class Integrity:
    _lock: asyncio.Lock | None = None

    @classmethod
    def guard(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @staticmethod
    def pushed(run_id: str | None) -> bool:
        return (run_id or "").startswith(PUSH)

    @staticmethod
    def push_id(token: str) -> str:
        return f"{PUSH}{token}"[:32]

    @staticmethod
    async def start_run(run_id: str, started: str):
        async with db.async_executor(model=IntegrityRun) as e:
            await e.insert(IntegrityRun(run_id, started))

    @staticmethod
    async def finish_run(run_id: str, status: str, summary: list):
        async with db.async_executor(model=IntegrityRun) as e:
            result = await e.exec(select(IntegrityRun).where(IntegrityRun.id == run_id))
            row = result.first()
            row.finished_at = utc_now()
            row.status = status
            row.groups = dumps(summary)

    @staticmethod
    async def persist(provider: str, record: dict, run_id: str) -> dict | None:
        fingerprint = spec.fingerprint(record)
        now = utc_now()
        context = {
            "boot": NodeIdentity.boot_id,
            "uptime": NodeIdentity.uptime(),
            "started_at": NodeIdentity.started_at
        }
        async with db.async_executor(model=IntegrityRecord) as e:
            result = await e.exec(select(IntegrityCurrent).where(IntegrityCurrent.artifact == record["id"]))
            current = result.first()
            previous = None
            if current:
                result = await e.exec(select(IntegrityRecord).where(IntegrityRecord.id == current.record_id))
                previous = result.first()
                if previous and previous.fingerprint == fingerprint:
                    current.confirmed_at = now
                    current.run_id = run_id
                    current.missing_since = None
                    return None

            row = await e.insert(IntegrityRecord(
                artifact=record["id"], provider=provider, fingerprint=fingerprint,
                previous=previous.fingerprint if previous else None,
                record=canonical_text(record), observed_at=now, run_id=run_id, context=dumps(context)
            ), True)
            if current:
                current.record_id = row.id
                current.confirmed_at = now
                current.run_id = run_id
                current.missing_since = None
            else:
                await e.insert(IntegrityCurrent(record["id"], row.id, now, run_id))
            return {
                "id": row.id, "artifact": record["id"], "provider": provider, "record": record,
                "fingerprint": fingerprint, "previous": row.previous, "run": run_id, "context": context
            }

    @staticmethod
    async def mark_missing(groups: list, run_id: str) -> list[str]:
        seen = { record["id"] for group in groups for record in group["records"] }
        failed = { group["provider"] for group in groups if group["status"] in ("failed", "invalid") }
        if any(provider.startswith("unknown-") for provider in failed): return []
        missing = []
        async with db.async_executor(model=IntegrityCurrent) as e:
            result = await e.exec(select(IntegrityCurrent, IntegrityRecord).join(
                IntegrityRecord, IntegrityRecord.id == IntegrityCurrent.record_id
            ), scalars=False)
            for current, record in result.all():
                if current.artifact in seen or current.missing_since: continue
                if record.provider in failed or Integrity.pushed(current.run_id): continue
                current.missing_since = utc_now()
                missing.append(current.artifact)
        return missing

    @staticmethod
    async def retract(provider: str, artifact: str) -> bool:
        async with db.async_executor(model=IntegrityCurrent) as e:
            result = await e.exec(select(IntegrityCurrent, IntegrityRecord).join(
                IntegrityRecord, IntegrityRecord.id == IntegrityCurrent.record_id
            ).where(IntegrityCurrent.artifact == artifact), scalars=False)
            row = result.first()
            if not row: return False
            current, record = row
            if current.missing_since or record.provider != provider: return False
            current.missing_since = utc_now()
            return True

    @staticmethod
    async def link(record_id: int, seq: int):
        async with db.async_executor(model=IntegrityRecord) as e:
            result = await e.exec(select(IntegrityRecord).where(IntegrityRecord.id == record_id))
            row = result.first()
            if row: row.ledger_seq = seq

    @staticmethod
    async def apply_replicated(content: dict):
        body = content.get("body") or {}
        kind = content.get("kind")
        if kind == "peering:integrity-missing":
            async with db.async_executor(model=IntegrityCurrent) as e:
                result = await e.exec(select(IntegrityCurrent).where(IntegrityCurrent.artifact == body.get("artifact")))
                current = result.first()
                if current: current.missing_since = content["ts"]
            return
        if kind != "peering:integrity": return
        try: record = spec.normalize(body.get("record"), body.get("provider"))
        except spec.IntegrityError as exc:
            log_factory.warning(f"[peering] Replicated integrity entry {content.get('seq')} is invalid: {exc}")
            return
        async with db.async_executor(model=IntegrityRecord) as e:
            row = await e.insert(IntegrityRecord(
                artifact=record["id"], provider=body.get("provider") or record.get("additive") or "unknown",
                fingerprint=spec.fingerprint(record), previous=body.get("previous"),
                record=canonical_text(record), observed_at=content["ts"], run_id=str(body.get("run") or "")[:32],
                context=dumps(body.get("context") or {})
            ), True)
            row.ledger_seq = content["seq"]
            result = await e.exec(select(IntegrityCurrent).where(IntegrityCurrent.artifact == record["id"]))
            current = result.first()
            if current:
                current.record_id = row.id
                current.confirmed_at = content["ts"]
                current.run_id = row.run_id
                current.missing_since = None
            else:
                await e.insert(IntegrityCurrent(record["id"], row.id, content["ts"], row.run_id))

    @staticmethod
    def _serialize(record: IntegrityRecord, current: IntegrityCurrent | None = None) -> dict:
        data = {
            "record": json.loads(record.record),
            "provider": record.provider,
            "fingerprint": record.fingerprint,
            "previous": record.previous,
            "observed_at": record.observed_at,
            "ledger_seq": record.ledger_seq,
            "context": loads(record.context, {})
        }
        if current is not None:
            data["confirmed_at"] = current.confirmed_at
            data["missing_since"] = current.missing_since
        return data

    @classmethod
    async def current(cls) -> list[dict]:
        from sqlalchemy import func
        groups: dict[str, list] = {}
        async with db.async_executor(model=IntegrityCurrent) as e:
            result = await e.exec(select(IntegrityRecord.artifact, func.count(IntegrityRecord.id))
                                  .group_by(IntegrityRecord.artifact), scalars=False)
            lengths = { artifact: count for artifact, count in result.all() }
            result = await e.exec(select(IntegrityCurrent, IntegrityRecord).join(
                IntegrityRecord, IntegrityRecord.id == IntegrityCurrent.record_id
            ).order_by(IntegrityCurrent.artifact), scalars=False)
            for current, record in result.all():
                item = cls._serialize(record, current)
                item["chain_length"] = lengths.get(record.artifact, 1)
                groups.setdefault(record.provider, []).append(item)
        return [{ "provider": provider, "records": records } for provider, records in sorted(groups.items())]

    @classmethod
    async def latest(cls, artifact: str) -> dict | None:
        async with db.async_executor(model=IntegrityCurrent) as e:
            result = await e.exec(select(IntegrityCurrent, IntegrityRecord).join(
                IntegrityRecord, IntegrityRecord.id == IntegrityCurrent.record_id
            ).where(IntegrityCurrent.artifact == artifact), scalars=False)
            row = result.first()
            if not row: return None
            current, record = row
            data = cls._serialize(record, current)
            from sqlalchemy import func
            result = await e.exec(select(func.count(IntegrityRecord.id)).where(
                IntegrityRecord.artifact == artifact
            ), scalars=False)
            data["chain_length"] = result.scalar() or 0
            return data

    @classmethod
    async def history(cls, artifact: str, limit: int = 100) -> list[dict]:
        async with db.async_executor(model=IntegrityRecord) as e:
            result = await e.exec(select(IntegrityRecord).where(
                IntegrityRecord.artifact == artifact
            ).order_by(IntegrityRecord.id.desc()).limit(limit))
            return [cls._serialize(row) for row in result.all()]

    @staticmethod
    async def last_run() -> dict | None:
        async with db.async_executor(model=IntegrityRun) as e:
            result = await e.exec(select(IntegrityRun).order_by(IntegrityRun.started_at.desc()).limit(1))
            row = result.first()
            if not row: return None
            return { "run": row.id, "started_at": row.started_at, "finished_at": row.finished_at,
                     "status": row.status, "groups": loads(row.groups, []) }

    @staticmethod
    async def observations(artifact: str | None = None, limit: int = 50) -> list[dict]:
        async with db.async_executor(model=Observation) as e:
            stmt = select(Observation)
            if artifact: stmt = stmt.where(Observation.artifact == artifact)
            result = await e.exec(stmt.order_by(Observation.id.desc()).limit(limit))
            return [{
                "artifact": row.artifact, "ts": row.ts, "status": row.status,
                "claimed_hash": row.claimed_hash, "observed_hash": row.observed_hash,
                "reference_hash": row.reference_hash, "served_version": row.served_version,
                "latest_version": row.latest_version, "detail": loads(row.detail, {})
            } for row in result.all()]
