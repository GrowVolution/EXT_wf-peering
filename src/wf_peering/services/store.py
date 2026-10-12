from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select, func
import json

from ..models.state import NodeState, Conflict
from ..protocol.canonical import digest
from ..protocol.entries import utc_now


def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def loads(value, default=None):
    if value is None: return default
    try: return json.loads(value)
    except (TypeError, ValueError): return default


class State:
    @staticmethod
    async def get(key: str, default=None):
        async with db.async_executor(model=NodeState) as e:
            result = await e.exec(select(NodeState).where(NodeState.key == key))
            row = result.first()
            return loads(row.value, default) if row else default

    @staticmethod
    async def set(key: str, value):
        async with db.async_executor(model=NodeState) as e:
            result = await e.exec(select(NodeState).where(NodeState.key == key))
            row = result.first()
            if row: row.value = dumps(value)
            else: await e.insert(NodeState(key, dumps(value)))


class Conflicts:
    @staticmethod
    def _signal(data: dict):
        from .role import current
        try: current().alert(data)
        except Exception as exc: log_factory.exception(exc, "[peering] Forwarding a conflict alert failed.")

    @classmethod
    async def record(cls, kind: str, severity: str, summary: str, evidence: dict,
                     subject: str | None = None, key=None) -> bool:
        fingerprint = digest({ "kind": kind, "subject": subject, "key": key if key is not None else evidence })
        async with db.async_executor(model=Conflict) as e:
            result = await e.exec(select(Conflict).where(Conflict.fingerprint == fingerprint))
            if result.first(): return False
            await e.insert(Conflict(
                kind=kind, severity=severity, summary=summary[:512], evidence=dumps(evidence),
                fingerprint=fingerprint, detected_at=utc_now(), subject=subject
            ))

        log_factory.warning(f"[peering] {severity.upper()} {kind}: {summary}")
        from .journal import Journal
        await Journal.append("peering:conflict", {
            "kind": kind, "severity": severity, "subject": subject,
            "summary": summary[:512], "fingerprint": fingerprint
        })
        cls._signal({ "kind": kind, "severity": severity, "subject": subject, "summary": summary[:512] })
        return True

    @staticmethod
    async def resolve(kind: str, subject: str | None = None):
        async with db.async_executor(model=Conflict) as e:
            stmt = select(Conflict).where(Conflict.kind == kind, Conflict.resolved_at.is_(None))
            if subject is not None: stmt = stmt.where(Conflict.subject == subject)
            result = await e.exec(stmt)
            for row in result.all(): row.resolved_at = utc_now()

    @staticmethod
    async def open(limit: int = 200) -> list[dict]:
        async with db.async_executor(model=Conflict) as e:
            result = await e.exec(select(Conflict).order_by(Conflict.id.desc()).limit(limit))
            return [_conflict(row) for row in result.all()]

    @staticmethod
    async def counts() -> dict:
        async with db.async_executor(model=Conflict) as e:
            result = await e.exec(select(Conflict.severity, func.count(Conflict.id)).where(
                Conflict.resolved_at.is_(None)
            ).group_by(Conflict.severity), scalars=False)
            return { severity: count for severity, count in result.all() }


def _conflict(row: Conflict) -> dict:
    return {
        "id": row.id,
        "kind": row.kind,
        "severity": row.severity,
        "subject": row.subject,
        "summary": row.summary,
        "evidence": loads(row.evidence, {}),
        "detected_at": row.detected_at,
        "resolved_at": row.resolved_at
    }
