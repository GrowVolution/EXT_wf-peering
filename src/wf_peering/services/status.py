from datetime import datetime, timedelta, UTC

from ..protocol.entries import utc_now, to_ts
from ..role import current as role
from ..settings import settings, PROTOCOL_VERSION, SCHEMA_VERSION
from .checkpoints import Checkpoints
from .identity import NodeIdentity
from .integrity import Integrity
from .ledger import Ledger
from .peers import Peers
from .store import Conflicts, State
from .uptime import Uptime


def next_at(hour: int, minute: int) -> str:
    now = datetime.now(UTC)
    moment = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if moment <= now: moment += timedelta(days=1)
    return to_ts(moment)


async def summary() -> dict:
    size, value = await Ledger.head()
    trust = None
    from .trust import Trust
    report = await Trust.latest()
    if report:
        host = report.get("host") or {}
        trust = {
            "computed_at": report.get("computed_at"),
            "score": host.get("score"), "level": host.get("level"), "status": host.get("status"),
            "basis": host.get("basis"), "completeness": host.get("completeness"),
            "perspective": host.get("perspective"), "color": host.get("color"),
            "population": report.get("population")
        }

    data = {
        "node": NodeIdentity.node_id(),
        "key": NodeIdentity.public_key(),
        "role": settings.role,
        "url": settings.origin,
        "host": settings.assessed,
        "protocol": PROTOCOL_VERSION,
        "schema": SCHEMA_VERSION,
        "debug": settings.debug,
        "now": utc_now(),
        "started_at": NodeIdentity.started_at,
        "uptime_seconds": NodeIdentity.uptime(),
        "ledger": { "size": size, "head": value },
        "checkpoint": await Checkpoints.latest(),
        "integrity": await Integrity.last_run(),
        "peers": { "active": await Peers.count() },
        "conflicts": await Conflicts.counts(),
        "trust": trust,
        "schedule": {
            "sync": next_at(*settings.sync_time) if settings.is_peer else None,
            "checkpoint": next_at(*settings.checkpoint_time),
            "timezone": "UTC"
        },
        "self": await Uptime.own(),
        "verification": await State.get("ledger_verification")
    }
    data.update(await role().status())
    return data
