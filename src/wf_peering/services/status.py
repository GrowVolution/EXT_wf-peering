from datetime import datetime, timedelta, UTC

from wf_peering.protocol.entries import utc_now, to_ts
from wf_peering.role import current as role
from wf_peering.services.checkpoints import CheckpointService
from wf_peering.services.conflicts import ConflictService
from wf_peering.services.identity import IdentityService
from wf_peering.services.integrity import IntegrityService
from wf_peering.services.ledger import LedgerService
from wf_peering.services.peers import PeerService
from wf_peering.services.state import StateService
from wf_peering.services.uptime import UptimeService
from wf_peering.settings import settings, PROTOCOL_VERSION, SCHEMA_VERSION


class StatusService:
    @staticmethod
    def next_at(hour: int, minute: int) -> str:
        now = datetime.now(UTC)
        moment = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if moment <= now: moment += timedelta(days=1)
        return to_ts(moment)

    @classmethod
    async def summary(cls) -> dict:
        size, value = await LedgerService.head()
        trust = None
        from wf_peering.services.trust import TrustService
        report = await TrustService.latest()
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
            "node": IdentityService.node_id(),
            "key": IdentityService.public_key(),
            "role": settings.role,
            "url": settings.origin,
            "host": settings.assessed,
            "protocol": PROTOCOL_VERSION,
            "schema": SCHEMA_VERSION,
            "debug": settings.debug,
            "now": utc_now(),
            "started_at": IdentityService.started_at,
            "uptime_seconds": IdentityService.uptime(),
            "ledger": { "size": size, "head": value },
            "checkpoint": await CheckpointService.latest(),
            "integrity": await IntegrityService.last_run(),
            "peers": { "active": await PeerService.count() },
            "conflicts": await ConflictService.counts(),
            "trust": trust,
            "schedule": {
                "sync": cls.next_at(*settings.sync_time) if settings.is_peer else None,
                "checkpoint": cls.next_at(*settings.checkpoint_time),
                "timezone": "UTC"
            },
            "self": await UptimeService.own(),
            "verification": await StateService.get("ledger_verification")
        }
        data.update(await role().status())
        return data
