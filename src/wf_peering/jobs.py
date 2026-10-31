from webfluid.utils.logging import factory as log_factory
from datetime import datetime, timedelta, UTC
import asyncio

from wf_peering.exceptions import CheckError
from wf_peering.protocol.entries import utc_now
from wf_peering.role import current as role
from wf_peering.services import StateService
from wf_peering.settings import settings, PEER_API


def guarded(name: str):
    def decorator(fn):
        async def wrapper(*args, **kwargs):
            try: return await fn(*args, **kwargs)
            except asyncio.CancelledError: raise
            except Exception as exc:
                log_factory.exception(exc, f"[peering] The {name} job failed.")
                return None
        wrapper.__name__ = f"peering_{name}"
        return wrapper
    return decorator


def schedule():
    from webfluid.core.ext import scheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.date import DateTrigger
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler.add_job(startup, DateTrigger(run_date=datetime.now(UTC) + timedelta(seconds=5)), misfire_grace_time=None)
    scheduler.add_job(heartbeat, IntervalTrigger(seconds=60))
    scheduler.add_job(probes, IntervalTrigger(seconds=settings.probe_interval))
    scheduler.add_job(trust, IntervalTrigger(seconds=settings.trust_interval))
    scheduler.add_job(verify, IntervalTrigger(hours=1))
    scheduler.add_job(activity, IntervalTrigger(hours=1))
    scheduler.add_job(retention, CronTrigger(hour=3, minute=17, timezone="UTC"))

    hour, minute = settings.checkpoint_time
    scheduler.add_job(checkpoint, CronTrigger(hour=hour, minute=minute, timezone="UTC"),
                      misfire_grace_time=3600, coalesce=True)


@guarded("startup")
async def startup():
    from wf_peering.services import UptimeService, PeerService, CheckpointService

    await UptimeService.boot()
    await PeerService.reset_connections(role().live_connections())
    await PeerService.expire()
    await CheckpointService.fill_missing()
    await role().startup()
    await probes()
    await verify()
    await trust()


@guarded("heartbeat")
async def heartbeat():
    from wf_peering.services import UptimeService
    await UptimeService.beat()
    await role().heartbeat()


@guarded("probes")
async def probes():
    from wf_peering.services import PeerService, CheckpointService
    from wf_peering.utils import netcheck

    try:
        await StateService.set("self_check", await netcheck.inspect(settings.origin))
    except Exception as exc:
        log_factory.warning(f"[peering] Inspecting the own origin failed: {exc}")

    await role().discover()

    for url in settings.peers:
        await PeerService.remember(url, "config")

    rows = [row for row in await PeerService.all(False)][:settings.max_peers]
    for row in rows:
        report = await PeerService.check_node(row.url)
        await PeerService.store_check(row.url, report, bool(report.get("ok")), report.get("error"))
        if not report.get("ok"): continue
        try:
            status, data, _ = await netcheck.get_json(row.url, f"{PEER_API}/checkpoints?limit=3", 512 * 1024)
            if status == 200 and isinstance(data, dict):
                for item in data.get("checkpoints") or []:
                    if isinstance(item, dict) and item.get("content"):
                        await CheckpointService.remember_remote(
                            { "checkpoint": item["content"], "signature": item.get("signature"),
                             "hash": item.get("hash") },
                            via="direct"
                        )
        except CheckError:
            pass
        if settings.is_peer:
            try:
                status, data, _ = await netcheck.get_json(row.url, f"{PEER_API}/peers", 512 * 1024)
                if status == 200 and isinstance(data, dict):
                    for peer in (data.get("peers") or [])[:16]:
                        url = PeerService.normalize_url(peer.get("url") or "") if isinstance(peer, dict) else None
                        if url: await PeerService.remember(url, "gossip")
            except CheckError:
                pass


@guarded("verify")
async def verify():
    from wf_peering.services import LedgerService, JournalService
    key = await LedgerService.host_key()
    report = await LedgerService.verify(key)
    journal = await JournalService.verify()
    await StateService.set("ledger_verification", dict(report, journal_problems=journal[:20],
                                                journal_valid=not journal, checked_at=utc_now()))
    if not report["valid"] or journal:
        from wf_peering.services import ConflictService
        await ConflictService.record("local-store-invalid", "critical",
                               "The stored ledger or journal failed its own verification.",
                               { "ledger": report["problems"][:20], "journal": journal[:20] },
                               subject="self", key={ "ledger": report["problems"][:3], "journal": journal[:3] })


@guarded("trust")
async def trust():
    from wf_peering.services import TrustService
    await TrustService.assess()


@guarded("checkpoint")
async def checkpoint():
    from wf_peering.services import CheckpointService
    await CheckpointService.compute()


@guarded("retention")
async def retention():
    from wf_peering.services import PeerService, TrustService
    await PeerService.prune_probes()
    await TrustService.prune()
    await PeerService.expire()
    for row in (await PeerService.inactive())[:settings.max_peers]:
        report = await PeerService.check_node(row.url)
        await PeerService.store_check(row.url, report, bool(report.get("ok")), report.get("error"))


@guarded("activity")
async def activity():
    from wf_peering.services import JournalService
    counts = Activity.drain()
    if counts: await JournalService.append("peering:activity", { "rest": counts, "until": utc_now() })


class Activity:
    counts: dict = {}

    @classmethod
    def count(cls, key: str):
        cls.counts[key] = cls.counts.get(key, 0) + 1

    @classmethod
    def drain(cls) -> dict:
        counts, cls.counts = cls.counts, {}
        return counts
