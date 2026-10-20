from webfluid.utils.logging import factory as log_factory
from datetime import datetime, timedelta, UTC
import asyncio

from .protocol.entries import utc_now
from .role import current as role
from .services.store import State
from .settings import settings, PEER_API


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


@guarded("startup")
async def startup():
    from .services.uptime import Uptime
    from .services.peers import Peers
    from .services.checkpoints import Checkpoints

    await Uptime.boot()
    await Peers.reset_connections(role().live_connections())
    await Peers.expire()
    await Checkpoints.fill_missing()
    await role().startup()
    await probes()
    await verify()
    await trust()


@guarded("heartbeat")
async def heartbeat():
    from .services.uptime import Uptime
    await Uptime.beat()
    await role().heartbeat()


@guarded("probes")
async def probes():
    from .services.peers import Peers, check_node, normalize_url
    from .utils import netcheck
    from .services.checkpoints import Checkpoints

    try:
        await State.set("self_check", await netcheck.inspect(settings.origin))
    except Exception as exc:
        log_factory.warning(f"[peering] Inspecting the own origin failed: {exc}")

    await role().discover()

    for url in settings.peers:
        await Peers.remember(url, "config")

    rows = [row for row in await Peers.all(False)][:settings.max_peers]
    for row in rows:
        report = await check_node(row.url)
        await Peers.store_check(row.url, report, bool(report.get("ok")), report.get("error"))
        if not report.get("ok"): continue
        try:
            status, data, _ = await netcheck.get_json(row.url, f"{PEER_API}/checkpoints?limit=3", 512 * 1024)
            if status == 200 and isinstance(data, dict):
                for item in data.get("checkpoints") or []:
                    if isinstance(item, dict) and item.get("content"):
                        await Checkpoints.remember_remote(
                            { "checkpoint": item["content"], "signature": item.get("signature"), "hash": item.get("hash") },
                            via="direct"
                        )
        except netcheck.CheckError:
            pass
        if settings.is_peer:
            try:
                status, data, _ = await netcheck.get_json(row.url, f"{PEER_API}/peers", 512 * 1024)
                if status == 200 and isinstance(data, dict):
                    for peer in (data.get("peers") or [])[:16]:
                        url = normalize_url(peer.get("url") or "") if isinstance(peer, dict) else None
                        if url: await Peers.remember(url, "gossip")
            except netcheck.CheckError:
                pass


@guarded("verify")
async def verify():
    from .services.ledger import Ledger
    from .services.journal import Journal
    key = await Ledger.host_key()
    report = await Ledger.verify(key)
    journal = await Journal.verify()
    await State.set("ledger_verification", dict(report, journal_problems=journal[:20],
                                                journal_valid=not journal, checked_at=utc_now()))
    if not report["valid"] or journal:
        from .services.store import Conflicts
        await Conflicts.record("local-store-invalid", "critical",
                               "The stored ledger or journal failed its own verification.",
                               { "ledger": report["problems"][:20], "journal": journal[:20] },
                               subject="self", key={ "ledger": report["problems"][:3], "journal": journal[:3] })


@guarded("trust")
async def trust():
    from .services.trust import Trust
    await Trust.assess()


@guarded("checkpoint")
async def checkpoint():
    from .services.checkpoints import Checkpoints
    await Checkpoints.compute()


@guarded("retention")
async def retention():
    from .services.peers import Peers, check_node
    from .services.trust import Trust
    await Peers.prune_probes()
    await Trust.prune()
    await Peers.expire()
    for row in (await Peers.inactive())[:settings.max_peers]:
        report = await check_node(row.url)
        await Peers.store_check(row.url, report, bool(report.get("ok")), report.get("error"))


class Activity:
    counts: dict = {}

    @classmethod
    def count(cls, key: str):
        cls.counts[key] = cls.counts.get(key, 0) + 1

    @classmethod
    def drain(cls) -> dict:
        counts, cls.counts = cls.counts, {}
        return counts


@guarded("activity")
async def activity():
    from .services.journal import Journal
    counts = Activity.drain()
    if counts: await Journal.append("peering:activity", { "rest": counts, "until": utc_now() })


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
