from webfluid.core.ext import db
from sqlalchemy import select
from datetime import datetime, timedelta, UTC

from wf_peering.models.peers import Probe
from wf_peering.protocol.entries import utc_now, to_ts, parse_ts
from wf_peering.services.identity import IdentityService
from wf_peering.services.state import StateService

GAP_TOLERANCE = 180


class UptimeService:
    @staticmethod
    async def boot():
        from wf_peering.services.journal import JournalService
        previous = await StateService.get("heartbeat")
        now = utc_now()
        if not await StateService.get("first_boot"): await StateService.set("first_boot", now)
        gap = None
        if previous and previous.get("ts"):
            try:
                seconds = int((parse_ts(now) - parse_ts(previous["ts"])).total_seconds())
                if seconds > GAP_TOLERANCE: gap = { "from": previous["ts"], "to": now, "seconds": seconds }
            except ValueError: pass

        downtimes = await StateService.get("downtimes", [])
        if gap:
            downtimes = (downtimes + [gap])[-500:]
            await StateService.set("downtimes", downtimes)
        await JournalService.append("peering:node-start", {
            "boot": IdentityService.boot_id,
            "previous_boot": (previous or {}).get("boot"),
            "last_heartbeat": (previous or {}).get("ts"),
            "downtime": gap,
            "key": IdentityService.public_key()
        })
        await StateService.set("boots", ((await StateService.get("boots", [])) + [{
            "boot": IdentityService.boot_id, "started_at": IdentityService.started_at, "after_gap": gap
        }])[-200:])
        await UptimeService.beat()

    @staticmethod
    async def beat():
        await StateService.set("heartbeat", { "ts": utc_now(), "boot": IdentityService.boot_id })

    @staticmethod
    async def own() -> dict:
        downtimes = await StateService.get("downtimes", [])
        boots = await StateService.get("boots", [])
        now = datetime.now(UTC)
        report = { "boot": IdentityService.boot_id, "started_at": IdentityService.started_at,
                   "uptime_seconds": IdentityService.uptime(), "restarts": boots[-20:],
                   "downtimes": downtimes[-50:], "source": "self-reported" }
        for name, days in (("24h", 1), ("7d", 7), ("30d", 30)):
            since = now - timedelta(days=days)
            lost = 0
            for gap in downtimes:
                try: start, end = parse_ts(gap["from"]), parse_ts(gap["to"])
                except (KeyError, ValueError): continue
                if end < since: continue
                lost += (end - max(start, since)).total_seconds()
            first = await StateService.get("first_boot")
            window = (now - max(since, parse_ts(first))).total_seconds() if first else days * 86400
            report[f"ratio_{name}"] = round(100 * max(0.0, 1 - lost / window)) if window > 0 else None
        return report

    @staticmethod
    async def observed(target: str, days: int = 7) -> dict:
        since = to_ts(datetime.now(UTC) - timedelta(days=days))
        async with db.async_executor(model=Probe) as e:
            result = await e.exec(select(Probe).where(Probe.target == target, Probe.ts >= since).order_by(Probe.ts))
            rows = list(result.all())
        if not rows:
            return { "target": target, "samples": 0, "ratio": None, "outages": [], "last_ok": None,
                     "last_failure": None, "source": "local-probes" }
        ok = sum(1 for row in rows if row.ok)
        outages, start, last_bad = [], None, None
        for row in rows:
            if not row.ok:
                start = start or row.ts
                last_bad = row
            elif start:
                outages.append({ "from": start, "to": row.ts, "error": last_bad.error if last_bad else None })
                start = None
        if start: outages.append({ "from": start, "to": None, "error": last_bad.error if last_bad else None })
        latencies = sorted(row.latency_ms for row in rows if row.ok and row.latency_ms is not None)
        return {
            "target": target,
            "samples": len(rows),
            "ratio": round(100 * ok / len(rows)),
            "outages": outages[-20:],
            "outage_count": len(outages),
            "last_ok": next((row.ts for row in reversed(rows) if row.ok), None),
            "last_failure": next((row.ts for row in reversed(rows) if not row.ok), None),
            "median_latency_ms": latencies[len(latencies) // 2] if latencies else None,
            "since": since,
            "source": "local-probes"
        }
