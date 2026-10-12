from webfluid.core.ext import db
from sqlalchemy import select
from datetime import datetime, timedelta, UTC
import json

from ..models.ledger import LedgerEntry
from ..models.state import Conflict, TrustSnapshot
from ..protocol import trust as score
from ..protocol.entries import utc_now, to_ts
from ..protocol.netpolicy import clusters, parse_target, PolicyError
from ..protocol.trust import Signal
from . import accounts
from .checkpoints import Checkpoints
from .identity import NodeIdentity
from .peers import Peers, serialize as serialize_peer
from .role import current as role
from .settings import settings
from .store import State, loads, dumps
from .uptime import Uptime

CONTEXT = "wf-trust-v1"
HOUR = 3600
DAY = 86400

EQUIVOCATION = ("host-equivocation", "host-history-truncated", "root-mismatch", "invalid-host-entry")


def _hostname(url: str | None) -> str | None:
    if not url: return None
    try: return parse_target(url, True, tuple(range(1, 65536))).host
    except PolicyError: return None


async def _open_conflicts(kinds: tuple, subject: str | None = None, days: int = 365) -> list:
    since = to_ts(datetime.now(UTC) - timedelta(days=days))
    async with db.async_executor(model=Conflict) as e:
        stmt = select(Conflict).where(Conflict.kind.in_(kinds), Conflict.resolved_at.is_(None),
                                      Conflict.detected_at >= since)
        if subject is not None: stmt = stmt.where(Conflict.subject == subject)
        result = await e.exec(stmt)
        return list(result.all())


def _observer(name: str, check: dict | None, url: str | None, node_key: str | None = None) -> dict:
    check = check or {}
    dns = check.get("dns") or {}
    return {
        "addresses": (dns.get("v4") or []) + (dns.get("v6") or []),
        "domain": _hostname(url),
        "cert_key": (check.get("tls") or {}).get("key"),
        "node_key": node_key
    }


async def _population() -> dict:
    rows = await Peers.all()
    host_check = await State.get("host_check") or {}
    observers = { "self": _observer("self", await State.get("self_check"), settings.origin, NodeIdentity.public_key()) }
    known = reported = reachable = verified = 0
    peers = []
    for row in rows:
        data = serialize_peer(row)
        if data["status"] != "active": continue
        known += 1
        if "host-reported" in data["sources"]: reported += 1
        check = data.get("check") or {}
        if check.get("ok"): reachable += 1
        good = check.get("ok") and check.get("identity") == "verified" and \
            (check.get("comparison") or {}).get("status") in ("match", "behind", "ahead", "empty")
        if good:
            verified += 1
            observers[data["url"]] = _observer(data["url"], check, data["url"], data.get("key"))
        peers.append(data)

    observers["@host"] = _observer("@host", host_check, settings.assessed)
    groups = clusters(observers)
    host_group = next((group for group in groups if "@host" in group), ["@host"])
    independent = [group for group in groups if "@host" not in group]
    largest = max((len(group) for group in independent), default=0)
    return {
        "known": known, "reported": reported, "reachable": reachable, "verified": verified,
        "clusters": groups, "independent": len(independent), "host_cluster": host_group,
        "largest_cluster": largest, "observers": len(observers) - 1, "peers": peers
    }


def _ratio_signal(name: str, category: str, data: dict | None, weight: int, severity="normal",
                  max_age: int | None = None) -> Signal:
    if not data or data.get("ratio") is None or not data.get("samples"):
        return Signal(name, category, None, weight, severity, "local", None, max_age)
    return Signal(name, category, data["ratio"], weight, severity, "local", data.get("last_ok") or data.get("last_failure"),
                  max_age, detail={ "samples": data["samples"], "outages": data.get("outage_count", 0) })


async def host_signals() -> tuple[list[Signal], dict]:
    population = await _population()
    signals: list[Signal] = []
    now = datetime.now(UTC)
    target = settings.assessed
    check = await State.get("host_check") or {}
    checked_at = check.get("checked_at")

    tls = check.get("tls") or {}
    if settings.is_host:
        signals.append(Signal("self_assessment", "integrity", 50, 5, "normal", "local",
                              utc_now(), detail={ "note": "A host cannot vouch for itself; compare with peers." }))
    if check:
        if (target or "").startswith("https://") and not settings.debug:
            signals.append(Signal("tls_valid", "reachability", 100 if tls.get("ok") else 0, 15, "high", "local",
                                  checked_at, 2 * DAY, cap=50, detail={ k: tls.get(k) for k in ("error", "issuer", "not_after") }))
            if tls.get("ok"):
                days = tls.get("days_left") or 0
                signals.append(Signal("cert_expiry_margin", "reachability", 100 if days > 14 else (60 if days > 3 else 20),
                                      5, "normal", "local", checked_at, 2 * DAY, detail={ "days_left": days }))
        elif not settings.debug:
            signals.append(Signal("https", "reachability", 0, 15, "high", "local", checked_at, 2 * DAY, cap=50))
        signals.append(Signal("endpoint_reachable", "reachability", 100 if check.get("ok") else 0, 10, "normal",
                              "local", checked_at, 2 * HOUR, detail={ "error": check.get("error") }))
        if settings.is_peer:
            identity = check.get("identity")
            signals.append(Signal("host_identity", "keys", 100 if identity == "verified" else 0, 10, "high",
                                  "local", checked_at, DAY, detail={ "identity": identity }))
    else:
        signals.append(Signal("endpoint_reachable", "reachability", None, 10, "normal", "local", None, 2 * HOUR))

    observed = await Uptime.observed(target, 1)
    signals.append(_ratio_signal("uptime_24h", "reachability", observed, 10, max_age=2 * HOUR))
    week = await Uptime.observed(target, 7)
    signals.append(_ratio_signal("uptime_7d", "reachability", week, 5, max_age=2 * DAY))

    signals.extend(await role().signals(now))

    verification = await State.get("ledger_verification") or {}
    if verification:
        signals.append(Signal("local_copy_valid", "integrity", 100 if verification.get("valid") else 0, 20,
                              "critical", "local", verification.get("checked_at"), 2 * DAY, cap=10,
                              detail={ "size": verification.get("size"), "problems": verification.get("problems", [])[:5] }))

    latest = await Checkpoints.latest()
    if latest:
        status = latest["status"]
        value = { "verified": 100, "overlap": 50, "stale": 30, "missing": 20, "failed": 0 }.get(status, 0)
        signals.append(Signal("checkpoint_status", "integrity", value, 10, "high", "local", latest["computed_at"],
                              2 * DAY, detail={ "day": latest["day"], "status": status }))

    agreement = await Checkpoints.agreement()
    nodes = [node for node in agreement.get("nodes") or [] if node["verdict"] != "ahead-unverified"]
    if nodes:
        good = sum(1 for node in nodes if node["verdict"] in ("match", "consistent-prefix"))
        bad = len(nodes) - good
        signals.append(Signal("root_agreement", "integrity", round(100 * good / len(nodes)), 20,
                              "critical" if bad else "normal", "peer", utc_now(), 2 * DAY,
                              cap=25 if bad and good == 0 else None,
                              detail={ "agree": good, "diverged": bad, "day": agreement.get("day") }))
    else:
        signals.append(Signal("root_agreement", "integrity", None, 20, "normal", "peer"))

    proofs = await _open_conflicts(EQUIVOCATION, "host")
    signals.append(Signal("equivocation_free", "integrity", 0 if proofs else 100, 20, "critical", "local", utc_now(),
                          None, cap=5, detail={ "proofs": [row.kind for row in proofs][:10] }))

    key_changes = await _open_conflicts(("host-key-changed",), "host")
    if settings.is_peer:
        signals.append(Signal("host_key_stable", "keys", 0 if key_changes else 100, 15, "critical", "local", utc_now(),
                              None, cap=30, detail={ "changes": len(key_changes) }))

    flagged = await accounts.flagged_counts()
    signals.append(Signal("keylog_and_actions_valid", "keys", 0 if flagged["critical"] else 100, 20, "critical", "local",
                          utc_now(), None, cap=15, detail=flagged))
    signals.append(Signal("host_asserted_key_changes", "keys",
                          max(0, 100 - 20 * flagged["host_asserted"]), 5, "normal", "local", utc_now(),
                          detail={ "count": flagged["host_asserted"] }))

    from .integrity import Integrity
    for group in await Integrity.current():
        for item in group["records"]:
            artifact = item["record"]["id"]
            seen = await role().observation(artifact)
            if not seen:
                continue
            status = seen.get("status")
            mapping = {
                "verified": (100, "normal", None), "outdated": (40, "high", 60),
                "served-mismatch": (0, "critical", 20), "reference-mismatch": (0, "critical", 20),
                "unreferenced": (70, "normal", None), "unreachable": (None, "normal", None),
                "not-served": (None, "normal", None)
            }
            value, severity, cap = mapping.get(status, (None, "normal", None))
            signals.append(Signal(f"artifact:{artifact}", "integrity", value, 10, severity, "local", seen.get("ts"),
                                  2 * DAY, cap, detail={ k: seen.get(k) for k in ("status", "served_version", "latest_version", "observed", "claimed") }))

    changes = await _integrity_changes(30)
    unexplained = [change for change in changes if not change["after_restart"]]
    if changes:
        signals.append(Signal("hash_changes_in_stable_periods", "history", max(0, 100 - 20 * len(unexplained)), 10,
                              "normal", "local", changes[-1]["ts"], None,
                              detail={ "changes": len(changes), "without_restart": len(unexplained) }))

    others = await _open_conflicts(("sync-failed", "invalid-checkpoint", "checkpoint-equivocation",
                                    "artifact-outdated", "peer-key-changed"), None, 30)
    signals.append(Signal("open_conflicts", "history", max(0, 100 - 10 * len(others)), 5, "normal", "local", utc_now(),
                          detail={ "count": len(others) }))

    signals.append(Signal("independent_observers", "diversity", min(100, 34 * population["independent"]), 15,
                          "high", "derived", utc_now(), detail={ "independent": population["independent"],
                                                                 "clusters": len(population["clusters"]) }))
    if population["verified"]:
        overlap = len([name for name in population["host_cluster"] if name not in ("@host",)])
        signals.append(Signal("peer_host_overlap", "diversity", max(0, 100 - 50 * overlap), 10, "high", "derived",
                              utc_now(), detail={ "sharing_infrastructure_with_host": overlap }))
        share = population["largest_cluster"] / max(1, population["verified"] + 1)
        signals.append(Signal("sybil_concentration", "diversity", round(100 * (1 - share)) if population["verified"] > 1 else None,
                              10, "normal", "derived", utc_now(), detail={ "largest_cluster": population["largest_cluster"] }))
    return signals, population


async def _integrity_changes(days: int) -> list[dict]:
    since = to_ts(datetime.now(UTC) - timedelta(days=days))
    async with db.async_executor(model=LedgerEntry) as e:
        result = await e.exec(select(LedgerEntry.content).where(
            LedgerEntry.kind == "peering:integrity", LedgerEntry.ts >= since
        ).order_by(LedgerEntry.seq))
        changes = []
        for text in result.all():
            content = json.loads(text)
            body = content.get("body") or {}
            if not body.get("previous"): continue
            context = body.get("context") or {}
            changes.append({ "ts": content["ts"], "artifact": body.get("artifact"),
                             "after_restart": (context.get("uptime") or 0) < 900 })
        return changes


async def peer_signals(peer: dict, population: dict) -> list[Signal]:
    check = peer.get("check") or {}
    checked_at = check.get("checked_at")
    signals = []
    tls = check.get("tls") or {}
    if check:
        if peer["url"].startswith("https://") and not settings.debug:
            signals.append(Signal("tls_valid", "reachability", 100 if tls.get("ok") else 0, 15, "high", "local",
                                  checked_at, 2 * DAY, cap=50, detail={ "error": tls.get("error") }))
        elif not settings.debug:
            signals.append(Signal("https", "reachability", 0, 15, "high", "local", checked_at, 2 * DAY, cap=50))
        signals.append(Signal("identity_verified", "keys", 100 if check.get("identity") == "verified" else 0, 20,
                              "critical", "local", checked_at, 2 * DAY, cap=20, detail={ "identity": check.get("identity") }))
        comparison = (check.get("comparison") or {}).get("status")
        mapping = { "match": 100, "behind": 80, "ahead": 70, "empty": 60, "diverged": 0, "unknown": None }
        signals.append(Signal("ledger_consistency", "integrity", mapping.get(comparison), 25,
                              "critical" if comparison == "diverged" else "normal", "local", checked_at, 2 * DAY,
                              cap=15 if comparison == "diverged" else None, detail={ "comparison": comparison }))
    else:
        signals.append(Signal("identity_verified", "keys", None, 20, "critical"))
    observed = await Uptime.observed(peer["url"], 7)
    signals.append(_ratio_signal("uptime_7d", "reachability", observed, 10, max_age=2 * DAY))
    if peer.get("connected") is not None and settings.is_host:
        signals.append(Signal("connected", "reachability", 100 if peer.get("connected") else 30, 5, "normal", "local",
                              peer.get("last_heartbeat_at")))
    key_changes = await _open_conflicts(("peer-key-changed",), peer["url"])
    signals.append(Signal("key_stable", "keys", 0 if key_changes else 100, 10, "high", "local", utc_now()))

    group = next((g for g in population["clusters"] if peer["url"] in g), None)
    if group is not None:
        shares_host = "@host" in group
        signals.append(Signal("independent_from_host", "diversity", 0 if shares_host else 100, 15, "high", "derived",
                              utc_now(), detail={ "cluster": group }))
        signals.append(Signal("cluster_size", "diversity", max(0, 100 - 25 * (len(group) - 1)), 10, "normal", "derived",
                              utc_now(), detail={ "size": len(group) }))
    return signals


class Trust:
    @staticmethod
    def sign(report: dict) -> dict:
        envelope = { "node": NodeIdentity.node_id(), "key": NodeIdentity.public_key(), "report": report }
        return { **envelope, "signature": NodeIdentity.sign(CONTEXT, envelope) }

    @classmethod
    async def assess(cls) -> dict:
        signals, population = await host_signals()
        host = score.compute(signals, population["independent"])
        host["target"] = settings.assessed
        host["perspective"] = "peer" if settings.is_peer else "self"
        peers = []
        for peer in population["peers"]:
            assessment = score.compute(await peer_signals(peer, population), 1)
            assessment["target"] = peer["url"]
            assessment["node"] = peer.get("node")
            assessment["sources"] = peer.get("sources")
            peers.append(assessment)
        report = {
            "computed_at": utc_now(),
            "role": settings.role,
            "debug": settings.debug,
            "host": host,
            "peers": peers,
            "population": { key: population[key] for key in
                            ("known", "reported", "reachable", "verified", "independent", "observers", "largest_cluster") },
            "clusters": population["clusters"]
        }
        async with db.async_executor(model=TrustSnapshot) as e:
            await e.insert(TrustSnapshot(host["target"], report["computed_at"], host["score"], host["level"], dumps(report)))
        return report

    @staticmethod
    async def latest() -> dict | None:
        async with db.async_executor(model=TrustSnapshot) as e:
            result = await e.exec(select(TrustSnapshot).order_by(TrustSnapshot.id.desc()).limit(1))
            row = result.first()
            return loads(row.content) if row else None

    @staticmethod
    async def history(limit: int = 48) -> list[dict]:
        async with db.async_executor(model=TrustSnapshot) as e:
            result = await e.exec(select(TrustSnapshot).order_by(TrustSnapshot.id.desc()).limit(limit))
            return [{ "computed_at": row.computed_at, "score": row.score, "level": row.level, "target": row.target }
                    for row in result.all()]

    @staticmethod
    async def prune(days: int = 30):
        from sqlalchemy import delete
        since = to_ts(datetime.now(UTC) - timedelta(days=days))
        async with db.async_executor(model=TrustSnapshot) as e:
            await e.exec(delete(TrustSnapshot).where(TrustSnapshot.computed_at < since), scalars=False)
