from webfluid.core.ext import db
from sqlalchemy import select, func
from datetime import datetime, timedelta, UTC

from ..models.peers import Peer, PeerConnection, Probe
from ..protocol.entries import utc_now, to_ts
from ..protocol.netpolicy import PolicyError, parse_target
from ..protocol.signing import verify, fingerprint, valid_ed25519
from . import netcheck
from .identity import NODE_CONTEXT
from .settings import settings
from .store import dumps, loads, Conflicts

SOURCES = ("connected", "host-reported", "config", "gossip", "self")


def normalize_url(url: str) -> str | None:
    try:
        where = parse_target(url, settings.allow_insecure, (443,) if not settings.allow_insecure else (443, 80))
    except PolicyError: return None
    return where.origin


def serialize(row: Peer) -> dict:
    return {
        "node": row.node_id,
        "key": row.public_key,
        "url": row.url,
        "sources": loads(row.sources, []),
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "connected": row.connected,
        "last_connected_at": row.last_connected_at,
        "last_disconnected_at": row.last_disconnected_at,
        "last_heartbeat_at": row.last_heartbeat_at,
        "head": { "seq": row.head_seq, "hash": row.head_hash } if row.head_seq is not None else None,
        "status": row.status,
        "failures": row.failures,
        "last_error": row.last_error,
        "key_changed_at": row.key_changed_at,
        "check": loads(row.check)
    }


class Peers:
    @staticmethod
    async def all(include_inactive: bool = True) -> list[Peer]:
        async with db.async_executor(model=Peer) as e:
            stmt = select(Peer).order_by(Peer.id)
            if not include_inactive: stmt = stmt.where(Peer.status == "active")
            result = await e.exec(stmt)
            return list(result.all())

    @staticmethod
    async def count() -> int:
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(func.count(Peer.id)).where(Peer.status == "active"), scalars=False)
            return result.scalar() or 0

    @staticmethod
    async def inactive() -> list[Peer]:
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(Peer).where(Peer.status == "inactive").order_by(Peer.id))
            return list(result.all())

    @staticmethod
    async def expire() -> list[str]:
        if settings.peer_inactive_days <= 0: return []
        since = to_ts(datetime.now(UTC) - timedelta(days=settings.peer_inactive_days))
        expired = []
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(Peer).where(Peer.status == "active", Peer.connected.is_(False)))
            for row in result.all():
                if (row.last_seen or row.first_seen) < since:
                    row.status = "inactive"
                    expired.append(row.url)
        if expired:
            from .journal import Journal
            await Journal.append("peering:peers-inactive", { "peers": expired, "days": settings.peer_inactive_days })
        return expired

    @classmethod
    async def remember(cls, url: str, source: str, node_id: str | None = None,
                       public_key: str | None = None) -> Peer | None:
        url = normalize_url(url)
        if url is None or url in (settings.origin, settings.host): return None
        now = utc_now()
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(Peer).where(Peer.url == url))
            row = result.first()
            if row is None:
                result = await e.exec(select(func.count(Peer.id)), scalars=False)
                if (result.scalar() or 0) >= settings.max_peers * 2: return None
                row = await e.insert(Peer(url, now, dumps([source]), node_id, public_key), True)
            else:
                sources = loads(row.sources, [])
                if source not in sources:
                    sources.append(source)
                    row.sources = dumps(sorted(sources))
            if source == "connected":
                row.last_seen = now
                row.status = "active"
            return row

    @staticmethod
    async def registrations_last_hour() -> int:
        since = to_ts(datetime.now(UTC) - timedelta(hours=1))
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(func.count(Peer.id)).where(Peer.first_seen >= since), scalars=False)
            return result.scalar() or 0

    @classmethod
    async def authenticated(cls, node_id: str, public_key: str, url: str, address: str | None) -> tuple[str | None, int | None]:
        url = normalize_url(url)
        if url is None: return "INVALID_URL", None
        now = utc_now()
        pending = []
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(Peer).where(Peer.node_id == node_id))
            by_node = result.first()
            result = await e.exec(select(Peer).where(Peer.url == url))
            by_url = result.first()

            if by_node is None and by_url is None:
                result = await e.exec(select(func.count(Peer.id)).where(Peer.status == "active"), scalars=False)
                if (result.scalar() or 0) >= settings.max_peers: return "TOO_MANY_PEERS", None
                since = to_ts(datetime.now(UTC) - timedelta(hours=1))
                result = await e.exec(select(func.count(Peer.id)).where(Peer.first_seen >= since), scalars=False)
                if (result.scalar() or 0) >= settings.registrations_per_hour: return "REGISTRATION_RATE", None
                row = await e.insert(Peer(url, now, dumps(["connected"]), node_id, public_key), True)
            else:
                row = by_node or by_url
                if by_node and by_url and by_node.id != by_url.id:
                    return "URL_CLAIMED_BY_OTHER_NODE", None
                if row.public_key and row.public_key != public_key:
                    row.key_changed_at = now
                    pending.append((row.url, row.public_key))
                if row.url != url:
                    row.url = url
                row.node_id = node_id
                row.public_key = public_key
                sources = loads(row.sources, [])
                if "connected" not in sources: row.sources = dumps(sorted(sources + ["connected"]))
                if row.status == "inactive": row.status = "active"

            row.connected = True
            row.last_seen = now
            row.last_connected_at = now
            row.last_heartbeat_at = now
            connection = await e.insert(PeerConnection(now, address), True)
            connection.node_id = node_id
            connection.authenticated = True
            connection_id = connection.id
        for old_url, old_key in pending:
            await Conflicts.record(
                "peer-key-changed", "high", f"The peer at {old_url} presented a different node key.",
                { "url": old_url, "old": old_key, "new": public_key }, subject=old_url
            )
        return None, connection_id

    @staticmethod
    async def heartbeat(node_id: str, head_seq: int | None, head_hash: str | None):
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(Peer).where(Peer.node_id == node_id))
            row = result.first()
            if not row: return
            row.connected = True
            row.status = "active"
            row.last_heartbeat_at = utc_now()
            row.last_seen = row.last_heartbeat_at
            if isinstance(head_seq, int) and isinstance(head_hash, str) and len(head_hash) == 64:
                row.head_seq = head_seq
                row.head_hash = head_hash

    @staticmethod
    async def disconnected(node_id: str | None, connection_id: int | None, reason: str, still_connected: bool = False):
        now = utc_now()
        async with db.async_executor(model=Peer) as e:
            if node_id and not still_connected:
                result = await e.exec(select(Peer).where(Peer.node_id == node_id))
                row = result.first()
                if row:
                    row.connected = False
                    row.last_disconnected_at = now
            if connection_id:
                result = await e.exec(select(PeerConnection).where(PeerConnection.id == connection_id))
                connection = result.first()
                if connection:
                    connection.closed_at = now
                    connection.reason = reason[:128]

    @staticmethod
    async def rejected(address: str | None, reason: str):
        now = utc_now()
        async with db.async_executor(model=PeerConnection) as e:
            connection = await e.insert(PeerConnection(now, address), True)
            connection.closed_at = now
            connection.reason = reason[:128]

    @staticmethod
    async def reset_connections(live: set[int] = frozenset()):
        now = utc_now()
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(PeerConnection).where(PeerConnection.closed_at.is_(None)))
            serving = set()
            for connection in result.all():
                if connection.id in live:
                    serving.add(connection.node_id)
                    continue
                connection.closed_at = now
                connection.reason = "NODE_RESTART"
            result = await e.exec(select(Peer).where(Peer.connected.is_(True)))
            for row in result.all():
                if row.node_id in serving: continue
                row.connected = False
                row.last_disconnected_at = now

    @staticmethod
    async def connections(node_id: str | None = None, limit: int = 50) -> list[dict]:
        async with db.async_executor(model=PeerConnection) as e:
            stmt = select(PeerConnection)
            if node_id: stmt = stmt.where(PeerConnection.node_id == node_id)
            result = await e.exec(stmt.order_by(PeerConnection.id.desc()).limit(limit))
            return [{
                "node": row.node_id, "opened_at": row.opened_at, "closed_at": row.closed_at,
                "authenticated": row.authenticated, "reason": row.reason
            } for row in result.all()]

    @staticmethod
    async def store_check(url: str, check: dict, ok: bool, error: str | None):
        pending = None
        async with db.async_executor(model=Peer) as e:
            result = await e.exec(select(Peer).where(Peer.url == url))
            row = result.first()
            if not row: return
            row.check = dumps(check)
            row.failures = 0 if ok else row.failures + 1
            row.last_error = None if ok else (error or "UNKNOWN")[:256]
            if ok:
                row.last_seen = utc_now()
                row.status = "active"
            node = check.get("node") or {}
            if ok and node.get("node") and node.get("key"):
                if row.public_key and row.public_key != node["key"]:
                    row.key_changed_at = utc_now()
                    pending = { "url": url, "old": row.public_key, "new": node["key"] }
                row.public_key = node["key"]
                row.node_id = node["node"]
        if pending:
            await Conflicts.record(
                "peer-key-changed", "high", f"The node at {url} now answers with a different key.",
                pending, subject=url
            )

    @staticmethod
    async def probe(target: str, ok: bool, latency_ms: int | None, error: str | None, detail: dict | None = None):
        async with db.async_executor(model=Probe) as e:
            await e.insert(Probe(target, utc_now(), ok, latency_ms, error, dumps(detail) if detail else None))

    @staticmethod
    async def prune_probes():
        since = to_ts(datetime.now(UTC) - timedelta(days=settings.probe_retention_days))
        from sqlalchemy import delete
        async with db.async_executor(model=Probe) as e:
            await e.exec(delete(Probe).where(Probe.ts < since), scalars=False)


def verify_statement(data, expected_url: str | None = None) -> tuple[dict | None, str | None]:
    if not isinstance(data, dict): return None, "NO_STATEMENT"
    statement, signature = data.get("statement"), data.get("signature")
    if not isinstance(statement, dict): return None, "NO_STATEMENT"
    key = statement.get("key")
    if not valid_ed25519(key): return None, "INVALID_NODE_KEY"
    if statement.get("node") != fingerprint(key): return None, "NODE_ID_MISMATCH"
    if not verify(key, NODE_CONTEXT, statement, signature or ""): return None, "INVALID_NODE_SIGNATURE"
    if expected_url is not None and normalize_url(statement.get("url") or "") != expected_url:
        return statement, "URL_MISMATCH"
    return statement, None


async def check_node(url: str) -> dict:
    from .ledger import Ledger
    api = settings.api_of(url)
    report = await netcheck.inspect(url)
    if report.get("error"):
        await Peers.probe(url, False, None, report["error"], { "stage": "inspect" })
        return report

    try:
        status, data, meta = await netcheck.get_json(url, f"{api}/node", 64 * 1024)
    except netcheck.CheckError as exc:
        report.update(ok=False, error=exc.code, detail=exc.detail)
        await Peers.probe(url, False, None, exc.code, { "stage": "node" })
        return report

    report["latency_ms"] = meta.get("latency_ms")
    if status != 200:
        report.update(ok=False, error=f"HTTP_{status}")
        await Peers.probe(url, False, meta.get("latency_ms"), report["error"], { "stage": "node" })
        return report

    statement, problem = verify_statement(data, normalize_url(url))
    report["node"] = statement
    report["identity"] = problem or "verified"
    if problem:
        report.update(ok=False, error=problem)
        await Peers.probe(url, False, meta.get("latency_ms"), problem, { "stage": "identity" })
        return report

    try:
        status, head, _ = await netcheck.get_json(url, f"{api}/ledger/head", 64 * 1024)
        report["head"] = head if status == 200 else None
    except netcheck.CheckError as exc:
        report["head"] = None
        report["head_error"] = exc.code

    try:
        status, latest, _ = await netcheck.get_json(url, f"{api}/checkpoints/latest", 256 * 1024)
        report["checkpoint"] = latest if status == 200 else None
    except netcheck.CheckError as exc:
        report["checkpoint"] = None
        report["checkpoint_error"] = exc.code

    report["ok"] = True
    report["comparison"] = await compare_head(report.get("head"), Ledger)
    await Peers.probe(url, True, report.get("latency_ms"), None, {
        "stage": "complete", "tls": (report.get("tls") or {}).get("ok")
    })
    return report


async def compare_head(remote, ledger) -> dict:
    if not isinstance(remote, dict) or not isinstance(remote.get("head"), dict):
        return { "status": "unknown" }
    head = remote["head"]
    size = head.get("seq")
    if not isinstance(size, int): return { "status": "unknown" }
    local_size, local_hash = await ledger.head()
    if size == 0 or local_size == 0: return { "status": "empty", "remote": size, "local": local_size }
    common = min(size, local_size)
    _, local_root = await ledger.root(common)
    if size == local_size:
        same = head.get("hash") == local_hash and head.get("root") == local_root
        return { "status": "match" if same else "diverged", "size": size,
                 "remote_root": head.get("root"), "local_root": local_root }
    if size < local_size:
        row = await ledger.get(size)
        same = row is not None and row.hash == head.get("hash")
        return { "status": "behind" if same else "diverged", "remote": size, "local": local_size }
    return { "status": "ahead", "remote": size, "local": local_size, "remote_hash": head.get("hash") }
