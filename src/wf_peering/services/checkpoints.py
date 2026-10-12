from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, UTC
import asyncio, json

from ..models.ledger import LedgerEntry
from ..models.sync import Checkpoint, RemoteCheckpoint
from ..protocol import entries, keylog, actions, integrity as spec
from ..protocol.canonical import canonical, canonical_text, digest
from ..protocol.merkle import leaf_hash, root
from ..protocol.signing import verify, fingerprint, valid_ed25519
from .identity import NodeIdentity
from .journal import Journal
from .ledger import Ledger
from .settings import settings, PROTOCOL_VERSION, SCHEMA_VERSION
from .role import current as role
from .store import Conflicts

CONTEXT = "wf-checkpoint-v1"
GENESIS = "0" * 64


def state_leaves(contents: list[dict]) -> dict:
    accounts_state: dict[str, tuple] = {}
    artifacts: dict[str, str] = {}
    from .accounts import CHANGE_PROTOCOL
    for content in contents:
        body = content.get("body") or {}
        protocol = body.get("protocol")
        if content.get("kind") == "peering:integrity":
            try: artifacts[body["record"]["id"]] = spec.fingerprint(spec.normalize(body["record"], body.get("provider")))
            except (KeyError, TypeError, spec.IntegrityError): pass
            continue
        if content.get("kind") == "peering:integrity-missing":
            artifacts.pop(body.get("artifact"), None)
            continue
        handle = None
        if protocol == keylog.PROTOCOL: handle = (body.get("statement") or {}).get("account")
        elif protocol == actions.PROTOCOL: handle = (body.get("action") or {}).get("account")
        elif protocol == CHANGE_PROTOCOL: handle = body.get("account")
        if not keylog.valid_handle(handle): continue
        keys, state = accounts_state.get(handle) or (keylog.AccountKeys(handle=handle), actions.ActionState())
        try:
            if protocol == keylog.PROTOCOL:
                _, keys = keylog.evaluate(keys, body)
            elif protocol == actions.PROTOCOL:
                try: recorded = int(entries.parse_ts(content.get("ts")).timestamp())
                except ValueError: recorded = None
                actions.evaluate(keys, state, body, recorded)
            else:
                actions.apply_unsigned(state, body.get("target"), body.get("params") or {}, body.get("result"))
        except Exception as exc:
            log_factory.warning(f"[peering] Replaying entry {content.get('seq')} failed: {exc}")
        accounts_state[handle] = (keys, state)

    rows = []
    for handle, (keys, state) in accounts_state.items():
        rows.append(["account", handle, digest({ "keys": keys.to_dict(), "actions": state.to_dict() })])
    for artifact, value in artifacts.items():
        rows.append(["artifact", artifact, value])
    rows.sort(key=lambda row: (row[0], row[1]))
    return {
        "root": root([leaf_hash(canonical(row)) for row in rows]),
        "accounts": len(accounts_state),
        "artifacts": len(artifacts)
    }


async def replay(size: int) -> dict:
    async with db.async_executor(model=LedgerEntry) as e:
        result = await e.exec(select(LedgerEntry.content).where(LedgerEntry.seq <= size).order_by(LedgerEntry.seq))
        contents = [json.loads(text) for text in result.all()]
    return await asyncio.get_running_loop().run_in_executor(None, state_leaves, contents)


def serialize(row: Checkpoint) -> dict:
    return {
        "day": row.day,
        "status": row.status,
        "hash": row.hash,
        "content": json.loads(row.content) if row.content else None,
        "signature": row.signature,
        "computed_at": row.computed_at
    }


class Checkpoints:
    _lock: asyncio.Lock | None = None

    @classmethod
    def _guard(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @staticmethod
    async def previous(day: str) -> Checkpoint | None:
        async with db.async_executor(model=Checkpoint) as e:
            result = await e.exec(select(Checkpoint).where(Checkpoint.day < day, Checkpoint.hash.is_not(None))
                                  .order_by(Checkpoint.day.desc()).limit(1))
            return result.first()

    @staticmethod
    async def get(day: str) -> Checkpoint | None:
        async with db.async_executor(model=Checkpoint) as e:
            result = await e.exec(select(Checkpoint).where(Checkpoint.day == day))
            return result.first()

    @classmethod
    async def compute(cls, day: str | None = None, moment: datetime | None = None) -> dict:
        moment = moment or datetime.now(UTC)
        day = day or (moment - timedelta(minutes=1)).strftime("%Y-%m-%d")
        async with cls._guard():
            existing = await cls.get(day)
            if existing and existing.status not in ("missing",):
                return serialize(existing)

            size, status, sync = await role().checkpoint_basis(day, moment)

            _, ledger_root = await Ledger.root(size)
            head_row = await Ledger.get(size) if size else None
            state = await replay(size)
            journal_size, journal_root = await Journal.root()
            previous = await cls.previous(day)

            content = {
                "v": 1,
                "node": NodeIdentity.node_id(),
                "key": NodeIdentity.public_key(),
                "role": settings.role,
                "origin": settings.assessed,
                "day": day,
                "status": status,
                "ledger": { "size": size, "root": ledger_root, "head": head_row.hash if head_row else GENESIS },
                "state": state,
                "journal": { "size": journal_size, "root": journal_root },
                "sync": { key: sync.get(key) for key in ("id", "status", "finished_at", "to_seq") },
                "prev": previous.hash if previous else GENESIS,
                "computed_at": entries.utc_now(),
                "protocol": PROTOCOL_VERSION,
                "schema": SCHEMA_VERSION
            }
            value = digest(content)
            signature = NodeIdentity.sign(CONTEXT, content)
            async with db.async_executor(model=Checkpoint) as e:
                if existing:
                    existing.status = status
                    existing.hash = value
                    existing.content = canonical_text(content)
                    existing.signature = signature
                    existing.computed_at = content["computed_at"]
                else:
                    await e.insert(Checkpoint(day, status, content["computed_at"], value,
                                              canonical_text(content), signature))

        await Journal.append("peering:checkpoint", { "day": day, "status": status, "hash": value,
                                                     "ledger": content["ledger"], "state_root": state["root"] })
        signed = { "checkpoint": content, "signature": signature, "hash": value }
        try: await role().publish_checkpoint(signed)
        except Exception as exc:
            log_factory.exception(exc, "[peering] Publishing the checkpoint failed.")
        if status != "verified":
            await Conflicts.record("checkpoint-" + status, "high" if status == "failed" else "normal",
                                   f"The checkpoint of {day} is {status}.", { "day": day, "sync": sync },
                                   subject="self", key=day)
        return { "day": day, "status": status, "hash": value, "content": content, "signature": signature }

    @classmethod
    async def fill_missing(cls):
        async with db.async_executor(model=Checkpoint) as e:
            result = await e.exec(select(Checkpoint).order_by(Checkpoint.day.desc()).limit(1))
            last = result.first()
        if last is None: return
        start = datetime.strptime(last.day, "%Y-%m-%d").replace(tzinfo=UTC).date() + timedelta(days=1)
        yesterday = (datetime.now(UTC) - timedelta(days=1)).date()
        missed = []
        async with db.async_executor(model=Checkpoint) as e:
            day = start
            while day <= yesterday and len(missed) < 366:
                missed.append(day.isoformat())
                await e.insert(Checkpoint(day.isoformat(), "missing", entries.utc_now()))
                day += timedelta(days=1)
        if missed:
            await Journal.append("peering:checkpoint-missing", { "days": missed })

    @staticmethod
    async def latest() -> dict | None:
        async with db.async_executor(model=Checkpoint) as e:
            result = await e.exec(select(Checkpoint).order_by(Checkpoint.day.desc()).limit(1))
            row = result.first()
            return serialize(row) if row else None

    @staticmethod
    async def latest_with_root() -> dict | None:
        async with db.async_executor(model=Checkpoint) as e:
            result = await e.exec(select(Checkpoint).where(Checkpoint.hash.is_not(None))
                                  .order_by(Checkpoint.day.desc()).limit(1))
            row = result.first()
            return serialize(row) if row else None

    @staticmethod
    async def history(limit: int = 30) -> list[dict]:
        async with db.async_executor(model=Checkpoint) as e:
            result = await e.exec(select(Checkpoint).order_by(Checkpoint.day.desc()).limit(limit))
            return [serialize(row) for row in result.all()]

    @staticmethod
    def check_signed(body: dict) -> tuple[dict | None, str | None]:
        content, signature = (body or {}).get("checkpoint"), (body or {}).get("signature")
        if not isinstance(content, dict): return None, "NO_CHECKPOINT"
        key = content.get("key")
        if not valid_ed25519(key) or content.get("node") != fingerprint(key): return content, "INVALID_KEY"
        if not verify(key, CONTEXT, content, signature or ""): return content, "INVALID_SIGNATURE"
        if (body or {}).get("hash") not in (None, digest(content)): return content, "HASH_MISMATCH"
        return content, None

    @classmethod
    async def remember_remote(cls, body: dict, via: str) -> str | None:
        content, problem = cls.check_signed(body)
        if content is None: return problem
        if problem:
            await Conflicts.record("invalid-checkpoint", "critical",
                                   f"A checkpoint attributed to {content.get('node')} failed verification: {problem}",
                                   { "body": body, "via": via }, subject=content.get("node"))
            return problem
        if content.get("node") == NodeIdentity.node_id(): return None
        value = digest(content)
        try:
            async with db.async_executor(model=RemoteCheckpoint) as e:
                result = await e.exec(select(RemoteCheckpoint).where(
                    RemoteCheckpoint.node_id == content["node"], RemoteCheckpoint.day == content.get("day")
                ))
                rows = list(result.all())
                if any(row.hash == value for row in rows): return None
                others = [row.hash for row in rows]
                await e.insert(RemoteCheckpoint(content["node"], str(content.get("day")), value,
                                                canonical_text(content), body.get("signature"), True, via,
                                                entries.utc_now()))
        except IntegrityError:
            return None
        if others:
            await Conflicts.record("checkpoint-equivocation", "critical",
                                   f"Node {content['node']} signed different checkpoints for {content.get('day')}.",
                                   { "day": content.get("day"), "hashes": sorted([value] + others) },
                                   subject=content["node"], key={ "day": content.get("day"), "node": content["node"] })
        return None

    @staticmethod
    async def remote(day: str | None = None, limit: int = 200) -> list[dict]:
        async with db.async_executor(model=RemoteCheckpoint) as e:
            stmt = select(RemoteCheckpoint)
            if day: stmt = stmt.where(RemoteCheckpoint.day == day)
            result = await e.exec(stmt.order_by(RemoteCheckpoint.id.desc()).limit(limit))
            return [{
                "node": row.node_id, "day": row.day, "hash": row.hash, "content": json.loads(row.content),
                "signature": row.signature, "verified": row.verified, "via": row.via, "received_at": row.received_at
            } for row in result.all()]

    @classmethod
    async def agreement(cls, day: str | None = None) -> dict:
        own = await cls.get(day) if day else None
        if own is None or not own.content:
            latest = await cls.latest_with_root()
            if latest is None: return { "day": day, "status": "no-checkpoint", "nodes": [] }
            day = latest["day"]
            own_content = latest["content"]
        else:
            own_content = json.loads(own.content)

        size, mine = own_content["ledger"]["size"], own_content["ledger"]["root"]
        local_size, _ = await Ledger.head()
        rows = []
        for item in await cls.remote(day):
            ledger = (item["content"].get("ledger") or {})
            other_size, other_root = ledger.get("size"), ledger.get("root")
            if not isinstance(other_size, int): continue
            if other_size == size: verdict = "match" if other_root == mine else "diverged"
            elif other_size <= local_size:
                _, at = await Ledger.root(other_size)
                verdict = "consistent-prefix" if at == other_root else "diverged"
            else: verdict = "ahead-unverified"
            rows.append({ "node": item["node"], "status": item["content"].get("status"), "size": other_size,
                          "root": other_root, "verdict": verdict, "via": item["via"],
                          "role": item["content"].get("role") })
        return { "day": day, "size": size, "root": mine, "status": own_content.get("status"), "nodes": rows }
