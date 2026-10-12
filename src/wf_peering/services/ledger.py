from webfluid.core.ext import db
from webfluid.utils.logging import factory as log_factory
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
import asyncio, json

from ..models.ledger import LedgerEntry
from ..protocol import entries
from ..protocol.canonical import canonical_text, CanonicalError
from ..protocol.merkle import root, inclusion_proof, consistency_proof
from . import accounts
from .identity import NodeIdentity
from .settings import settings, PROTOCOL_VERSION, SCHEMA_VERSION
from .store import dumps, loads, Conflicts, State


class LedgerError(Exception):
    def __init__(self, code: str, detail: dict | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail or {}


def serialize(row: LedgerEntry) -> dict:
    return {
        "seq": row.seq,
        "hash": row.hash,
        "content": json.loads(row.content),
        "signature": row.signature,
        "verification": loads(row.flags)
    }


class Ledger:
    _lock: asyncio.Lock | None = None
    _listeners: set = set()

    @classmethod
    def _guard(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    def subscribe(cls, listener):
        cls._listeners.add(listener)

    @classmethod
    def unsubscribe(cls, listener):
        cls._listeners.discard(listener)

    @classmethod
    def _notify(cls, entry: dict):
        for listener in list(cls._listeners):
            try: listener(entry)
            except Exception as exc: log_factory.exception(exc, "[peering] A ledger listener failed.")

    @staticmethod
    async def head() -> tuple[int, str]:
        async with db.async_executor(model=LedgerEntry) as e:
            result = await e.exec(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(1))
            row = result.first()
            return (row.seq, row.hash) if row else (0, entries.GENESIS)

    @staticmethod
    async def size() -> int:
        async with db.async_executor(model=LedgerEntry) as e:
            result = await e.exec(select(func.max(LedgerEntry.seq)), scalars=False)
            return result.scalar() or 0

    @staticmethod
    def signing_key() -> str | None:
        return NodeIdentity.public_key() if settings.is_host else None

    @classmethod
    async def append(cls, kind: str, source: str, body: dict, subject: str | None = None,
                     ref: str | None = None, auth: dict | None = None) -> dict:
        if not settings.is_host: raise LedgerError("NOT_A_HOST")

        if ref is not None:
            existing = await cls.by_ref(ref)
            if existing: return { "seq": existing.seq, "hash": existing.hash, "duplicate": True }

        async with cls._guard():
            seq, prev = await cls.head()
            content = entries.make(seq + 1, prev, kind, source, body, subject=subject, ref=ref, auth=auth)
            issues = entries.problems(content)
            if issues: raise LedgerError("INVALID_ENTRY", { "issues": issues })

            value = entries.entry_hash(content)
            signature = entries.sign_hash(NodeIdentity.signer, entries.LEDGER_CONTEXT, value)
            try:
                async with db.async_executor(model=LedgerEntry) as e:
                    verification = await accounts.apply(e, content)
                    await e.insert(LedgerEntry(
                        seq=content["seq"], hash=value, leaf=entries.entry_leaf(content), prev=prev,
                        kind=kind, source=source, subject=subject, ref=ref, ts=content["ts"],
                        content=canonical_text(content), signature=signature,
                        received_at=content["ts"], flags=dumps(verification)
                    ))
            except IntegrityError:
                if ref is not None:
                    existing = await cls.by_ref(ref)
                    if existing: return { "seq": existing.seq, "hash": existing.hash, "duplicate": True }
                raise

        entry = { "seq": content["seq"], "hash": value, "content": content, "signature": signature,
                  "verification": verification }
        await cls._report(content, verification)
        cls._notify(entry)
        return { "seq": content["seq"], "hash": value, "verification": verification }

    @staticmethod
    async def _report(content: dict, verification: dict):
        bad = accounts.critical(verification)
        if not bad: return
        await Conflicts.record(
            "ledger-entry-invalid", "critical",
            f"Ledger entry {content['seq']} ({content['kind']}) failed verification: "
            + ", ".join(flag["code"] for flag in bad),
            { "seq": content["seq"], "kind": content["kind"], "flags": bad },
            subject=verification.get("account")
        )

    @staticmethod
    async def by_ref(ref: str) -> LedgerEntry | None:
        async with db.async_executor(model=LedgerEntry) as e:
            result = await e.exec(select(LedgerEntry).where(LedgerEntry.ref == ref))
            return result.first()

    @staticmethod
    async def get(seq: int) -> LedgerEntry | None:
        async with db.async_executor(model=LedgerEntry) as e:
            result = await e.exec(select(LedgerEntry).where(LedgerEntry.seq == seq))
            return result.first()

    @classmethod
    async def ingest(cls, item: dict, host_key: str) -> str:
        content, signature = item.get("content"), item.get("signature")
        issues = entries.problems(content)
        if issues: raise LedgerError("INVALID_ENTRY", { "issues": issues, "seq": (content or {}).get("seq") })

        try: value = entries.entry_hash(content)
        except CanonicalError: raise LedgerError("INVALID_ENTRY", { "issues": ["NOT_CANONICALIZABLE"] })
        if item.get("hash") not in (None, value):
            raise LedgerError("HASH_MISMATCH", { "seq": content["seq"] })
        if not entries.verify_hash(host_key, entries.LEDGER_CONTEXT, value, signature or ""):
            raise LedgerError("INVALID_HOST_SIGNATURE", { "seq": content["seq"] })

        async with cls._guard():
            seq, prev = await cls.head()
            if content["seq"] <= seq:
                stored = await cls.get(content["seq"])
                if stored and stored.hash == value: return "duplicate"
                await Conflicts.record(
                    "host-equivocation", "critical",
                    f"The host signed two different ledger entries for sequence {content['seq']}.",
                    {
                        "seq": content["seq"],
                        "stored": { "hash": stored.hash, "content": json.loads(stored.content), "signature": stored.signature } if stored else None,
                        "received": { "hash": value, "content": content, "signature": signature }
                    },
                    subject="host", key={ "seq": content["seq"], "hashes": sorted([value, stored.hash if stored else ""]) }
                )
                raise LedgerError("FORK", { "seq": content["seq"] })
            if content["seq"] > seq + 1:
                raise LedgerError("GAP", { "have": seq, "got": content["seq"] })
            if content["prev"] != prev:
                await Conflicts.record(
                    "host-equivocation", "critical",
                    f"Ledger entry {content['seq']} does not extend the history the host signed before.",
                    { "seq": content["seq"], "expected_prev": prev, "received": { "hash": value, "content": content, "signature": signature } },
                    subject="host", key={ "seq": content["seq"], "prev": prev, "hash": value }
                )
                raise LedgerError("FORK", { "seq": content["seq"] })

            async with db.async_executor(model=LedgerEntry) as e:
                verification = await accounts.apply(e, content)
                await e.insert(LedgerEntry(
                    seq=content["seq"], hash=value, leaf=entries.entry_leaf(content), prev=prev,
                    kind=content["kind"], source=content["source"], subject=content["subject"],
                    ref=content["ref"], ts=content["ts"], content=canonical_text(content),
                    signature=signature, received_at=entries.utc_now(), flags=dumps(verification)
                ))
        await cls._report(content, verification)
        return "appended"

    @staticmethod
    async def range(start: int, limit: int, kind: str | None = None, subject: str | None = None,
                    end: int | None = None) -> list[dict]:
        async with db.async_executor(model=LedgerEntry) as e:
            stmt = select(LedgerEntry).where(LedgerEntry.seq >= max(1, start))
            if end is not None: stmt = stmt.where(LedgerEntry.seq <= end)
            if kind:
                stmt = stmt.where(LedgerEntry.kind.like(kind[:-1] + "%") if kind.endswith("*") else LedgerEntry.kind == kind)
            if subject: stmt = stmt.where(LedgerEntry.subject == subject)
            result = await e.exec(stmt.order_by(LedgerEntry.seq).limit(limit))
            return [serialize(row) for row in result.all()]

    @staticmethod
    async def leaves(size: int | None = None) -> list[str]:
        async with db.async_executor(model=LedgerEntry) as e:
            stmt = select(LedgerEntry.leaf).order_by(LedgerEntry.seq)
            if size is not None: stmt = stmt.where(LedgerEntry.seq <= size)
            result = await e.exec(stmt)
            return list(result.all())

    @classmethod
    async def root(cls, size: int | None = None) -> tuple[int, str]:
        leaves = await cls.leaves(size)
        return len(leaves), root(leaves)

    @classmethod
    async def proof(cls, seq: int, size: int | None = None) -> dict:
        leaves = await cls.leaves(size)
        if not 1 <= seq <= len(leaves): raise LedgerError("OUT_OF_RANGE")
        return {
            "seq": seq,
            "size": len(leaves),
            "leaf": leaves[seq - 1],
            "root": root(leaves),
            "path": inclusion_proof(seq - 1, leaves)
        }

    @classmethod
    async def consistency(cls, first: int, second: int | None = None) -> dict:
        leaves = await cls.leaves(second)
        if not 0 < first <= len(leaves): raise LedgerError("OUT_OF_RANGE")
        return {
            "first": first,
            "second": len(leaves),
            "first_root": root(leaves[:first]),
            "second_root": root(leaves),
            "proof": consistency_proof(first, leaves)
        }

    @classmethod
    async def signed_head(cls) -> dict:
        size, value = await cls.head()
        _, tree = await cls.root(size)
        origin = settings.origin if settings.is_host else settings.host
        head = entries.head(size, value, tree, entries.utc_now(), origin, PROTOCOL_VERSION, SCHEMA_VERSION)
        return {
            "head": head,
            "signer": NodeIdentity.node_id(),
            "key": NodeIdentity.public_key(),
            "signature": NodeIdentity.sign(entries.HEAD_CONTEXT, head),
            "host_key": settings.host_key if settings.is_peer else NodeIdentity.public_key()
        }

    @staticmethod
    async def verify(public_key: str | None, upto: int | None = None) -> dict:
        problems = []
        previous_seq, previous_hash = 0, entries.GENESIS
        count = 0
        async with db.async_executor(model=LedgerEntry) as e:
            stmt = select(LedgerEntry).order_by(LedgerEntry.seq)
            if upto is not None: stmt = stmt.where(LedgerEntry.seq <= upto)
            result = await e.exec(stmt)
            for row in result.all():
                count += 1
                try:
                    content = json.loads(row.content)
                    if canonical_text(content) != row.content: problems.append(f"{row.seq}:NOT_CANONICAL")
                    if entries.entry_hash(content) != row.hash: problems.append(f"{row.seq}:HASH_MISMATCH")
                    if entries.entry_leaf(content) != row.leaf: problems.append(f"{row.seq}:LEAF_MISMATCH")
                    problems.extend(f"{row.seq}:{issue}" for issue in entries.problems(content))
                    problems.extend(f"{row.seq}:{issue}" for issue in entries.check_link(content, previous_hash, previous_seq))
                except (ValueError, CanonicalError):
                    problems.append(f"{row.seq}:UNREADABLE")
                if public_key and not entries.verify_hash(public_key, entries.LEDGER_CONTEXT, row.hash, row.signature):
                    problems.append(f"{row.seq}:INVALID_HOST_SIGNATURE")
                previous_seq, previous_hash = row.seq, row.hash
        return { "size": count, "head": previous_hash, "problems": problems[:100], "valid": not problems }

    @staticmethod
    async def host_key() -> str | None:
        if settings.is_host: return NodeIdentity.public_key()
        return settings.host_key or await State.get("host_key")
