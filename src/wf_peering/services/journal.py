from webfluid.core.ext import db
from sqlalchemy import select, func
import asyncio, json

from ..models.ledger import JournalEntry
from ..protocol import entries
from ..protocol.canonical import canonical_text
from ..protocol.merkle import root
from .identity import NodeIdentity

SOURCE = "peering"


class Journal:
    _lock: asyncio.Lock | None = None

    @classmethod
    def _guard(cls) -> asyncio.Lock:
        if cls._lock is None: cls._lock = asyncio.Lock()
        return cls._lock

    @staticmethod
    async def head() -> tuple[int, str]:
        async with db.async_executor(model=JournalEntry) as e:
            result = await e.exec(select(JournalEntry).order_by(JournalEntry.seq.desc()).limit(1))
            row = result.first()
            return (row.seq, row.hash) if row else (0, entries.GENESIS)

    @classmethod
    async def append(cls, kind: str, body: dict) -> dict:
        async with cls._guard():
            seq, prev = await cls.head()
            content = entries.make(seq + 1, prev, kind, SOURCE, body, auth={ "type": "node" })
            value = entries.entry_hash(content)
            signature = entries.sign_hash(NodeIdentity.signer, entries.JOURNAL_CONTEXT, value)
            async with db.async_executor(model=JournalEntry) as e:
                await e.insert(JournalEntry(
                    seq=seq + 1, hash=value, leaf=entries.entry_leaf(content), prev=prev,
                    kind=kind, ts=content["ts"], content=canonical_text(content), signature=signature
                ))
            return { "seq": seq + 1, "hash": value }

    @staticmethod
    async def range(start: int, limit: int, kind: str | None = None) -> list[dict]:
        async with db.async_executor(model=JournalEntry) as e:
            stmt = select(JournalEntry).where(JournalEntry.seq >= start)
            if kind: stmt = stmt.where(JournalEntry.kind == kind)
            result = await e.exec(stmt.order_by(JournalEntry.seq).limit(limit))
            return [
                { "seq": row.seq, "hash": row.hash, "content": json.loads(row.content), "signature": row.signature }
                for row in result.all()
            ]

    @staticmethod
    async def recent(kinds: tuple, limit: int = 50) -> list[dict]:
        async with db.async_executor(model=JournalEntry) as e:
            result = await e.exec(select(JournalEntry).where(JournalEntry.kind.in_(kinds))
                                  .order_by(JournalEntry.seq.desc()).limit(limit))
            return [json.loads(row.content) for row in result.all()]

    @staticmethod
    async def root(size: int | None = None) -> tuple[int, str]:
        async with db.async_executor(model=JournalEntry) as e:
            stmt = select(JournalEntry.leaf).order_by(JournalEntry.seq)
            if size is not None: stmt = stmt.where(JournalEntry.seq <= size)
            result = await e.exec(stmt)
            leaves = list(result.all())
            return len(leaves), root(leaves)

    @staticmethod
    async def count_since(kind: str, since: str) -> int:
        async with db.async_executor(model=JournalEntry) as e:
            result = await e.exec(select(func.count(JournalEntry.seq)).where(
                JournalEntry.kind == kind, JournalEntry.ts >= since
            ), scalars=False)
            return result.scalar() or 0

    @staticmethod
    async def verify() -> list[str]:
        problems = []
        previous_seq, previous_hash = 0, entries.GENESIS
        key = NodeIdentity.public_key()
        async with db.async_executor(model=JournalEntry) as e:
            result = await e.exec(select(JournalEntry).order_by(JournalEntry.seq))
            for row in result.all():
                content = json.loads(row.content)
                if canonical_text(content) != row.content: problems.append(f"{row.seq}:NOT_CANONICAL")
                if entries.entry_hash(content) != row.hash: problems.append(f"{row.seq}:HASH_MISMATCH")
                problems.extend(f"{row.seq}:{issue}" for issue in entries.check_link(content, previous_hash, previous_seq))
                if not entries.verify_hash(key, entries.JOURNAL_CONTEXT, row.hash, row.signature):
                    problems.append(f"{row.seq}:INVALID_SIGNATURE")
                previous_seq, previous_hash = row.seq, row.hash
        return problems
