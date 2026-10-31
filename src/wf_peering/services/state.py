from webfluid.core.ext import db
from sqlalchemy import select

from wf_peering.models.state import NodeState
from wf_peering.utils.serialization import dumps, loads


class StateService:
    @staticmethod
    async def get(key: str, default=None):
        async with db.async_executor(model=NodeState) as e:
            result = await e.exec(select(NodeState).where(NodeState.key == key))
            row = result.first()
            return loads(row.value, default) if row else default

    @staticmethod
    async def set(key: str, value):
        async with db.async_executor(model=NodeState) as e:
            result = await e.exec(select(NodeState).where(NodeState.key == key))
            row = result.first()
            if row: row.value = dumps(value)
            else: await e.insert(NodeState(key, dumps(value)))
