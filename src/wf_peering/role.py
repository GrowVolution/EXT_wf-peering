from datetime import datetime


class NodeRole:
    name: str = ""
    software: str = ""

    async def startup(self) -> None:
        pass

    async def heartbeat(self) -> None:
        pass

    async def discover(self) -> None:
        pass

    async def checkpoint_basis(self, day: str, moment: datetime) -> tuple[int, str, dict]:
        raise NotImplementedError

    async def publish_checkpoint(self, signed: dict) -> None:
        pass

    async def signals(self, now: datetime) -> list:
        return []

    async def observation(self, artifact: str) -> dict | None:
        return None

    async def status(self) -> dict:
        return {}

    def live_connections(self) -> set[int]:
        return set()

    def alert(self, data: dict) -> None:
        pass


_role: NodeRole | None = None


def use(role: NodeRole) -> NodeRole:
    global _role
    _role = role
    return role


def current() -> NodeRole:
    if _role is None: raise RuntimeError("wf-peering has not been expanded with a role yet.")
    return _role
