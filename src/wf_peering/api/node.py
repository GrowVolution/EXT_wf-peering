from fastapi import Request
from .utils import public


async def node_request(request: Request):
    from ..services.identity import NodeIdentity
    return public(NodeIdentity.signed_statement())


async def status_request(request: Request):
    from ..services.status import summary
    return public(await summary())


async def uptime_request(request: Request):
    from ..services.uptime import Uptime
    from ..settings import settings
    from ..services.peers import Peers
    data = { "self": await Uptime.own() }
    target = settings.host if settings.is_peer else None
    if target: data["host"] = await Uptime.observed(target, 7)
    data["peers"] = { row.url: await Uptime.observed(row.url, 7) for row in await Peers.all(False) }
    return public(data)
