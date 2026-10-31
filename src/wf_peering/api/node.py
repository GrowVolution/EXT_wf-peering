from fastapi import Request

from wf_peering.api.utils import public


async def node_request(request: Request):
    from wf_peering.services import IdentityService
    return public(IdentityService.signed_statement())


async def status_request(request: Request):
    from wf_peering.services import StatusService
    return public(await StatusService.summary())


async def uptime_request(request: Request):
    from wf_peering.services import UptimeService, PeerService
    from wf_peering.settings import settings
    data = { "self": await UptimeService.own() }
    target = settings.host if settings.is_peer else None
    if target: data["host"] = await UptimeService.observed(target, 7)
    data["peers"] = { row.url: await UptimeService.observed(row.url, 7) for row in await PeerService.all(False) }
    return public(data)
