from fastapi import Request

from wf_peering.api.utils import public, error


async def trust_request(request: Request):
    from wf_peering.services import TrustService
    report = await TrustService.latest()
    if report is None: return error("NOT_ASSESSED_YET", 404)
    return public(TrustService.sign(report))


async def trust_history_request(request: Request):
    from wf_peering.services import TrustService
    return public({ "history": await TrustService.history() })


async def conflicts_request(request: Request):
    from wf_peering.services import ConflictService
    return public({ "conflicts": await ConflictService.open(), "open": await ConflictService.counts() })
