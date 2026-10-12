from fastapi import Request
from .utils import public, error


async def trust_request(request: Request):
    from ..services.trust import Trust
    report = await Trust.latest()
    if report is None: return error("NOT_ASSESSED_YET", 404)
    return public(Trust.sign(report))


async def trust_history_request(request: Request):
    from ..services.trust import Trust
    return public({ "history": await Trust.history() })


async def conflicts_request(request: Request):
    from ..services.store import Conflicts
    return public({ "conflicts": await Conflicts.open(), "open": await Conflicts.counts() })
