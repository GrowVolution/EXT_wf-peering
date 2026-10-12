from fastapi import Request

from .utils import public, error, bounded, valid_day


async def checkpoints_request(request: Request):
    from ..services.checkpoints import Checkpoints
    return public({ "checkpoints": await Checkpoints.history(bounded(request.query_params.get("limit"), 30, 1, 366)) })


async def latest_request(request: Request):
    from ..services.checkpoints import Checkpoints
    latest = await Checkpoints.latest()
    if latest is None: return error("NO_CHECKPOINT", 404)
    latest["verified_root"] = await Checkpoints.latest_with_root() if latest["status"] == "missing" else None
    return public(latest)


async def remote_request(request: Request):
    from ..services.checkpoints import Checkpoints
    day = request.query_params.get("day")
    if not valid_day(day): return error("INVALID_DAY")
    return public({
        "claim": "Checkpoints of other nodes as received; each carries its own signature.",
        "checkpoints": await Checkpoints.remote(day)
    })


async def agreement_request(request: Request):
    from ..services.checkpoints import Checkpoints
    day = request.query_params.get("day")
    if not valid_day(day): return error("INVALID_DAY")
    return public(await Checkpoints.agreement(day))

