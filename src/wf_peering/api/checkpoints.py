from fastapi import Request

from wf_peering.api.utils import public, error, bounded, valid_day


async def checkpoints_request(request: Request):
    from wf_peering.services import CheckpointService
    return public({ "checkpoints": await CheckpointService.history(bounded(request.query_params.get("limit"), 30, 1,
                                                                           366)) })


async def latest_request(request: Request):
    from wf_peering.services import CheckpointService
    latest = await CheckpointService.latest()
    if latest is None: return error("NO_CHECKPOINT", 404)
    latest["verified_root"] = await CheckpointService.latest_with_root() if latest["status"] == "missing" else None
    return public(latest)


async def remote_request(request: Request):
    from wf_peering.services import CheckpointService
    day = request.query_params.get("day")
    if not valid_day(day): return error("INVALID_DAY")
    return public({
        "claim": "Checkpoints of other nodes as received; each carries its own signature.",
        "checkpoints": await CheckpointService.remote(day)
    })


async def agreement_request(request: Request):
    from wf_peering.services import CheckpointService
    day = request.query_params.get("day")
    if not valid_day(day): return error("INVALID_DAY")
    return public(await CheckpointService.agreement(day))
