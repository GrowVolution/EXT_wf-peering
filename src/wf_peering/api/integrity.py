from fastapi import Request
import re

from .utils import public, error, bounded

_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,127}$")


async def integrity_request(request: Request):
    from ..services.integrity import Integrity
    from ..services.settings import settings
    return public({
        "source": "host-ledger" if settings.is_peer else "providers",
        "groups": await Integrity.current(),
        "run": await Integrity.last_run()
    })


async def hash_request(request: Request):
    from ..services.integrity import Integrity
    from ..services.settings import settings
    artifact = request.query_params.get("id")
    if not isinstance(artifact, str) or not _ID.match(artifact): return error("INVALID_ID")
    latest = await Integrity.latest(artifact)
    if latest is None: return error("UNKNOWN_ARTIFACT", 404)
    record = latest["record"]
    data = {
        "id": artifact,
        "algorithm": record["algorithm"],
        "hash": record["hash"],
        "version": record.get("version"),
        "served_version": record.get("served_version"),
        "latest_version": record.get("latest_version"),
        "chain_length": latest.get("chain_length"),
        "confirmed_at": latest.get("confirmed_at"),
        "missing_since": latest.get("missing_since"),
        "ledger_seq": latest.get("ledger_seq"),
        "record": record,
        "source": "host-ledger" if settings.is_peer else "providers"
    }
    from ..services.role import current as role
    observation = await role().observation(artifact)
    if observation is not None or settings.is_peer: data["observation"] = observation
    return public(data)


async def history_request(request: Request):
    from ..services.integrity import Integrity
    artifact = request.query_params.get("id")
    if not isinstance(artifact, str) or not _ID.match(artifact): return error("INVALID_ID")
    return public({ "id": artifact,
                    "history": await Integrity.history(artifact, bounded(request.query_params.get("limit"), 50, 1, 500)) })


async def observations_request(request: Request):
    from ..services.integrity import Integrity
    artifact = request.query_params.get("id")
    if artifact is not None and not _ID.match(artifact): return error("INVALID_ID")
    return public({ "observations": await Integrity.observations(artifact, bounded(request.query_params.get("limit"), 50, 1, 500)) })
