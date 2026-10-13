from fastapi import Request
from .utils import public


async def peers_request(request: Request):
    from ..services.peers import Peers, serialize
    from ..settings import settings
    from ..services.identity import NodeIdentity
    peers = []
    for row in await Peers.all(False):
        data = serialize(row)
        data.pop("check", None)
        check = row.check
        if check:
            from ..services.store import loads
            parsed = loads(check, {})
            data["last_check"] = {
                "checked_at": parsed.get("checked_at"), "ok": parsed.get("ok"), "error": parsed.get("error"),
                "identity": parsed.get("identity"), "tls": (parsed.get("tls") or {}).get("ok"),
                "comparison": (parsed.get("comparison") or {}).get("status"),
                "addresses": parsed.get("dns")
            }
        peers.append(data)
    return public({
        "reporter": { "node": NodeIdentity.node_id(), "role": settings.role, "url": settings.origin },
        "claim": "This list is what this node knows about. It is one source, not proof of completeness.",
        "peers": peers
    })


async def connections_request(request: Request):
    from ..services.peers import Peers
    return public({ "connections": await Peers.connections() })
