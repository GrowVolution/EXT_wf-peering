from fastapi import Request

from wf_peering.api.utils import public


async def peers_request(request: Request):
    from wf_peering.services import PeerService, IdentityService
    from wf_peering.settings import settings
    peers = []
    for row in await PeerService.all(False):
        data = PeerService.serialize(row)
        data.pop("check", None)
        check = row.check
        if check:
            from wf_peering.utils.serialization import loads
            parsed = loads(check, {})
            data["last_check"] = {
                "checked_at": parsed.get("checked_at"), "ok": parsed.get("ok"), "error": parsed.get("error"),
                "identity": parsed.get("identity"), "tls": (parsed.get("tls") or {}).get("ok"),
                "comparison": (parsed.get("comparison") or {}).get("status"),
                "addresses": parsed.get("dns")
            }
        peers.append(data)
    return public({
        "reporter": { "node": IdentityService.node_id(), "role": settings.role, "url": settings.origin },
        "claim": "This list is what this node knows about. It is one source, not proof of completeness.",
        "peers": peers
    })


async def connections_request(request: Request):
    from wf_peering.services import PeerService
    return public({ "connections": await PeerService.connections() })
