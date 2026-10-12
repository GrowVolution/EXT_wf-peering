from functools import wraps
from fastapi import APIRouter

from . import checkpoints, integrity, ledger, node, peers, trust

ROUTES = (
    ("/node", "120/minute", node.node_request),
    ("/status", "120/minute", node.status_request),
    ("/uptime", "60/minute", node.uptime_request),
    ("/ledger", "120/minute", ledger.ledger_request),
    ("/ledger/head", "240/minute", ledger.head_request),
    ("/ledger/root", "120/minute", ledger.root_request),
    ("/ledger/proof", "120/minute", ledger.proof_request),
    ("/ledger/consistency", "120/minute", ledger.consistency_request),
    ("/journal", "60/minute", ledger.journal_request),
    ("/accounts/{handle}", "120/minute", ledger.account_request),
    ("/integrity", "120/minute", integrity.integrity_request),
    ("/hash", "240/minute", integrity.hash_request),
    ("/integrity/history", "60/minute", integrity.history_request),
    ("/peers", "120/minute", peers.peers_request),
    ("/checkpoints", "120/minute", checkpoints.checkpoints_request),
    ("/checkpoints/latest", "240/minute", checkpoints.latest_request),
    ("/checkpoints/peers", "60/minute", checkpoints.remote_request),
    ("/checkpoints/agreement", "60/minute", checkpoints.agreement_request),
    ("/trust", "120/minute", trust.trust_request),
    ("/trust/history", "60/minute", trust.trust_history_request),
    ("/conflicts", "60/minute", trust.conflicts_request),
)

connections_request = peers.connections_request
observations_request = integrity.observations_request


def counted(path: str, handler):
    group = path.strip("/").split("/")[0] or "root"

    @wraps(handler)
    async def wrapper(*args, **kwargs):
        from ..services.tasks import Activity
        Activity.count(group)
        return await handler(*args, **kwargs)
    return wrapper


def route(router: APIRouter, limit, path: str, rate: str, handler):
    router.get(path)(limit(rate)(counted(path, handler)))


def register(router: APIRouter, limit) -> APIRouter:
    for path, rate, handler in ROUTES:
        route(router, limit, path, rate, handler)
    return router
