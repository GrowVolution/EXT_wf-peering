from fastapi import Request
import json

from .utils import public, error, bounded, valid_kind, valid_subject

MAX_PAGE_BYTES = 4 * 1024 * 1024


async def ledger_request(request: Request):
    from ..services.ledger import Ledger
    from ..settings import settings
    query = request.query_params
    start = bounded(query.get("from"), 1, 1, 2 ** 53 - 1)
    limit = bounded(query.get("limit"), 100, 1, settings.ledger_page)
    kind, subject = query.get("kind"), query.get("subject")
    if not valid_kind(kind): return error("INVALID_KIND")
    if not valid_subject(subject): return error("INVALID_SUBJECT")

    items, size = [], 0
    for item in await Ledger.range(start, limit, kind, subject):
        size += len(json.dumps(item))
        if items and size > MAX_PAGE_BYTES: break
        items.append(item)
    head, value = await Ledger.head()
    return public({
        "entries": items,
        "head": { "seq": head, "hash": value },
        "next": items[-1]["seq"] + 1 if items else None,
        "signer": await Ledger.host_key()
    })


async def head_request(request: Request):
    from ..services.ledger import Ledger
    return public(await Ledger.signed_head())


async def root_request(request: Request):
    from ..services.ledger import Ledger
    size = request.query_params.get("size")
    head, _ = await Ledger.head()
    size = bounded(size, head, 0, head) if size is not None else head
    count, value = await Ledger.root(size)
    return public({ "size": count, "root": value })


async def proof_request(request: Request):
    from ..services.ledger import Ledger, LedgerError
    query = request.query_params
    head, _ = await Ledger.head()
    try:
        return public(await Ledger.proof(bounded(query.get("seq"), 0, 0, head),
                                         bounded(query.get("size"), head, 1, head) if query.get("size") else None))
    except LedgerError as exc:
        return error(exc.code, 404)


async def consistency_request(request: Request):
    from ..services.ledger import Ledger, LedgerError
    query = request.query_params
    head, _ = await Ledger.head()
    try:
        return public(await Ledger.consistency(bounded(query.get("first"), 0, 0, head),
                                               bounded(query.get("second"), head, 1, head) if query.get("second") else None))
    except LedgerError as exc:
        return error(exc.code, 404)


async def journal_request(request: Request):
    from ..services.journal import Journal
    from ..services.identity import NodeIdentity
    query = request.query_params
    kind = query.get("kind")
    if not valid_kind(kind): return error("INVALID_KIND")
    items = await Journal.range(bounded(query.get("from"), 1, 1, 2 ** 53 - 1),
                                bounded(query.get("limit"), 100, 1, 500), kind)
    seq, value = await Journal.head()
    return public({ "entries": items, "head": { "seq": seq, "hash": value }, "signer": NodeIdentity.public_key() })


async def account_request(request: Request, handle: str):
    from ..services import accounts
    from ..protocol.keylog import valid_handle
    if not valid_handle(handle): return error("INVALID_ACCOUNT")
    view = await accounts.view(handle)
    if view is None: return error("UNKNOWN_ACCOUNT", 404)
    return public(view)
