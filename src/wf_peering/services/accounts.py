from webfluid.core.ext import db
from sqlalchemy import select

from ..models.state import AccountView
from ..protocol import keylog, actions
from ..protocol.canonical import CanonicalError
from ..protocol.entries import parse_ts, utc_now
from ..protocol.keylog import AccountKeys, Flag
from ..protocol.actions import ActionState
from .store import dumps, loads

CHANGE_PROTOCOL = "wf-change-v1"
PROTOCOLS = (keylog.PROTOCOL, actions.PROTOCOL, CHANGE_PROTOCOL)


def _account(body: dict) -> str | None:
    protocol = body.get("protocol")
    if protocol == keylog.PROTOCOL: return ((body.get("statement") or {}).get("account"))
    if protocol == actions.PROTOCOL: return ((body.get("action") or {}).get("account"))
    if protocol == CHANGE_PROTOCOL: return body.get("account")
    return None


async def _load(e, handle: str):
    result = await e.exec(select(AccountView).where(AccountView.handle == handle))
    view = result.first()
    if view is None:
        return None, AccountKeys(handle=handle), ActionState()
    return view, AccountKeys.from_dict(loads(view.keys)), ActionState.from_dict(loads(view.actions, {}))


async def _save(e, view, handle: str, keys: AccountKeys, state: ActionState, flags: list, seq: int):
    history = (loads(view.flags, []) if view else []) + [dict(flag, seq=seq) for flag in flags]
    if view is None:
        await e.insert(AccountView(
            handle=handle, keys=dumps(keys.to_dict()), actions=dumps(state.to_dict()),
            flags=dumps(history[-200:]), ledger_seq=seq, updated_at=utc_now()
        ))
        return
    view.keys = dumps(keys.to_dict())
    view.actions = dumps(state.to_dict())
    view.flags = dumps(history[-200:])
    view.ledger_seq = seq
    view.updated_at = utc_now()


def _verdict(flags: list) -> str:
    severities = { flag["severity"] for flag in flags }
    if "critical" in severities: return "invalid"
    if severities & { "high", "normal" }: return "flagged"
    return "verified"


async def apply(e, content: dict) -> dict:
    body = content.get("body") or {}
    protocol = body.get("protocol")
    if protocol not in PROTOCOLS:
        return { "protocol": protocol, "verification": "host-claimed", "flags": [] }

    handle = _account(body)
    if not keylog.valid_handle(handle):
        return { "protocol": protocol, "verification": "invalid",
                 "flags": [{ "code": "INVALID_ACCOUNT", "severity": "critical" }] }

    view, keys, state = await _load(e, handle)
    info = {}
    try:
        if protocol == keylog.PROTOCOL:
            verdict, keys = keylog.evaluate(keys, body)
            flags = [flag.to_dict() for flag in verdict.flags]
        elif protocol == actions.PROTOCOL:
            try: recorded = int(parse_ts(content.get("ts")).timestamp())
            except ValueError: recorded = None
            raw, info = actions.evaluate(keys, state, body, recorded)
            flags = [flag.to_dict() for flag in raw]
        else:
            flags = _change(state, body)
    except CanonicalError:
        flags = [{ "code": "NOT_CANONICALIZABLE", "severity": "critical" }]

    await _save(e, view, handle, keys, state, flags, content.get("seq") or 0)
    result = { "protocol": protocol, "account": handle, "verification": _verdict(flags), "flags": flags }
    if info.get("execution"): result["execution"] = info["execution"]
    return result


def _change(state: ActionState, body: dict) -> list[dict]:
    target, params = body.get("target"), body.get("params")
    if not isinstance(target, str) or not isinstance(params, dict):
        return [{ "code": "INVALID_CHANGE", "severity": "critical" }]
    outcome = actions.apply_unsigned(state, target, params, body.get("result"))
    return [{ "code": "UNSIGNED_CHANGE", "severity": "info" }] + [flag.to_dict() for flag in outcome["flags"]]


async def view(handle: str) -> dict | None:
    async with db.async_executor(model=AccountView) as e:
        result = await e.exec(select(AccountView).where(AccountView.handle == handle))
        row = result.first()
        if not row: return None
        state = loads(row.actions, {})
        return {
            "account": row.handle,
            "keys": loads(row.keys),
            "devices": state.get("devices") or {},
            "actions": len(state.get("ids") or []),
            "targets": {
                name: actions.state_digest(values) for name, values in (state.get("targets") or {}).items()
            },
            "flags": loads(row.flags, []),
            "ledger_seq": row.ledger_seq,
            "updated_at": row.updated_at
        }


async def flagged_counts() -> dict:
    counts = { "critical": 0, "high": 0, "normal": 0, "host_asserted": 0 }
    async with db.async_executor(model=AccountView) as e:
        result = await e.exec(select(AccountView.flags))
        for raw in result.all():
            for flag in loads(raw, []):
                severity = flag.get("severity")
                if severity in counts: counts[severity] += 1
                if str(flag.get("code", "")).startswith("HOST_ASSERTED"): counts["host_asserted"] += 1
    return counts


def critical(result: dict) -> list[dict]:
    return [flag for flag in result.get("flags") or [] if flag.get("severity") == "critical"]


__all__ = ["apply", "view", "flagged_counts", "critical", "PROTOCOLS", "CHANGE_PROTOCOL", "Flag"]
