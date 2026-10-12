import re
from dataclasses import dataclass, field

from .canonical import digest, CanonicalError
from .keylog import AccountKeys, Flag, valid_handle
from .signing import verify

PROTOCOL = "wf-action-v1"
CONTEXT = "wf-action-v1"
GENESIS = "0" * 64
MAX_LIFETIME = 900
CLOCK_SKEW = 300

_ACTION = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9][a-z0-9_.-]{0,63}$")
_TARGET = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}:[A-Za-z0-9_.:-]{1,128}$")
_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")
_FINGERPRINT = re.compile(r"^[A-Za-z0-9_-]{22}$")


@dataclass
class DeviceChain:
    seq: int = 0
    head: str = GENESIS

    def to_dict(self) -> dict:
        return { "seq": self.seq, "head": self.head }


@dataclass
class ActionState:
    devices: dict = field(default_factory=dict)
    ids: set = field(default_factory=set)
    targets: dict = field(default_factory=dict)

    def chain(self, device: str) -> DeviceChain:
        return self.devices.setdefault(device, DeviceChain())

    def to_dict(self) -> dict:
        return {
            "devices": { key: chain.to_dict() for key, chain in sorted(self.devices.items()) },
            "ids": sorted(self.ids),
            "targets": { key: value for key, value in sorted(self.targets.items()) }
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ActionState":
        return cls(
            devices={ key: DeviceChain(**value) for key, value in (data.get("devices") or {}).items() },
            ids=set(data.get("ids") or []),
            targets=dict(data.get("targets") or {})
        )


def action_hash(action: dict) -> str:
    return digest(action)


def shape(action) -> list[str]:
    if not isinstance(action, dict): return ["NOT_AN_OBJECT"]
    issues = []
    expected = { "v", "account", "device", "action", "target", "params", "id", "seq", "prev", "iat", "exp" }
    if set(action) != expected: issues.append("UNEXPECTED_FIELDS")
    if action.get("v") != 1: issues.append("UNSUPPORTED_VERSION")
    if not valid_handle(action.get("account")): issues.append("INVALID_ACCOUNT")
    if not isinstance(action.get("device"), str) or not _FINGERPRINT.match(action.get("device") or ""):
        issues.append("INVALID_DEVICE")
    if not isinstance(action.get("action"), str) or not _ACTION.match(action.get("action") or ""):
        issues.append("INVALID_ACTION")
    if not isinstance(action.get("target"), str) or not _TARGET.match(action.get("target") or ""):
        issues.append("INVALID_TARGET")
    if not isinstance(action.get("params"), dict): issues.append("INVALID_PARAMS")
    if not isinstance(action.get("id"), str) or not _ID.match(action.get("id") or ""):
        issues.append("INVALID_ID")
    for key in ("seq", "iat", "exp"):
        value = action.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < (1 if key == "seq" else 0):
            issues.append(f"INVALID_{key.upper()}")
    prev = action.get("prev")
    if not isinstance(prev, str) or not re.match(r"^[0-9a-f]{64}$", prev): issues.append("INVALID_PREV")
    if not issues:
        if action["exp"] <= action["iat"] or action["exp"] - action["iat"] > MAX_LIFETIME:
            issues.append("INVALID_LIFETIME")
    return issues


def reduce(state: dict | None, params: dict) -> dict | None:
    if not isinstance(params, dict): return None
    if not ({ "set", "unset", "replace" } >= set(params)) or "set" not in params and "unset" not in params:
        return None
    values = params.get("set") or {}
    removed = params.get("unset") or []
    if not isinstance(values, dict) or not isinstance(removed, list): return None
    if not all(isinstance(key, str) for key in removed): return None
    current = {} if params.get("replace") or state is None else dict(state)
    current.update(values)
    for key in removed: current.pop(key, None)
    return current


def state_digest(state: dict) -> str:
    return digest(state)


def evaluate(keys: AccountKeys, state: ActionState, envelope: dict,
             recorded_at: int | None = None) -> tuple[list[Flag], dict]:
    flags: list[Flag] = []
    action = (envelope or {}).get("action")
    signature = (envelope or {}).get("signature")
    result = (envelope or {}).get("result") or {}
    info = { "execution": "unverified", "valid": False }

    issues = shape(action)
    if issues or (envelope or {}).get("protocol") != PROTOCOL:
        return [Flag(code, "critical") for code in issues or ["UNKNOWN_PROTOCOL"]], info
    if action["account"] != keys.handle:
        return [Flag("ACCOUNT_MISMATCH", "critical")], info
    if keys.broken:
        flags.append(Flag("KEYLOG_BROKEN", "critical"))
    if not keys.device:
        return flags + [Flag("NO_BOUND_DEVICE", "critical")], info
    if keys.device_fingerprint != action["device"]:
        return flags + [Flag("FOREIGN_DEVICE_KEY", "critical")], info
    if not verify(keys.device["sig"], CONTEXT, action, signature or ""):
        return flags + [Flag("INVALID_ACTION_SIGNATURE", "critical")], info

    try: own_hash = action_hash(action)
    except CanonicalError:
        return flags + [Flag("NOT_CANONICALIZABLE", "critical")], info

    if action["id"] in state.ids:
        return flags + [Flag("ACTION_REPLAY", "critical")], info

    chain = state.chain(action["device"])
    if action["seq"] <= chain.seq:
        flags.append(Flag("ACTION_SEQUENCE_REUSED", "critical"))
        return flags, info
    if action["seq"] > chain.seq + 1:
        flags.append(Flag("ACTION_SEQUENCE_GAP", "high"))
    elif action["prev"] != chain.head:
        flags.append(Flag("ACTION_CHAIN_FORK", "critical"))

    if recorded_at is not None:
        if recorded_at < action["iat"] - CLOCK_SKEW or recorded_at > action["exp"] + CLOCK_SKEW:
            flags.append(Flag("ACTION_OUTSIDE_VALIDITY", "high"))

    state.ids.add(action["id"])
    chain.seq = action["seq"]
    chain.head = own_hash
    info["valid"] = True
    info["hash"] = own_hash

    outcome = transition(state, action["target"], action["params"], result)
    flags.extend(outcome["flags"])
    info["execution"] = outcome["execution"]
    if outcome.get("state"): info["state"] = outcome["state"]
    return flags, info


def _claimed(result: dict) -> tuple[dict | None, str | None]:
    values = result.get("state_values")
    if not isinstance(values, dict): return None, None
    try: return values, state_digest(values)
    except CanonicalError: return None, None


def transition(state: ActionState, target: str, params: dict, result: dict | None) -> dict:
    result = result or {}
    prior = state.targets.get(target)
    reduced = reduce(prior, params)
    values, claimed = _claimed(result)

    if reduced is None:
        if values is None: return { "flags": [], "execution": "host-claimed" }
        if result.get("state") != claimed:
            return { "flags": [Flag("RESULT_MISMATCH", "critical")], "execution": "mismatch" }
        state.targets[target] = values
        return { "flags": [], "execution": "host-claimed", "state": claimed }

    if prior is None and not params.get("replace"):
        if values is None:
            return { "flags": [Flag("BASELINE_UNKNOWN", "info")], "execution": "unverifiable" }
        consistent = result.get("state") == claimed and all(values.get(k) == v for k, v in (params.get("set") or {}).items())             and not any(k in values for k in params.get("unset") or [])
        if not consistent:
            return { "flags": [Flag("RESULT_MISMATCH", "critical")], "execution": "mismatch" }
        state.targets[target] = values
        return { "flags": [Flag("BASELINE_CLAIMED", "info")], "execution": "baseline-claimed", "state": claimed }

    expected = state_digest(reduced)
    state.targets[target] = reduced
    if result.get("state") is None:
        return { "flags": [Flag("RESULT_NOT_REPORTED", "normal")], "execution": "unreported", "state": expected }
    if result.get("state") != expected:
        return { "flags": [Flag("RESULT_MISMATCH", "critical")], "execution": "mismatch", "state": expected }
    return { "flags": [], "execution": "deterministic", "state": expected }


def apply_unsigned(state: ActionState, target: str, params: dict, result: dict | None = None) -> dict:
    return transition(state, target, params, result)
