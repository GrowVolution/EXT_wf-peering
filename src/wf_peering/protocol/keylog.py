import hashlib, re
from dataclasses import dataclass, field

from .canonical import digest, CanonicalError
from .signing import b64encode, verify, valid_ed25519, valid_x25519, fingerprint

PROTOCOL = "wf-keylog-v1"
SUBJECT_CONTEXT = "wf-keylog-v1:subject"
AUTHORITY_CONTEXT = "wf-keylog-v1:authority"
GENESIS = "0" * 64

TYPES = ("device.bind", "device.revoke", "recovery.set", "browser.bind", "browser.revoke")
AUTHORITIES = ("self", "device", "recovery", "host", "legacy")

_HANDLE = re.compile(r"^a1\.[A-Za-z0-9_-]{22}$")


def normalize_origin(origin: str) -> str:
    text = (origin or "").strip().lower()
    while text.endswith("/"): text = text[:-1]
    return text


def account_handle(origin: str, user_id: int) -> str:
    raw = f"wf-account-v1\n{normalize_origin(origin)}\n{int(user_id)}".encode("utf-8")
    return "a1." + b64encode(hashlib.sha256(raw).digest()[:16])


def valid_handle(value) -> bool:
    return isinstance(value, str) and bool(_HANDLE.match(value))


@dataclass
class Flag:
    code: str
    severity: str

    def to_dict(self) -> dict:
        return { "code": self.code, "severity": self.severity }


@dataclass
class AccountKeys:
    handle: str
    seq: int = 0
    head: str = GENESIS
    device: dict | None = None
    recovery: str | None = None
    browsers: list = field(default_factory=list)
    broken: bool = False
    flags: list = field(default_factory=list)

    @property
    def anchored(self) -> bool:
        return self.device is not None or self.recovery is not None

    @property
    def device_fingerprint(self) -> str | None:
        return fingerprint(self.device["sig"]) if self.device else None

    def to_dict(self) -> dict:
        return {
            "account": self.handle,
            "seq": self.seq,
            "head": self.head,
            "device": dict(self.device) if self.device else None,
            "device_fingerprint": self.device_fingerprint,
            "recovery": self.recovery,
            "browsers": list(self.browsers),
            "broken": self.broken,
            "flags": [flag.to_dict() for flag in self.flags]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AccountKeys":
        return cls(
            handle=data["account"], seq=data["seq"], head=data["head"],
            device=data.get("device"), recovery=data.get("recovery"),
            browsers=list(data.get("browsers") or []), broken=bool(data.get("broken")),
            flags=[Flag(**flag) for flag in data.get("flags") or []]
        )


@dataclass
class Verdict:
    valid: bool
    applied: bool
    flags: list

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "applied": self.applied,
            "flags": [flag.to_dict() for flag in self.flags]
        }


def statement_hash(statement: dict) -> str:
    return digest(statement)


def _shape(statement) -> list[str]:
    if not isinstance(statement, dict): return ["NOT_AN_OBJECT"]
    issues = []
    allowed = { "v", "account", "seq", "prev", "type", "authority", "keys", "ts", "reset" }
    if not set(statement) <= allowed or not { "v", "account", "seq", "prev", "type", "authority", "keys", "ts" } <= set(statement):
        issues.append("UNEXPECTED_FIELDS")
    if statement.get("v") != 1: issues.append("UNSUPPORTED_VERSION")
    if not valid_handle(statement.get("account")): issues.append("INVALID_ACCOUNT")
    seq = statement.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1: issues.append("INVALID_SEQ")
    if statement.get("type") not in TYPES: issues.append("INVALID_TYPE")
    if statement.get("authority") not in AUTHORITIES: issues.append("INVALID_AUTHORITY")
    if not isinstance(statement.get("keys"), dict): issues.append("INVALID_KEYS")
    ts = statement.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0: issues.append("INVALID_TS")
    if "reset" in statement and not isinstance(statement["reset"], bool): issues.append("INVALID_RESET")
    return issues


def _authority_key(state: AccountKeys, authority: str) -> str | None:
    if authority == "device" and state.device: return state.device["sig"]
    if authority == "recovery" and state.recovery: return state.recovery
    return None


def evaluate(state: AccountKeys, envelope: dict) -> tuple[Verdict, AccountKeys]:
    flags: list[Flag] = []
    statement = (envelope or {}).get("statement")
    signatures = (envelope or {}).get("signatures") or {}

    issues = _shape(statement)
    if issues or (envelope or {}).get("protocol") != PROTOCOL:
        return Verdict(False, False, [Flag(code, "critical") for code in issues or ["UNKNOWN_PROTOCOL"]]), state
    if statement["account"] != state.handle:
        return Verdict(False, False, [Flag("ACCOUNT_MISMATCH", "critical")]), state
    if state.broken:
        return Verdict(False, False, [Flag("AFTER_INVALID_STATEMENT", "critical")]), state

    try: own_hash = statement_hash(statement)
    except CanonicalError:
        return Verdict(False, False, [Flag("NOT_CANONICALIZABLE", "critical")]), state

    if statement["seq"] != state.seq + 1 or statement["prev"] != state.head:
        flags.append(Flag("KEYLOG_CHAIN_BROKEN", "critical"))
        return Verdict(False, False, flags), _broken(state, flags)

    kind, authority, keys = statement["type"], statement["authority"], statement["keys"]

    subject_key = None
    if kind == "device.bind":
        if not valid_ed25519(keys.get("sig")) or not valid_x25519(keys.get("enc")) or set(keys) != { "sig", "enc" }:
            flags.append(Flag("INVALID_KEY_MATERIAL", "critical"))
        subject_key = keys.get("sig")
    elif kind == "recovery.set":
        if not valid_ed25519(keys.get("recovery")) or set(keys) != { "recovery" }:
            flags.append(Flag("INVALID_KEY_MATERIAL", "critical"))
        subject_key = keys.get("recovery")
    elif kind == "browser.bind":
        if not valid_x25519(keys.get("enc")) or set(keys) != { "enc" }:
            flags.append(Flag("INVALID_KEY_MATERIAL", "critical"))
    elif kind == "browser.revoke":
        if set(keys) != { "enc" } or keys.get("enc") not in state.browsers:
            flags.append(Flag("UNKNOWN_BROWSER_KEY", "high"))
    elif kind == "device.revoke":
        if keys and set(keys) != { "sig" }:
            flags.append(Flag("INVALID_KEY_MATERIAL", "critical"))
        if not state.device:
            flags.append(Flag("NOTHING_TO_REVOKE", "high"))

    if any(flag.severity == "critical" for flag in flags):
        return Verdict(False, False, flags), _broken(state, flags)

    if subject_key is not None:
        if signatures.get("subject"):
            if not verify(subject_key, SUBJECT_CONTEXT, statement, signatures["subject"]):
                flags.append(Flag("INVALID_SUBJECT_SIGNATURE", "critical"))
                return Verdict(False, False, flags), _broken(state, flags)
        elif authority in ("host", "legacy"):
            flags.append(Flag("NO_PROOF_OF_POSSESSION", "normal"))
        else:
            flags.append(Flag("INVALID_SUBJECT_SIGNATURE", "critical"))
            return Verdict(False, False, flags), _broken(state, flags)

    if authority == "self":
        if state.anchored:
            flags.append(Flag("SELF_AUTHORITY_ON_ANCHORED_ACCOUNT", "critical"))
            return Verdict(False, False, flags), _broken(state, flags)
        if kind in ("device.revoke", "browser.revoke"):
            flags.append(Flag("SELF_AUTHORITY_NOT_ALLOWED", "critical"))
            return Verdict(False, False, flags), _broken(state, flags)
    elif authority in ("device", "recovery"):
        key = _authority_key(state, authority)
        if key is None:
            flags.append(Flag("AUTHORITY_KEY_MISSING", "critical"))
            return Verdict(False, False, flags), _broken(state, flags)
        if not verify(key, AUTHORITY_CONTEXT, statement, signatures.get("authority") or ""):
            flags.append(Flag("INVALID_AUTHORITY_SIGNATURE", "critical"))
            return Verdict(False, False, flags), _broken(state, flags)
    elif authority == "legacy":
        if statement["seq"] != 1 or kind != "device.bind":
            flags.append(Flag("LEGACY_OUTSIDE_GENESIS", "critical"))
            return Verdict(False, False, flags), _broken(state, flags)
        flags.append(Flag("LEGACY_IMPORT", "normal"))
    elif authority == "host":
        if state.anchored and not statement.get("reset"):
            flags.append(Flag("HOST_ASSERTED_KEY_CHANGE", "critical"))
        elif state.anchored:
            flags.append(Flag("HOST_ASSERTED_RESET", "high"))
        else:
            flags.append(Flag("HOST_ASSERTED_BINDING", "normal"))

    if kind == "browser.bind" and state.device is not None:
        flags.append(Flag("BROWSER_BIND_WHILE_DEVICE_BOUND", "high"))

    nxt = AccountKeys(
        handle=state.handle, seq=statement["seq"], head=own_hash,
        device=dict(state.device) if state.device else None,
        recovery=state.recovery, browsers=list(state.browsers),
        flags=list(state.flags) + flags
    )
    if statement.get("reset") and authority == "host":
        nxt.recovery = None
        nxt.browsers = []
    if kind == "device.bind":
        nxt.device = { "sig": keys["sig"], "enc": keys["enc"] }
        if state.device is None or state.device["sig"] != keys["sig"]:
            nxt.browsers = [] if authority in ("recovery", "host") else nxt.browsers
    elif kind == "device.revoke":
        nxt.device = None
    elif kind == "recovery.set":
        nxt.recovery = keys["recovery"]
    elif kind == "browser.bind":
        if keys["enc"] not in nxt.browsers: nxt.browsers.append(keys["enc"])
    elif kind == "browser.revoke":
        nxt.browsers = [key for key in nxt.browsers if key != keys.get("enc")]

    return Verdict(True, True, flags), nxt


def _broken(state: AccountKeys, flags: list) -> AccountKeys:
    return AccountKeys(
        handle=state.handle, seq=state.seq, head=state.head,
        device=state.device, recovery=state.recovery, browsers=list(state.browsers),
        broken=True, flags=list(state.flags) + flags
    )


def replay(handle: str, envelopes: list[dict]) -> tuple[AccountKeys, list[Verdict]]:
    state = AccountKeys(handle=handle)
    verdicts = []
    for envelope in envelopes:
        verdict, state = evaluate(state, envelope)
        verdicts.append(verdict)
    return state, verdicts
