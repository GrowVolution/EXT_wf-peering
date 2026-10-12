from datetime import datetime, UTC
import re

from .canonical import canonical, sha256_hex, CanonicalError
from .merkle import leaf_hash
from .signing import verify

VERSION = 1
LEDGER_CONTEXT = "wf-ledger-v1"
JOURNAL_CONTEXT = "wf-journal-v1"
HEAD_CONTEXT = "wf-ledger-head-v1"
GENESIS = "0" * 64

_KIND = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9][a-z0-9_.:-]{0,95}$")
_SOURCE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX = re.compile(r"^[0-9a-f]{64}$")

MAX_ENTRY_BYTES = 64 * 1024


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_ts(value: datetime) -> str:
    if value.tzinfo is None: value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str) -> datetime:
    if not isinstance(value, str) or not _TS.match(value):
        raise ValueError("INVALID_TIMESTAMP")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def make(seq: int, prev: str, kind: str, source: str, body: dict, ts: str | None = None,
         subject: str | None = None, ref: str | None = None, auth: dict | None = None) -> dict:
    return {
        "v": VERSION,
        "seq": seq,
        "prev": prev,
        "kind": kind,
        "source": source,
        "ts": ts or utc_now(),
        "subject": subject,
        "ref": ref,
        "auth": auth or { "type": "host" },
        "body": body
    }


def content_bytes(content: dict) -> bytes:
    return canonical(content)


def entry_hash(content: dict) -> str:
    return sha256_hex(content_bytes(content))


def entry_leaf(content: dict) -> str:
    return leaf_hash(content_bytes(content))


def problems(content) -> list[str]:
    issues = []
    if not isinstance(content, dict): return ["NOT_AN_OBJECT"]
    expected = { "v", "seq", "prev", "kind", "source", "ts", "subject", "ref", "auth", "body" }
    if set(content) != expected: issues.append("UNEXPECTED_FIELDS")
    if content.get("v") != VERSION: issues.append("UNSUPPORTED_VERSION")
    seq = content.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1: issues.append("INVALID_SEQ")
    if not isinstance(content.get("prev"), str) or not _HEX.match(content.get("prev") or ""):
        issues.append("INVALID_PREV")
    if not isinstance(content.get("kind"), str) or not _KIND.match(content.get("kind") or ""):
        issues.append("INVALID_KIND")
    if not isinstance(content.get("source"), str) or not _SOURCE.match(content.get("source") or ""):
        issues.append("INVALID_SOURCE")
    if not isinstance(content.get("ts"), str) or not _TS.match(content.get("ts") or ""):
        issues.append("INVALID_TIMESTAMP")
    for key in ("subject", "ref"):
        value = content.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 256):
            issues.append(f"INVALID_{key.upper()}")
    if not isinstance(content.get("auth"), dict) or not isinstance((content.get("auth") or {}).get("type"), str):
        issues.append("INVALID_AUTH")
    if not isinstance(content.get("body"), dict): issues.append("INVALID_BODY")
    if not issues:
        try:
            if len(content_bytes(content)) > MAX_ENTRY_BYTES: issues.append("ENTRY_TOO_LARGE")
        except CanonicalError: issues.append("NOT_CANONICALIZABLE")
    return issues


def sign_hash(signer, context: str, value: str) -> str:
    return signer.sign(context, value.encode("ascii"))


def verify_hash(public_key: str, context: str, value: str, signature: str) -> bool:
    return verify(public_key, context, value.encode("ascii"), signature)


def check_link(content: dict, previous_hash: str, previous_seq: int) -> list[str]:
    issues = []
    if content.get("seq") != previous_seq + 1: issues.append("SEQUENCE_GAP")
    if content.get("prev") != previous_hash: issues.append("BROKEN_CHAIN")
    return issues


def head(seq: int, value: str, root: str, ts: str, origin: str, protocol: int, schema: int) -> dict:
    return {
        "seq": seq,
        "hash": value,
        "root": root,
        "ts": ts,
        "origin": origin,
        "protocol": protocol,
        "schema": schema
    }
