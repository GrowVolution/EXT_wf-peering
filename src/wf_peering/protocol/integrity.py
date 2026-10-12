import re

from .canonical import canonical, digest, CanonicalError

ALGORITHMS = { "sha256": 64, "sha384": 96, "sha512": 128 }
PROVENANCE = (
    "unsigned", "signed", "reference-match", "reference-mismatch",
    "reference-unavailable", "unknown"
)
MAX_RECORD_BYTES = 16 * 1024
MAX_RECORDS = 256

_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{1,127}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_STRINGS = ("additive", "type", "version", "served_version", "latest_version", "label", "parent")
_OBJECTS = ("context", "provenance", "reference", "extra")
_IDENTITY = ("hash", "algorithm", "version", "served_version", "latest_version", "url", "parent")


class IntegrityError(ValueError):
    pass


def _hash(value, algorithm) -> str:
    if not isinstance(value, str): raise IntegrityError("INVALID_HASH")
    value = value.strip().lower()
    if len(value) != ALGORITHMS[algorithm] or not _HEX.match(value):
        raise IntegrityError("INVALID_HASH")
    return value


def normalize(record, provider: str | None = None) -> dict:
    if not isinstance(record, dict): raise IntegrityError("NOT_AN_OBJECT")
    artifact = record.get("id")
    if not isinstance(artifact, str) or not _ID.match(artifact):
        raise IntegrityError("INVALID_ID")

    algorithm = (record.get("algorithm") or "sha256")
    if algorithm not in ALGORITHMS: raise IntegrityError("UNSUPPORTED_ALGORITHM")

    out = {
        "id": artifact,
        "algorithm": algorithm,
        "hash": _hash(record.get("hash"), algorithm),
        "additive": record.get("additive") or provider
    }
    for key in _STRINGS:
        if key == "additive": continue
        value = record.get(key)
        if value is None: continue
        if not isinstance(value, str) or len(value) > 256:
            raise IntegrityError(f"INVALID_{key.upper()}")
        out[key] = value
    if out["additive"] is not None and not isinstance(out["additive"], str):
        raise IntegrityError("INVALID_ADDITIVE")

    for key in _OBJECTS:
        value = record.get(key)
        if value is None: continue
        if not isinstance(value, dict): raise IntegrityError(f"INVALID_{key.upper()}")
        out[key] = value

    url = record.get("url")
    if url is not None:
        if not isinstance(url, str) or not url.startswith("/") or url.startswith("//") or len(url) > 512:
            raise IntegrityError("INVALID_URL")
        out["url"] = url

    served = record.get("served")
    if served is not None:
        if not isinstance(served, bool): raise IntegrityError("INVALID_SERVED")
        out["served"] = served

    size = record.get("size")
    if size is not None:
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise IntegrityError("INVALID_SIZE")
        out["size"] = size

    computed = record.get("computed_at")
    if computed is not None:
        if not isinstance(computed, str) or not _TS.match(computed):
            raise IntegrityError("INVALID_COMPUTED_AT")
        out["computed_at"] = computed

    provenance = out.get("provenance")
    if provenance is not None and provenance.get("status") not in PROVENANCE:
        raise IntegrityError("INVALID_PROVENANCE")

    reference = out.get("reference")
    if reference is not None and reference.get("hash") is not None:
        ref_algorithm = reference.get("algorithm") or algorithm
        if ref_algorithm not in ALGORITHMS: raise IntegrityError("INVALID_REFERENCE")
        reference = dict(reference)
        reference["hash"] = _hash(reference["hash"], ref_algorithm)
        out["reference"] = reference

    try: size = len(canonical(out))
    except CanonicalError as exc: raise IntegrityError("NOT_CANONICALIZABLE") from exc
    if size > MAX_RECORD_BYTES: raise IntegrityError("RECORD_TOO_LARGE")
    return out


def identity(record: dict) -> dict:
    out = { key: record.get(key) for key in _IDENTITY }
    out["provenance"] = (record.get("provenance") or {}).get("status")
    out["reference"] = (record.get("reference") or {}).get("hash")
    return out


def fingerprint(record: dict) -> str:
    return digest(identity(record))


def aggregate(results) -> list[dict]:
    groups = []
    if not isinstance(results, list): results = [results]
    for index, result in enumerate(results):
        group = { "provider": None, "status": "ok", "records": [], "errors": [] }
        if result is None:
            group["status"] = "failed"
            group["errors"].append({ "code": "PROVIDER_FAILED" })
            group["provider"] = f"unknown-{index}"
            groups.append(group)
            continue
        if isinstance(result, dict): result = [result]
        if not isinstance(result, list):
            group["status"] = "invalid"
            group["errors"].append({ "code": "NOT_A_LIST" })
            group["provider"] = f"unknown-{index}"
            groups.append(group)
            continue

        seen = set()
        for position, record in enumerate(result[:MAX_RECORDS]):
            provider = record.get("additive") if isinstance(record, dict) else None
            group["provider"] = group["provider"] or provider
            try:
                normalized = normalize(record, provider)
            except IntegrityError as exc:
                group["errors"].append({ "code": str(exc), "position": position })
                continue
            if normalized["id"] in seen:
                group["errors"].append({ "code": "DUPLICATE_ID", "position": position })
                continue
            seen.add(normalized["id"])
            group["records"].append(normalized)

        if len(result) > MAX_RECORDS:
            group["errors"].append({ "code": "TOO_MANY_RECORDS" })
        if group["errors"]:
            group["status"] = "partial" if group["records"] else "invalid"
        group["provider"] = group["provider"] or f"unknown-{index}"
        groups.append(group)
    return groups
