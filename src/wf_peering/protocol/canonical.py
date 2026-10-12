import hashlib

MAX_INT = 2 ** 53 - 1
MAX_DEPTH = 32

_SHORT = {
    "\"": "\\\"",
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t"
}


class CanonicalError(ValueError):
    pass


def _string(value: str) -> str:
    out = ['"']
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise CanonicalError("Lone surrogates cannot be canonicalized.")
        if char in _SHORT:
            out.append(_SHORT[char])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _key(value) -> str:
    if not isinstance(value, str):
        raise CanonicalError("Object keys must be strings.")
    if not value or any(not 0x20 <= ord(char) <= 0x7E for char in value):
        raise CanonicalError(f"Object key {value!r} must be non-empty printable ASCII.")
    return value


def _encode(value, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalError("Value is nested too deeply.")
    if value is None: return "null"
    if value is True: return "true"
    if value is False: return "false"
    if isinstance(value, int):
        if not -MAX_INT <= value <= MAX_INT:
            raise CanonicalError("Integers must stay within +/- 2^53 - 1.")
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("Floating point numbers are not canonical.")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(_key(key) for key in value)
        return "{" + ",".join(
            f"{_string(key)}:{_encode(value[key], depth + 1)}" for key in keys
        ) + "}"
    raise CanonicalError(f"Type {type(value).__name__} cannot be canonicalized.")


def canonical(value) -> bytes:
    return _encode(value, 0).encode("utf-8")


def canonical_text(value) -> str:
    return _encode(value, 0)


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_commitment(value) -> str | None:
    if value is None: return None
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()
