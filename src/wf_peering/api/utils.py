from fastapi.responses import JSONResponse
import re

HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
}

_KIND = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9][a-z0-9_.:*-]{0,95}$")
_SUBJECT = re.compile(r"^[A-Za-z0-9_.:@/-]{1,256}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")


def public(data, status: int = 200) -> JSONResponse:
    return JSONResponse(content=data, status_code=status, headers=HEADERS)


def error(code: str, status: int = 400) -> JSONResponse:
    return public({ "detail": code }, status)


def bounded(value, default: int, low: int, high: int) -> int:
    try: number = int(value)
    except (TypeError, ValueError): return default
    return max(low, min(number, high))


def valid_kind(value) -> bool:
    return value is None or bool(_KIND.match(value))


def valid_subject(value) -> bool:
    return value is None or bool(_SUBJECT.match(value))


def valid_day(value) -> bool:
    return value is None or bool(re.match(r"^\d{4}-\d{2}-\d{2}$", value))
