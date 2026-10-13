from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from datetime import datetime, UTC
import asyncio, hashlib, json, socket, ssl, time
import httpx

from ..protocol.netpolicy import Target, PolicyError, parse_target, address_allowed
from ..settings import settings

USER_AGENT = "webfluid-peering/1"
CONCURRENCY = 8

_VERIFY_CODES = {
    9: "CERT_NOT_YET_VALID",
    10: "CERT_EXPIRED",
    18: "SELF_SIGNED",
    19: "SELF_SIGNED_CHAIN",
    20: "UNTRUSTED_ISSUER",
    21: "UNTRUSTED_ISSUER",
    62: "HOSTNAME_MISMATCH"
}


class CheckError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


_semaphore: asyncio.Semaphore | None = None


def _gate() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None: _semaphore = asyncio.Semaphore(CONCURRENCY)
    return _semaphore


def target(url: str, allowed_ports=(443,)) -> Target:
    try: return parse_target(url, settings.allow_insecure, allowed_ports)
    except PolicyError as exc: raise CheckError(str(exc)) from exc


async def resolve(where: Target) -> dict:
    if where.is_ip:
        if not address_allowed(where.host, settings.allow_insecure):
            raise CheckError("ADDRESS_NOT_ALLOWED", where.host)
        family = "v6" if ":" in where.host else "v4"
        return { "v4": [where.host] if family == "v4" else [], "v6": [where.host] if family == "v6" else [],
                 "rejected": [] }

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(where.host, where.port, type=socket.SOCK_STREAM), timeout=5
        )
    except (socket.gaierror, OSError) as exc: raise CheckError("DNS_FAILED", str(exc)) from exc
    except asyncio.TimeoutError as exc: raise CheckError("DNS_TIMEOUT") from exc

    v4, v6, rejected = [], [], []
    for family, _, _, _, sockaddr in infos:
        address = sockaddr[0]
        if not address_allowed(address, settings.allow_insecure):
            if address not in rejected: rejected.append(address)
            continue
        bucket = v4 if family == socket.AF_INET else v6
        if address not in bucket: bucket.append(address)
    if rejected and not settings.allow_insecure:
        raise CheckError("ADDRESS_NOT_ALLOWED", ",".join(rejected))
    if not v4 and not v6: raise CheckError("NO_ADDRESS")
    return { "v4": sorted(v4), "v6": sorted(v6), "rejected": rejected }


def _context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _name(entries) -> str:
    return ", ".join("=".join(part) for entry in entries or () for part in entry)


async def tls(where: Target, address: str) -> dict:
    if where.scheme != "https": return { "ok": False, "error": "NO_TLS" }
    started = time.monotonic()
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(
            address, where.port, ssl=_context(), server_hostname=where.host
        ), timeout=settings.timeout)
        tls_object = writer.get_extra_info("ssl_object")
        info = tls_object.getpeercert()
        der = tls_object.getpeercert(binary_form=True)
        certificate = x509.load_der_x509_certificate(der)
        key = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        not_after = certificate.not_valid_after_utc
        return {
            "ok": True,
            "version": tls_object.version(),
            "subject": _name(info.get("subject")),
            "issuer": _name(info.get("issuer")),
            "names": [value for kind, value in info.get("subjectAltName", ()) if kind == "DNS"],
            "not_before": certificate.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_left": int((not_after - datetime.now(UTC)).total_seconds() // 86400),
            "key": hashlib.sha256(key).hexdigest(),
            "latency_ms": int((time.monotonic() - started) * 1000)
        }
    except ssl.SSLCertVerificationError as exc:
        return { "ok": False, "error": _VERIFY_CODES.get(exc.verify_code, "CERT_INVALID"),
                 "detail": exc.verify_message }
    except ssl.SSLError as exc:
        return { "ok": False, "error": "TLS_FAILED", "detail": str(exc)[:200] }
    except asyncio.TimeoutError:
        return { "ok": False, "error": "TLS_TIMEOUT" }
    except OSError as exc:
        return { "ok": False, "error": "UNREACHABLE", "detail": str(exc)[:200] }
    finally:
        if writer is not None:
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (asyncio.TimeoutError, OSError, ssl.SSLError): pass


def _literal(address: str) -> str:
    return f"[{address}]" if ":" in address else address


async def fetch(where: Target, address: str, path: str, max_bytes: int | None = None) -> dict:
    if not path.startswith("/") or path.startswith("//"): raise CheckError("INVALID_PATH")
    limit = max_bytes or settings.max_response_bytes
    default = 443 if where.scheme == "https" else 80
    host_header = where.host if where.port == default else f"{where.host}:{where.port}"
    url = f"{where.scheme}://{_literal(address)}:{where.port}{path}"
    extensions = { "sni_hostname": where.host } if where.scheme == "https" else {}
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
                verify=_context(), timeout=httpx.Timeout(settings.timeout),
                follow_redirects=False, trust_env=False
        ) as client:
            async with client.stream("GET", url, headers={
                "Host": host_header, "Accept": "application/json, */*;q=0.5", "User-Agent": USER_AGENT
            }, extensions=extensions) as response:
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > limit: raise CheckError("RESPONSE_TOO_LARGE")
                    chunks.append(chunk)
                return {
                    "status": response.status_code,
                    "body": b"".join(chunks),
                    "type": response.headers.get("content-type", ""),
                    "latency_ms": int((time.monotonic() - started) * 1000)
                }
    except httpx.TimeoutException as exc: raise CheckError("TIMEOUT") from exc
    except httpx.ConnectError as exc:
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text:
            code = "HOSTNAME_MISMATCH" if "mismatch" in text.lower() or "doesn't match" in text.lower() else "CERT_INVALID"
            raise CheckError(code, text[:200]) from exc
        raise CheckError("UNREACHABLE", text[:200]) from exc
    except httpx.HTTPError as exc: raise CheckError("HTTP_FAILED", str(exc)[:200]) from exc


async def get(url: str, path: str, max_bytes: int | None = None, allowed_ports=(443,)) -> dict:
    async with _gate():
        where = target(url, allowed_ports)
        addresses = await resolve(where)
        candidates = addresses["v4"] + addresses["v6"]
        last = None
        for address in candidates[:3]:
            try:
                result = await fetch(where, address, path, max_bytes)
                result["address"] = address
                result["addresses"] = addresses
                return result
            except CheckError as exc:
                last = exc
                if exc.code not in ("UNREACHABLE", "TIMEOUT"): raise
        raise last or CheckError("UNREACHABLE")


async def get_json(url: str, path: str, max_bytes: int | None = None) -> tuple[int, object, dict]:
    result = await get(url, path, max_bytes)
    try: data = json.loads(result["body"].decode("utf-8")) if result["body"] else None
    except (UnicodeDecodeError, ValueError): data = None
    return result["status"], data, result


async def reference(url: str, max_bytes: int = 512 * 1024) -> bytes:
    if not isinstance(url, str) or not url.startswith("https://"):
        raise CheckError("REFERENCE_NOT_HTTPS")
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.hostname not in settings.reference_hosts or parts.username or parts.password or parts.port not in (None, 443):
        raise CheckError("REFERENCE_HOST_NOT_ALLOWED", parts.hostname or "")
    path = parts.path + (f"?{parts.query}" if parts.query else "")
    async with _gate():
        where = Target("https", parts.hostname, 443, False)
        addresses = await resolve(where)
        result = await fetch(where, (addresses["v4"] + addresses["v6"])[0], path, max_bytes)
    if result["status"] != 200: raise CheckError("REFERENCE_HTTP_ERROR", str(result["status"]))
    return result["body"]


async def inspect(url: str) -> dict:
    report = { "url": url, "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") }
    try:
        where = target(url, (443,) if not settings.allow_insecure else (443, 80))
    except CheckError as exc:
        report.update(ok=False, error=exc.code)
        return report
    report["https"] = where.scheme == "https"
    try:
        report["dns"] = await resolve(where)
    except CheckError as exc:
        report.update(ok=False, error=exc.code, detail=exc.detail)
        return report
    address = (report["dns"]["v4"] + report["dns"]["v6"])[0]
    async with _gate():
        report["tls"] = await tls(where, address)
    return report
