import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.jp", "ne.jp", "or.jp", "com.au", "net.au",
    "org.au", "co.nz", "com.br", "com.cn", "com.tr", "co.in", "co.za", "com.mx", "github.io",
    "gitlab.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "onrender.com",
    "fly.dev", "workers.dev", "azurewebsites.net", "cloudfront.net", "appspot.com"
}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    is_ip: bool

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")


def parse_target(url: str, allow_insecure: bool = False, allowed_ports=(443,)) -> Target:
    if not isinstance(url, str) or len(url) > 512 or any(ord(char) < 0x21 for char in url):
        raise PolicyError("INVALID_URL")
    try: parts = urlsplit(url.strip())
    except ValueError as exc: raise PolicyError("INVALID_URL") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("https", "http") or (scheme == "http" and not allow_insecure):
        raise PolicyError("HTTPS_REQUIRED")
    if parts.username is not None or parts.password is not None:
        raise PolicyError("CREDENTIALS_NOT_ALLOWED")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise PolicyError("ORIGIN_ONLY")

    host = (parts.hostname or "").lower().rstrip(".")
    if not host: raise PolicyError("INVALID_HOST")
    try: port = parts.port
    except ValueError as exc: raise PolicyError("INVALID_PORT") from exc
    port = port or (443 if scheme == "https" else 80)
    if port not in allowed_ports and not (allow_insecure and port >= 1024):
        raise PolicyError("PORT_NOT_ALLOWED")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        labels = host.split(".")
        if len(host) > 253 or any(not label or len(label) > 63 for label in labels):
            raise PolicyError("INVALID_HOST")
        if not all(char.isalnum() or char == "-" for label in labels for char in label):
            raise PolicyError("INVALID_HOST")
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") \
                or host.endswith(".internal") or "." not in host:
            if not allow_insecure: raise PolicyError("INTERNAL_HOST")
    return Target(scheme, host, port, is_ip)


def address_allowed(address: str, allow_private: bool = False) -> bool:
    try: ip = ipaddress.ip_address(address)
    except ValueError: return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast: return False
    if allow_private: return True
    return ip.is_global and not ip.is_reserved


def registrable_domain(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError: pass
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2: return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def network_prefix(address: str) -> str | None:
    try: ip = ipaddress.ip_address(address)
    except ValueError: return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/48", strict=False))


def clusters(observers: dict[str, dict]) -> list[list[str]]:
    parent = { name: name for name in observers }

    def find(name):
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb: parent[rb] = ra

    owners = {}
    for name, info in observers.items():
        markers = set()
        for address in info.get("addresses") or []:
            prefix = network_prefix(address)
            if prefix: markers.add(f"net:{prefix}")
        domain = info.get("domain")
        if domain: markers.add(f"domain:{registrable_domain(domain)}")
        for key in ("cert_key", "node_key", "operator"):
            if info.get(key): markers.add(f"{key}:{info[key]}")
        for marker in markers:
            if marker in owners: union(owners[marker], name)
            else: owners[marker] = name

    groups = {}
    for name in observers:
        groups.setdefault(find(name), []).append(name)
    return sorted((sorted(group) for group in groups.values()), key=lambda group: group[0])
