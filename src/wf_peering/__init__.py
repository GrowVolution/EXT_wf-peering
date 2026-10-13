from importlib.metadata import PackageNotFoundError, version as _version

try: __version__ = _version("wf-peering")
except PackageNotFoundError: __version__ = "0+unknown"

from .extension import Peering, peering, ASSETS
from .role import NodeRole
from .settings import HOST_API, PEER_API, HOST_SOCKET, PROTOCOL_VERSION, SCHEMA_VERSION

__all__ = [
    "Peering", "peering", "NodeRole", "ASSETS",
    "HOST_API", "PEER_API", "HOST_SOCKET", "PROTOCOL_VERSION", "SCHEMA_VERSION",
    "__version__"
]
