
TABLE_PREFIX = "peering_"


def all_models() -> list:
    from .ledger import LedgerEntry, JournalEntry
    from .peers import Peer, PeerConnection, Probe
    from .sync import SyncRun, Checkpoint, RemoteCheckpoint
    from .integrity import IntegrityRun, IntegrityRecord, IntegrityCurrent, Observation
    from .state import NodeState, Conflict, TrustSnapshot, AccountView
    return [
        LedgerEntry, JournalEntry, Peer, PeerConnection, Probe, SyncRun, Checkpoint,
        RemoteCheckpoint, IntegrityRun, IntegrityRecord, IntegrityCurrent, Observation,
        NodeState, Conflict, TrustSnapshot, AccountView
    ]


def set_bind(key):
    if not key: return
    for model in all_models():
        if getattr(model, "__bind_key__", None) is None:
            model.set_bind(key)


from .ledger import LedgerEntry, JournalEntry
from .peers import Peer, PeerConnection, Probe
from .sync import SyncRun, Checkpoint, RemoteCheckpoint
from .integrity import IntegrityRun, IntegrityRecord, IntegrityCurrent, Observation
from .state import NodeState, Conflict, TrustSnapshot, AccountView

__all__ = [
    "TABLE_PREFIX", "all_models", "set_bind",
    "LedgerEntry", "JournalEntry", "Peer", "PeerConnection", "Probe", "SyncRun", "Checkpoint",
    "RemoteCheckpoint", "IntegrityRun", "IntegrityRecord", "IntegrityCurrent", "Observation",
    "NodeState", "Conflict", "TrustSnapshot", "AccountView"
]
