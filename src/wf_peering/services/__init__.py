
__all__ = [
    "AccountService", "CheckpointService", "ConflictService", "IdentityService", "IntegrityService",
    "JournalService", "LedgerService", "PeerService", "StateService", "StatusService", "TrustService",
    "UptimeService"
]


def __getattr__(name):
    if name == "AccountService":
        from wf_peering.services.accounts import AccountService
        return AccountService

    if name == "CheckpointService":
        from wf_peering.services.checkpoints import CheckpointService
        return CheckpointService

    if name == "ConflictService":
        from wf_peering.services.conflicts import ConflictService
        return ConflictService

    if name == "IdentityService":
        from wf_peering.services.identity import IdentityService
        return IdentityService

    if name == "IntegrityService":
        from wf_peering.services.integrity import IntegrityService
        return IntegrityService

    if name == "JournalService":
        from wf_peering.services.journal import JournalService
        return JournalService

    if name == "LedgerService":
        from wf_peering.services.ledger import LedgerService
        return LedgerService

    if name == "PeerService":
        from wf_peering.services.peers import PeerService
        return PeerService

    if name == "StateService":
        from wf_peering.services.state import StateService
        return StateService

    if name == "StatusService":
        from wf_peering.services.status import StatusService
        return StatusService

    if name == "TrustService":
        from wf_peering.services.trust import TrustService
        return TrustService

    if name == "UptimeService":
        from wf_peering.services.uptime import UptimeService
        return UptimeService

    raise AttributeError(name)


def __dir__(): return sorted(__all__)
