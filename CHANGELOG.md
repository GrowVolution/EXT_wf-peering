# Changelog

## 1.0.0a1 — unreleased

First version, extracted from the `peering` Additive so that the host (Additive) and the peer (the
`peering` app) share one implementation instead of the peer running the host's Additive.

- Protocols: WF-CJSON-1 canonical JSON, RFC 6962/9162 Merkle roots with inclusion and consistency proofs,
  signed ledger entries and heads, node journal, key log (`wf-keylog-v1`), signed actions (`wf-action-v1`),
  integrity records, checkpoints, trust reports, the host–peer handshake.
- Storage of both roles in `peering_*` tables, the signed ledger with `append` (host) and `ingest` (peer)
  including fork, truncation and equivocation detection.
- Account replay, integrity storage, network policy with DNS pinning, peer directory, uptime, daily
  checkpoints with a role-specific basis, trust assessment with disclosed basis and caps.
- `NodeRole` as the only seam between host and peer.
- The public API handlers with `register()`, and the status page served under `/wf-peering/static`.
- Shared jobs; the startup reset keeps peer sockets that connected before the startup job ran.
- Requires `EXT_BABEL`: the status page is translated on the server (`i18n/default.json`, English and
  German, `PEERING_*` keys) instead of in `status.js` by the browser language.
- Debug mode (`wf run -d`) allows `http` and local addresses like `PEERING_ALLOW_INSECURE`, leaves the
  HTTPS and TLS signals out of the trust assessment and discloses `debug` in every signed trust report.
- Peers without contact for `PEERING_PEER_INACTIVE_DAYS` days (30; `0` turns it off) become inactive and
  leave `GET /peers`, the status counts and the trust population; they are re-checked daily, come back on
  the next contact, and every expiry is journaled as `peering:peers-inactive`.
- Key log: `browser.link` and `browser.unlink` with the replayed `links`, `HOST_ASSERTED_LINK` (critical) and
  `HOST_ASSERTED_UNLINK` (normal); `self` may not link or unlink; links end with a device bound by recovery
  or the host and with `device.revoke`. A `device.revoke` with `reset: true` is valid without a bound device.
- Layout: the settings, `NodeRole` and the shared jobs are modules of their own (`wf_peering.settings`,
  `wf_peering.role`, `wf_peering.jobs`, the latter formerly `services/tasks.py`), and the network checks
  moved to `wf_peering.utils.netcheck`; `services/` keeps the stateful parts. The package's `__all__` is
  unchanged.
- Pushed integrity records (`Integrity.push_id`, `Integrity.retract`): appended when an artifact changes,
  never marked missing by an integrity run, retracted only by their owner. Records with `served: false`
  are listed separately on the status page.
