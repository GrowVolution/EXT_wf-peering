# wf-peering

> A WebFluid extension: the shared node core of the peering network.

Independent peers replicate, verify and checkpoint what a WebFluid host publishes about itself, so
nobody has to take the host's word for it. The network has two sides with different jobs:

| Role                              | Job                                                                                                                                                                       |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Host**                          | The application that publishes about itself: it keeps the signed ledger, accepts peers on its socket and serves the API under `/peering/api/v1`.                          |
| **Peer**                          | An independent application that watches a host: live replication, the daily full sync, observations of what the host really serves, checkpoints, the API under `/api/v1`. |
| **`wf-peering`** (this extension) | Everything both roles need identically: the protocols, the storage, the verification, checkpoints, the trust assessment and the public API handlers.                      |

Host and peer must reach the same verdict about the same bytes. Keeping that code in one package instead of
a copy on each side is the reason this extension exists; neither role needs the other's code to run.

---

## Why

A host cannot prove by itself that it serves what it claims, and integrity checks that every
project writes for itself are checks nobody can compare. `wf-peering` is the one implementation
both sides of the peering network share — the host and the independent peers — so a
host and its peers reach the same verdict about the same bytes, and every improvement to the
protocol reaches all of them at once. Projects do not build transparency logs or peer
verification; they enable this.

---

## What it contains

| Package                 | Content                                                                                                                                                                               |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `wf_peering.protocol`   | Pure, I/O-free protocol code: canonical JSON, Merkle trees and proofs, ledger entries, key log, signed actions, integrity records, network policy, trust scoring, handshake contexts. |
| `wf_peering.models`     | The SQLAlchemy models (`peering_*` tables) both roles store their state in.                                                                                                           |
| `wf_peering.services`   | Node identity, the signed ledger (`append` on the host, `ingest` on a peer), journal, account replay, integrity storage, peer directory, uptime, checkpoints, trust, status.          |
| `wf_peering.utils`      | `netcheck`: fetching and inspecting a remote origin under the network policy (DNS pinning, TLS, size limits).                                                                         |
| `wf_peering.settings`   | The `PEERING_*` settings of the process (`settings`, `configure`) and the protocol constants (`HOST_API`, `PEER_API`, `HOST_SOCKET`, versions).                                       |
| `wf_peering.role`       | `NodeRole`, the seam between host and peer, and the role the extension was expanded with.                                                                                             |
| `wf_peering.jobs`       | The shared jobs (startup, heartbeat, probes, trust, ledger verification, activity, retention, checkpoint) and `guarded`, which an application wraps its own jobs in.                  |
| `wf_peering.api`        | The public, read-only API handlers both roles serve, and `register()` to mount them on a router.                                                                                      |
| `static/`, `templates/` | The status page both roles render (`/wf-peering/static/…`).                                                                                                                           |

Everything that differs between host and peer is behind one interface, `NodeRole`
(`wf_peering.role`): the startup work, where a checkpoint's ledger size comes from and where it is
published, the signals only one side can observe, the extra status fields. Each side implements it once,
as its host or peer role; the shared services never import a role implementation.

---

## Using it

```python
from wf_peering import peering

peering.expand_fluid(fluid, role=MyHostRole(), root=additive_dir)  # a host, e.g. in an Additive's before_enable
peering.expand_fluid(app, role=MyPeerRole())                       # a peer, e.g. in its prepare_fluid()
```

The extension is expanded with the role of the process that uses it; the settings, jobs, API and
status page it brings are described in [CONTRACT.md](CONTRACT.md).

## For developers and agents

- [CONTRACT.md](CONTRACT.md) — expansion, settings, protocols, public API, trust, limits
- [.agents/SKILL.md](.agents/SKILL.md) — what a coding agent needs to work on or with it
- [CHANGELOG.md](CHANGELOG.md) — what changed, version by version

---

## Installation and tests

```bash
pip install -e extensions/peering          # or: wf ocean install -e peering
pip install -e "extensions/peering[test]"
pytest                                      # in extensions/peering: protocol tests
```

These tests cover the protocol. A role implementation tests its own side against this extension in its
own repository.

---

## License

wf-peering is licensed under the [GNU General Public License v3.0](LICENSE).

## Guide

[DOCS.md](DOCS.md) explains setup, operation and troubleshooting.
