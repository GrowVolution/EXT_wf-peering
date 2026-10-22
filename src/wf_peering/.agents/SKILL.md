---
name: extension-wf-peering
description: Work on or with `wf-peering`, the WebFluid extension that both sides of the peering network share — node identity, the signed hash-chained ledger, key log and signed-action replay, integrity records, Merkle proofs, checkpoints, the trust assessment and the public read-only API. Load it before changing any protocol, verification, ledger or trust code of the peering network, before writing a `NodeRole`, and before mounting its API in a host or peer application.
---

# wf-peering — agent guide

<!-- index -->
This file is short enough to read whole; the ranges are for coming back to one section. Every file
it points to opens with an index of the same shape — read those first 30 lines, then only the ranges
the task needs.

- `23-41` **Rules**
- `42-48` **Verify**
- `49-66` **Contract map**
<!-- /index -->

`wf-peering` is the one implementation every host and every peer run, so both reach the same
verdict about the same bytes. It is a `FluidExtension` that is
expanded with a role, not a battery: the process says whether it is the host or a peer, and the
extension brings storage, jobs, the public API and the status page for that role.

## Rules

1. **Protocol code is pure.** `wf_peering.protocol` does no I/O and depends on nothing but the
   standard library and `cryptography`; a change there changes what every node accepts, so it needs
   a test vector and a version bump of the format it touches.
2. **Host and peer differ only behind `NodeRole`.** Shared services never import a role
   implementation; a new difference becomes a method of the role.
3. **Expand exactly once per process, with one role.** `peering.expand_fluid(fluid, role=…,
   root=…)`; a second expansion with another role raises.
4. **Never weaken a verification to make a sync pass.** Forks, truncations, equivocations and
   signature failures are findings to record, not errors to swallow.
5. **Debug mode is disclosed.** Anything relaxed under `DEBUG_MODE` must keep appearing as
   `debug: true` in signed reports and `/status`.
6. **The public API is read-only** and mounted with the application's limiter through
   `wf_peering.api.register(router, limit)`; write paths belong to the role's own routes.
7. **Every change of a route, a setting or a record format is a contract change.** Record it in
   `CHANGELOG.md` and `CONTRACT.md` with the version it lands in, so every role implementation can
   follow it; this package never adapts itself to one of them.

## Verify

- `pytest` in `../../..` runs the protocol tests; a role implementation tests its own side
  in its own repository.
- `GET /status` of a node shows its role, protocol and schema version, debug flag, ledger head and
  latest checkpoint.

## Contract map

<!-- index ../CONTRACT.md -->
Sections of `../CONTRACT.md`, as that file stands now:

- `26-39` **At a glance**
- `40-93` **Using it**
  - `70-77` Status page and translations
  - `78-93` Debug mode
- `94-127` **Configuration**
- `128-158` **Protocols**
- `159-211` **Public API**
  - `189-203` Integrity records
  - `204-211` Reference manifests
- `212-223` **Trust score**
- `224-234` **Security notes**
- `235-242` **Limits**
<!-- /index -->
