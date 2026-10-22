# wf-peering — Documentation

`wf-peering` is the shared core of the peering network: the code a **host** and its independent
**peers** both run, so that they reach the same verdict about the same bytes. A host publishes facts
about itself — what it serves, which keys its users' accounts hold, what those users signed — and
peers that anyone can operate replicate those facts, check every signature and hash themselves,
observe what the host really serves, and sign what they found. Nobody has to take the host's word
for it.

This guide explains the ideas behind the protocol, how a process takes one of the two roles, what an
operator configures, and what the network can and cannot prove. The exact settings, routes and
signature contexts are in [CONTRACT.md](src/wf_peering/CONTRACT.md).

---

## The ideas

**A node** is one running process in the network, host or peer. It has an Ed25519 **node key**,
created on first start and kept in a file, and a signed **statement**: its id, key, role, public URL
and the host it belongs to. Everything a node says is signed with that key.

**The ledger** is the host's append-only record. Each entry is hashed together with the previous
one, so the entries form a chain, and the host signs every entry and every **head** (the size, the
latest hash and the Merkle root over all entries). An entry records an integrity change, an account
key statement or a signed user action. Peers copy the ledger and verify each entry as it arrives; a
host that rewrites, truncates or forks its history contradicts a signed head it already gave out,
and the peers keep both as evidence.

**Merkle proofs** let anyone check that one entry is part of a ledger of a given size, or that a
larger ledger extends a smaller one, without downloading either — the same construction as
certificate transparency (RFC 6962/9162).

**The journal** is a node's own signed log of what it did: connections, syncs, conflicts, peers that
went inactive. It makes a node's behaviour reviewable, not only the host's.

**Account replay.** Account key changes and signed user actions are in the ledger, so a peer replays
every account from the ledger and arrives at the same state as the host — or records exactly where
it does not. A key change the host asserts without a proof from the account's own keys is flagged.

**Integrity records** say which artifact — a script, a source tree, a release — has which hash. Peers
fetch the publicly served ones and compare, and they compare the host's claim with a **reference
manifest** the artifact's maintainer publishes elsewhere, so even a host that lies consistently to
everyone can be caught for artifacts with an independent reference.

**Checkpoints.** Once a day every node signs a checkpoint: the ledger size, root and head it
verified, the replayed account state, its journal, and the previous checkpoint. Peers exchange
checkpoints and the network shows where they agree.

**The trust score** condenses all of this into 0–100, from five categories — integrity, keys,
reachability, history and diversity. Severe findings cap the score instead of being averaged away,
and a score without at least two independent observers is capped at 70. Without any independent
observer, or with too little data, the status is **unclear** — never green. Every report discloses
its signals, their age and the basis it was computed on.

---

## Two roles, one package

Everything host and peer do differently sits behind one interface, `NodeRole`: what runs at startup,
where a checkpoint's ledger size comes from and where it is published, which signals only one side
can observe, what the status page shows in addition. A process expands the extension once, with
exactly one role:

```python
from wf_peering import peering

peering.expand_fluid(fluid, role=MyHostRole(), root=additive_dir)   # a host
peering.expand_fluid(app, role=MyPeerRole())                        # a peer
```

Expansion binds the `peering_*` tables, loads or creates the node key, registers the status page
assets, template and translations, and — unless `PEERING_SCHEDULE = False` — schedules the jobs both
roles share: heartbeat, probes, trust, ledger verification, activity, retention and the daily
checkpoint. Each role adds its own jobs on top. The shared services never import a role, so the
host side never carries peer code and the other way round.

`wf-peering` is not a battery: it is not switched on with an `EXT_*` flag but expanded by the code
that takes a role. It needs the SQLAlchemy and Babel batteries, and the scheduling battery unless
jobs are off; expansion names the missing one if it is not enabled.

---

## Operating a node

**The node key.** `PEERING_KEY_FILE` (default `keys/node.key`, relative to the role's root) holds the
seed and is created with mode `0600`. Keep it out of version control and in your backups: a node that
loses its key becomes a new node, and a host whose key changes is reported by every peer. A peer can
pin the host's key with `PEERING_HOST_KEY` instead of trusting the first one it sees.

**One origin.** A node's public URL is part of its signed statement, and account handles derive from
the host's origin. Serve the host under exactly one address; a host reached as `localhost` in one
place and as a LAN address in another makes its peers report a mismatch.

**Network policy.** Every outgoing request goes through one policy: `https` only, global addresses
only, DNS resolved once and pinned, bounded sizes and timeouts, no proxies and no redirects.
`PEERING_ALLOW_INSECURE` lifts the first two for local development; debug mode (`wf run -d`) implies
it, keeps the HTTPS signals out of the trust score and stamps every report with `debug: true`, so a
debug report is never mistaken for a production one.

**One process per node.** The scheduler and the live link state are in memory. Run a node as a
single process.

**Schedules.** The daily checkpoint runs at `PEERING_CHECKPOINT_TIME` (UTC), integrity work every
`PEERING_INTEGRITY_INTERVAL` seconds, probes and trust on their own intervals. Peers that have not
been seen for `PEERING_PEER_INACTIVE_DAYS` drop out of every statistic until they are seen again.

---

## What the network can and cannot establish

It can establish that the host's history is consistent, that every signature and hash chain
verifies, that account key changes carry the account's own proof, that what the host serves matches
what it claims, and — where a maintainer publishes a reference — that the claim matches the
reference. Every finding is recorded with the signed evidence.

It cannot see inside the host's server. A host that lies the same way to everyone from the start is
caught only where an independent reference exists, and a host decides which peers it lists — though
peers compare among themselves, and their API is public, so anyone can ask a peer instead of the
host. The independence check sees infrastructure, not operators: two peers of one person on
unrelated providers count as independent. A clean result means agreement, not a guarantee.

Nodes exchange only public data: signed statements, ledger entries with pseudonymous account handles
and public keys, checkpoints and reports. No private key, credential, session or plaintext profile
data is ever replicated.

---

## Installing

```bash
wf ocean install -e peering --prefer-stable
```

or, from a checkout, `pip install -e extensions/peering`. The test suite covers the protocol:

```bash
pip install -e "extensions/peering[test]"
pytest
```

`tests/vectors.py` produces the cross-language vectors that any other implementation of the
canonical JSON and signatures must reproduce byte for byte.

---

## Troubleshooting

| You see                                       | Because                                                                                   |
|-----------------------------------------------|-------------------------------------------------------------------------------------------|
| Expansion raises a `FrameworkException`       | A required battery is not enabled; the message names it                                   |
| Requests fail with `HTTPS_REQUIRED`           | A node is on `http` or a local address outside debug mode — set `PEERING_ALLOW_INSECURE` for development only |
| The trust status stays **unclear**            | There is no independent observer yet, or not enough data                                  |
| Peers report a URL mismatch                   | The host is reached under more than one address                                           |
| A conflict about a changed node key           | The node lost its key file, or someone else answers under its address                     |
| A peer is missing from the statistics         | It was not seen for `PEERING_PEER_INACTIVE_DAYS` and counts as inactive until it is again |

---

## Further reading

- [CONTRACT.md](src/wf_peering/CONTRACT.md) — expansion, every setting, the signature contexts, the public API, limits
- [CHANGELOG.md](CHANGELOG.md) — what changed, release by release
- [.agents/SKILL.md](src/wf_peering/.agents/SKILL.md) — how a coding agent works on or with the extension
