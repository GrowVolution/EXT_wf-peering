# wf-peering

> A WebFluid extension: the shared node core of the peering network.

Independent peers replicate, verify and checkpoint what a WebFluid host publishes about itself, so
nobody has to take the host's word for it. The network has two sides with different jobs:

| Part                                  | Runs on  | Job                                                                                                                                                                        |
|---------------------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`peering` Additive**                | the host | The optional contract for the host's Additives (`peering_integrity`, `peering_record`, …), the signed ledger, the `/peer` WebSocket, the host API under `/peering/api/v1`. |
| **`peering` app** (WebFluid main app) | a peer   | The peer server: live replication, the daily full sync, observations of what the host really serves, checkpoints, the peer API under `/api/v1`.                            |
| **`wf-peering`** (this extension)     | both     | Everything both sides need identically: the protocols, the storage, the verification, checkpoints, the trust assessment and the public API handlers.                       |

Host and peer must reach the same verdict about the same bytes. Keeping that code in one package — instead
of a copy on each side or a peer that runs the host's Additive — is the reason this extension exists. The
peer app runs without `WF_ADDITIVES`.

---

## What it contains

| Package                 | Content                                                                                                                                                                                                   |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `wf_peering.protocol`   | Pure, I/O-free protocol code: canonical JSON, Merkle trees and proofs, ledger entries, key log, signed actions, integrity records, network policy, trust scoring, handshake contexts.                     |
| `wf_peering.models`     | The SQLAlchemy models (`peering_*` tables) both roles store their state in.                                                                                                                               |
| `wf_peering.services`   | Node identity, the signed ledger (`append` on the host, `ingest` on a peer), journal, account replay, integrity storage, network checks, peer directory, uptime, checkpoints, trust, status, shared jobs. |
| `wf_peering.api`        | The public, read-only API handlers both roles serve, and `register()` to mount them on a router.                                                                                                          |
| `static/`, `templates/` | The status page both roles render (`/wf-peering/static/…`).                                                                                                                                               |

Everything that differs between host and peer is behind one interface, `NodeRole`
(`wf_peering.services.role`): the startup work, where a checkpoint's ledger size comes from and where it is
published, the signals only one side can observe, the extra status fields. The Additive implements it as
`HostRole`, the peer app as `PeerRole`; the shared services never import either side.

---

## Using it

The extension is not a battery: it is expanded with the role of the process that uses it.

```python
from wf_peering import peering

peering.expand_fluid(app, role=PeerRole())                     # the peering app, in prepare_fluid()
peering.expand_fluid(fluid, role=HostRole(), root=additive_dir)  # the peering Additive, in before_enable
```

`expand_fluid` reads the `PEERING_*` keys, binds the models, loads or creates the node key, registers the
status page assets, template and translations and — unless `PEERING_SCHEDULE = False` — schedules the jobs
both roles run (startup, heartbeat, probes, trust, ledger verification, activity, retention, the daily
checkpoint). Each side adds its own jobs: the host its integrity collection, the peer its observations and
the daily full sync.

Mount the API with the application's limiter:

```python
from wf_peering.api import register, route, observations_request

v1 = APIRouter(prefix="/v1")
register(v1, app.limit)
route(v1, app.limit, "/integrity/observations", "60/minute", observations_request)
```

Requires `EXT_SQLALCHEMY`, `EXT_BABEL` and — with scheduling on — `EXT_SCHEDULING`. `expand_fluid` raises a
`FrameworkException` naming the missing battery.

### Status page and translations

The status page is rendered on the server in the request's locale: `expand_fluid` registers the extension's
translations (`i18n/default.json`, English and German, every key prefixed `PEERING_`) in the `messages`
domain, the template translates its static text with `_()`, and the strings `status.js` needs are rendered
into the page as JSON (`#peering-texts`). An application offers German by listing `de` in
`BABEL_SUPPORTED_LOCALES`.

### Debug mode

Under `wf run -d` (`DEBUG_MODE`) the extension behaves as if `PEERING_ALLOW_INSECURE` were set — a host and
its peers can run on `http://localhost` without `HTTPS_REQUIRED` failures — and the trust assessment leaves
out the `https`, `tls_valid` and `cert_expiry_margin` signals instead of capping the score. Every signed
trust report carries `debug: true` or `false`, and the status page shows a notice, so a report from a
debug node is never mistaken for a production one. Debug never reaches a deployment: `wf run` sets
`DEBUG_MODE` only with `-d`.

---

## Configuration

Every key is optional unless noted. Keys are read with `fluid.config.get`, so the defaults below live in the
extension; the Additive and the peer app list the ones that matter to them in their own config.

| Key                              | Default                         | Meaning                                                                                       |
|----------------------------------|---------------------------------|-----------------------------------------------------------------------------------------------|
| `PEERING_PUBLIC_URL`             | `BASE_URL`                      | The origin this node is reachable at; part of its signed statement.                           |
| `PEERING_HOST`                   | —                               | **Peer only, required.** The host this peer watches.                                          |
| `PEERING_HOST_KEY`               | trust on first use              | Peer only: pins the host's node key instead of trusting the first one seen.                   |
| `PEERING_KEY_FILE`               | `keys/node.key`                 | The node's Ed25519 seed, created with mode `0600`. Relative to the Additive or the app root.  |
| `PEERING_NODE_KEY`               | env `PEERING_NODE_KEY`          | The seed itself (base64url), instead of a file.                                               |
| `PEERING_PEERS`                  | `[]`                            | Further peers to check, next to the ones the host reports and gossip finds.                   |
| `PEERING_TRUSTED_REFERENCES`     | `{}`                            | Peer only: artifact id → reference manifest URL the peer trusts instead of the host's claim.  |
| `PEERING_REFERENCE_HOSTS`        | `["raw.githubusercontent.com"]` | The only hosts reference manifests may come from.                                             |
| `PEERING_ALLOW_INSECURE`         | `False` (`True` in debug mode)  | Allows `http` and non-global addresses. Local development only.                               |
| `PEERING_MAX_PEERS`              | `64`                            | Upper bound for known and connected peers.                                                    |
| `PEERING_REGISTRATIONS_PER_HOUR` | `20`                            | Host only: new peers accepted per hour.                                                       |
| `PEERING_SCHEDULE`               | `True`                          | Turns all jobs off (tests, one-off scripts).                                                  |
| `PEERING_SYNC_TIME`              | `(23, 59)`                      | Peer only: the daily full sync, UTC.                                                          |
| `PEERING_CHECKPOINT_TIME`        | `(0, 0)`                        | The daily checkpoint, UTC.                                                                    |
| `PEERING_CHECKPOINT_GRACE`       | `300`                           | Seconds a checkpoint waits for a full sync of the same day that is still running.             |
| `PEERING_SYNC_ATTEMPTS`          | `3`                             | Attempts of a full sync before it is recorded as failed.                                      |
| `PEERING_INTEGRITY_INTERVAL`     | `900`                           | Seconds between integrity collections (host) or observations (peer).                          |
| `PEERING_PROBE_INTERVAL`         | `300`                           | Seconds between checks of the host and the known peers.                                       |
| `PEERING_TRUST_INTERVAL`         | `600`                           | Seconds between trust assessments.                                                            |
| `PEERING_HEARTBEAT_INTERVAL`     | `30`                            | Seconds between WebSocket heartbeats; four missed ones close the link.                        |
| `PEERING_REQUEST_TIMEOUT`        | `10`                            | Seconds per outgoing request.                                                                 |
| `PEERING_MAX_RESPONSE_BYTES`     | `2097152`                       | Upper bound for any response body this node reads.                                            |
| `PEERING_PROBE_RETENTION_DAYS`   | `30`                            | How long probe results and trust snapshots are kept.                                          |
| `PEERING_PEER_INACTIVE_DAYS`     | `30`                            | Days without contact after which a peer becomes inactive (see below). `0` keeps peers active. |
| `PEERING_LEDGER_PAGE`            | `500`                           | Ledger entries per page (10–2000).                                                            |
| `PEERING_MODELS_DB_BIND`         | —                               | A SQLAlchemy bind key for the `peering_*` tables.                                             |

---

## Protocols

All signatures are Ed25519 over `"<context>\n" + canonical JSON` (or over a hash, where noted). Canonical
JSON is **WF-CJSON-1**: sorted ASCII keys, no whitespace, no floats, integers within ±(2^53−1), minimal
escaping (`\b \f \n \r \t`, other control characters as lowercase `\u00XX`, everything else literal UTF-8),
lone surrogates rejected. Python, the users Additive's `e2ee.js` and the Users SDK implement it identically;
`tests/vectors.py` produces the cross-language vectors the SDK checks.

| Context                                                       | Signs                                                                                                           |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `wf-ledger-v1`                                                | The hash of a ledger entry (`seq`, `prev`, `kind`, `source`, `subject`, `ref`, `ts`, `body`, `auth`). Host key. |
| `wf-ledger-head-v1`                                           | A ledger head: size, head hash, Merkle root (RFC 6962/9162), time, origin, protocol and schema.                 |
| `wf-journal-v1`                                               | The hash of an entry in a node's own journal (activity, connections, syncs, conflicts).                         |
| `wf-peering-node-v1`                                          | A node's statement: id, key, role, URL, the host it belongs to, software, boot.                                 |
| `wf-checkpoint-v1`                                            | A daily checkpoint: ledger size/root/head, replayed state root, journal root, sync basis, previous checkpoint.  |
| `wf-trust-v1`                                                 | A trust report with all signals, its basis and the observer population.                                         |
| `wf-peer-hello-v1` / `wf-peer-auth-v1` / `wf-peer-welcome-v1` | The mutual WebSocket handshake between host and peer.                                                           |
| `wf-keylog-v1:subject` / `wf-keylog-v1:authority`             | Account key statements (device and browser binding, recovery, revocation).                                      |
| `wf-action-v1`                                                | Signed user actions with replay protection (`seq`, `prev`, lifetime ≤ 900 s).                                   |

Peers replay the key log and the signed actions of every account from the ledger themselves and reach the
same state as the host — or flag where they do not. Key changes the host asserts without a proof by the
account's own keys are recorded with the flag `NO_PROOF_OF_POSSESSION`.

---

## Public API

Read-only, unauthenticated, `Access-Control-Allow-Origin: *`, `Cache-Control: no-store`. The host serves it
under **`/peering/api/v1`** (through its Additive), every peer under **`/api/v1`** (as an app).

| Route                                                                                   | Answer                                                                   |
|-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `GET /node`                                                                             | The signed node statement.                                               |
| `GET /status` · `GET /uptime`                                                           | Summary of this node; its own and its observed uptime.                   |
| `GET /ledger?from&limit&kind&subject`                                                   | A page of ledger entries with their verification flags.                  |
| `GET /ledger/head`                                                                      | The signed head.                                                         |
| `GET /ledger/root?size` · `/ledger/proof?seq&size` · `/ledger/consistency?first&second` | Merkle root, inclusion and consistency proofs.                           |
| `GET /journal?from&limit&kind`                                                          | This node's own signed journal.                                          |
| `GET /accounts/{handle}`                                                                | The replayed keys, actions and flags of one pseudonymous account handle. |
| `GET /integrity` · `GET /hash?id=` · `GET /integrity/history?id=`                       | Current integrity records, one artifact, its hash chain.                 |

### Integrity records

Records reach the ledger two ways, both as `peering:integrity` entries and both with the same per-artifact
hash chain:

- **Collected** — every integrity run asks the `peering_integrity` collector of the host. An artifact a
  provider stops reporting is recorded as missing.
- **Pushed** — a host Additive appends one record at the moment it changes (`peering_artifact`), for
  artifacts that are too many to collect or that are not publicly served, such as package releases. Pushed
  records carry a run id starting with `push:`; integrity runs never mark them missing — only their owner
  retracts them (`peering_artifact:retract`).

A record with `served: false` is not publicly fetchable; peers keep it and answer `/hash?id=` for it, but do
not observe it. The status page lists such records separately.

### Reference manifests

Peers read a trusted reference (`PEERING_TRUSTED_REFERENCES`, or the manifest the host names) in two
formats: format 1 describes one artifact (`artifact`, `versions`, `latest`), format 2 several
(`{"format": 2, "artifacts": { "<id>": { "versions", "latest" } } }`). An artifact a format 2 manifest does
not list is reported as `NOT_IN_REFERENCE`, never as a mismatch.
| `GET /peers`                              | The active peers this node knows — one source, not proof of completeness.       |
| `GET /checkpoints?limit` · `/checkpoints/latest` · `/checkpoints/peers?day` · `/checkpoints/agreement?day` | Own checkpoints, received ones, and their agreement. |
| `GET /trust` · `GET /trust/history`       | The signed trust report and its history.                                        |
| `GET /conflicts`                          | Recorded conflicts (equivocation, failed verification, key changes, …).         |

A peer that was not seen — no connection, heartbeat or successful check — for `PEERING_PEER_INACTIVE_DAYS`
days becomes `inactive` at startup and in the daily retention job, which records it in the journal
(`peering:peers-inactive`). Inactive peers stay in the database but leave every statistic: `GET /peers`,
the active count of `GET /status`, the observer population and the per-peer assessments of the trust
report. The daily job checks them once more, and the next connection, heartbeat or successful check makes a
peer active again.

Only the host: `GET /peers/connections` and the WebSocket `/peering/ws/peer`. Only peers: `GET /sync` and
`GET /integrity/observations`.

---

## Trust score

`0–100` from five weighted categories — integrity 35, keys 25, reachability 15, history 15, diversity 10.
Severe findings cap the score (critical 20, high 60) instead of being averaged away; fewer than two
independent observers cap it at 70. Observers count as independent only when they share no /24 or /48
network, registrable domain, certificate key or node key with the host or each other.

Every assessment discloses its signals, their age and its **basis** (`complete`, `partial`, `insufficient`,
`stale`, `none`), and whether the node ran in debug mode (`debug`). Without at least one independent observer or with too little data the status is
**`unclear`** — never green. The colour runs continuously from red over yellow to green
(`hsl(score × 1.2, …)`) with WCAG-checked lightness for text, border and surface in light and dark mode.

---

## Security notes

- Nodes exchange only public data: signed statements, ledger entries (pseudonymous account handles,
  public keys, salted commitments), checkpoints and reports. No private key, credential, session or
  plaintext profile data is ever replicated.
- Every outgoing request goes through one policy: `https` only (unless `PEERING_ALLOW_INSECURE`), global
  addresses only, DNS resolved once and pinned with SNI, bounded sizes and timeouts, no proxies, no redirects.
- The node key never leaves the node; the key file is created with mode `0600`.
- A host that rewrites, truncates or forks its history is caught by the peers' verified copies and recorded
  as a critical conflict with the conflicting signed evidence.

## Limits

- A fully compromised host can still lie consistently to everyone, or decide which peers it lists. Peers
  narrow that: they compare among themselves, and the manual check in the users integrity repository lets
  people ask peers directly.
- The independence check sees infrastructure, not operators. Two peers of one person on unrelated
  providers count as independent.
- One process per node: the scheduler and the in-memory link state are not shared between workers.

---

## Installation and tests

```bash
pip install -e extensions/peering          # or: wf ocean install -e peering
pip install -e "extensions/peering[test]"
pytest                                      # in extensions/peering: protocol tests
```

The host side is tested in the `peering` Additive (`additives/peering/tests`), the peer side in the `peering`
app (`tests/`), both against this extension.

---

## License

wf-peering is licensed under the [GNU General Public License v3.0](LICENSE).
