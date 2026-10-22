# wf-peering — Contract

<!-- index -->
Read this file in parts. Each range is `first-last` as the file stands now — open one with the Read
tool's `offset`/`limit`, or `sed -n 'first,lastp'`.

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

The integration surface of the `wf-peering` extension: how a process expands it, the settings it
reads, the protocols both roles speak, the public API it serves, how trust is assessed, and the
limits it enforces. Every host and every peer implements one role and consumes this contract; no
role implementation is part of it.

## At a glance

|              |                                                                                                                          |
|--------------|--------------------------------------------------------------------------------------------------------------------------|
| Distribution | `wf-peering` (Python package `wf_peering`), entry point `peering` in `webfluid.extensions`                               |
| Requires     | WebFluid `>=1.0.0rc1`; batteries `EXT_SQLALCHEMY`, `EXT_BABEL`, with scheduling `EXT_SCHEDULING`                         |
| Expand       | `peering.expand_fluid(fluid, role=<NodeRole>, root=<dir>)` — once per process, with exactly one role                     |
| Seam         | `wf_peering.role.NodeRole`: everything host and peer do differently                                                      |
| Storage      | `peering_*` tables, bound by `PEERING_MODELS_DB_BIND`                                                                    |
| Serves       | the read-only public API via `wf_peering.api.register(router, limit)`, the status page assets under `/wf-peering/static` |
| Keys         | the node key file `PEERING_KEY_FILE` (created on first start, never commit it)                                           |

---

## Using it

The extension is not a battery: it is expanded with the role of the process that uses it.

```python
from wf_peering import peering

peering.expand_fluid(fluid, role=MyHostRole(), root=additive_dir)  # a host, e.g. in an Additive's before_enable
peering.expand_fluid(app, role=MyPeerRole())                       # a peer, e.g. in its prepare_fluid()
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
trust report carries `debug: true` or `false`, and so does `GET /status`; the status page shows a notice,
so a report from a debug node is never mistaken for a production one. Browser checks of the host use the
`debug` of `/status` for one thing only: a page on a loopback address may then stand for the host's
declared `url`, which is how a phone in the LAN and a browser on `localhost` test against the same host.
Debug never reaches a deployment: `wf run` sets `DEBUG_MODE` only with `-d`.

A peer that connects to a host names its public URL in the handshake. `services.peers.verify_claim(url,
node)` fetches that URL's `/node` statement and answers `URL_UNREACHABLE`, `URL_NOT_VERIFIED` or `None`;
the host role refuses the connection on any code, so only addresses that serve the connecting node are
ever listed.

## Configuration

Every key is optional unless noted. Keys are read with `fluid.config.get`, so the defaults below live in the
extension; a role implementation lists the ones that matter to it in its own config.

| Key                              | Default                         | Meaning                                                                                       |
|----------------------------------|---------------------------------|-----------------------------------------------------------------------------------------------|
| `PEERING_PUBLIC_URL`             | `BASE_URL`                      | The origin this node is reachable at; part of its signed statement.                           |
| `PEERING_HOST`                   | —                               | **Peer only, required.** The host this peer watches.                                          |
| `PEERING_HOST_KEY`               | trust on first use              | Peer only: pins the host's node key instead of trusting the first one seen.                   |
| `PEERING_KEY_FILE`               | `keys/node.key`                 | The node's Ed25519 seed, created with mode `0600`. Relative to `root`, else the app root.     |
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

## Protocols

All signatures are Ed25519 over `"<context>\n" + canonical JSON` (or over a hash, where noted). Canonical
JSON is **WF-CJSON-1**: sorted ASCII keys, no whitespace, no floats, integers within ±(2^53−1), minimal
escaping (`\b \f \n \r \t`, other control characters as lowercase `\u00XX`, everything else literal UTF-8),
lone surrogates rejected. Every implementation, in any language, must produce identical bytes;
`../../tests/vectors.py` produces the cross-language vectors to check one against.

| Context                                                       | Signs                                                                                                           |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `wf-ledger-v1`                                                | The hash of a ledger entry (`seq`, `prev`, `kind`, `source`, `subject`, `ref`, `ts`, `body`, `auth`). Host key. |
| `wf-ledger-head-v1`                                           | A ledger head: size, head hash, Merkle root (RFC 6962/9162), time, origin, protocol and schema.                 |
| `wf-journal-v1`                                               | The hash of an entry in a node's own journal (activity, connections, syncs, conflicts).                         |
| `wf-peering-node-v1`                                          | A node's statement: id, key, role, URL, the host it belongs to, software, boot.                                 |
| `wf-checkpoint-v1`                                            | A daily checkpoint: ledger size/root/head, replayed state root, journal root, sync basis, previous checkpoint.  |
| `wf-trust-v1`                                                 | A trust report with all signals, its basis and the observer population.                                         |
| `wf-peer-hello-v1` / `wf-peer-auth-v1` / `wf-peer-welcome-v1` | The mutual WebSocket handshake between host and peer.                                                           |
| `wf-keylog-v1:subject` / `wf-keylog-v1:authority`             | Account key statements (device and browser binding, browser links, recovery, revocation).                       |
| `wf-action-v1`                                                | Signed user actions with replay protection (`seq`, `prev`, lifetime ≤ 900 s).                                   |

Peers replay the key log and the signed actions of every account from the ledger themselves and reach the
same state as the host — or flag where they do not. Key changes the host asserts without a proof by the
account's own keys are recorded with the flag `NO_PROOF_OF_POSSESSION`.

Browser links (`browser.link`, `browser.unlink`) carry only the browser's X25519 key and an authority
signature: a link needs the account's device or recovery key, a release may also come from the host
(`HOST_ASSERTED_UNLINK`, normal — releasing grants nothing), while a link the host asserts is critical
(`HOST_ASSERTED_LINK`). The replayed state lists the linked keys as `links`; a device bound by the
recovery key or the host and a revoked device drop them. A host `device.revoke` with `reset: true`
closes an account even when no device is bound.

## Public API

Read-only, unauthenticated, `Access-Control-Allow-Origin: *`, `Cache-Control: no-store`. The host serves it
under **`/peering/api/v1`** (`HOST_API`), every peer under **`/api/v1`** (`PEER_API`).

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
| `GET /peers`                                                                            | The active peers this node knows — one source, not proof of completeness. |
| `GET /checkpoints?limit` · `/checkpoints/latest` · `/checkpoints/peers?day` · `/checkpoints/agreement?day` | Own checkpoints, received ones, and their agreement. |
| `GET /trust` · `GET /trust/history`                                                     | The signed trust report and its history.                                 |
| `GET /conflicts`                                                                        | Recorded conflicts (equivocation, failed verification, key changes, …).  |

A peer that was not seen — no connection, heartbeat or successful check — for `PEERING_PEER_INACTIVE_DAYS`
days becomes `inactive` at startup and in the daily retention job, which records it in the journal
(`peering:peers-inactive`). Inactive peers stay in the database but leave every statistic: `GET /peers`,
the active count of `GET /status`, the observer population and the per-peer assessments of the trust
report. The daily job checks them once more, and the next connection, heartbeat or successful check makes a
peer active again.

Only the host: `GET /peers/connections` and the WebSocket `/peering/ws/peer`. Only peers: `GET /sync` and
`GET /integrity/observations`.

### Integrity records

Records reach the ledger two ways, both as `peering:integrity` entries and both with the same per-artifact
hash chain:

- **Collected** — the host gathers its artifacts on every integrity run. An artifact that is no longer
  reported is recorded as missing.
- **Pushed** — the host appends one record at the moment an artifact changes, for
  artifacts that are too many to collect or that are not publicly served, such as package releases. Pushed
  records carry a run id starting with `push:`; integrity runs never mark them missing — only their owner
  retracts them.

A record with `served: false` is not publicly fetchable; peers keep it and answer `/hash?id=` for it, but do
not observe it. The status page lists such records separately.

### Reference manifests

Peers read a trusted reference (`PEERING_TRUSTED_REFERENCES`, or the manifest the host names) in two
formats: format 1 describes one artifact (`artifact`, `versions`, `latest`), format 2 several
(`{"format": 2, "artifacts": { "<id>": { "versions", "latest" } } }`). An artifact a format 2 manifest does
not list is reported as `NOT_IN_REFERENCE`, never as a mismatch.


## Trust score

`0–100` from five weighted categories — integrity 35, keys 25, reachability 15, history 15, diversity 10.
Severe findings cap the score (critical 20, high 60) instead of being averaged away; fewer than two
independent observers cap it at 70. Observers count as independent only when they share no /24 or /48
network, registrable domain, certificate key or node key with the host or each other.

Every assessment discloses its signals, their age and its **basis** (`complete`, `partial`, `insufficient`,
`stale`, `none`), and whether the node ran in debug mode (`debug`). Without at least one independent observer or with too little data the status is
**`unclear`** — never green. The colour runs continuously from red over yellow to green
(`hsl(score × 1.2, …)`) with WCAG-checked lightness for text, border and surface in light and dark mode.

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
  narrow that: they compare among themselves, and because their API is public and unauthenticated, anyone
  can ask a peer directly instead of the host.
- The independence check sees infrastructure, not operators. Two peers of one person on unrelated
  providers count as independent.
- One process per node: the scheduler and the in-memory link state are not shared between workers.
