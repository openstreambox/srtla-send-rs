# ADR-003: Versioned Optional Bind-Map Sidecar (`--bind-map`)

## Status

Accepted

> **Numbering note.** This is the third ADR in `srtla-send-rs`. It defines a **new,
> additive, fully optional** control channel for the sender. It does **not** redefine
> the telemetry JSON schema owned by `srtla/docs/adr/ADR-001-telemetry-ipc.md` (the
> canonical schema, referenced here, never modified), nor the JSON-RPC transport in
> `srtla-send-rs/docs/adr/ADR-001-control-protocol.md`, nor the cumulative-bytes
> extension in `ADR-002-session-bytes-telemetry.md`. Telemetry *echoes* of the
> identifiers defined here are specified separately and land additively on top of the
> ADR-001 schema.

## Context

`srtla_send` identifies an uplink by its **local source IP**. The four-positional CLI
contract passes a `BIND_IPS_FILE` holding newline-separated source IPs
(`src/main.rs`, `src/sender/mod.rs::read_ip_list`), one bound UDP socket per IP, and
`SIGHUP` reloads that file in place. That has been the whole of the sender's link
identity since the C original, and CeraUI's `buildSrtlaSendArgs` emits exactly that
shape.

Source IP alone is no longer sufficient on a real modem bond:

1. **Duplicate source IPs are normal, not pathological.** Two identical USB
   modems in HiLink/RNDIS mode both present `192.168.8.100`. The pool builder
   (`src/sender/connections.rs`) deduped by `IpAddr` alone, so the second modem was
   **silently collapsed into the first** and never carried traffic. The operator saw
   one link where two were plugged in, with no diagnostic anywhere. This ADR moves
   that dedup onto the `(ip, iface)` socket key.
2. **The IP is not a stable identity.** DHCP renewal, a modem replug, or a carrier
   re-attach can change it. Every piece of per-link state the UI shows — telemetry,
   naming, history — is keyed on a positional `conn_id` that shifts whenever the
   file is reordered.
3. **Egress cannot be pinned per interface.** `SourceIpBinder` (`src/net/socket.rs`)
   binds `(ip, 0)` and relies on host source routing. Per-interface pinning needs
   `SO_BINDTODEVICE`, and nothing could construct such a binder because nothing told
   the sender which interface a source IP belongs to. This ADR supplies that fact;
   `DeviceBinder` (`src/net/socket.rs`) consumes it.

The missing information is a **mapping**: which interface (and which stable,
writer-assigned identity) each row of the IP list refers to. The writer — CeraUI's
modem layer — already knows it. The sender has no channel to receive it.

### Why not change `BIND_IPS_FILE`

The IP-only file is a **load-bearing parity contract** (root `AGENTS.md` → CRITICAL
CONSTRAINTS; this repo's `AGENTS.md` → PARITY CONTRACT). Stock senders, hand-run
invocations, BELABOX-shaped tooling, and every already-deployed CeraUI all write and
read it in its current form. Adding columns, a header line, or a version marker to
that file breaks all of them at once, and the file has no place to carry a version
that an old reader would tolerate.

So the mapping goes in a **separate, optional sidecar file**, and the IP-only file
stays **byte-unchanged**.

## Decision

**Add one optional flag, `--bind-map <path>`, naming a versioned JSON sidecar that
describes the `BIND_IPS_FILE` positionally. Absent the flag, the sender's behavior is
byte-identical to today's.**

This ADR fixes the file format, the read protocol, the coherence rules, the
degradation semantics, and the pre-spawn capability probe. It is a **gate**:
the `DeviceBinder` activation work, the telemetry echo of `link_id`, and CeraUI's
writer all implement against exactly what is written here.

### Scope of this ADR

| In scope | Out of scope (separate change) |
|---|---|
| Sidecar file format + version | Activating `DeviceBinder` / `SO_BINDTODEVICE` |
| Coherence + read protocol + retry | Socket lifecycle, reconnect, ifindex staleness |
| Fail-open degradation semantics | Telemetry field emission (`iface`, `link_id`) |
| `--capabilities-json` document | Route-invariant health checks |

The parser and the resolution state machine defined here are **pure**: they read
files and produce a typed decision. They bind no sockets and change no scheduling.

---

## 1. Files

Two files, one directory, one writer.

| File | Owner | Format | Changed by this ADR |
|---|---|---|---|
| `BIND_IPS_FILE` (4th positional) | writer | newline-separated IPs | **NO — byte-unchanged** |
| `--bind-map <path>` sidecar | writer | JSON, versioned | new, optional |

### 1.1 The sidecar document

A single JSON object. Formatting (whitespace, key order, trailing newline) is **not**
part of the contract — only the parsed value is.

```json
{
  "schema_version": 1,
  "generation": 7,
  "ips_file_sha256": "5f8d3c1b2a...64 lowercase hex chars total...9e",
  "links": [
    {"link_id": "modem-a", "ip": "192.168.8.100", "iface": "wwan0", "id_path": "/sys/devices/platform/usb1/1-1.3/net/wwan0"},
    {"link_id": "modem-b", "ip": "192.168.8.100", "iface": "wwan1"}
  ]
}
```

#### Header

| Field | Type | Rule |
|---|---|---|
| `schema_version` | integer | MUST be `1`. Any other value ⇒ the pair is unusable (`unsupported`). |
| `generation` | integer | MUST be ≥ 1. See §3. |
| `ips_file_sha256` | string | 64 **lowercase** hex chars: SHA-256 over the **raw bytes** of the `BIND_IPS_FILE` this document describes. |

#### Row (`links[]`)

| Field | Type | Rule |
|---|---|---|
| `link_id` | string | **Opaque, writer-assigned.** 1–64 bytes, printable ASCII `0x21`–`0x7E` (no space, no control chars). Unique within the document. The sender **never parses meaning out of it** and never invents one. |
| `ip` | string | An IPv4 or IPv6 literal. MUST equal the IP of the correspondingly-positioned `BIND_IPS_FILE` entry (§2). |
| `iface` | string | A network-interface name: 1–15 bytes, no `/`, no whitespace, no NUL, not `.` or `..`. MUST exist on the host. |
| `id_path` | string, optional | Writer provenance for the physical device behind `link_id`, e.g. a sysfs path. MUST be absolute and ≤ 4096 bytes when present. The sender treats it as **opaque**: it is never opened, stat-ed, resolved, or used for any decision. It exists so a human debugging a bond can tie a `link_id` back to hardware. |

**Same IP on different interfaces is LEGAL** — that is the entire point. Duplicate
`(ip, iface)` pairs are not, because they name the same socket key twice.

#### Forward compatibility

Within `schema_version: 1`, a reader **ignores unknown keys** at both the document and
the row level. Any field added later MUST therefore be optional and ignorable by an
older reader. A change that an older reader could not safely ignore requires a new
`schema_version`, which older readers reject outright (`unsupported`) rather than
misinterpret.

### 1.2 `link_id` is the identity; `(ip, iface)` is only the socket key

`link_id` is stable across reloads, reconnects, IP changes, and interface renames.
Downstream work attaches registration, statistics, and telemetry state to it.
`(ip, iface)` is the *current* socket key and nothing more; it may change under a
stable `link_id`. The positional `conn_id` remains what it has always been — the
index into the IP list — and remains transient.

---

## 2. The row-correspondence contract

**The sidecar describes the IP file positionally. The Nth `links[]` row describes the
Nth accepted entry of `BIND_IPS_FILE`.**

This is what disambiguates duplicate IPs: two rows may both say `192.168.8.100`, and
they are told apart by *position*, exactly as the sender's own pool is.

"Nth accepted entry" is defined by the **legacy parsing rules, unchanged**, i.e. the
exact behavior of `read_ip_list`:

1. split the file into lines;
2. trim each line;
3. skip empty lines;
4. parse the rest as an IP address; **skip** (with a warning) anything that fails.

The resulting ordered list of accepted IPs — duplicates preserved — is the sequence the
sidecar must match. A parser divergence here would silently mis-map every row, so the
implementation shares one definition and a test pins it against `read_ip_list` output
over a fixture matrix.

Correspondence is valid only when **both** hold:

- `links.len()` equals the number of accepted IPs, and
- for every index `i`, `links[i].ip` equals accepted IP `i`.

A count mismatch, a reorder, or any single differing IP invalidates the **whole pair**.
There is no partial acceptance: a mapping that is right for some rows and wrong for
others is worse than no mapping, because the wrong rows would bind traffic to the wrong
radio.

---

## 3. `generation`

`generation` is a **monotonic per-writer-session counter**, not a lock, not a token,
and not an authorization.

**Scope.** One *writer session* = one writer process lifetime. Within a session the
writer increments `generation` by at least 1 on **every** publication, including a
publication whose `BIND_IPS_FILE` bytes did not change.

**Reset.** A new writer session restarts at `1`. The reader MUST tolerate this: a
generation that decreases is indistinguishable from a legitimate writer restart, so a
decrease alone is **never** a rejection.

**Why it exists.** `ips_file_sha256` cannot detect a **mapping-only** change — moving
`modem-b` from `wwan1` to `wwan2` leaves the IP list byte-identical. `generation` is the
only thing that distinguishes "same mapping, re-read" from "new mapping, same IPs".

**Change detection.** A freshly read pair is a *new* mapping iff

```
sha256 != last_applied.sha256   OR   generation != last_applied.generation
```

Note `!=`, not `>`. A writer restart (generation back to 1) must still register as a
change. **Mapping-only change ⇒ same `sha256`, new `generation` ⇒ a VALID pair.**

**Stale generation (a rejection class).** The pair is rejected as `stale-generation`
when all of the following hold:

- `generation == last_applied.generation`, **and**
- `sha256 == last_applied.sha256`, **and**
- the row content **differs** from what was applied.

That combination is a writer-contract violation: the mapping changed without the counter
moving, so the reader cannot order the two versions and refuses to guess. If all three
match, the read is a **no-op** — the current pool stays, and that is not an error.

`generation == 0` is malformed. Reserving `0` gives writers an "unset" sentinel that can
never be mistaken for a real generation.

---

## 4. Read protocol

```
1. read BIND_IPS_FILE as BYTES (one read)
     ├─ SHA-256 the bytes                 → computed_sha
     └─ parse the same bytes (legacy rules) → accepted[]
2. read the sidecar → parse → validate header
3. if sidecar.ips_file_sha256 != computed_sha  → TRANSIENT MISMATCH → retry from 1
4. validate rows (syntax → interfaces → correspondence → uniqueness → generation)
5. success → mapped pool
   failure → FAIL OPEN, duplicate-safe (§6)
```

Step 1 hashes and parses **the same bytes from the same read**. Reading twice would let
the file change in between and produce a hash that describes content the sender did not
parse.

### 4.1 Validation order

Deterministic, so the reported reason is reproducible:

| # | Check | Failure |
|---|---|---|
| 1 | sidecar present / readable / regular file / not a symlink / not group- or world-writable | `missing-file`, `unreadable` |
| 2 | valid JSON | `malformed` |
| 3 | `schema_version == 1` | `unsupported` |
| 4 | header: `generation ≥ 1`, `ips_file_sha256` is 64 lowercase hex | `malformed` |
| 5 | **hash coherence** | `hash-mismatch` → **retry** |
| 6 | per-row syntax (`link_id`, `ip`, `iface`, `id_path`), in index order | `malformed` |
| 7 | every `iface` exists on the host | `unknown-iface` |
| 8 | row correspondence: count, then per-index IP (§2) | `malformed` |
| 9 | uniqueness: `(ip, iface)` and `link_id` | `malformed` |
| 10 | generation staleness (§3) | `malformed` |

The hash check sits ahead of row validation deliberately: a mismatch means the rows in
hand may be about to be replaced, so there is no value in validating — or logging about
— content that is already known to be stale.

### 4.2 Bounded retry

Retry exists for exactly one condition — **hash mismatch** — because that is the only
failure the writer's own publication window can produce (§5). Every other rejection is a
genuine content error that re-reading cannot fix, so it is not retried.

| Constant | Value |
|---|---|
| `BIND_MAP_RETRY_ATTEMPTS` | `5` (1 initial read + 4 retries) |
| `BIND_MAP_RETRY_DELAY_MS` | `400` |
| `BIND_MAP_RETRY_BUDGET_MS` | `2000` (hard ceiling) |

Worst case `4 × 400 ms = 1600 ms`, inside the 2 s budget. Each retry re-reads **both**
files. A mismatch that survives the budget is reported as `retry-exhausted` and falls
through to §6.

The budget is bounded because this runs on the startup path and on the `SIGHUP` path:
an unbounded wait would hold the stream hostage to a writer bug.

---

## 5. Atomic publication and the honest window

### 5.1 Writer rules

1. **Atomic rename.** Each file is written to a **unique** temporary sibling, `fsync`-ed,
   then `rename(2)`-d into place. Temp names carry the writer's PID and a per-session
   counter (`<target>.<pid>.<counter>.tmp`) so two writers — which should not exist, but
   might — cannot clobber one temp. Readers ignore `*.tmp` siblings.
2. **Publish order: `BIND_IPS_FILE` first, sidecar second.** The sidecar names the sha256
   of the exact bytes the first rename committed.
3. **The sidecar rename is the COMMIT POINT.** The mapping is not published until that
   rename lands.
4. **`SIGHUP` last**, after both renames.
5. **At startup, republish both files BEFORE spawning the sender**, so the sender's first
   read sees a coherent pair rather than leftovers from a previous session.
6. **Single writer, serialized publication.** Concurrent publication is a writer-side bug.
   The reader does not attempt to arbitrate it; it defends via the hash + retry protocol
   and, failing that, degrades safely.

### 5.2 The window, stated honestly

Between the two renames the on-disk state is **NEW `BIND_IPS_FILE` + OLD sidecar**. A
reader landing there computes a hash that does not match the sidecar's claim.

This is **detectable, not silent**, and it is precisely what the bounded retry absorbs.

The guarantee runs one way, and only one way:

> A reader that sees the **NEW sidecar** is guaranteed the `BIND_IPS_FILE` content it
> names is already on disk, because the writer committed that content first.

The converse does not hold and is not claimed. Making it hold would need both files in
one atomic unit — a single combined file (which would break the byte-unchanged IP-file
contract) or a directory swap (which the writer cannot perform against a caller-chosen
path). Naming the window and absorbing it with a bounded retry is the honest design;
pretending it does not exist is not.

### 5.3 Reader safety rules

- The sidecar is opened with `O_NOFOLLOW`: a **symlink at the final path component is
  refused**, so a sidecar path cannot be redirected at a file the service should not read.
- The sidecar must be a **regular file**.
- A sidecar that is **group- or world-writable** is refused. The mapping decides where
  device traffic egresses; it must be owned by the service that writes it.
- These checks apply to the **sidecar only**. `BIND_IPS_FILE` keeps its existing,
  unchanged read path.

---

## 6. Fail-open, duplicate-safe

Fail-open means "keep streaming". It does **not** mean "guess".

The unsafe naive fallback would be: no map ⇒ collapse duplicate IPs and carry on. That
is exactly the silent-collapse bug this ADR exists to fix, so degradation is
**duplicate-safe**: legacy IP-only behavior applies to **unique-IP rows only**, and rows
inside a same-IP collision group are never blindly collapsed.

Two phases, two different correct answers.

### 6.1 STARTUP — no valid map has ever been applied

- Unique-IP rows run exactly as legacy does.
- Each same-IP **collision group** keeps **one deterministic representative** — the
  **first occurrence in file order** — and the remaining rows are **excluded and
  reported**, naming the colliding IP, the effective row, and the excluded rows.

The *effective link set* here equals what legacy would have produced. The difference is
not which links run; it is that the ambiguity is **named** instead of silently swallowed.
That is the point: an operator with two modems and one visible link gets told why. No row
is ever bound to a guessed interface.

### 6.2 RELOAD — a valid map was applied, and the new read is degraded

The sender **rejects the reload and retains the last valid mapped pool**, marked
degraded, until a coherent pair arrives.

Retention applies to **every** degraded reload, including one where the new IP list
happens to have no duplicates. Falling back to legacy in that case would silently drop
per-interface egress pinning from every link of a live, working bond — a worse outcome
than continuing on the last known-good mapping. A degraded reload changes nothing about
the running bond except its reported status.

### 6.3 ABSENT — `--bind-map` was not supplied

**Byte-identical legacy behavior.** No hashing, no sidecar read, no exclusion, no new
failure mode, no new file. The bind-map code path is not entered at all.

### 6.4 Typed outcome

Two orthogonal fields, both consumed by downstream telemetry so the UI renders the
sender's *actual* operating mode from typed data instead of inferring it.

**Status** — is the map in force?

| Value | Meaning |
|---|---|
| `active` | A coherent, valid pair is applied. |
| `absent` | `--bind-map` was not supplied. |
| `degraded(reason)` | The map is configured but not in force. |

**Degraded reason** — exactly seven values:

| Value | Cause |
|---|---|
| `hash_mismatch` | Coherence check failed (and was not resolved by retry). |
| `malformed` | Bad JSON, bad header, bad row, bad correspondence, duplicate pair/id, stale generation. |
| `unknown_iface` | A row names an interface that does not exist on the host. |
| `retry_exhausted` | Hash mismatch persisted past the retry budget. |
| `missing_file` | The sidecar path does not exist. |
| `unreadable` | I/O error, symlink, non-regular file, or unsafe permissions. |
| `unsupported` | A `schema_version` this build does not implement. |

A build with no bind-map support does not produce a degraded read at all — it has no
`--bind-map` flag, so it rejects the argument at parse time. That case is signalled ahead
of spawn by `capabilities.bind_map: false` (§7), never by a status field.

**Disposition** — what is the sender actually running?

| Value | Meaning |
|---|---|
| `mapped` | The map is in force. |
| `retained_last_valid` | A degraded reload was rejected; the last valid mapped pool is still running. |
| `legacy_unique_only` | Legacy behavior; no collision groups were present. |
| `startup_collision_excluded` | Degraded at startup with at least one collision group; representatives run, the rest are excluded and reported. |

`startup_collision_excluded` carries the affected groups: the colliding IP, the effective
row, and the excluded rows.

---

## 7. `--capabilities-json` — the pre-spawn probe

A caller must decide **before spawning a stream** whether the installed binary understands
`--bind-map`. Passing an unknown flag to an old binary makes it exit non-zero with a usage
error, which at spawn time is a failed stream, not a graceful downgrade.

**`--capabilities-json` prints one machine-readable capability document to stdout and
exits `0`.** It is one-shot, side-effect free (no logging init, no sockets, no file
writes, no positional arguments required), and returns immediately.

```json
{"schema_version":1,"binary":"srtla_send","version":"4.0.1","capabilities":{"bind_map":true,"stats_file":true,"dry_run":true,"control_socket_jsonrpc":true,"conn_timeout_ms":true,"modes":["classic","enhanced"]}}
```

The key set is this build's (`src/capabilities.rs`); it is an **open map** and
consumers ignore keys they do not know. `version` is by definition the crate
version, so it moves with every release and is never part of the contract.

| Field | Meaning |
|---|---|
| `schema_version` | Version of the **capability document** (currently `1`), independent of the sidecar's. |
| `binary` | Always `srtla_send`. |
| `version` | The crate version. |
| `capabilities.bind_map` | `true` on Linux builds; `false` elsewhere, because egress pinning is `SO_BINDTODEVICE`. |
| `capabilities.dry_run` / `stats_file` / `control_socket_jsonrpc` / `conn_timeout_ms` / `modes` | Existing surfaces, declared so a caller can probe once instead of version-sniffing. |

### 7.1 Caller contract (this is the load-bearing half)

> **Non-zero exit, unparseable output, or a timeout ⇒ NO SUPPORT.** The caller MUST NOT
> pass `--bind-map` and MUST fall back to the legacy spawn.

A binary predating the flag answers `--capabilities-json` with
`error: unexpected argument`, exit code `2`. That is the intended negative signal.
A caller MUST treat *any* non-zero exit the same way rather than matching on `2` or on
the message text.

Consumers ignore unknown fields; `capabilities` is an open map that will gain keys.

---

## 8. Consequences

**Good**

- The IP-only file is untouched, so every existing writer, reader, and deployed device
  keeps working with no coordination.
- Duplicate-IP bonds become expressible for the first time, and the failure mode when
  they are not expressible is *reported* rather than silent.
- Degradation never loses a stream: startup keeps a deterministic subset running, reload
  keeps the whole bond running on the last good mapping.
- The transient publication window is named, bounded, and absorbed rather than denied.
- `link_id` gives downstream work a stable identity that survives IP churn.

**Costs**

- Two files must be published in the right order. The writer carries that burden; the
  reader defends against getting it wrong.
- A `generation` that the writer forgets to increment turns a mapping change into a
  rejected read. That is deliberate — the alternative is applying an unordered mapping.
- One new dependency (`sha2`) enters the shipped binary.
- The reader can only ever be as correct as the writer's `iface` claims; it validates that
  an interface *exists*, not that the IP is actually configured on it.

**Explicitly not decided here**

Socket binding, reconnect behavior, ifindex staleness, route-invariant health, and the
telemetry field emission all consume this contract. They are implemented alongside it in
this repo: `src/net/socket.rs` (`DeviceBinder`), `src/net/spec.rs`
(`UplinkSpec`/`SocketKey`), `src/net/egress.rs` (ifindex staleness),
`src/net/route.rs` + `src/sender/egress_tick.rs` (the read-only route invariant), and
`src/stats.rs` + `src/telemetry_doc.rs` (the telemetry echo).

## 9. Required binding (opt-in extension)

A caller requiring device isolation probes for literal
`capabilities.bind_map_required == true` before spawning with
`--require-bind-map --bind-map <path>`. The capability is true only on Linux,
where both source binding and `SO_BINDTODEVICE` are enforced. It is advertised
by both the pre-spawn probe and runtime `get_capabilities`; support does not
mean the flag is enabled. Missing/false capability, failed probe, malformed
output or timeout means the caller MUST refuse a required-binding spawn.
It MUST NOT downgrade that spawn to source-only links.

The flag requires a sidecar path. Without the flag, §§6–7 remain unchanged.
In particular, `bind_map: true` alone does **not** guarantee fail-closed startup.

### 9.1 STARTUP and recovery

Before a valid pair has been applied, **any** degraded read refuses the entire
pair, including unique IPs and same-IP representatives. No uplink sockets are
created. The listener stays alive with an empty pool, awaiting SIGHUP; device
arrival requires a new read, not a process restart. The pair is atomic: a single
missing interface refuses all its rows rather than applying a partial mapping.

Existing telemetry reports `bind_map_status.state = degraded` with the existing
reason and `disposition.state = required_binding_refused`. `connections` is
empty, and each new snapshot has its normal fresh publish timestamp. There
are no collision representatives to report. Logs include the degradation reason
and disposition. The producer fixture is
`tests/fixtures/telemetry-required-binding-refused.json`; required fields and
`schema_version = 1` are unchanged.

### 9.2 Applied mappings and RELOAD

Required mode also rejects unspecified source addresses (`0.0.0.0` / `::`),
including the IPv4-mapped spelling `::ffff:0.0.0.0`,
as `malformed`: binding a wildcard would not pin a source.
Required-mode dry-run uses the same canonical-address validation and Linux
platform guard as runtime. Default dry-run behavior is unchanged.
Every accepted link uses the existing device-first, source-second binder.
Failure of either operation refuses that socket and logs the failure; it never
retries with a source-only binder. Existing bound reconnect and interface
staleness handling remain in force. A valid map status describes validation,
not proof that every socket connected; consumers also inspect connections.

A degraded reload after a valid pair retains the last valid mapped pool and
reports `retained_last_valid`, exactly as §6.2. This is **not withdrawal**:
supervisors needing immediate withdrawal must fence that path and publish a
valid replacement, then observe fresh producer evidence of socket removal.
Before the first valid pair, every degraded reload remains empty and refused.
`--dry-run` continues to reject unusable pairs with nonzero exit; it does not
open sockets or prove runtime bind permissions.

### 9.3 Explicit empty-map withdrawal

`capabilities.bind_map_required_empty_reload == true` advertises the additional
required-mode empty-reload contract. Consumers needing final-link withdrawal
MUST require this literal capability as well as `bind_map_required == true`.
Earlier builds advertising only `bind_map_required` cannot acknowledge a final
withdrawal. Both capabilities are Linux-only and use the existing probe/runtime
capability document; they advertise support, not the enabled invocation mode.

With `--require-bind-map`, a coherent, valid empty mapping (empty accepted IP
list, matching SHA-256, valid generation, `links: []`) explicitly removes ALL
uplink connections, sockets and packet readers. Fresh telemetry acknowledges
the applied state with `connections: []`, `active` / `mapped`. The listener
stays alive. Registration state is reset so a later coherent nonempty mapping
and SIGHUP can create new sockets and bootstrap a fresh handshake.

An empty list alone is never withdrawal authority. Missing/unreadable files,
malformed sidecars, SHA mismatch or invalid/stale generations remain degraded
and retain the last valid pool, including an already-empty pool. Existing
generation rules (§3) still apply: counters can restart; changing the SHA with
the same generation is not by itself a rejection. Without required mode,
empty reloads keep their existing refusal/retention behavior.

### 9.4 Unicast sources and completed withdrawal receipts

**Probe `capabilities.bind_map_contract` as an integer >= 2**, in addition to
both `bind_map_required == true` and `bind_map_required_empty_reload == true`,
before relying on the repaired receipt contract. Revision `2` adds identified,
ordered application (§9.5) to the required binding contract: fail-closed startup,
canonical assigned unicast sources,
checked local binding, pending state, joined teardown and atomic applied
acknowledgement. It is advertised by the CLI and runtime capability document
only on Linux; other platforms emit `0`. Absent, zero, non-integer or failed
probe means these guarantees are unverified and the consumer MUST NOT rely on
them or downgrade a required-binding spawn.

Earlier builds advertised the two booleans while accepting non-unicast sources
and acknowledging empty reloads before teardown completed. The booleans alone
therefore do not establish §9.4. This new numeric revision started at `1`;
future revisions increase monotonically and retain earlier guarantees, allowing
a consumer to require its minimum revision rather than accumulate booleans.
The number describes supported behavior, not whether required mode is enabled.
It is independent of the capability-document, bind-map and telemetry schema
versions; those stay unchanged.

Required-mode sources are canonical unicast addresses: unspecified, limited
broadcast and multicast addresses are rejected, including IPv4-mapped IPv6
spellings. Directed IPv4 broadcasts are rejected using the selected device's
current address/netmask where available; /31 and /32 have no directed broadcast.
IPv6 has no broadcast; its multicast addresses are rejected.

Dry-run and socket creation also require the source to be assigned to the
selected device. Private addresses, loopback and link-local unicast are allowed
when assigned there. IPv6 link-local binding sets the selected device's scope
index explicitly. After binding, the socket's actual local IP must equal the
canonical mapped source (and link-local scope must match). Any failure refuses
the socket; it never substitutes an IP-only binder. Dry-run opens no sockets
and cannot prove runtime permissions or future interface state. Existing
non-required binders keep their behavior.

A required-mode reload reports `disposition.state = pending_apply` until
application completes. It is not a withdrawal acknowledgement, even when the
previous connection snapshot was empty. Reader tasks holding old sockets are
aborted AND joined before removal is acknowledged. Only after connection/I/O
changes and reader teardown complete are the final report and connection
snapshot published together under one lock. Fresh empty `active` / `mapped`
therefore acknowledges that owned uplink sockets are closed. The local listener
remains alive. Startup publishes its mapped report with its actual connection
snapshot, avoiding an initial active/empty report while uplink sockets exist.

### 9.5 Revision 2: identified, ordered application

Consumers needing causal withdrawal evidence MUST require integer
`capabilities.bind_map_contract >= 2`, both strict booleans, and the exact
supervised producer lifetime. Revision 1's wall-clock timestamp and two
booleans cannot establish which map was applied.

Required-mode file and runtime snapshots add two optional identity objects:
`bind_map_applied` and `bind_map_pending`. Each has exactly
`{generation, ips_file_sha256}`. The SHA is the validated sidecar digest of
the EXACT IP-file bytes, without reformatting or added LF; an empty file is
zero bytes. The applied identity is published for the first valid startup
map, including an empty first map, and for every completed valid reload.
It shares the connections/report snapshot lock and is committed only after
joined application. Missing identities are omitted, never null.

`pending_apply` begins when request ingress is accepted, before file I/O.
Before the candidate is known, `bind_map_pending` is absent. After validation
it names the queued target; `bind_map_applied` still names the previously
applied map. Pending is intent, never acknowledgement. On completion, pending
is omitted and applied names the completed target. A stale captured snapshot
may be serialized with a fresh wall-clock time: that does NOT update its
applied identity and cannot acknowledge a different publication.

In required mode, generations are positive safe integers (at most
9007199254740991) and monotonically nondecreasing per sender lifetime.
A changed pool requires a STRICT increase; the same generation is allowed only
for an identical pool. This overrides §3's writer-reset tolerance for required
mode. Restarting a writer counter requires a new supervised sender lifetime
or continuing above the live accepted watermark. Default mode keeps §3.

Each ingress request supersedes earlier reads and queued applies. Results
carry their ingress epoch; obsolete results are discarded even if they finish
after a newer empty acknowledgement. A same-generation no-op cannot clear a
newer pending request. Request ingress and final applied publication share a
gate, checked again after joined socket work: a superseded apply cannot publish
a completed receipt. A canceled candidate's generation remains an acceptance
watermark, but degraded reads retain the actually applied pool, never an
accepted-but-unapplied candidate.

The consumer requires a valid applied object with safe-integer generation and
64 lowercase hex SHA exactly matching its latest local publication, and no
pending acknowledgement. Fresh `last_updated_ms` alone is NEVER causal proof.
All schema versions remain 1; this is an additive revision-2 contract.
