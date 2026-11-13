<!-- Moved verbatim from AGENTS.md on 2026-10-05 by lean-rules-docs-landing-latam -->

## PARITY CONTRACT (CeraUI depends on every bullet; change only with a versioned decision)

- **Binary name** is exactly `srtla_send`, installed at `/usr/bin/srtla_send`.
- **CLI positional order:** `srtla_send <SRT_LISTEN_PORT> <SRTLA_HOST> <SRTLA_PORT>
  <BIND_IPS_FILE> [OPTIONS]`. CeraUI's `buildSrtlaSendArgs` emits them in that order.
- **`--verbose`** turns on debug-level logging. **`--dry-run`** parses the IP list,
  resolves the receiver, prints both, and exits `0` without binding a socket; a
  missing, unreadable, empty, or all-invalid IP list (or, with `--bind-map`, an unusable
  sidecar) exits non-zero with a specific error. `tests/cli_surface.rs`.
- **Control dialect is upstream's JSON-RPC 2.0, extended additively (ADR-004).**
  `--control-socket <path>` speaks upstream's snake_case methods (`get_status`,
  `get_stats`, `set_mode`, `set_quality`, `set_stall_deselect`, `set_conn_timeout`,
  `subscribe`, `unsubscribe`, ...). CERALIVE adds `get_capabilities` and optional fields
  inside upstream's existing payloads (`get_stats` and the `stats` topic return
  upstream's `StatsSnapshot`, whose rate field is `bitrate_bytes_per_sec`, plus
  `bytes_sent_total`, `iface`, `link_id`, `bind_map_status`, `disposition`; the ADR-001
  document with `bitrate_bps` is the FILE shape only). There is **no `hello`, no `subscribe-events`, and
  no kebab-case method**; ADR-001's transport section is superseded. Upstream's
  `SubscriptionHub` (`src/subscriptions.rs`) keeps no last frame, so a subscriber that
  needs immediate state calls `get_stats` once after subscribing. `src/control.rs`,
  `docs/CONTROL_PROTOCOL.md`, `docs/adr/ADR-004-control-dialect.md`.
- **`--capabilities-json` is the pre-spawn probe.** One line of JSON on stdout, exit
  `0`, before logging is initialized, no socket bound, no file written. Frozen key set:
  `bind_map`, `bind_map_contract`, `bind_map_required`, `bind_map_required_empty_reload`, `stats_file`, `dry_run`, `control_socket_jsonrpc`, `conn_timeout_ms`,
  `modes`. The runtime `get_capabilities` returns the **same document plus `methods`**,
  pinned by `get_capabilities_matches_the_pre_spawn_probe_document`. The load-bearing
  half is the caller's: any non-zero exit, unparseable output, or timeout means NO
  SUPPORT, so fall back to the legacy spawn. Never match on the code or the message.
  `src/capabilities.rs`, `tests/capabilities_probe.rs`.
- **Telemetry contract (`--stats-file <path>`, `--stats-file-interval <ms>`, ADR-001 +
  ADR-002 + ADR-003).** Opt-in: absent means no file is ever written. A newline-free
  JSON document, atomically published (temp sibling, `fsync`, `rename(2)`, with the
  fsync off the forwarding loop), shape
  `{"schema_version":1,"last_updated_ms":<wall-clock ms>,"connections":[{"conn_id","rtt_ms","nak_count","weight_percent","window","in_flight","bitrate_bps", ...}],"bytes_sent_total":<bytes>}`.
  `bitrate_bps` is wire bytes/s **× 8** (mandatory). `conn_id` is the string IP-list index
  (transient across a SIGHUP reorder). `window` and `in_flight` are required. Cadence
  defaults to 1000 ms. The live file and its `.tmp` sibling are unlinked on clean
  shutdown. `last_updated_ms` comes from `wall_clock_ms()`, not the monotonic
  `now_ms()`, because the consumer compares it against `Date.now()`. The document model
  is `src/telemetry_doc.rs`; publish mechanics are `src/telemetry_file.rs`; the snapshot
  is fed from upstream's `src/stats.rs`, not a parallel collector.
  Writer-thread creation is fallible: `TelemetryWriter::new` returns `anyhow::Result`,
  propagated through `spawn_telemetry_sink` to `main` as a contextual startup error,
  never a panic. Once started, filesystem publish failures remain best-effort warnings.
- **`bytes_sent_total` (ADR-002)** is additive at both scopes, counted in **bytes** (no
  ×8), counted at the same call site as `bitrate_bps`, and monotonic for the process
  lifetime: it does not reset on a per-link socket replacement and does not regress
  when a SIGHUP reload drops a link (the bond figure is a delta-banking accumulator,
  `SessionBytes` in `src/stats.rs`, not a sum of the live links). `schema_version` stays
  `1`. Absent means unknown, never zero.
- **ADR-003 telemetry echo: OPTIONAL additive fields, `schema_version` stays 1.**
  Per connection `iface` and `link_id` (echoed from the sidecar, never minted here); top
  level `bind_map_status {state: active|absent|degraded, reason?}` (seven frozen
  reasons) and `disposition {state: mapped|retained_last_valid|legacy_unique_only|
  startup_collision_excluded|required_binding_refused|pending_apply, collisions?}`. The top-level pair is always present (an
  unmapped run reads `absent` / `legacy_unique_only`); the per-connection pair and
  `reason`/`collisions` are omitted (never `null`, never `""`) when they do not apply, so
  an unmapped run's document is the pre-ADR-003 producer's plus the top-level pair.
  `schema_version` names the shape of the REQUIRED fields;
  never bump it for an additive field. Types are projected from `src/bind_map/report.rs`;
  do not introduce a parallel status type.
  Required revision-2 snapshots also carry optional `bind_map_applied` and
  `bind_map_pending` publication identities, each `{generation, ips_file_sha256}`;
  unknown identities are omitted and pending never acknowledges application.

- **Fixtures.** `tests/fixtures/*.json` are the producer goldens, written by
  `tests/telemetry_fixtures.rs` (regenerate deliberately with
  `UPDATE_GOLDEN=1 cargo test --test telemetry_fixtures`). `telemetry-legacy-producer.json`
  is the frozen pre-ADR-003 document and is never regenerated. The TypeScript reader and
  its copies of these fixtures live in CeraUI, not here.
- **`--bind-map <path>` (ADR-003) is additive and never required.** `BIND_IPS_FILE`
  stays byte-unchanged; the sidecar is a separate versioned JSON file describing it
  **positionally** (`{schema_version, generation, ips_file_sha256}` header, rows of
  `{link_id, ip, iface, id_path?}`). Absent `--bind-map` means byte-identical legacy
  behavior, pinned by `a_legacy_invocation_without_bind_map_produces_byte_identical_output`
  (`tests/bind_map_contract.rs`). A hash mismatch is retried (5 × 400 ms, 2 s ceiling)
  and then fails open, duplicate-safe: at startup a same-IP collision group keeps one
  deterministic representative and reports the rest excluded; on a valid-to-degraded
  reload the last valid mapped pool is retained. A mapped link binds with
  `SO_BINDTODEVICE` **and** `bind(ip, 0)` (`DeviceBinder`, `src/net/socket.rs`); an
  unmapped link takes `SourceIpBinder` verbatim. Full contract:
  `docs/adr/ADR-003-bind-map-contract.md`.
- **Link identity is `link_id`; `(ip, iface)` is only the socket key**
  (`src/net/spec.rs`). Anything that must survive a reload, reorder, reconnect, or
  interface move keys on `link_id`. A reload that moves a `link_id` to a different
  socket key recreates the socket and the registration rather than carrying
  interface-scoped state across (`src/sender/connections.rs`).
- **The interface is re-resolved by name every housekeeping tick.** A changed ifindex
  forces a rebind; a vanished interface puts the link in a `removed` state that waits
  for a reload; an `ENODEV` send does the same from the data path. Per-interface
  default-route presence is observed read-only from `/proc/net/route` and reported on
  its own axis (a lost route is a `WARN`, a regained one an `INFO`; `Unknown` crossings
  are silent). No policy routing is ever installed. `src/net/egress.rs`,
  `src/net/route.rs`, `src/sender/egress_tick.rs`.
- **A `SIGHUP` with `--bind-map` runs the sidecar read off the forwarding loop**
  (`src/sender/links.rs`), because a retried mismatch could otherwise stall forwarding
  for up to 2 s. Without `--bind-map`, SIGHUP is upstream's reload plus the guard below.
- **IP-list reload (`SIGHUP`)** keeps surviving uplinks' sockets and registrations (no
  re-handshake) and rebuilds the pool in file order. A reload resolving to zero valid
  source IPs is refused with a specific log and the stream keeps running on the
  existing links (`src/sender/reload.rs`).
- **IPs-file lines may carry an optional upstream weight, `<ip> <weight>`** (integer
  1..10, used in classic mode only). CeraUI's bare-IP lines read as weight 1. One shared
  parser (`parse_ip_line`, `src/sender/reload.rs`) serves startup, `SIGHUP`, `--dry-run`
  and bind-map coherence (`src/bind_map/parser.rs`). Weight is not link identity: it is
  outside the socket key, and a weight-only reload keeps the registration.
- **`--config <toml>` is upstream's flag.** It is read once at startup and validated by
  `--dry-run` (an unknown key or a parse failure exits non-zero). CeraUI does not pass
  it. `src/toml_config.rs`, `tests/cli_surface.rs`.
- **`get_stats` and `stats` links gain upstream's additive `weight` field**
  (`src/stats.rs`). The ADR-001 `--stats-file` document does not carry it.
- **Empty start is not fatal.** A missing, empty, or all-invalid `BIND_IPS_FILE` at
  startup binds the local listener, starts with an empty uplink pool, and waits for a
  `SIGHUP`. It must never crash-loop the device. `tests/signal_parity.rs`.
- **Startup bind ordering.** The local `SRT_LISTEN_PORT` listener is bound before the
  IP list is read and before any uplink is dialed, because CeraUI dials that port
  immediately after spawn with no readiness handshake. Never move the bind below uplink
  setup. `tests/startup_bind_ordering.rs`.
- **Clean shutdown (`SIGTERM`/`SIGINT`)** exits `0` well inside CeraUI's 10 s SIGKILL
  window and unlinks the stats file. `tests/signal_parity.rs`. This holds during
  start-up too: the pair read and the uplink dial are both raced against the two
  signals, and exit does not wait for a receiver lookup. `tests/signal_shutdown.rs`.
  SIGHUP is ignored from the first statement of `main` until the handlers are
  registered, so an early reload signal cannot kill the sender.
- **NAT-keepalive control padding.** Every control-plane send (keepalive, REG1/REG2)
  is zero-padded to at least `MIN_CONTROL_PKT_LEN = 32` bytes
  (`crates/srtla-protocol/src/constants.rs`, applied in `src/sender/uplink.rs`), parity
  with the C `pad_sendto`. DATA is never padded.
- **`--conn-timeout-ms` is upstream's flag; CeraUI passes `15000`.** Upstream's default
  is `CONN_TIMEOUT = 5` s (`crates/srtla-protocol/src/constants.rs`), clamped to
  `1000..=60000` ms and also settable at runtime via `set_conn_timeout`. The 15 s value
  that matches the receiver's `CONN_TIMEOUT` is **not baked into the binary**; the CeraUI
  package sets it on the command line. Do not change the constant here.
- **Re-home and stall deselect are upstream defaults, ON.** `--no-rehome` and
  `--no-stall-deselect` are the opt-outs. Neither is a CERALIVE experimental flag; they
  are upstream behavior and are documented by upstream's README sections below.
- **`-v/--version`** is operator-visible (CeraUI renders it in Settings → Versions).
  Shape: `<version> [(<branch>@<hash>[-dirty])] [srtla_send]`; the parenthetical is
  omitted, not placeholdered, when there is no git context. `src/version.rs`.
- **Scheduling modes are upstream's two:** `classic` and `enhanced` (default). No other
  value is accepted, pinned by `mode_accepts_only_the_upstream_value_set`.

- **Required binding (ADR-003 §9)** is opt-in via `--require-bind-map` with
  `--bind-map`. Probe `bind_map_required == true` first. Degraded first reads
  run no uplinks; SIGHUP can recover. Degraded reload retains mapped sockets.

- **Final-link withdrawal (ADR-003 §9.3)** requires
  `bind_map_required_empty_reload == true` and required mode. Only validated
  empty mappings remove all links; degraded reads retain, and later re-add
  starts fresh registration. Default empty-reload behavior is unchanged.

- **Required source/receipt checks (ADR-003 §9.4):** canonical unicast only;
  limited/multicast and determinable directed broadcasts refused. Runtime and
  dry-run require assignment to the selected interface. Checked device binding
  verifies the actual local source and link-local scope. Required reloads report
  `pending_apply` until reader cancellation is joined and connection/report
  snapshots are committed together. Empty active/mapped is a completed receipt.

- **Retired required links (ADR-003 §9.4):** a required link whose source is not
  verifiably on its mapped device holds no socket and sends nothing. Its row keeps
  `link_id`/`iface` and adds the OPTIONAL per-connection key
  `binding_state: "retired"` (absent on every other row and outside required
  mode). The sender retries the checked bind on the reconnect backoff and the
  link returns without a reload. Unit tests in `src/sender/housekeeping.rs`; the
  privileged `tests/strict_source_netns.rs` (root and iproute2 only, self-skips)
  proves it on real interfaces; fixture `telemetry-required-retired.json`.

- **Required-binding contract revision:** require integer `bind_map_contract >= 2`
  alongside both required-binding booleans for §9.4 guarantees. Linux advertises
  2; other platforms 0. Missing/zero is unverified; future revisions retain the
  earlier behavior guarantees. Schema versions are independent.

- **Revision 2 (ADR-003 §9.5)** identifies applied and pending maps by generation
  and exact IP-file SHA. Strict generations never regress within one producer
  lifetime; a same-generation no-op cannot overtake newer ingress/pending work.
  Request ingress and joined publication share a gate. Consumers require
  `bind_map_contract >= 2` and exact applied identity, not wall-clock freshness.
