# SRTLA Sender (Rust)

[![CI](https://github.com/CERALIVE/srtla-send-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/CERALIVE/srtla-send-rs/actions/workflows/ci.yml)
[![Release](https://github.com/CERALIVE/srtla-send-rs/actions/workflows/release.yml/badge.svg)](https://github.com/CERALIVE/srtla-send-rs/actions/workflows/release.yml)

A Rust implementation of the SRTLA bonding sender. SRTLA is a SRT transport proxy with link aggregation for connection bonding that can transport [SRT](https://github.com/Haivision/srt/) traffic over multiple network links for capacity aggregation and redundancy. Traffic is balanced dynamically, depending on the network conditions. The intended application is bonding mobile modems for live streaming.

This application is experimental. Be prepared to troubleshoot it and experiment with various settings for your needs.

This repository is [CERALIVE](https://github.com/CERALIVE)'s fork of [`irlserver/srtla_send`](https://github.com/irlserver/srtla_send). Upstream's code is used as-is; a thin layer of operator flags, telemetry, and packaging that the CeraUI device integration needs sits on top. That layer is described in [The CERALIVE layer](#the-ceralive-layer) below; everything else on this page is upstream's documentation and applies unchanged.

## Credits & Acknowledgments

This Rust implementation builds upon several open source projects and ideas:

- **[Moblin](https://github.com/eerimoq/moblin)** - Inspired by ideas and algorithms
- **[Original SRTLA](https://github.com/BELABOX/srtla)** - The foundational SRTLA protocol and reference implementation by Belabox

## Features

### Core SRTLA Functionality

- Multi-uplink bonding using a list of local source IPs
- Registration flow (REG1/REG2/REG3) with ID propagation
- SRT ACK and NAK handling (with correct NAK attribution to sending uplink)
- Dynamic path selection with automatic load distribution across all connections
- Keepalives with RTT measurement and time-based window recovery
- Live IP list reload on Unix via SIGHUP
- Runtime configuration via stdin or Unix socket (no restart required)

### Scheduling Modes

The sender supports two mutually exclusive scheduling modes:

#### Enhanced Mode (Default)

- **Exponential NAK Decay**: Smooth recovery from packet loss over ~8 seconds
- **NAK Burst Detection**: Extra penalties for connections experiencing severe packet loss (≥5 NAKs)
- **RTT-Aware Selection**: Small bonus (3% max) for lower-latency connections
- **Quality Scoring**: Automatic preference for higher-quality connections
- **Score Hysteresis**: 10% threshold prevents noise-driven flip-flopping while maintaining natural load distribution

#### Classic Mode

- Exact match to original `srtla_send.c` implementation
- Pure capacity-based selection without quality awareness
- Enable via `--mode classic`

### Stalled-Link Deselect (On by Default)

- **What it does**: Temporarily excludes a link that is holding a large in-flight backlog while producing no fresh delivery proof (no earned ACK and no keepalive round-trip within the staleness window), as long as a healthier link can carry the traffic.
- **Independent liveness signal**: The staleness clock is stamped only on an earned ACK or a completed keepalive round-trip, never on generic inbound bytes, so a link that merely echoes traffic while its data path is dead still goes stale.
- **Self-recovering**: A deselected link keeps sending keepalives. Its next keepalive round-trip clears the stall on its own, so the scheduler never probes a dead link blindly. Genuinely dead links are still pruned by the normal 15 second connection timeout.
- **Selection penalty only**: It never affects timeouts, re-registration, or connection liveness. It is a routing decision, nothing more.
- **Disable via**: `--no-stall-deselect`, or the `set_stall_deselect` JSON-RPC method. Thresholds are tunable with `--stall-min-in-flight` and `--stall-ack-stale-ms`.
- **Use Case**: Satellite links (Starlink) during obstructions or handovers, where a link keeps a backlog but briefly stops delivering.

## Assumptions and Prerequisites

This tool assumes that data is streamed from a SRT _sender_ in _caller_ mode to a SRT _receiver_ in _listener_ mode. To get any benefit over using SRT directly, the _sender_ should have 2 or more network links to the SRT listener (in the typical application, these would be internet-connected 4G modems). The sender needs to have [source routing](https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.rpdb.simple.html) configured, as srtla uses `bind()` to map UDP sockets to a given connection.

## Install

Each [release](https://github.com/CERALIVE/srtla-send-rs/releases) ships the `srtla` package as a `.deb` for `amd64` and `arm64`. It's built on Debian 12 (Bookworm) and needs glibc 2.36 or newer:

```bash
sudo dpkg -i srtla_*_arm64.deb
```

On other platforms, build from source.

## Requirements

- Rust and Cargo. `rust-toolchain.toml` pins `nightly-2026-06-12` (see [Toolchain](#toolchain)), and rustup installs it on the first `cargo` command. `rustfmt.toml` uses unstable options, so formatting needs that nightly too.
- Unix (Linux/macOS) or Windows
  - Note: SIGHUP-based IP reload is Unix-only; Windows runs without that arm

## Build

```bash
cd srtla_send
cargo build --release
# binary at target/release/srtla_send
```

## Testing

The project includes test suites covering unit tests, integration tests, and end-to-end tests.

### Run Tests Locally

The `xlint` and `xtest` aliases in `.cargo/config.toml` run the same commands as CI, across every crate in the workspace.

```bash
# Run all tests in the workspace, as CI does
cargo xtest

# Run clippy, as CI does
cargo xlint

# Run a specific test
cargo test test_connection_score

# Format code (pinned nightly)
cargo fmt --all
```

### CI/CD

GitHub Actions runs on every push and pull request:

- Formatting and clippy
- Tests on Linux, Windows and macOS, plus Rust stable and beta
- Miri over the unsafe batch-receive code, and Loom over the subscription hub
- Supply chain checks with cargo-audit and cargo-deny
- A `.deb` build for `arm64` and `amd64`

Pushing a `v<version>` tag publishes the release. Both workflows are described under [CI and packaging](#ci-and-packaging) in the CERALIVE section.

## Usage

```bash
srtla_send [OPTIONS] SRT_LISTEN_PORT SRTLA_HOST SRTLA_PORT BIND_IPS_FILE
```

### Required Arguments

- `SRT_LISTEN_PORT`: UDP port on which to receive SRT packets locally
- `SRTLA_HOST`: hostname or IP of the SRTLA receiver (e.g., srtla_rec)
- `SRTLA_PORT`: UDP port of the SRTLA receiver
- `BIND_IPS_FILE`: path to a file with newline-separated local source IPs (uplinks). Each line is `<ip>[ <weight>]`: the optional
  weight (integer 1..10, default 1) is a link priority in the style of Moblin's
  "connection priorities". Weights are normalised so the lowest link is 1; in
  classic mode a link's score is multiplied by its weight while its window is
  above 20 000, the multiplier fades linearly to 1 between 20 000 and 10 000,
  and is ignored below. Enhanced mode ignores weights. Exported per link as
  `srtla_send_link_weight`.

### Options

- `--mode <MODE>`: Scheduling mode: `classic`, `enhanced` (default)
- `--no-quality`: Disable quality scoring (enhanced only)
- `--no-stall-deselect`: Disable the stalled-link deselect guard (on by default). The guard skips a link whose in-flight backlog is high while its last delivery proof (an earned ACK or keepalive round-trip) has gone stale, provided a healthier link can carry the traffic. The link recovers automatically on its next keepalive round-trip, so nothing is probed blindly. This mainly helps satellite links (Starlink obstructions and handovers) that keep a large backlog while briefly delivering nothing.
- `--stall-min-in-flight <N>`: In-flight backlog (packets) at or above which a link becomes a stall candidate (default 32)
- `--stall-ack-stale-ms <MS>`: Delivery-proof staleness window in milliseconds after which a stall candidate is deselected (default 3000)
- `--conn-timeout-ms <MS>`: Per-link liveness timeout. Silence past this tears the link down and re-registers it (default 5000, clamped to 1000..=60000, also settable at runtime with `set_conn_timeout`). A timed-out link that was registered before makes its first 4 reconnect attempts 1 s apart, so a short modem or tether blip re-registers before SRT's 5 s peer-idle timeout ends the session. After that it retries every 5 s until it registers again.
- `--no-rehome`: Disable whole-bond re-home (on by default). When every uplink has been down for longer than the all-links-failed window *and* the receiver hostname no longer resolves to the address the bond is pinned to, the sender moves every uplink together to the newly-resolved address and re-registers from scratch over the ordinary REG1/REG2/REG3 flow. It is deliberately conservative: a bond with any live uplink is never touched, a merely reordered DNS answer is not a move, a failed lookup is not a move, and at most one migration is attempted per minute. Pass this to keep the old behaviour of staying on the cached address until the process is restarted.
- `--config <PATH>`: Path to a TOML config file, read once at startup. Each key is the long flag name with underscores (for example `stall_ack_stale_ms = 2000`), and a flag given on the command line wins over the file. The supported keys are `mode`, `no_quality`, `no_stall_deselect`, `stall_min_in_flight`, `stall_ack_stale_ms` and `conn_timeout_ms`. An unknown key or a file that fails to parse stops startup.
- `--control-socket <PATH>`: Unix domain socket path for remote control (e.g., `/tmp/srtla.sock`)
- `--priority-bind <ADDR:PORT>`: UDP sidecar address for encoder keyframe priority hints
- `--metrics-bind <ADDR:PORT>`: Expose a Prometheus scrape endpoint at `/metrics`
- `-v, --version`: Print version and exit (see [Version output](#version-output))

The CERALIVE fork adds `--verbose`, `--dry-run`, `--stats-file`, `--stats-file-interval`, `--bind-map`, and `--capabilities-json`. They are documented in [The CERALIVE layer](#the-ceralive-layer).

### Version output

`srtla_send -v` prints the crate version, an optional git build-metadata parenthetical, and the package name:

```bash
$ ./target/release/srtla_send -v
4.2.0 (main@974c8b9) [srtla_send]
```

The parenthetical is emitted only when the build could resolve a commit. Building outside a git checkout (an exported source tarball, a container that copies only `src/`, a vendored crate) is a normal build with nothing to name, so the metadata is omitted entirely rather than filled with a placeholder:

```bash
$ ./target/release/srtla_send -v
4.2.0 [srtla_send]
```

A tag build (detached HEAD) reports the bare hash, `4.2.0 (974c8b9) [srtla_send]`, and a build from a modified working tree suffixes the hash with `-dirty`.

## The CERALIVE layer

Everything in this section is CERALIVE's addition on top of upstream. It exists because [CeraUI](https://github.com/CERALIVE/CeraUI) spawns `srtla_send` on the device, reads its telemetry, and packages it into the device image. The contract CeraUI depends on is written down in [the parity contract](docs/agents/parity-contract-ceraui-depends-on-every-bullet-change-only-w.md); this is the operator's view of the same things.

### Version and upstream sync

The fork is based on upstream `df0b3938791ff24eced4aed8b29e3d49d0efb639` (v4.0.1). The last-merged upstream commit is `9e63d8f` (the 2026-11 sync, recorded in [`docs/notes/upstream-sync-2026-11.md`](docs/notes/upstream-sync-2026-11.md)). It ships as **`4.2.0`**. The version follows upstream's semver line, not CalVer, so a CERALIVE release stays traceable to the upstream release it builds on. Upstream merges are manual and gated: they land in a dedicated PR, run the full gate on the pinned toolchain, and must not regress the contract below. There is no automatic sync. The upstream remote is added only for the duration of a merge and removed before the PR is opened.

### Toolchain

`rust-toolchain.toml` pins `nightly-2026-06-12` (the crate needs nightly for its `rustfmt` configuration; upstream floats on `nightly`, the fork pins a date so the device image is reproducible). `cargo` picks it up automatically; the "Build" section above still applies.

### Flags added by the fork

- `--verbose`: enable debug-level logging (equivalent to `RUST_LOG=debug` for the sender's own spans).
- `--dry-run`: parse `BIND_IPS_FILE`, resolve `SRTLA_HOST`, print both, and exit `0` **without binding any socket**. A missing, unreadable, empty, or all-invalid IP list exits non-zero with a specific error. With `--bind-map`, an unusable sidecar is also an error here rather than a fallback.
- `--stats-file <PATH>`: publish the telemetry snapshot described below to this path. Opt-in: omit the flag and no file is ever written.
- `--stats-file-interval <MS>`: publish cadence for `--stats-file` (default `1000`).
- `--bind-map <PATH>`: an optional sidecar that adds interface binding and stable link identity to `BIND_IPS_FILE`, described below.
- `--capabilities-json`: print one line of JSON describing what this build supports and exit `0`, before logging starts and without binding anything.

Two upstream defaults matter to the device integration and are left as upstream ships them: whole-bond re-home and stalled-link deselect are **on** (`--no-rehome`, `--no-stall-deselect` to opt out), and the per-link liveness timeout defaults to 5 s. CeraUI passes `--conn-timeout-ms 15000` on the command line to match the bonding receiver's own timeout; the binary does not bake that value in.

### Telemetry file contract

With `--stats-file`, the sender writes a single-line JSON document on every interval. Each publish is atomic (written to a temp sibling, `fsync`ed, then renamed over the target), so a reader never sees a partial file, and the fsync runs off the packet-forwarding loop. On a clean `SIGTERM`/`SIGINT` the file and its `.tmp` sibling are removed.

If the OS cannot create the telemetry writer thread, startup exits non-zero with a `spawn telemetry writer thread` error and the underlying OS cause, rather than panicking. Once the writer has started, filesystem publish failures remain best-effort warnings and do not stop the stream.

```json
{"schema_version":1,"last_updated_ms":1749556546000,"connections":[{"conn_id":"0","rtt_ms":42,"nak_count":3,"weight_percent":50,"window":8192,"in_flight":100,"bitrate_bps":2500000,"bytes_sent_total":812000000,"iface":"wwan0","link_id":"modem-a"},{"conn_id":"1","rtt_ms":42,"nak_count":3,"weight_percent":50,"window":8192,"in_flight":100,"bitrate_bps":2500000,"bytes_sent_total":812000000,"iface":"wwan1","link_id":"modem-b"}],"bytes_sent_total":1620000000,"bind_map_status":{"state":"active"},"disposition":{"state":"mapped"}}
```

- `schema_version` is `1` and names the shape of the **required** fields. The schema grows only by addition; added fields are always optional and never bump the version.
- `last_updated_ms` is wall-clock epoch milliseconds (a consumer compares it against its own clock to detect a stale producer).
- The seven required per-connection fields are `conn_id`, `rtt_ms`, `nak_count`, `weight_percent`, `window`, `in_flight`, `bitrate_bps`. `bitrate_bps` is wire bytes per second **× 8**. `conn_id` is the string index of the uplink in `BIND_IPS_FILE`, so a `SIGHUP` reorder changes it; anything that must survive a reload keys on `link_id` instead.
- `bytes_sent_total` (per connection and for the whole bond) is a cumulative **byte** count, no ×8, monotonic for the process lifetime: it survives a link's socket replacement and does not go backwards when a reload drops a link. Absent means unknown, never zero. See [ADR-002](docs/adr/ADR-002-session-bytes-telemetry.md).
- `bind_map_status` and `disposition` are always present at the top level (an unmapped run reports `{"state":"absent"}` and `{"state":"legacy_unique_only"}`). The per-connection `iface` and `link_id` appear only for a mapped link and are omitted (never `null`, never `""`) otherwise, as is `bind_map_status.reason` when there is no degradation. See [ADR-003](docs/adr/ADR-003-bind-map-contract.md).
- An idle sender publishes `"connections":[]`; it does not stop publishing.

`docs/adr/ADR-001-control-protocol.md` holds the original schema record. Its control-socket transport section is superseded by [ADR-004](docs/adr/ADR-004-control-dialect.md): the sender uses upstream's JSON-RPC dialect as-is and extends it only additively. Note that `get_stats` and the `stats` subscription return upstream's richer stats snapshot (whose rate field is `bitrate_bytes_per_sec`, in bytes), extended with the same optional `bytes_sent_total`, `iface`, `link_id`, `bind_map_status`, and `disposition` fields. The file is the ADR-001 document; the socket is upstream's shape plus those additions.

### Bind-map sidecar

`BIND_IPS_FILE` identifies an uplink by source IP alone, which cannot tell two identical USB modems apart when both present the same address. `--bind-map <PATH>` names a separate JSON file that describes the IP list **positionally**: the Nth row describes the Nth accepted IP line and carries `{link_id, ip, iface, id_path?}`, under a header of `{schema_version, generation, ips_file_sha256}`. The IP list itself is byte-unchanged, and without the flag the sender behaves exactly as upstream does.

With a mapping in place, a link's socket is bound to its interface with `SO_BINDTODEVICE` **and** to its source address, so egress leaves the named interface and the wire source is deterministic. `link_id` is the stable identity across reloads, reconnects, and interface changes. The interface is re-resolved by name every housekeeping tick (a replugged modem gets a fresh socket; a vanished one waits for a reload), and each interface's default route is observed read-only and reported on its own axis in the status log. The sidecar must name the exact IP-list bytes it describes; a mismatch is retried briefly and then fails open in a duplicate-safe way (at startup, one representative of a same-IP collision group is kept and the rest reported excluded; on a reload, the last valid mapped pool is retained). Full contract: [ADR-003](docs/adr/ADR-003-bind-map-contract.md).

### Capability probe

A supervisor has to decide **before spawning** whether the installed binary understands the optional flags. `--capabilities-json` answers that:

```bash
$ srtla_send --capabilities-json
{"schema_version":1,"binary":"srtla_send","version":"4.2.0","capabilities":{"bind_map":true,"stats_file":true,"dry_run":true,"control_socket_jsonrpc":true,"conn_timeout_ms":true,"modes":["classic","enhanced"]}}
```

The `get_capabilities` JSON-RPC method on `--control-socket` returns the same document plus a `methods` array. A binary that predates the flag rejects it with a usage error and a non-zero exit; callers treat **any** non-zero exit, unparseable output, or timeout as "no support" and fall back to the plain spawn. See [ADR-004](docs/adr/ADR-004-control-dialect.md).

### Control socket

The control dialect is upstream's JSON-RPC 2.0 exactly as documented in [docs/CONTROL_PROTOCOL.md](docs/CONTROL_PROTOCOL.md). CERALIVE adds `get_capabilities` and the optional telemetry fields above, nothing else: no handshake method, no second subscription method, no alternative naming. Subscriptions carry no replay of the last frame, so a client that wants immediate state calls `get_stats` once after subscribing.

### Startup and shutdown behavior

- The local `SRT_LISTEN_PORT` listener is bound before the IP list is read and before any uplink is dialed, so an encoder that connects immediately after spawn never hits a closed port.
- A missing, empty, or all-invalid `BIND_IPS_FILE` at startup is not fatal: the sender starts with no uplinks and waits for a `SIGHUP`.
- A `SIGHUP` reload that resolves to zero valid source IPs is refused with a specific log line and the existing links keep running.
- `SIGTERM`/`SIGINT` exit `0` promptly and remove the stats file, including while start-up is still reading the bind-map or dialing uplinks.
- Control-plane frames (keepalive, REG1/REG2) are zero-padded to at least 32 bytes so carrier NATs do not drop them. Data is never padded.

### CI and packaging

Two workflows, both on the pinned nightly:

- `ci.yml` (push and PR): formatting, clippy with warnings as errors, the bounded test suite, `cargo audit` and `cargo deny`, upstream's stable/beta/Windows/macOS lanes, a blocking **Loom** lane over the subscription hub (`RUSTFLAGS="--cfg loom" cargo test --test subscription_loom`, 2 tests), a blocking **Miri** lane over the five pure pointer-logic tests in `src/net/batch_recv.rs`, and a `.deb` build matrix for `arm64` and `amd64` so a packaging break is caught before any tag.
- `release.yml` (tag `v*`): the same gate, then both `.deb`s built inside `debian:bookworm-slim` with a **`GLIBC_2.36`** ceiling check on each binary (Debian 12 is the device image), attached to the GitHub release with their `.sha256` files.

The package is **`srtla`**, the binary installs at `/usr/bin/srtla_send`, and the artifact is named `srtla_<version>_<arch>.deb` (`srtla_4.2.0_arm64.deb`, `srtla_4.2.0_amd64.deb`). `ci/build-deb.sh` is the single source of truth for that metadata and re-runs the device image builder's fetch glob against the real filename as a self-test. A release tag must be `v<version>` with the version taken from `Cargo.toml`.

Privileged network-namespace tests (`tests/netns_*.rs`, including the duplicate-IP twin-modem scenarios in `tests/netns_twin.rs`) self-skip on ordinary runners and are run locally through `scripts/netns_test_gate.sh`.
The stall-latch fixture fix reduced the flake, but `silence pull engaged` can still rarely fail when the dead link's backlog stays below `--stall-min-in-flight` (32); pinning and backlog preconditions remain follow-ups.
ACKs for retransmitted sequences and duplicate probes retain delivery/accounting effects but do not sample RTT, because a sequence ACK cannot identify which copy arrived.
The wire-loss fixture holds the real SRT caller at 4 Mbps below either 6 Mbps path, preserving its original per-link and CC thresholds.

### License

Upstream's MIT license and credits are kept intact in this repository. CERALIVE applies AGPLv3 at the distribution layer, not by altering upstream's notices.

## Example Usage

Let's assume that the receiver has IP address 10.0.0.1 and the sender has 2 (unreliable) modems with IP addresses 192.168.0.2 and 192.168.1.2 respectively, which can reach the receiver. We'll set up the srtla sender to forward SRT traffic from port 6000 to the receiver's srtla service on port 5000.

### Sender Setup

```bash
echo 192.168.0.2 > /tmp/srtla_ips
echo 192.168.1.2 >> /tmp/srtla_ips
./target/release/srtla_send 6000 10.0.0.1 5000 /tmp/srtla_ips
```

With `srtla_send` running on the sender, SRT-enabled applications should stream to port `6000` on the sender and this data will be forwarded through srtla to the receiver.

### Additional Examples

**With logging and Unix socket control:**

```bash
RUST_LOG=info ./target/release/srtla_send --control-socket /tmp/srtla.sock 6000 rec.example.com 5000 ./uplinks.txt
```

**With classic mode:**

```bash
./target/release/srtla_send --mode classic 6000 rec.example.com 5000 ./uplinks.txt
```

**With quality scoring disabled:**

```bash
./target/release/srtla_send --no-quality 6000 rec.example.com 5000 ./uplinks.txt
```

Sample `uplinks.txt`:

```text
192.0.2.10
198.51.100.23
203.0.113.5
```

## Logging

This tool uses `tracing` with `EnvFilter`.

- Control verbosity with `RUST_LOG` (e.g., `RUST_LOG=info`, `RUST_LOG=debug`).
- Example:

```bash
RUST_LOG=info,hyper=off ./target/release/srtla_send 6000 host 5000 ./uplinks.txt
```

## Runtime Configuration

The sender supports dynamic runtime configuration changes through two methods:

### Method 1: Standard Input (stdin)

Type commands directly into the running process and press Enter.

### Method 2: Unix Domain Socket (Unix only)

Use the `--control-socket` option to enable remote control via Unix socket. The wire format is JSON-RPC 2.0, one request per line. Full method reference lives at [docs/CONTROL_PROTOCOL.md](docs/CONTROL_PROTOCOL.md).

```bash
# Start with Unix socket control
./target/release/srtla_send --control-socket /tmp/srtla.sock 6000 10.0.0.1 5000 /tmp/srtla_ips

# Fetch current status
echo '{"jsonrpc":"2.0","id":1,"method":"get_status"}' \
    | socat - UNIX-CONNECT:/tmp/srtla.sock

# Switch scheduler mode
echo '{"jsonrpc":"2.0","id":1,"method":"set_mode","params":{"mode":"classic"}}' \
    | socat - UNIX-CONNECT:/tmp/srtla.sock
```

### Available Methods

- `set_mode { "mode": "classic"|"enhanced" }`
- `set_quality { "enabled": bool }`
- `get_status` returns the full config snapshot and priority-sidecar counters
- `get_stats` returns per-link telemetry JSON
- `subscribe` / `unsubscribe` to a topic (`stats` or `priority.window`) for streamed updates

Keyframe priority hints travel on a dedicated UDP sidecar, not the control socket. See [docs/KEYFRAME_PRIORITY.md](docs/KEYFRAME_PRIORITY.md).

## Prometheus `/metrics`

Pass `--metrics-bind ADDR:PORT` to expose a Prometheus scrape endpoint at `/metrics`. No additional deps — hand-rolled over `tokio::net::TcpListener`. Serves `GET /metrics` and `GET /` with text format (version 0.0.4); anything else returns 404. Example:

```
srtla_send --metrics-bind 127.0.0.1:9099 \
           --priority-bind 127.0.0.1:7000 \
           --control-socket /tmp/srtla.sock \
           6000 rec.example.com 5000 /tmp/uplinks
```

```
curl -s 127.0.0.1:9099/metrics
```

Exposed series include `srtla_send_link_up`, `srtla_send_link_rtt_ms`, `srtla_send_link_window`, `srtla_send_link_in_flight`, `srtla_send_link_nak_total`, `srtla_send_link_bitrate_bytes_per_second`, `srtla_send_link_quality_multiplier`, plus aggregate `srtla_send_active_links`, `srtla_send_total_window`, `srtla_send_critical_windows_total`, and the current `srtla_send_mode` as a numeric gauge.

### Connection Selection Algorithm Details

**Classic Mode**: Matches the original srtla_send logic without any enhancements.

**Enhanced Mode** (default): Quality-based scoring that punishes connections with recent NAKs. More recent NAKs mean more punishment. Additional 30% penalty (0.7x multiplier) for NAK bursts (≥5 NAKs in short time).

## IP List Reload (Unix only)

Send SIGHUP to trigger an IP list reload without restarting:

```bash
kill -HUP <pid_of_srtla_send>
```

On Windows this arm is disabled; restart the process after editing the IP list.

## How It Works

The core idea is that srtla keeps track of the number of packets in flight (sent but unacknowledged) for each link, together with a dynamic window size that tracks the capacity of each link - similarly to TCP congestion control. These are used together to balance the traffic through each link proportionally to its capacity. However, note that no congestion control is applied.

### srtla v2 Improvements

The main improvement in srtla v2 is that it supports multiple _srtla senders_ connecting to a single _srtla receiver_ by establishing _connection groups_. To support this feature, a 2-phase connection registration process is used:

Normal registration:

- Sender (conn 0): `SRTLA_REG1(sender_id = SRTLA_ID_LEN bytes sender-generated random id)`
- Receiver: `SRTLA_REG2(full_id = sender_id with the last SRTLA_ID_LEN/2 bytes replaced with receiver-generated values)`
- Sender (conn 0): `SRTLA_REG2(full_id)`
- Receiver: `SRTLA_REG3`
- [...]
- Sender (conn n): `SRTLA_REG2(full_id)`
- Receiver: `SRTLA_REG3`

### Implementation Details

- For each IP in `BIND_IPS_FILE`, the sender binds a UDP socket to that source address and sends to `SRTLA_HOST:SRTLA_PORT` with `sendto`. The socket is deliberately left unconnected, so it still accepts replies from a multi-homed receiver that answers from another address, or through a NAT that rewrites the reply source (`src/net/batch_recv.rs`).
- Incoming SRT UDP packets are read on `SRT_LISTEN_PORT` and forwarded over the currently selected uplink based on the score `window / (in_flight + 1)`.
- ACKs are applied to all uplinks to reduce in-flight counts; NAKs are attributed to the uplink that originally sent the sequence (tracked), falling back to the receiver uplink if unknown.
- **Burst NAK Detection**: The system tracks NAK bursts (multiple NAKs within 1 second) per connection. When quality scoring is enabled, connections with recent NAK bursts (≥5 NAKs in burst, within last 3 seconds) receive an additional 0.7x multiplier (30% reduction) to their quality score, helping avoid connections experiencing packet loss issues.
- Keepalives are sent when idle, and periodically for RTT measurement; the RTT is smoothed. Window recovery is conservative and time-based when there are no recent NAKs.

## Notes

- Ensure your system has the specified local source IPs configured and routable.
- The local SRT producer (e.g., `srt-live-transmit`) should send to `udp://127.0.0.1:SRT_LISTEN_PORT`.
- The SRTLA receiver must understand the SRTLA protocol (REG1/2/3, ACK, NAK, KEEPALIVE).
- The sender **should** implement congestion control using adaptive bitrate based on the SRT `SRTO_SNDDATA` size or on the measured `RTT`. Due to reordering, these values may be slightly higher during uncongested operation over srtla compared to direct SRT operation over one of the same network links.

## License

This Rust implementation is licensed under the MIT License. See the [LICENSE](./LICENSE) file for full details.

## Expected Behavior

### Load Distribution

With properly configured connections, you should observe:

**All connections active**: Traffic should appear on all uplinks (e.g., if you have 4 uplinks, all 4 should show active bitrate)

**Proportional distribution**:

- With equal connections: roughly equal traffic distribution (e.g., 25% each with 4 uplinks)
- With varying quality (enhanced mode): better connections get more traffic, degraded connections get less
- With varying capacity: connections with larger windows get proportionally more traffic

**Dynamic adaptation (enhanced mode)**:

- Connections experiencing NAKs automatically receive less traffic
- Connections recover to full capacity within ~8 seconds after issues resolve
- System continuously rebalances based on current conditions

### Monitoring

**Status logs** (every 30 seconds) show:

- Total bitrate across all connections
- Individual connection status (active/timed out)
- Window sizes and in-flight packet counts
- RTT measurements and connection quality metrics
- Current mode and configuration

**Debug logs** (when `RUST_LOG=debug`) show:

- Per-packet connection selection decisions
- Quality multiplier calculations
- NAK burst detections and recovery
- Hysteresis decisions

### Troubleshooting

**If only some connections are used**:

1. Check for NAKs in logs - degraded connections naturally get less traffic in enhanced mode
2. Try classic mode via `set_mode { "mode": "classic" }` - disables quality awareness for pure capacity-based distribution
3. Temporarily disable quality scoring via `set_quality { "enabled": false }`
4. Verify all uplinks can reach the receiver (check for timeout messages)
5. Check RTT differences - high-RTT connections get slightly less traffic in enhanced mode (3% max difference)

**If throughput is lower than expected**:

1. Verify SRT is not limiting the bitrate (check encoder settings)
2. Check for high packet loss (NAKs) on connections - indicates network issues
3. Ensure sender has sufficient CPU and network capacity
4. Monitor SRT `SRTO_SNDDATA` buffer - if full, increase bitrate or improve connections
5. Check connection windows in status logs - low windows indicate capacity limits

**If connections are flip-flopping**:

1. This should be minimal with 10% hysteresis in enhanced mode
2. Check if scores are truly identical (look for hysteresis messages in debug logs)
3. Verify connections have stable quality (no intermittent NAKs)
4. Consider using classic mode for perfectly equal connections

## Performance Tuning

### Constants (Advanced)

If needed, these can be adjusted in `src/sender/selection/`:

**Enhanced Mode (`enhanced.rs`):**

- `SWITCH_THRESHOLD`: 1.10 (10% hysteresis) - increase for more stability, decrease for faster response

**Quality Scoring (`quality.rs`):**

- `STARTUP_GRACE_PERIOD_MS`: 30000ms (30 seconds) - grace period before quality penalties apply
- `PERFECT_CONNECTION_BONUS`: 1.1 (10% bonus) - bonus for connections with no NAKs
- `STARTUP_NAK_PENALTY`: 0.98 (2% penalty) - light penalty during grace period
- `HALF_LIFE_MS`: 2000ms (2 seconds) - NAK penalty decay speed
- `MAX_PENALTY`: 0.5 (50% penalty) - maximum initial penalty after NAK
- `NAK_BURST_THRESHOLD`: 5 NAKs - minimum burst size to trigger extra penalty
- `NAK_BURST_MAX_AGE_MS`: 3000ms (3 seconds) - max age for burst penalty
- `NAK_BURST_PENALTY`: 0.7 (30% reduction) - multiplier applied for bursts
- `RTT_BONUS_THRESHOLD_MS`: 200ms - RTT threshold for bonus calculation
- `MIN_RTT_MS`: 50ms - minimum RTT for calculation (prevents division issues)
- `MAX_RTT_BONUS`: 1.03 (3% max bonus) - maximum RTT bonus multiplier

### Runtime Optimization

For maximum throughput:

- Use enhanced mode (default) to automatically avoid degraded connections
- Ensure adequate SRT buffer size (`SRTO_SNDDATA`)
- Monitor for connection timeouts - these interrupt traffic flow
- Use `RUST_LOG=info` for minimal logging overhead (avoid debug in production)

For maximum stability:

- Use classic mode (`--mode classic`) for predictable, simple behavior
- Increase hysteresis threshold if experiencing unnecessary switching

For device-isolated uplinks, probe `capabilities.bind_map_required == true` and
pass `--require-bind-map --bind-map <path>`. Degraded startup waits with no
uplinks; degraded reload retains the last mapped pool. See
[ADR-003 §9](docs/adr/ADR-003-bind-map-contract.md#9-required-binding-opt-in-extension).

Consumers needing explicit final-link withdrawal must also require
`capabilities.bind_map_required_empty_reload == true`. In required mode a
valid empty mapping removes all uplinks, reports fresh empty connections,
and stays alive for re-add on SIGHUP (ADR-003 §9.3).

Required sources must be assigned unicast addresses on the selected device;
broadcast/multicast sources are refused, including mapped representations.
During required reload application, `pending_apply` is not a withdrawal receipt.
Empty `active` / `mapped` is published only after owned uplink sockets close.
See ADR-003 §9.4.

To rely on assigned-unicast sources and completed teardown acknowledgements,
also require integer `capabilities.bind_map_contract >= 2`. Earlier binaries
may advertise both required-binding booleans without these guarantees.

For causal publication/withdrawal receipts require `bind_map_contract >= 2`.
Match `bind_map_applied.generation` and `ips_file_sha256` to the exact latest
publication within the supervised producer lifetime; timestamps and pending
identities do not acknowledge application. Required generations cannot regress.
See ADR-003 §9.5 and the `telemetry-rev2-*.json` producer fixtures.

A refused required reload updates its degraded report and applied identity with
the actual connection snapshot; it does not queue a retained-pool application or
cancel live readers. The [control protocol reference](docs/CONTROL_PROTOCOL.md#get_stats)
lists the pending/refused states and the identities on runtime snapshots too.

Required-mode sends also canonicalize IPv4-mapped receiver addresses, so an
IPv4 source can forward to a receiver written as `::ffff:<IPv4>`, including
after reconnect. Native IPv6 destination scopes and default-mode behavior stay
unchanged.
