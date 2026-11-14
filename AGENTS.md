# srtla-send-rs

Parent: [Workspace rules](https://github.com/CERALIVE/ceralive/blob/master/AGENTS.md).

<!-- workspace-hard-rules:begin -->
## Workspace hard rules (identical in every CeraLive AGENTS.md)
- Commits and PRs carry the human author only: no Co-authored-by, no AI attribution.
- Start from the updated canonical branch; rebase to update; never `reset --hard` or discard others' work.
- One focused PR per repo, opened against CERALIVE/<repo>; the root policy PR merges first.
- A repo is self-contained: no path above its root; consume @ceralive packages from the registry, never link:/file:.
- Never delete, skip or weaken a test; every behavior change ships with a test.
- A user-visible change updates docs.ceralive.tv in English and Spanish (es-419), and any ceralive.tv claim it touches, in the same release.
- AGENTS.md holds rules and routing only, within budget; contracts and history live in docs/agents/.
- Full canon: https://github.com/CERALIVE/ceralive/blob/master/AGENTS.md
<!-- workspace-hard-rules:end -->

## ROLE

CERALIVE hard fork of the upstream Rust SRTLA sender: upstream forwarding and scheduling plus a thin device-integration parity layer.
No npm bindings live here; the TypeScript helper is a CeraUI workspace package.

## STRUCTURE

- `src/` — sender, control, telemetry, sockets and bind-map integration.
- `crates/` — protocol, core and dev-only network simulation.
- `tests/` — parity, integration, Loom and privileged topology tests.
- `scripts/` — documentation, workflow and version contract gates.
- `ci/` — Debian packaging.
- `docs/` — ADRs, protocols, notes and relocated agent contracts.
- `.github/` — CI and release workflows.

## COMMANDS

Pinned `nightly-2026-06-12` is selected by `rust-toolchain.toml`.

```bash
cargo build --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check && cargo check --release
cargo test --lib
timeout --foreground --kill-after=10s 600s cargo test --workspace --all-features --verbose
timeout --foreground --kill-after=10s 600s cargo test --workspace --features test-internals
cargo audit && cargo deny check advisories sources
RUSTFLAGS="--cfg loom" cargo test --test subscription_loom
uv run scripts/release_workflow_contract_test.py
uv run scripts/rust_cache_contract_test.py
uv run scripts/workflow_authority_contract_test.py
bash scripts/release_version_contract_test.sh
bash scripts/deb_version_ordering_test.sh
bash scripts/check-doc-refs.sh
```

Five Miri filters, cross-channel/OS lanes, privileged netns prerequisites, stall-latch fixtures and RTT sample eligibility: [full gate contract](docs/agents/build-gate.md).

## WHERE TO LOOK

| Task / code path | Contract |
|---|---|
| Before changing anything else here, open docs/agents/README.md and read the contract for the subsystem you touch | [Contract index](docs/agents/README.md) |
| Overview | [overview.md](docs/agents/overview.md) |
| UPSTREAM RELATIONSHIP | [upstream-relationship.md](docs/agents/upstream-relationship.md) |
| PINNED TOOLCHAIN | [pinned-toolchain.md](docs/agents/pinned-toolchain.md) |
| PARITY CONTRACT (CeraUI depends on every bullet; change only with a versioned decision) | [parity-contract-ceraui-depends-on-every-bullet-change-only-w.md](docs/agents/parity-contract-ceraui-depends-on-every-bullet-change-only-w.md) |
| BUILD / GATE | [build-gate.md](docs/agents/build-gate.md) |
| CI / PACKAGING | [ci-packaging.md](docs/agents/ci-packaging.md) |
| CODEBASE (upstream layout + the CERALIVE additions) | [codebase-upstream-layout-the-ceralive-additions.md](docs/agents/codebase-upstream-layout-the-ceralive-additions.md) |
| ANTI-PATTERNS | [anti-patterns.md](docs/agents/anti-patterns.md) |
| DOCS DISCIPLINE (Rule A) | [docs-discipline-rule-a.md](docs/agents/docs-discipline-rule-a.md) |

## HARD RULES

- Preserve upstream MIT license and credits; layer AGPLv3 at distribution only.
- Upstream sync is manual, compat-gated and merge-commit merged; remove the transient remote before push or PR.
- Keep nightly-2026-06-12, smallvec =2.0.0-alpha.12 and libc 0.2 pinned unless deliberately approved and fully gated.
- Binary is srtla_send at /usr/bin/srtla_send; CLI order is <SRT_LISTEN_PORT> <SRTLA_HOST> <SRTLA_PORT> <BIND_IPS_FILE> [OPTIONS].
- Control is additive upstream JSON-RPC 2.0 over --control-socket (ADR-004 supersedes ADR-001 transport); --stats-file remains optional.
- No hello, subscribe-events, kebab-case methods or replay-on-subscribe; immediate state requires get_stats after subscribe.
- ADR-001 schema_version=1; rtt_ms is Kalman-smoothed RTT in ms; bitrate_bps is wire bytes/s ×8; additions optional, absent means unknown.
- Keep bytes_sent_total process-monotonic in bytes; never reset on replacement or reload, never treat missing as zero.
- Capability probe keys are frozen; nonzero exit, malformed output or timeout means no support, regardless of error wording.
- --bind-map stays optional; IP-list bytes stay unchanged; degraded reload retains the last valid mapped pool.
- Stable identity is link_id, not IP or (ip, iface); mapped sockets bind both interface and source IP.
- Never install policy routes or silently source-filter upstream's unconnected uplink sockets.
- Bind the local listener before reading the IP list or dialing uplinks; empty startup waits for SIGHUP, never crash-loops.
- Refuse zero-valid-IP reload while keeping live links; clean SIGTERM/SIGINT exits 0 within the device's 10 s window.
- Control frames are padded to at least 32 bytes; DATA is never padded.
- Only classic/enhanced scheduling; never restore retired experimental modes or selectors.
- Match receiver destinations to each source socket family at startup, reload, reconnect and whole-bond re-home; log and skip unavailable families. Preserve surviving registrations on reload and register replacement sockets.
- Keep CONN_TIMEOUT = 5 s; CeraUI supplies --conn-timeout-ms 15000. Never bake 15 s into the binary.
- No bindings directory, npm package or binding tag namespace here; the TypeScript helper lives and is tested in CeraUI.
- Package is srtla, artifact srtla_<ver>_<arch>.deb; tags match Cargo.toml; release builds stay Bookworm with GLIBC_2.36 ceiling.
- Keep telemetry-legacy-producer.json frozen; fixtures, wire and device parity changes require a deliberate versioned decision.
