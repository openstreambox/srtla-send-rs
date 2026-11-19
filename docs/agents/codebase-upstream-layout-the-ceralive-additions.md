<!-- Moved verbatim from AGENTS.md on 2026-10-05 by lean-rules-docs-landing-latam -->

## CODEBASE (upstream layout + the CERALIVE additions)

```
crates/srtla-protocol/   wire constants and packet types (CONN_TIMEOUT, MIN_CONTROL_PKT_LEN)
crates/srtla-core/       connection, registration, selection, config snapshot, utils
crates/srtla-core/src/windowed_min.rs   time-windowed RTT floor
crates/network-sim/      dev-only netns harness; twin/ = duplicate-IP topology + sidecar publisher
src/main.rs              clap CLI (positionals, upstream flags, CERALIVE flags)
src/control.rs           JSON-RPC dispatch (+ get_capabilities)      src/subscriptions.rs  SubscriptionHub
src/capabilities.rs      --capabilities-json document                src/version.rs        -v line
src/telemetry_doc.rs     ADR-001 document model                      src/telemetry_file.rs --stats-file sink
src/toml_config.rs       applied --config file (read once at startup)
src/stats.rs             upstream snapshot + SessionBytes + bind-map report slot
src/bind_map/            ADR-003 sidecar: parser, coherence, retry, resolve, report
src/net/                 sockets (SourceIpBinder/DeviceBinder), spec, egress, route, batch I/O
src/sender/              forwarding loop, links (ips file vs bind-map pair), connections,
                         reload guard, egress_tick, housekeeping, rehome,
                         receiver_addrs (per-link address failover), status
src/sender/client_dedup.rs   forwards each SRT ACK/NAK to the client once
docs/adr/                ADR-001 (historical), ADR-002, ADR-003, ADR-004
ci/build-deb.sh          the .deb packager      scripts/  contract tests + netns gate
```

Conventions (enforced by the gate): edition 2024, `anyhow::Result`, `tracing` macros,
Tokio, imports grouped std → external → crate, constants `SCREAMING_SNAKE_CASE`.
Commit messages follow Conventional Commits. The repository root also keeps a symlink to `AGENTS.md`.

