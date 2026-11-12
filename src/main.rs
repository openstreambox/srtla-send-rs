// The CLI is a thin shell over the `srtla_send` library: it parses arguments,
// starts the optional sidecars, picks an egress binder for the platform, and
// hands off to `sender::run_sender_with_config`. Consuming the library rather
// than re-declaring its modules keeps one compilation of the tree instead of
// two, and keeps the library's embedder-facing surface (the Android and Apple
// binders no CLI ever constructs) from reading as dead code here.
//
// Under `--cfg loom` the library compiles down to `subscriptions` alone (see
// `lib.rs`), so there is nothing for this shell to consume; the Loom lane never
// runs the binary, it only has to link one.
#[cfg(not(loom))]
use std::net::{IpAddr, SocketAddr};
#[cfg(not(loom))]
use std::str::FromStr;

#[cfg(not(loom))]
use anyhow::{Context, Result, anyhow};
#[cfg(not(loom))]
use clap::Parser;
#[cfg(not(loom))]
use clap::builder::{PossibleValuesParser, TypedValueParser};
#[cfg(not(loom))]
use srtla_core::mode::SchedulingMode;
#[cfg(not(loom))]
use srtla_send::{
    capabilities, config, control_socket, metrics, net, priority_listener, sender, stats,
    subscriptions, telemetry_file, toml_config, version,
};
#[cfg(not(loom))]
use tracing_subscriber::EnvFilter;

#[cfg(loom)]
fn main() {}

// Use mimalloc as the global allocator for the binary (non-Windows only).
// Gated default-on via the `mimalloc` feature; --no-default-features builds
// fall back to the system allocator (docs/notes/mimalloc-decision.md).
#[cfg(all(not(windows), not(loom), feature = "mimalloc"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Flags that answer a question and exit, so the four stream positionals are
/// not required alongside them.
#[cfg(not(loom))]
const EARLY_EXIT_FLAGS: [&str; 2] = ["print_version", "capabilities_json"];

#[cfg(not(loom))]
#[derive(Parser, Debug)]
#[command(
    name = "srtla_send",
    author,
    version,
    disable_version_flag = true,
    about = "SRTLA sender CLI",
    override_usage = "srtla_send [OPTIONS] SRT_LISTEN_PORT SRTLA_HOST SRTLA_PORT BIND_IPS_FILE"
)]
struct Cli {
    /// Print the version and exit
    #[arg(short = 'v', long = "version", action = clap::ArgAction::SetTrue)]
    print_version: bool,

    /// Print a single line of JSON describing what this build supports, then
    /// exit 0 without binding a socket or writing a file. Intended as a
    /// pre-spawn probe: a binary that predates the flag answers with a usage
    /// error and a non-zero exit, which is the "no support" signal.
    #[arg(long = "capabilities-json")]
    capabilities_json: bool,

    /// Local UDP port to listen for SRT packets (from srt-live-transmit or SRT
    /// app)
    #[arg(required_unless_present_any = EARLY_EXIT_FLAGS)]
    local_srt_port: Option<u16>,
    /// Receiver host (srtla_rec or SRT listener)
    #[arg(required_unless_present_any = EARLY_EXIT_FLAGS)]
    receiver_host: Option<String>,
    /// Receiver UDP port to send SRTLA packets to
    #[arg(required_unless_present_any = EARLY_EXIT_FLAGS)]
    receiver_port: Option<u16>,
    /// Path to file containing newline-separated local source IPs to use for
    /// uplinks
    #[arg(required_unless_present_any = EARLY_EXIT_FLAGS)]
    ips_file: Option<String>,

    /// Path to the optional ADR-003 bind-map sidecar describing BIND_IPS_FILE
    /// positionally (`link_id` + egress interface per row). Additive and fully
    /// optional: omit it and the sender behaves exactly as it always has.
    #[arg(long = "bind-map")]
    bind_map: Option<String>,

    /// Require source and device binding for every uplink; degraded startup
    /// waits with no uplinks for a valid bind-map and SIGHUP.
    #[arg(long = "require-bind-map", requires = "bind_map")]
    require_bind_map: bool,

    /// Unix domain socket path for remote toggle control (e.g.,
    /// /tmp/srtla.sock)
    #[arg(long = "control-socket")]
    control_socket: Option<String>,

    /// Path to TOML config file (reloaded on SIGHUP)
    #[arg(long = "config")]
    config_file: Option<String>,

    /// Enable verbose (debug-level) logging
    #[arg(long = "verbose")]
    verbose: bool,

    /// Validate the IP list and resolve the receiver, then exit without binding
    /// sockets (non-zero exit if the IP list is unusable)
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Publish a per-uplink telemetry snapshot to this path (ADR-001). Opt-in:
    /// omit it and no file is ever written. Each publish is atomic (temp
    /// sibling, fsync, rename) and the file is unlinked on clean shutdown.
    #[arg(long = "stats-file")]
    stats_file: Option<std::path::PathBuf>,

    /// Publish cadence for `--stats-file`, in milliseconds.
    #[arg(long = "stats-file-interval", default_value_t = telemetry_file::DEFAULT_STATS_FILE_INTERVAL_MS)]
    stats_file_interval: u64,

    /// Scheduling mode: classic, enhanced (default)
    //
    // `SchedulingMode` is a pure core type and deliberately knows nothing about
    // clap. The CLI coupling lives here in the shell: parse the allowed strings
    // (which drive --help text and completion) and map through the core type's
    // own `FromStr`.
    #[arg(
        long = "mode",
        default_value = "enhanced",
        value_parser = PossibleValuesParser::new(["classic", "enhanced"])
            .map(|s| s.parse::<SchedulingMode>().expect("possible values are valid modes")),
    )]
    mode: SchedulingMode,
    /// Disable quality scoring (enhanced only)
    #[arg(long = "no-quality")]
    no_quality: bool,

    /// Disable the stalled-link deselect guard (on by default). The guard skips
    /// a link whose in-flight backlog is high while its last delivery proof has
    /// gone stale, provided a healthier link can carry the traffic. While
    /// gated the link carries keepalives plus a sparse duplicate-packet probe
    /// trickle; it rejoins after delivery proof has been sustained for the
    /// rejoin dwell (quick to drop, conservative to rejoin).
    #[arg(long = "no-stall-deselect")]
    no_stall_deselect: bool,
    /// In-flight packet backlog at or above which a link becomes a stall
    /// candidate for `--no-stall-deselect`.
    #[arg(long = "stall-min-in-flight", default_value_t = config::STALL_MIN_IN_FLIGHT_PACKETS)]
    stall_min_in_flight: i32,
    /// Ceiling (ms) on the delivery-proof staleness window after which a
    /// stall-candidate link is deselected. The effective window is
    /// RTT-adaptive (4x smoothed RTT, floored at 1000 ms) and this value caps
    /// it; links without an RTT baseline use the ceiling directly.
    #[arg(long = "stall-ack-stale-ms", default_value_t = config::STALL_ACK_STALE_MS)]
    stall_ack_stale_ms: u64,
    /// Per-link liveness timeout (ms): silence past this tears the link down
    /// and re-registers it. Also settable at runtime over JSON-RPC
    /// (`set_conn_timeout`) so a latency-aware client can scale it to
    /// `max(default, 2 x latency budget)` — an outage the receiver buffer
    /// can absorb should resume warm, not re-handshake. Clamped to
    /// 1000..=60000.
    #[arg(long = "conn-timeout-ms", default_value_t = config::CONN_TIMEOUT_MS)]
    conn_timeout_ms: u64,

    /// Disable whole-bond re-home (on by default). When every uplink has been
    /// down for longer than the all-links-failed window AND the receiver
    /// hostname no longer resolves to the address the bond is pinned to, the
    /// sender moves every uplink together to the newly-resolved address and
    /// re-registers from scratch over the ordinary REG1/REG2/REG3 flow. It
    /// never touches a bond with a live uplink, never follows a merely
    /// reordered DNS answer, and attempts at most one migration per minute.
    /// Pass this to keep the pre-existing behaviour of staying on the cached
    /// address until the process is restarted.
    #[arg(long = "no-rehome")]
    no_rehome: bool,

    /// UDP bind address for the keyframe priority sidecar. The encoder
    /// front-end sends 5-byte datagrams here to open a critical routing
    /// window. Unauthenticated same-device IPC: bind loopback. Omit to
    /// disable the sidecar (the keyframe-priority override is then inactive).
    /// Example: `127.0.0.1:7000`.
    #[arg(long = "priority-bind")]
    priority_bind: Option<std::net::SocketAddr>,

    /// TCP bind address for the Prometheus `/metrics` scrape endpoint.
    /// Unauthenticated: bind loopback. Omit to disable.
    /// Example: `127.0.0.1:9099`.
    #[arg(long = "metrics-bind")]
    metrics_bind: Option<std::net::SocketAddr>,
}

/// Warn when a sidecar is bound to a non-loopback address. These endpoints
/// are unauthenticated same-device IPC (encoder front-end and local scrapers),
/// so a routable bind exposes an open control / scrape surface. We warn rather
/// than refuse so an operator can still bind elsewhere on a trusted network if
/// they explicitly choose to.
#[cfg(not(loom))]
fn warn_if_not_loopback(what: &str, addr: std::net::SocketAddr) {
    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "{what} bound to a non-loopback address; it is unauthenticated and \
             should normally bind 127.0.0.1 / ::1"
        );
    }
}

#[cfg(not(loom))]
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Answered before the subscriber is installed: a probe's stdout must carry
    // the document and nothing else, and an operator's RUST_LOG must not be
    // able to contaminate what a supervisor parses.
    if args.capabilities_json {
        println!("{}", capabilities::capability_json());
        return Ok(());
    }

    // `--verbose` raises the default log level to debug (parity with the C
    // sender's --verbose); an explicit RUST_LOG still wins. Without the flag,
    // upstream's RUST_LOG-driven default is unchanged.
    let env_filter = if args.verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
    } else {
        EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    if args.print_version {
        println!("{}", version::version_line());
        return Ok(());
    }

    let local_srt_port = args.local_srt_port.expect("required");
    let receiver_host = args.receiver_host.as_deref().expect("required");
    let receiver_port = args.receiver_port.expect("required");
    let ips_file = args.ips_file.as_deref().expect("required");

    if args.require_bind_map {
        srtla_send::bind_map::ensure_required_binding_supported()?;
    }

    // `--dry-run` validates the configuration and exits before any socket is
    // bound: the local SRT listener is bound inside `run_sender_with_config`,
    // which this path never reaches.
    if args.dry_run {
        let report = dry_run_resolve(ips_file, receiver_host, receiver_port).await?;
        // A degraded map is an ERROR here, not a fallback: the operator asked
        // whether the configuration is valid, so answering "it will limp" with
        // exit 0 would defeat the flag.
        let mapping = match args.bind_map.as_deref() {
            None => None,
            Some(sidecar) => Some(
                srtla_send::bind_map::dry_run_validate(ips_file, sidecar)
                    .await
                    .and_then(|pool| {
                        if args.require_bind_map {
                            srtla_send::bind_map::validate_required_pool(pool)
                        } else {
                            Ok(pool)
                        }
                    })
                    .map_err(|e| anyhow!("bind-map is unusable ({}): {e}", e.reason()))?,
            ),
        };
        println!("dry-run: configuration valid; no sockets bound");
        println!(
            "receiver {receiver_host}:{receiver_port} resolves to {} address(es):",
            report.receiver_addrs.len()
        );
        for addr in &report.receiver_addrs {
            println!("  {addr}");
        }
        println!("source uplink IPs ({}):", report.source_ips.len());
        for ip in &report.source_ips {
            println!("  {ip}");
        }
        if let Some(pool) = mapping {
            println!(
                "bind-map generation {} maps {} uplink(s):",
                pool.generation,
                pool.rows.len()
            );
            for row in &pool.rows {
                println!(
                    "  {} on {} [{}]",
                    row.ip,
                    row.iface.as_str(),
                    row.link_id.as_str()
                );
            }
        }
        return Ok(());
    }

    // Load TOML config (if specified), then apply CLI overrides
    if let Some(ref path) = args.config_file {
        let toml_cfg = toml_config::TomlConfig::load_or_default(std::path::Path::new(path));
        tracing::debug!("TOML config loaded: {:?}", toml_cfg);
    }

    let config = config::DynamicConfig::from_cli(
        args.mode,
        args.no_quality,
        args.no_stall_deselect,
        args.stall_min_in_flight,
        args.stall_ack_stale_ms,
        args.conn_timeout_ms,
        args.no_rehome,
    );

    // Create shared stats for telemetry export
    let shared_stats = stats::SharedStats::new();

    let subscription_hub = subscriptions::SubscriptionHub::new();

    let critical_window = srtla_core::priority::CriticalWindow::new();
    if let Some(bind) = args.priority_bind {
        warn_if_not_loopback("priority sidecar (--priority-bind)", bind);
        priority_listener::spawn_listener(
            bind,
            critical_window.clone(),
            Some(subscription_hub.clone()),
        );
    }

    if let Some(bind) = args.metrics_bind {
        warn_if_not_loopback("metrics endpoint (--metrics-bind)", bind);
        metrics::spawn_server(
            bind,
            shared_stats.clone(),
            config.clone(),
            critical_window.clone(),
        );
    }

    // Stdin reader stays blocking; Unix socket goes async to support
    // subscription pushes.
    config::spawn_stdin_listener(
        config.clone(),
        shared_stats.clone(),
        critical_window.clone(),
    );
    if let Some(sock_path) = args.control_socket {
        control_socket::spawn(
            sock_path,
            config.clone(),
            shared_stats.clone(),
            critical_window.clone(),
            subscription_hub.clone(),
        );
    }

    // The CLI binds each uplink by its source IP, which on a multi-homed host
    // selects the egress via source-based routing. Darwin has no source-based
    // routing, so there the same IP list is resolved to interfaces and pinned
    // with IP_BOUND_IF instead; binding the source address alone would leave
    // every uplink on the default route.
    #[cfg(not(target_vendor = "apple"))]
    let binder: std::sync::Arc<dyn net::UplinkBinder> = std::sync::Arc::new(net::SourceIpBinder);
    #[cfg(target_vendor = "apple")]
    let binder: std::sync::Arc<dyn net::UplinkBinder> =
        std::sync::Arc::new(net::AppleInterfaceBinder::new());

    // Shutdown hooks run once when the sender returns (SIGTERM/SIGINT, or any
    // early exit). The `--stats-file` sink registers its telemetry-file unlink
    // here so no stale snapshot outlives the process.
    let mut on_shutdown = sender::ShutdownHooks::new();
    let telemetry = args
        .stats_file
        .map(|path| spawn_telemetry_sink(path, args.stats_file_interval, &shared_stats));
    if let Some(writer) = &telemetry {
        let path = writer.path().to_path_buf();
        on_shutdown.register(move || telemetry_file::remove(&path));
    }

    let outcome = sender::run_sender_with_config(
        local_srt_port,
        receiver_host,
        receiver_port,
        ips_file,
        args.bind_map.as_deref(),
        args.require_bind_map,
        config,
        shared_stats,
        critical_window,
        subscription_hub,
        binder,
        on_shutdown,
    )
    .await
    .context("srtla_send failed");

    // Dropping the writer joins its thread, which drains any pending snapshot
    // and then unlinks the live file and its `.tmp` sibling. Holding it until
    // here makes that the LAST filesystem action of the process, so the unlink
    // cannot be undone by a publish that was already in flight.
    drop(telemetry);
    outcome
}

/// Start the opt-in ADR-001 `--stats-file` sink and its publisher task.
///
/// The returned [`TelemetryWriter`] owns the OS thread that does the actual
/// temp -> fsync -> `rename(2)`; the spawned task only serializes a snapshot and
/// hands it over, so neither the fsync nor the rename ever runs on the
/// packet-forwarding loop. The task holds a weak reference and exits once the
/// caller drops the writer.
#[cfg(not(loom))]
fn spawn_telemetry_sink(
    path: std::path::PathBuf,
    interval_ms: u64,
    shared_stats: &stats::SharedStats,
) -> std::sync::Arc<telemetry_file::TelemetryWriter> {
    let writer = std::sync::Arc::new(telemetry_file::TelemetryWriter::new(path, interval_ms));
    let period = writer.period();
    let weak = std::sync::Arc::downgrade(&writer);
    let stats = shared_stats.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(writer) = weak.upgrade() else {
                return;
            };
            writer.publish_prebuilt(&telemetry_file::build_current_telemetry_json(&stats.get()));
        }
    });
    writer
}

/// Resolved `--dry-run` inputs: the parsed source IPs and the receiver
/// addresses the host resolved to.
#[cfg(not(loom))]
struct DryRunReport {
    source_ips: Vec<IpAddr>,
    receiver_addrs: Vec<SocketAddr>,
}

/// Validate the run configuration without binding any sockets.
///
/// Reads and parses `ips_file` through the sender's own startup parser
/// ([`sender::read_ip_list`]), then resolves `receiver_host:receiver_port`.
/// Returns a specific error when the IP list is unusable (missing/unreadable,
/// empty, or zero valid IPs) or the receiver cannot be resolved.
#[cfg(not(loom))]
async fn dry_run_resolve(
    ips_file: &str,
    receiver_host: &str,
    receiver_port: u16,
) -> Result<DryRunReport> {
    let source_ips = match sender::read_ip_list(ips_file).await {
        Ok(ips) if !ips.is_empty() => ips.to_vec(),
        // The file was read but yielded no usable IPs. Re-read only to tell
        // "no content" from "content that does not parse" — the same
        // distinction the SIGHUP reload guard makes — so the operator gets an
        // actionable message instead of a generic one.
        Ok(_) => return Err(classify_unusable_ips_file(ips_file)),
        Err(e) => {
            return Err(anyhow!(
                "ips file not found or unreadable: {ips_file} ({e:#})"
            ));
        }
    };

    let receiver_addrs: Vec<SocketAddr> = tokio::net::lookup_host((receiver_host, receiver_port))
        .await
        .with_context(|| {
            format!("failed to resolve receiver address {receiver_host}:{receiver_port}")
        })?
        .collect();

    if receiver_addrs.is_empty() {
        return Err(anyhow!(
            "receiver host {receiver_host}:{receiver_port} resolved to no addresses"
        ));
    }

    Ok(DryRunReport {
        source_ips,
        receiver_addrs,
    })
}

/// Build the specific error for an ips file that yielded zero valid IPs.
///
/// `read_ip_list` deliberately collapses a missing/empty/all-invalid file to an
/// empty list (startup tolerates an empty pool); a dry run wants the
/// operator-facing reason instead.
#[cfg(not(loom))]
fn classify_unusable_ips_file(ips_file: &str) -> anyhow::Error {
    let text = std::fs::read_to_string(ips_file).unwrap_or_default();
    let mut saw_content = false;
    let mut first_invalid: Option<(usize, String)> = None;
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        saw_content = true;
        if IpAddr::from_str(trimmed).is_err() && first_invalid.is_none() {
            first_invalid = Some((idx + 1, trimmed.to_string()));
        }
    }

    if !saw_content {
        return anyhow!("no valid source IPs in {ips_file}: ips file is empty");
    }
    let (line_no, content) = first_invalid.unwrap_or((1, String::new()));
    anyhow!(
        "no valid source IPs in {ips_file}: first invalid entry on line {line_no} ('{content}')"
    )
}
