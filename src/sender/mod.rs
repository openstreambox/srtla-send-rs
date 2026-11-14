mod client_dedup;
mod connections;
mod egress_tick;
mod housekeeping;
mod links;
mod packet_handler;
mod rehome;
mod reload;
pub(crate) use reload::{normalise_link_weights, parse_ip_line};
mod sequence;
mod status;
mod uplink;
mod uplink_recv;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
pub(crate) use client_dedup::ClientDedup;
// Re-export connection management functions for tests
#[allow(unused_imports)]
pub use connections::{
    PendingConnectionChanges, apply_connection_changes, create_connections_from_ips,
    create_connections_from_links, recover_connection, specs_from_effective_links, specs_from_ips,
};
// Re-export public items used by tests
#[allow(unused_imports)]
pub use housekeeping::GLOBAL_TIMEOUT_MS;
use housekeeping::handle_housekeeping;
// ADR-003: where the uplink set comes from (legacy ips file, or the bind-map
// pair read).
#[allow(unused_imports)]
pub use links::{LinkSource, SenderPaths, read_bind_map};
// Re-exported for the NAK-attribution conformance tests so they drive the real
// production path rather than a mirrored copy.
#[allow(unused_imports)]
pub(crate) use packet_handler::{attribute_nak, process_connection_events};
use packet_handler::{drain_packet_queue, handle_srt_packet};
// Re-exported so the ported DATA-padding test drives the same production flush
// path the send loop uses, not a mirrored copy.
#[allow(unused_imports)]
pub(crate) use packet_handler::{flush_all_batches, handle_uplink_packet};
// Scripted resolver seam for tests that drive the re-home trigger policy.
#[cfg(any(test, feature = "test-internals"))]
pub use rehome::StubResolver;
#[allow(unused_imports)]
pub use rehome::{REHOME_MIN_INTERVAL_MS, ReceiverResolver, RehomeGate};
#[allow(unused_imports)]
pub use sequence::{SEQ_TRACKING_SIZE, SEQUENCE_TRACKING_MAX_AGE_MS, SequenceTracker};
use smallvec::SmallVec;
use srtla_core::registration::SrtlaRegistrationManager;
use status::log_connection_status;
use tokio::net::UdpSocket;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{self, Duration, Instant};
use tracing::{debug, info, warn};
// `ConnIo` is constructed only by tests (production builds it inside
// `connections::connect_uplink`); re-export it just for the test surface.
#[cfg(any(test, feature = "test-internals"))]
pub use uplink::ConnIo;
pub use uplink::ConnIoMap;
#[cfg(test)]
pub(crate) use uplink::UplinkPacket;
use uplink::{ConnectionId, ReaderHandle, create_uplink_channel, sync_readers};
// Re-exported so the handshake-sniffing tests drive the real receive path.
#[allow(unused_imports)]
pub(crate) use uplink_recv::process_uplink_packet;

use crate::config::DynamicConfig;
use crate::stats::SharedStats;

pub const HOUSEKEEPING_INTERVAL_MS: u64 = 1000;
const STATUS_LOG_INTERVAL_MS: u64 = 30_000;

/// Cleanup callbacks run exactly once when the sender returns.
///
/// The sender drains and runs every registered hook on its way out — on
/// SIGTERM/SIGINT, when the uplink packet channel closes, or on any early
/// return/error — so a caller can guarantee that a resource it created for the
/// run is released with the run. Hooks run in registration order, synchronously,
/// and at most once: [`run`](Self::run) drains the set, and [`Drop`] routes
/// through the same drain as a safety net for the error paths.
///
/// This is the registration point the `--stats-file` sink (a later port) uses
/// to unlink its telemetry file and `.tmp` sibling, so no stale snapshot
/// outlives the process even if the run ends by returning `Err`.
///
/// Hooks are infallible and take no arguments; handle a cleanup step's own
/// error inside the hook (e.g. ignore a failed `remove_file`). A panicking hook
/// is a bug — it will abort during unwinding.
#[derive(Default)]
pub struct ShutdownHooks {
    hooks: Vec<Box<dyn FnOnce() + Send>>,
}

impl ShutdownHooks {
    /// An empty hook set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cleanup callback to run on shutdown. Later registrations run
    /// later.
    pub fn register(&mut self, hook: impl FnOnce() + Send + 'static) {
        self.hooks.push(Box::new(hook));
    }

    /// Run every registered hook in registration order, exactly once.
    pub fn run(&mut self) {
        for hook in self.hooks.drain(..) {
            hook();
        }
    }
}

impl Drop for ShutdownHooks {
    fn drop(&mut self) {
        self.run();
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_sender_with_config(
    local_srt_port: u16,
    receiver_host: &str,
    receiver_port: u16,
    ips_file: &str,
    bind_map: Option<&str>,
    config: DynamicConfig,
    shared_stats: SharedStats,
    critical_window: srtla_core::priority::CriticalWindow,
    subscription_hub: crate::subscriptions::SubscriptionHub,
    binder: std::sync::Arc<dyn crate::net::UplinkBinder>,
    mut on_shutdown: ShutdownHooks,
) -> Result<()> {
    info!(
        "starting srtla_send: local_srt_port={}, receiver={}:{}, ips_file={}, mode={}",
        local_srt_port,
        receiver_host,
        receiver_port,
        ips_file,
        config.mode()
    );
    // Bind the local SRT listener FIRST, ahead of reading the ips file and
    // dialing any uplink. An encoder is typically pointed at this port the
    // moment the process is spawned, with no readiness handshake, so every
    // await before the bind is a window where that connect finds a closed port.
    // Uplink setup is the worst offender: it resolves the receiver and dials
    // each bonded link sequentially, so with a hostname receiver the window is
    // one uncached DNS lookup per modem and grows with the size of the bond —
    // exactly the multi-link case this sender exists for. Binding a UDP port
    // needs nothing from the uplinks, so it belongs up here.
    //
    // It also removes a rare startup failure: an uplink's ephemeral source port
    // landing on `local_srt_port` used to make this wildcard bind fail with
    // AddrInUse.
    let local_listener = UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, local_srt_port)))
        .await
        .context("bind local SRT UDP listener")?;
    info!("listening for SRT on [::]:{}", local_srt_port);

    // Where the uplink set comes from. Without `--bind-map` this reads the ips
    // file exactly as it always has and every spec is unmapped, so the bind-map
    // module is never entered at all.
    let mut link_source = LinkSource::new(&SenderPaths { ips_file, bind_map });

    // A missing / empty / all-invalid ips file at startup is NOT fatal: bind no
    // uplinks, start with an EMPTY pool, and wait for a SIGHUP reload. CeraUI
    // writes the IP file and signals the sender only once interfaces appear, so
    // exiting here would crash-loop the device before the first modem is up.
    let links = match link_source.startup().await {
        Ok(links) => links,
        Err(e) => {
            warn!("ips file unreadable at startup ({e:#}); starting with an empty uplink pool");
            SmallVec::new()
        }
    };
    shared_stats.set_bind_map(link_source.report().clone());
    debug!(
        "uplinks loaded: {}",
        links
            .iter()
            .map(|spec| spec.origin())
            .collect::<SmallVec<_, 4>>()
            .join(", ")
    );
    if links.is_empty() {
        warn!("no valid source IPs at startup; waiting for SIGHUP reload");
    }

    // Shell-owned I/O half of every connection, keyed by conn_id (never by
    // index — so no lockstep with the connections vec through add/remove).
    let mut conn_io: ConnIoMap = std::collections::HashMap::new();
    let mut connections =
        create_connections_from_links(&links, receiver_host, receiver_port, &binder, &mut conn_io)
            .await;

    let mut reg = SrtlaRegistrationManager::new();

    // Probing bootstraps the connection group. With an empty pool there is
    // nothing to probe, so it stays NotStarted and is restarted once a SIGHUP
    // reload populates the pool (see the queued-changes block in the main loop).
    if !connections.is_empty() {
        let probes = reg.start_probing(&mut connections, srtla_core::utils::now_ms());
        for (idx, pkt) in probes {
            if let Some(conn) = connections.get(idx)
                && let Some(io) = conn_io.get(&conn.conn_id)
            {
                let _ = io.send_control_padded(&pkt).await;
            }
        }
    }

    let (packet_tx, mut packet_rx) = create_uplink_channel();
    let mut reader_handles: HashMap<ConnectionId, ReaderHandle> = HashMap::new();
    sync_readers(&connections, &conn_io, &mut reader_handles, &packet_tx);

    // Create instant ACK forwarding channel (sends client addr with packet)
    let (instant_tx, mut instant_rx) =
        tokio::sync::mpsc::unbounded_channel::<(SocketAddr, SmallVec<u8, 64>)>();

    // Wrap local_listener in Arc for sharing
    let local_listener = Arc::new(local_listener);

    // Spawn instant forwarding task
    {
        let local_listener_clone = local_listener.clone();
        tokio::spawn(async move {
            while let Some((client_addr, ack_packet)) = instant_rx.recv().await {
                let _ = local_listener_clone.send_to(&ack_packet, client_addr).await;
            }
        });
    }

    let mut recv_buf = vec![0u8; srtla_protocol::MTU];
    let mut housekeeping_timer = time::interval_at(
        Instant::now() + Duration::from_millis(HOUSEKEEPING_INTERVAL_MS),
        Duration::from_millis(HOUSEKEEPING_INTERVAL_MS),
    );
    housekeeping_timer.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    // Batch flush timer (15ms interval like Moblin)
    // This ensures packets are sent even when traffic is light
    const BATCH_FLUSH_INTERVAL_MS: u64 = 15;
    let mut batch_flush_timer = time::interval_at(
        Instant::now() + Duration::from_millis(BATCH_FLUSH_INTERVAL_MS),
        Duration::from_millis(BATCH_FLUSH_INTERVAL_MS),
    );
    batch_flush_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut status_elapsed_ms: u64 = 0;
    let mut last_client_addr: Option<SocketAddr> = None;
    // Zero-allocation ring buffer for sequence tracking
    let mut seq_tracker = SequenceTracker::new();
    let mut client_dedup = ClientDedup::new();
    let mut last_selected_idx: Option<usize> = None;
    let mut all_failed_at: Option<u64> = None;
    // Whole-bond re-home: only ever consulted once every uplink has been down
    // past the all-failed window, and only then to follow the receiver hostname
    // to a genuinely new address. `--no-rehome` turns it off entirely.
    let mut rehome = RehomeGate::new(config.rehome_on_failure());
    let mut pending_changes: Option<PendingConnectionChanges> = None;
    // Weak-link classifier. Its per-link `weak` verdict is consumed by
    // Enhanced selection as an admission gate.
    let mut weak_link_filter = srtla_core::selection::classifier::WeakLinkFilter::new();
    // Per-link CC soft-cap controller. `cc_target_bps` feeds the soft-cap
    // multiplier and in-flight cap; `loss_degraded` feeds the loss gate.
    let mut link_cc_controller = srtla_core::selection::link_cc::LinkCcController::new();

    // Prepare SIGHUP stream (Unix only) or a never-completing future (non-Unix)
    #[cfg(unix)]
    let mut sighup = signal(SignalKind::hangup())?;
    // SIGTERM/SIGINT drive a graceful `Ok(())` return so the process exits 0
    // well inside CeraUI's 10s SIGKILL window and any registered shutdown hooks
    // (the `--stats-file` unlink, a later port) run instead of being skipped by
    // an abrupt default-action kill.
    #[cfg(unix)]
    let mut sigterm = signal(SignalKind::terminate())?;
    #[cfg(unix)]
    let mut sigint = signal(SignalKind::interrupt())?;
    // Answers from the off-loop ADR-003 pair read a SIGHUP spawns.
    #[cfg(unix)]
    let (bind_map_tx, mut bind_map_rx) =
        tokio::sync::mpsc::unbounded_channel::<links::PairReadResult>();

    // Main loop - run housekeeping frequently like C version
    // Run housekeeping once before entering the main event loop so we start in a clean state.
    {
        let classic = config.mode().is_classic();
        if let Err(err) = handle_housekeeping(
            &mut connections,
            &mut conn_io,
            &mut reg,
            &mut seq_tracker,
            receiver_host,
            classic,
            srtla_core::utils::now_ms(),
            &mut all_failed_at,
            &mut reader_handles,
            &packet_tx,
            &mut rehome,
        )
        .await
        {
            warn!("initial housekeeping failed: {err}");
        }
    }

    // Use a macro to avoid duplicating the event loop for Unix/non-Unix
    // The only difference is SIGHUP handling on Unix
    macro_rules! event_loop {
        ($($sighup_branch:tt)*) => {
            loop {
                tokio::select! {
                    res = local_listener.recv_from(&mut recv_buf) => {
                        let config_snap = config.snapshot();
                        handle_srt_packet(
                            res,
                            &mut recv_buf,
                            &mut connections,
                            &mut conn_io,
                            &mut last_selected_idx,
                            &mut seq_tracker,
                            &mut last_client_addr,
                            reg.has_connected,
                            &config_snap,
                            &critical_window,
                        )
                        .await;
                        drain_packet_queue(
                            &mut packet_rx,
                            &mut connections,
                            &conn_io,
                            &mut reg,
                            &instant_tx,
                            &mut client_dedup,
                            last_client_addr,
                            &local_listener,
                            &seq_tracker,
                            &config_snap,
                            &config,
                        )
                        .await;
                    }
                    packet = packet_rx.recv() => {
                        let config_snap = config.snapshot();
                        if let Some(packet) = packet {
                            handle_uplink_packet(
                                packet,
                                &mut connections,
                                &conn_io,
                                &mut reg,
                                &instant_tx,
                                &mut client_dedup,
                                last_client_addr,
                                &local_listener,
                                &seq_tracker,
                                &config_snap,
                                &config,
                            ).await;
                            drain_packet_queue(
                                &mut packet_rx,
                                &mut connections,
                                &conn_io,
                                &mut reg,
                                &instant_tx,
                                &mut client_dedup,
                                last_client_addr,
                                &local_listener,
                                &seq_tracker,
                                &config_snap,
                                &config,
                            ).await;
                        } else {
                            on_shutdown.run();
                            return Ok(());
                        }
                    }
                    _ = housekeeping_timer.tick() => {
                        let classic = config.mode().is_classic();
                        if let Err(err) = handle_housekeeping(
                            &mut connections,
                            &mut conn_io,
                            &mut reg,
                            &mut seq_tracker,
                            receiver_host,
                            classic,
                            srtla_core::utils::now_ms(),
                            &mut all_failed_at,
                            &mut reader_handles,
                            &packet_tx,
                            &mut rehome,
                        ).await {
                            warn!("housekeeping failed: {err}");
                        }

                        // Run the weak-link classifier and per-link CC
                        // controller, stamp results onto each connection
                        // for selection to consume, and surface via stats.
                        let housekeeping_snap = config.snapshot();
                        let classification = weak_link_filter
                            .classify(&connections, housekeeping_snap.negotiated_latency_ms);
                        let link_cc_snapshots = link_cc_controller
                            .tick_all(&connections, srtla_core::utils::now_ms());
                        for conn in connections.iter_mut() {
                            let entry = classification
                                .per_link
                                .iter()
                                .find(|e| e.conn_id == conn.conn_id);
                            conn.weak = entry.map(|e| e.weak).unwrap_or(false);
                            // Selection needs the reason, not just the verdict:
                            // a late link is kept off unique payload entirely,
                            // an under-used one keeps a trickle of it.
                            conn.weak_reason = entry
                                .map(|e| e.reason)
                                .unwrap_or(srtla_core::selection::classifier::WeakReason::Healthy);
                            let cc_snap = link_cc_snapshots.get(&conn.conn_id);
                            conn.cc_backing_off = cc_snap
                                .map(|s| s.state == srtla_core::selection::link_cc::CcState::BackingOff)
                                .unwrap_or(false);
                            conn.cc_target_bps = cc_snap.map(|s| s.target_bps).unwrap_or(0);
                            conn.loss_degraded =
                                cc_snap.map(|s| s.loss_degraded).unwrap_or(false);
                        }
                        shared_stats.update(
                            &connections,
                            &housekeeping_snap,
                            Some(&classification),
                            Some(&link_cc_snapshots),
                            Some(&link_identities(&connections, &conn_io)),
                        );

                        // Fan the fresh snapshot out to any `stats` subscribers
                        // on the async control socket. Cheap no-op if no one
                        // is subscribed.
                        let snap = shared_stats.get();
                        if let Ok(value) = serde_json::to_value(&snap) {
                            subscription_hub.publish("stats", value).await;
                        }

                        if let Some(changes) = pending_changes.take()
                            && let Some(new_links) = changes.new_links
                        {
                            info!("applying queued connection changes: {} uplinks", new_links.len());
                            let previous_ids: Vec<u64> = connections.iter().map(|c| c.conn_id).collect();
                            apply_connection_changes(
                                &mut connections,
                                &mut conn_io,
                                &new_links,
                                &changes.receiver_host,
                                changes.receiver_port,
                                &mut last_selected_idx,
                                &mut seq_tracker,
                                &binder,
                            ).await;
                            info!("connection changes applied successfully");
                            sync_readers(&connections, &conn_io, &mut reader_handles, &packet_tx);
                            // Reload can replace or reorder the sockets the registration
                            // manager indexes. Reconcile before any queued reply is handled.
                            {
                                let probes = reg.reload_connections(
                                    &previous_ids,
                                    &mut connections,
                                    srtla_core::utils::now_ms(),
                                );
                                for (idx, pkt) in probes {
                                    if let Some(conn) = connections.get(idx)
                                        && let Some(io) = conn_io.get(&conn.conn_id)
                                    {
                                        let _ = io.send_control_padded(&pkt).await;
                                    }
                                }
                            }
                        }

                        status_elapsed_ms = status_elapsed_ms.saturating_add(HOUSEKEEPING_INTERVAL_MS);
                        if status_elapsed_ms >= STATUS_LOG_INTERVAL_MS {
                            log_connection_status(&connections, &conn_io, last_selected_idx, &config);
                            status_elapsed_ms = status_elapsed_ms.saturating_sub(STATUS_LOG_INTERVAL_MS);
                        }

                        sync_readers(&connections, &conn_io, &mut reader_handles, &packet_tx);
                        let config_snap = config.snapshot();
                        drain_packet_queue(
                            &mut packet_rx,
                            &mut connections,
                            &conn_io,
                            &mut reg,
                            &instant_tx,
                            &mut client_dedup,
                            last_client_addr,
                            &local_listener,
                            &seq_tracker,
                            &config_snap,
                            &config,
                        )
                        .await;
                    }
                    $($sighup_branch)*
                    _ = batch_flush_timer.tick() => {
                        flush_all_batches(&mut connections, &mut conn_io, &mut seq_tracker).await;
                    }
                }
            }
        };
    }

    #[cfg(unix)]
    event_loop! {
        _ = sighup.recv() => {
            info!("received SIGHUP - evaluating uplink IP reload from {}", ips_file);
            // With `--bind-map` the reload runs the ADR-003 pair protocol, whose
            // bounded hash-mismatch retry can take up to 2 s. Holding the event
            // loop for that long would stall packet forwarding, so the read goes
            // to a spawned task and answers back through `bind_map_rx`.
            if let Some((ips_path, sidecar, prior)) = link_source.read_args() {
                let tx = bind_map_tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(links::read_bind_map(ips_path, sidecar, prior).await);
                });
            } else {
                // Legacy reload guard: refuse a reload that resolves to zero
                // usable IPs (missing, empty, or all-garbage file) and keep the
                // current links up rather than queuing an empty list, which
                // would tear down every connection. Mirrors the C sender.
                match reload::analyze_ip_reload(ips_file) {
                    reload::IpReload::Apply { ips, weights, first_invalid_line } => {
                        if let Some(line) = first_invalid_line {
                            warn!(
                                "ips file has an invalid entry starting at line {line}; applying valid IPs only"
                            );
                        }
                        pending_changes = Some(PendingConnectionChanges {
                            new_links: Some(specs_from_ips(&ips, &weights)),
                            receiver_host: receiver_host.to_string(),
                            receiver_port,
                        });
                        info!(
                            "uplink IP changes queued for next processing cycle: {}",
                            describe_weights(&ips, &weights)
                        );
                    }
                    reload::IpReload::Refuse(reason) => {
                        warn!(
                            "refusing SIGHUP reload ({reason:?}); keeping current connections"
                        );
                    }

                }
            }
            let config_snap = config.snapshot();
            drain_packet_queue(
                &mut packet_rx,
                &mut connections,
                &conn_io,
                &mut reg,
                &instant_tx,
                &mut client_dedup,
                last_client_addr,
                &local_listener,
                &seq_tracker,
                &config_snap,
                &config,
            )
            .await;
        }
        Some(read) = bind_map_rx.recv() => {
            let new_links = link_source.adopt(read);
            shared_stats.set_bind_map(link_source.report().clone());
            if new_links.is_empty() {
                // Every degraded arm that still has something to run returns a
                // non-empty set, so an empty one means the ips file itself was
                // unusable. Tearing down a live bond for that would be worse
                // than ignoring the reload.
                warn!("bind-map reload produced no usable uplinks; keeping current connections");
            } else {
                pending_changes = Some(PendingConnectionChanges {
                    new_links: Some(new_links),
                    receiver_host: receiver_host.to_string(),
                    receiver_port,
                });
                info!("uplink changes queued for next processing cycle");
            }
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM - shutting down");
            on_shutdown.run();
            return Ok(());
        }
        _ = sigint.recv() => {
            info!("received SIGINT - shutting down");
            on_shutdown.run();
            return Ok(());
        }
    }

    #[cfg(not(unix))]
    event_loop! {}
}

/// The ADR-003 identity echo for every live uplink, keyed by `conn_id`.
///
/// Built from the I/O map rather than the connections themselves: `iface` and
/// `link_id` are facts about the socket, and the pure core deliberately does
/// not carry them. An unmapped link contributes an entry with both `None`, so
/// its telemetry record omits both keys entirely.
fn link_identities(
    connections: &[srtla_core::connection::SrtlaConnection],
    conn_io: &ConnIoMap,
) -> HashMap<ConnectionId, crate::stats::LinkIdentity> {
    connections
        .iter()
        .filter_map(|conn| {
            let io = conn_io.get(&conn.conn_id)?;
            Some((
                conn.conn_id,
                crate::stats::LinkIdentity {
                    iface: io.spec.iface.as_ref().map(|i| i.as_str().to_string()),
                    link_id: io.spec.link_id.as_ref().map(|i| i.as_str().to_string()),
                },
            ))
        })
        .collect()
}

pub async fn read_ip_list(path: &str) -> Result<SmallVec<IpAddr, 4>> {
    Ok(read_weighted_ip_list(path).await?.0)
}

/// `ip weight` pairs for a log line, e.g. `192.168.0.15 (weight 10), 192.168.0.2
/// (weight 1)`.
#[cfg(unix)]
fn describe_weights(ips: &[IpAddr], weights: &[u8]) -> String {
    ips.iter()
        .enumerate()
        .map(|(index, ip)| {
            format!(
                "{ip} (weight {})",
                weights
                    .get(index)
                    .copied()
                    .unwrap_or(srtla_core::connection::LINK_WEIGHT_MIN)
            )
        })
        .collect::<SmallVec<_, 4>>()
        .join(", ")
}

/// [`read_ip_list`] plus the normalised operator weight of each IP (same
/// order). An unweighted file yields all 1s.
pub async fn read_weighted_ip_list(path: &str) -> Result<(SmallVec<IpAddr, 4>, SmallVec<u8, 4>)> {
    let text = std::fs::read_to_string(Path::new(path)).context("read IPs file")?;
    // Shares the SIGHUP reload guard's parser so startup and reload agree on what
    // counts as a valid IP. At startup an empty or all-invalid file is tolerated
    // (returns an empty list); the zero-valid-IP refusal only matters on reload,
    // where dropping every live link would be worse than ignoring a bad edit.
    match reload::analyze_ip_reload_text(&text) {
        reload::IpReload::Apply {
            ips,
            weights,
            first_invalid_line,
        } => {
            if let Some(line) = first_invalid_line {
                warn!("ips file has an invalid entry starting at line {line}; skipping it");
            }
            Ok((ips, weights))
        }
        reload::IpReload::Refuse(_) => Ok((SmallVec::new(), SmallVec::new())),
    }
}

#[cfg(test)]
mod shutdown_hook_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::ShutdownHooks;

    #[test]
    fn hooks_run_on_drop_in_registration_order() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            let mut hooks = ShutdownHooks::new();
            for n in 0..3 {
                let order = order.clone();
                hooks.register(move || order.lock().unwrap().push(n));
            }
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn explicit_run_then_drop_runs_each_hook_exactly_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        {
            let mut hooks = ShutdownHooks::new();
            let calls = calls.clone();
            hooks.register(move || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            hooks.run();
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "an explicit run drains the set, so Drop must not run the hook again"
        );
    }
}
