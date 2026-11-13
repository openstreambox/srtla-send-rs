use std::collections::HashMap;

use anyhow::{Result, anyhow};
use srtla_core::connection::{STARTUP_GRACE_MS, SrtlaConnection};
use srtla_core::registration::SrtlaRegistrationManager;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, warn};

use super::connections::{reconnect_uplink, recover_connection, revive_uplink};
use super::egress_tick;
use super::rehome::{RehomeGate, try_rehome};
use super::sequence::SequenceTracker;
use super::uplink::{
    ConnIo, ConnIoMap, ConnectionId, ReaderHandle, UplinkPacket, restart_reader_for,
};
use crate::net::source::HostAddrs;

pub const GLOBAL_TIMEOUT_MS: u64 = 10_000;

/// Handle periodic housekeeping tasks.
///
/// With the ring buffer sequence tracker, we no longer need periodic cleanup
/// since old entries are naturally overwritten.
#[allow(clippy::too_many_arguments)]
pub async fn handle_housekeeping(
    connections: &mut [SrtlaConnection],
    conn_io: &mut ConnIoMap,
    reg: &mut SrtlaRegistrationManager,
    seq_tracker: &mut SequenceTracker,
    receiver_host: &str,
    classic: bool,
    now_ms: u64,
    all_failed_at: &mut Option<u64>,
    reader_handles: &mut HashMap<ConnectionId, ReaderHandle>,
    packet_tx: &UnboundedSender<UplinkPacket>,
    rehome: &mut RehomeGate,
) -> Result<()> {
    // If we're waiting on a REG2 response past the timeout, proactively retry REG1.
    // A REG1 "sent" to a link without a socket never left, so it is released
    // first rather than timed out: the timeout would drop the target entirely.
    let current_ms = now_ms;
    retarget_reg1(reg, connections, conn_io);
    let _ = reg.clear_pending_if_timed_out(current_ms);

    if reg.is_probing() {
        let was_probing = true;
        reg.check_probing_complete();
        // If probing just completed, reset grace period for the selected connection
        if !reg.is_probing()
            && was_probing
            && let Some(idx) = reg.get_selected_connection_idx()
            && let Some(conn) = connections.get_mut(idx)
        {
            conn.reconnection.startup_grace_deadline_ms = current_ms + STARTUP_GRACE_MS;
            debug!(
                "{}: Reset grace period after being selected for initial registration",
                conn.label
            );
        }
    }

    // One reading of the host's addresses serves every required link this
    // tick; a bond without required links never takes it.
    let mut host_addrs: Option<HostAddrs> = None;

    // housekeeping: drive registration, send keepalives
    for (i, conn) in connections.iter_mut().enumerate() {
        // A retired required link holds no socket, so nothing below applies to
        // it. Its only business is the retry: on the reconnect backoff, bind
        // again through the checked path, which refuses until the source is
        // assigned to the mapped device.
        if conn_io.is_retired(conn.conn_id) {
            if conn.should_attempt_reconnect(current_ms) {
                conn.record_reconnect_attempt(current_ms);
                match revive_uplink(conn, conn_io, seq_tracker, current_ms) {
                    Ok(()) => {
                        info!(
                            "{}: mapped source is on its device again; link socket re-established",
                            conn.label
                        );
                        if let Some(io) = conn_io.get(&conn.conn_id) {
                            restart_reader_for(conn, io.socket.clone(), reader_handles, packet_tx)
                                .await;
                        }
                        resend_registration(i, conn, reg, conn_io, current_ms).await;
                    }
                    Err(e) => debug!("{}: still retired ({e:#})", conn.label),
                }
            }
            continue;
        }

        // Source assignment can change without an ifindex change. Required
        // links must stop using the old socket before this tick sends anything.
        if let Some(io) = conn_io.get(&conn.conn_id)
            && let Some(e) = unverified_source(conn, io, &mut host_addrs)
        {
            log_retired_for(conn, &e);
            super::uplink::retire_uplink(conn, conn_io, reader_handles, seq_tracker).await;
            continue;
        }

        // Re-resolve the egress interface by NAME and re-read the route
        // invariant before anything else touches this link's socket. A replug
        // leaves the socket holding an ifindex that no longer names the device,
        // and neither the liveness timeout nor a send error would report it in
        // time. Inert for an unmapped link.
        let egress_flow = if let Some(io) = conn_io.get_mut(&conn.conn_id) {
            egress_tick::handle_egress(
                conn,
                io,
                reader_handles,
                packet_tx,
                seq_tracker,
                receiver_host,
                current_ms,
            )
            .await
        } else {
            egress_tick::TickFlow::Continue
        };
        if egress_flow == egress_tick::TickFlow::Retire {
            super::uplink::retire_uplink(conn, conn_io, reader_handles, seq_tracker).await;
        }
        if egress_flow != egress_tick::TickFlow::Continue {
            continue;
        }

        // Simple reconnect-on-timeout, then allow reg driver to proceed
        if conn.is_timed_out(current_ms) {
            if conn.should_attempt_reconnect(current_ms) {
                let label = conn.label.clone();
                conn.record_reconnect_attempt(current_ms);
                if conn.connection_established_ms() == 0 {
                    debug!("{} initial registration timed out; retrying", label);
                } else {
                    warn!("{} timed out; attempting full socket reconnection", label);
                }
                // Perform full socket reconnection (re-opens the socket in the
                // I/O map; the connection itself owns no socket).
                match conn_io.get_mut(&conn.conn_id) {
                    Some(io) => {
                        if let Err(e) =
                            reconnect_uplink(conn, io, receiver_host, seq_tracker, current_ms).await
                        {
                            warn!("{} failed to reconnect: {}", label, e);
                            if io.binder.requires_checked_device() {
                                super::uplink::retire_uplink(
                                    conn,
                                    conn_io,
                                    reader_handles,
                                    seq_tracker,
                                )
                                .await;
                                continue;
                            }
                            recover_connection(conn, seq_tracker);
                        } else {
                            restart_reader_for(conn, io.socket.clone(), reader_handles, packet_tx)
                                .await;
                        }
                    }
                    None => {
                        warn!("{} has no I/O entry; marking for recovery", label);
                        recover_connection(conn, seq_tracker);
                    }
                }

                resend_registration(i, conn, reg, conn_io, current_ms).await;
            } else {
                debug!("{} timed out but in retry interval", conn.label);
            }
            continue;
        }

        if conn.needs_keepalive(current_ms) {
            let ka = conn.keepalive_packet(current_ms);
            if let Some(io) = conn_io.get(&conn.conn_id) {
                let _ = io.send_control_padded(&ka).await;
            }
        }
        if conn.needs_rtt_measurement(current_ms) {
            let ka = conn.keepalive_packet(current_ms);
            if let Some(io) = conn_io.get(&conn.conn_id) {
                let _ = io.send_control_padded(&ka).await;
            }
        }
        if !classic {
            conn.perform_window_recovery(current_ms);
        }
        // Update bitrate calculation
        conn.calculate_bitrate(current_ms);
        // Drive link lifecycle phase transitions
        conn.update_phase(current_ms);
        // Adapt the per-connection batch-send regime to the observed
        // load. Cheap; no-op when the regime hasn't changed.
        conn.recompute_batch_regime();

        // The reader task self-heals via CONN_TIMEOUT, but a task death
        // (panic / early return) would otherwise go undetected until that window.
        // Poll its handle cheaply each tick and respawn it for a still-active link
        // so inbound ACK/NAK/keepalive traffic resumes immediately, not seconds later.
        let reader_dead = reader_handles
            .get(&conn.conn_id)
            .is_some_and(|reader| reader.handle.is_finished());
        if reader_dead && let Some(io) = conn_io.get(&conn.conn_id) {
            warn!("{}: uplink reader task ended; restarting", conn.label);
            restart_reader_for(conn, io.socket.clone(), reader_handles, packet_tx).await;
        }
    }

    // Update active connections count (matches C implementation behavior)
    // C code resets active_connections=0 then counts non-timed-out connections
    reg.update_active_connections(connections);

    // drive registration (send REG1/REG2 as needed), never through a link
    // that has no socket to send it on
    retarget_reg1(reg, connections, conn_io);
    let sends = reg.reg_driver_pending_sends(connections.len(), current_ms);
    if let Some((idx, pkt)) = sends.reg1
        && let Some(conn) = connections.get_mut(idx)
        && let Some(io) = conn_io.get(&conn.conn_id)
    {
        match io.send_control_padded(&pkt).await {
            Ok(_) => conn.note_sent(current_ms),
            Err(e) => warn!("Failed to send REG1 to uplink #{idx}: {e:?}"),
        }
    }
    if let Some(pkt) = sends.broadcast_reg2 {
        for (i, conn) in connections.iter_mut().enumerate() {
            if let Some(io) = conn_io.get(&conn.conn_id)
                && io.send_control_padded(&pkt).await.is_ok()
            {
                conn.note_sent(current_ms);
                debug!("REG2 → uplink #{i} sent");
            }
        }
    }

    // Check for connection failures and output appropriate error messages
    // This matches the C implementation's connection_housekeeping logic
    let active_connections = connections
        .iter()
        .filter(|c| !c.is_timed_out(current_ms))
        .count();

    if connections.is_empty() {
        // Empty start: no uplinks are configured yet (missing/empty/all-invalid
        // ips file). There is nothing to fail, so keep the all-links-failed
        // timer disarmed and wait for a SIGHUP reload — otherwise a device that
        // boots before its modems appear would exit after one
        // GLOBAL_TIMEOUT_MS instead of waiting for them.
        *all_failed_at = None;
    } else if active_connections == 0 {
        if all_failed_at.is_none() {
            // Monotonic ms stamp on the single now_ms() clock; the all-links-failed
            // timeout below is a plain difference against the per-tick current_ms.
            *all_failed_at = Some(current_ms);
        }

        if reg.has_connected {
            error!("warning: no available connections");
        }

        // Timeout when all connections have failed. Measure elapsed-time-since-failure
        // so a transient all-down blip only trips after a full GLOBAL_TIMEOUT_MS of
        // sustained failure, not the instant uptime exceeds it.
        if let Some(failed_at) = all_failed_at
            && current_ms.saturating_sub(*failed_at) > GLOBAL_TIMEOUT_MS
        {
            // The bond is genuinely dead: every uplink is timed out and has
            // stayed that way for a full all-failed window. That, and only
            // that, is where a whole-bond re-home is allowed to consider
            // moving to a newly-resolved receiver address — see
            // `super::rehome` for why it is all-or-nothing and why a bond with
            // any live uplink is never touched. It also decides for itself
            // whether DNS actually drifted and whether the rate limit permits
            // an attempt; `false` means nothing changed and the existing
            // behaviour below stands.
            let dead_for_ms = current_ms.saturating_sub(*failed_at);
            if try_rehome(
                rehome,
                connections,
                conn_io,
                reg,
                seq_tracker,
                reader_handles,
                packet_tx,
                receiver_host,
                dead_for_ms,
                current_ms,
            )
            .await
            {
                // The bond now points somewhere new and is re-registering from
                // REG1. Re-arm the timer so the fresh handshake gets a full
                // window before the bond is declared unrecoverable again.
                *all_failed_at = Some(current_ms);
                return Ok(());
            }

            if reg.has_connected {
                error!("Failed to re-establish any connections");
                return Err(anyhow!("Failed to re-establish any connections"));
            } else {
                error!("Failed to establish any initial connections");
                return Err(anyhow!("Failed to establish any initial connections"));
            }
        }
    } else {
        *all_failed_at = None;
    }

    // NOTE: With the ring buffer sequence tracker, no cleanup is needed.
    // Old entries are naturally overwritten when the buffer wraps around.

    Ok(())
}

/// Why a live link may not keep its socket: only a required link whose source
/// is not verified on its mapped device in this reading of the host.
fn unverified_source(
    conn: &SrtlaConnection,
    io: &ConnIo,
    addrs: &mut Option<HostAddrs>,
) -> Option<anyhow::Error> {
    if !io.binder.requires_checked_device() {
        return None;
    }
    io.spec
        .iface
        .as_ref()
        .map_or_else(
            || Err(anyhow!("required link has no mapped device")),
            |iface| {
                addrs
                    .get_or_insert_with(HostAddrs::read)
                    .require_assigned(conn.local_ip, iface.as_str())
            },
        )
        .err()
}

fn log_retired_for(conn: &SrtlaConnection, e: &anyhow::Error) {
    warn!(
        "{}: {e}; link retired, retrying until its source is verified on its device",
        conn.label
    );
}

/// Required-mode check between housekeeping ticks.
///
/// Source assignment can change at any moment, and a socket bound before the
/// change keeps sending with the old source until something notices. This runs
/// on a short interval so that is a fraction of a tick: every live required
/// link is checked against one reading of the host's addresses, and the ones
/// that fail are retired exactly as housekeeping would. Returns whether any
/// link was retired. Takes no reading when no live link is required.
pub async fn retire_unverified_sources(
    connections: &mut [SrtlaConnection],
    conn_io: &mut ConnIoMap,
    reader_handles: &mut HashMap<ConnectionId, ReaderHandle>,
    seq_tracker: &mut SequenceTracker,
) -> bool {
    let mut addrs = None;
    let mut retired = false;
    for conn in connections.iter_mut() {
        if let Some(io) = conn_io.get(&conn.conn_id)
            && let Some(e) = unverified_source(conn, io, &mut addrs)
        {
            log_retired_for(conn, &e);
            super::uplink::retire_uplink(conn, conn_io, reader_handles, seq_tracker).await;
            retired = true;
        }
    }
    retired
}

/// Keep the group registration on links that own a socket.
fn retarget_reg1(
    reg: &mut SrtlaRegistrationManager,
    connections: &[SrtlaConnection],
    conn_io: &ConnIoMap,
) {
    reg.retarget_reg1(connections.len(), |idx| {
        connections
            .get(idx)
            .is_some_and(|conn| conn_io.contains_key(&conn.conn_id))
    });
}

/// Put a link that just got a new socket back in front of the receiver: REG1
/// when it is the link the group registration is waiting on, REG2 otherwise.
async fn resend_registration(
    i: usize,
    conn: &mut SrtlaConnection,
    reg: &mut SrtlaRegistrationManager,
    conn_io: &ConnIoMap,
    current_ms: u64,
) {
    match reg.pending_reg2_idx() {
        Some(idx) if idx == i => {
            info!("{} marked for recovery; re-sending REG1", conn.label);
            let pkt = reg.build_reg1_for(i, current_ms);
            if let Some(io) = conn_io.get(&conn.conn_id) {
                match io.send_control_padded(&pkt).await {
                    Ok(_) => conn.note_sent(current_ms),
                    Err(e) => warn!("Failed to send REG1 to uplink #{i}: {e:?}"),
                }
            }
        }
        Some(_) => {
            debug!(
                "{} timed out but another uplink is awaiting REG2; deferring",
                conn.label
            );
        }
        None => {
            info!("{} marked for recovery; re-sending REG2", conn.label);
            let pkt = reg.build_reg2(i);
            if let Some(io) = conn_io.get(&conn.conn_id) {
                match io.send_control_padded(&pkt).await {
                    Ok(_) => conn.note_sent(current_ms),
                    Err(e) => warn!("Failed to send REG2 to uplink #{i}: {e:?}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use srtla_core::utils::now_ms;

    use super::*;
    use crate::sender::rehome::StubResolver;
    use crate::sender::uplink::{create_uplink_channel, sync_readers};
    use crate::test_helpers::{
        create_test_conn_io_map, create_test_connection, create_test_connections,
    };

    #[tokio::test]
    async fn dead_reader_is_restarted_for_active_connection() {
        let mut connections = vec![create_test_connection().await];
        let conn_id = connections[0].conn_id;
        let mut conn_io = create_test_conn_io_map(&connections);
        let mut reg = SrtlaRegistrationManager::new();
        let mut all_failed_at: Option<u64> = None;
        let mut seq_tracker = SequenceTracker::new();

        let (packet_tx, _packet_rx) = create_uplink_channel();
        let mut reader_handles: HashMap<ConnectionId, ReaderHandle> = HashMap::new();
        sync_readers(&connections, &conn_io, &mut reader_handles, &packet_tx).await;

        // Abort the reader and let the runtime drive cancellation to completion,
        // reproducing a silently dead task (a handle that reports is_finished()).
        reader_handles.get(&conn_id).unwrap().handle.abort();
        for _ in 0..1000 {
            if reader_handles.get(&conn_id).unwrap().handle.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            reader_handles.get(&conn_id).unwrap().handle.is_finished(),
            "reader task should be dead after abort"
        );

        handle_housekeeping(
            &mut connections,
            &mut conn_io,
            &mut reg,
            &mut seq_tracker,
            "127.0.0.1",
            false,
            now_ms(),
            &mut all_failed_at,
            &mut reader_handles,
            &packet_tx,
            &mut RehomeGate::new(false),
        )
        .await
        .expect("housekeeping on an active connection must not fail");

        // A finished handle can never un-finish itself; a live handle proves
        // housekeeping spawned a fresh reader in its place.
        assert!(
            !reader_handles.get(&conn_id).unwrap().handle.is_finished(),
            "housekeeping must respawn the dead reader for the still-active connection"
        );
    }

    /// The all-uplinks-failed timeout must measure time *since* the links failed,
    /// not the uptime captured at the moment of failure. With the buggy
    /// uptime-at-failure measure, the timer tripped on the first all-down pass as
    /// soon as total uptime exceeded `GLOBAL_TIMEOUT_MS`, erroring on a transient
    /// blip. Arming and the first re-check must not error; only a full
    /// `GLOBAL_TIMEOUT_MS` of sustained failure may fire it.
    ///
    /// `handle_housekeeping` takes `now` as an argument, so the elapsed-since-
    /// failure window is driven by the explicit timestamps passed here — no tokio
    /// virtual clock. `now_ms()` is monotonic and not tokio-controlled, so a paused
    /// clock could not drive this anymore.
    #[tokio::test]
    async fn all_failed_timeout_measures_elapsed_since_failure() {
        let mut connections = create_test_connections(2).await;
        let mut conn_io = create_test_conn_io_map(&connections);
        let mut reg = SrtlaRegistrationManager::new();
        // Models a stream that was established and then lost every link.
        reg.has_connected = true;
        let mut reader_handles: HashMap<ConnectionId, ReaderHandle> = HashMap::new();
        let (packet_tx, _packet_rx) = tokio::sync::mpsc::unbounded_channel::<UplinkPacket>();
        let mut all_failed_at: Option<u64> = None;
        let mut seq_tracker = SequenceTracker::new();

        let t0 = now_ms();

        // Drop all uplinks. Stamp the last reconnect attempt past the whole
        // test window so housekeeping reaches the timeout branch instead of
        // attempting a socket reconnection.
        for conn in connections.iter_mut() {
            conn.mark_for_recovery();
            conn.reconnection.last_reconnect_attempt_ms = t0 + 10 * GLOBAL_TIMEOUT_MS;
        }

        // Arm: first all-down pass. Uptime is irrelevant (only now - failed_at
        // matters), so arming must not error however long the process has run.
        let armed = handle_housekeeping(
            &mut connections,
            &mut conn_io,
            &mut reg,
            &mut seq_tracker,
            "127.0.0.1",
            false,
            t0,
            &mut all_failed_at,
            &mut reader_handles,
            &packet_tx,
            &mut RehomeGate::new(false),
        )
        .await;
        assert!(armed.is_ok(), "arming the all-failed timer must not error");
        assert!(all_failed_at.is_some(), "the failure timer should be armed");

        // Still within the window: no error until a full GLOBAL_TIMEOUT_MS elapses.
        let within = handle_housekeeping(
            &mut connections,
            &mut conn_io,
            &mut reg,
            &mut seq_tracker,
            "127.0.0.1",
            false,
            t0 + GLOBAL_TIMEOUT_MS - 1000,
            &mut all_failed_at,
            &mut reader_handles,
            &packet_tx,
            &mut RehomeGate::new(false),
        )
        .await;
        assert!(
            within.is_ok(),
            "no error until a full {GLOBAL_TIMEOUT_MS}ms has elapsed since the links failed"
        );

        // Past the window: fires.
        let fired = handle_housekeeping(
            &mut connections,
            &mut conn_io,
            &mut reg,
            &mut seq_tracker,
            "127.0.0.1",
            false,
            t0 + GLOBAL_TIMEOUT_MS + 1000,
            &mut all_failed_at,
            &mut reader_handles,
            &packet_tx,
            &mut RehomeGate::new(false),
        )
        .await;
        assert!(
            fired.is_err(),
            "the all-failed timeout must fire once a full {GLOBAL_TIMEOUT_MS}ms has elapsed since \
             failure"
        );
    }

    /// A bond in the shape the re-home trigger cares about: uplinks on
    /// 127.0.0.1 (so a socket rebuild really binds), all pinned to `remote`.
    struct RehomeFixture {
        connections: Vec<SrtlaConnection>,
        conn_io: ConnIoMap,
        reg: SrtlaRegistrationManager,
        seq_tracker: SequenceTracker,
        reader_handles: HashMap<ConnectionId, ReaderHandle>,
        all_failed_at: Option<u64>,
    }

    impl RehomeFixture {
        async fn new(remote: SocketAddr) -> Self {
            let connections = vec![
                create_test_connection().await,
                create_test_connection().await,
            ];
            let mut conn_io = create_test_conn_io_map(&connections);
            for io in conn_io.values_mut() {
                io.remote = remote;
            }
            let mut reg = SrtlaRegistrationManager::new();
            // Models a stream that was established and then lost, so the
            // all-failed branch takes the "re-establish" path.
            reg.has_connected = true;
            Self {
                connections,
                conn_io,
                reg,
                seq_tracker: SequenceTracker::new(),
                reader_handles: HashMap::new(),
                all_failed_at: None,
            }
        }

        /// Keep every uplink live as of `now` (fresh delivery proof, grace
        /// window open), so the bond reads as healthy however far the test
        /// clock has advanced.
        fn keep_all_uplinks_live(&mut self, now: u64) {
            for conn in self.connections.iter_mut() {
                conn.connected = true;
                conn.last_received = Some(now);
                conn.reconnection.startup_grace_deadline_ms = now + STARTUP_GRACE_MS;
            }
        }

        /// Drop every uplink and stamp its last reconnect attempt past the test
        /// window so housekeeping reaches the all-failed branch rather than
        /// spending the tick on per-link socket reconnections.
        fn kill_all_uplinks(&mut self, at: u64) {
            for conn in self.connections.iter_mut() {
                conn.mark_for_recovery();
                conn.reconnection.last_reconnect_attempt_ms = at + 10 * GLOBAL_TIMEOUT_MS;
            }
        }

        async fn tick(&mut self, gate: &mut RehomeGate, now: u64) -> Result<()> {
            let (packet_tx, _packet_rx) = create_uplink_channel();
            handle_housekeeping(
                &mut self.connections,
                &mut self.conn_io,
                &mut self.reg,
                &mut self.seq_tracker,
                "rec.example.com",
                false,
                now,
                &mut self.all_failed_at,
                &mut self.reader_handles,
                &packet_tx,
                gate,
            )
            .await
        }

        fn remotes(&self) -> Vec<SocketAddr> {
            let mut remotes: Vec<SocketAddr> = self
                .connections
                .iter()
                .map(|c| self.conn_io.get(&c.conn_id).unwrap().remote)
                .collect();
            remotes.sort();
            remotes.dedup();
            remotes
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn checked_source_loss_closes_socket_and_marks_link_down() {
        for iface in ["missing0", "lo"] {
            let mut f = RehomeFixture::new(remote(1)).await;
            f.connections.truncate(1);
            let id = f.connections[0].conn_id;
            let io = f.conn_io.get_mut(&id).unwrap();
            io.binder = std::sync::Arc::new(crate::net::RequiredBinding);
            // Models an address that remains local but leaves the mapped device.
            io.spec.iface = Some(crate::bind_map::IfaceName::parse(iface).unwrap());
            let socket = std::sync::Arc::downgrade(&io.socket);
            let (tx, _rx) = create_uplink_channel();
            super::super::uplink::sync_readers(
                &f.connections,
                &f.conn_io,
                &mut f.reader_handles,
                &tx,
            )
            .await;
            f.keep_all_uplinks_live(1_000_000);
            if iface == "lo" {
                recover_connection(&mut f.connections[0], &mut f.seq_tracker);
                f.connections[0].reconnection.last_reconnect_attempt_ms = 0;
            }
            f.tick(&mut RehomeGate::new(false), 1_000_000)
                .await
                .unwrap();
            assert!(!f.conn_io.contains_key(&id), "invalid socket retained");
            assert!(!f.reader_handles.contains_key(&id));
            assert!(
                socket.upgrade().is_none(),
                "reader still owns invalid socket"
            );
            assert!(!f.connections[0].connected);
            let stats = crate::stats::SharedStats::new();
            stats.update_with_bind_map(
                &f.connections,
                &crate::config::ConfigSnapshot::default(),
                None,
                None,
                None,
                None,
            );
            assert_eq!(stats.get().active_links, 0);
        }
    }

    /// A required binder whose mapped source can leave its device and come
    /// back, standing in for an address the kernel would have to be asked to
    /// remove. While the source is away every bind is refused, exactly as the
    /// checked device binder refuses one.
    #[cfg(target_os = "linux")]
    struct SwitchedBinder(std::sync::Arc<std::sync::atomic::AtomicBool>);

    #[cfg(target_os = "linux")]
    impl crate::net::UplinkBinder for SwitchedBinder {
        fn requires_checked_device(&self) -> bool {
            true
        }

        fn bind(&self, sock: &socket2::Socket, ip: IpAddr) -> Result<()> {
            anyhow::ensure!(
                self.0.load(std::sync::atomic::Ordering::SeqCst),
                "source is not assigned to device lo"
            );
            crate::net::SourceIpBinder.bind(sock, ip)
        }
    }

    /// One established required link on `lo`, mapped as `path-a`, whose source
    /// the returned switch takes away and gives back.
    #[cfg(target_os = "linux")]
    async fn required_link(
        remote: SocketAddr,
        assigned: bool,
    ) -> (
        RehomeFixture,
        ConnectionId,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut f = RehomeFixture::new(remote).await;
        f.connections.truncate(1);
        let id = f.connections[0].conn_id;
        f.connections[0].reconnection.connection_established_ms = 1;
        let switch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(assigned));
        let io = f.conn_io.get_mut(&id).unwrap();
        io.binder = std::sync::Arc::new(SwitchedBinder(switch.clone()));
        io.spec.iface = Some(crate::bind_map::IfaceName::parse("lo").unwrap());
        io.spec.link_id = Some(crate::bind_map::LinkId::parse("path-a").unwrap());
        let (tx, _rx) = create_uplink_channel();
        sync_readers(&f.connections, &f.conn_io, &mut f.reader_handles, &tx).await;
        (f, id, switch)
    }

    /// The transient-loss blocker: a required link that lost its source must
    /// come back by itself, with no reload, once the source is on its device
    /// again — and must not own a socket or send anything in between.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_retired_link_returns_by_itself_once_its_source_is_back() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut f, id, assigned) = required_link(receiver.local_addr().unwrap(), false).await;
        let old_socket = std::sync::Arc::downgrade(&f.conn_io.get(&id).unwrap().socket);
        let mut gate = RehomeGate::new(false);

        // The link times out and its checked reconnect is refused: retired.
        let t0 = 1_000_000;
        recover_connection(&mut f.connections[0], &mut f.seq_tracker);
        f.connections[0].reconnection.last_reconnect_attempt_ms = 0;
        f.tick(&mut gate, t0).await.unwrap();
        assert!(f.conn_io.is_retired(id));
        assert!(old_socket.upgrade().is_none(), "retired socket still open");

        // Source away: every backoff retry is refused, no socket exists, and
        // not one datagram leaves on this link's behalf.
        let mut datagram = [0u8; 64];
        for second in 1..=5 {
            f.tick(&mut gate, t0 + second * 1000).await.unwrap();
            assert!(
                !f.conn_io.contains_key(&id),
                "socket opened while the source was away"
            );
            assert!(f.conn_io.is_retired(id));
            assert!(!f.reader_handles.contains_key(&id));
            assert!(
                receiver.try_recv_from(&mut datagram).is_err(),
                "a retired link transmitted"
            );
        }
        assert!(
            f.connections[0].reconnection.reconnect_failure_count >= 4,
            "the retry must run on the reconnect backoff"
        );

        // Source back, no reload: the next due retry binds and re-registers.
        assigned.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut returned_after = None;
        for second in 6..=9 {
            f.tick(&mut gate, t0 + second * 1000).await.unwrap();
            if f.conn_io.contains_key(&id) {
                returned_after = Some(second - 5);
                break;
            }
        }
        assert!(
            returned_after.is_some_and(|seconds| seconds <= 4),
            "link did not return within the slow backoff: {returned_after:?}"
        );
        assert!(!f.conn_io.is_retired(id));
        // It starts over like any rebuilt link: fresh protocol state and a new
        // registration grace window from the moment it came back.
        let back_at = t0 + (5 + returned_after.unwrap()) * 1000;
        assert_eq!(
            f.connections[0].reconnection.startup_grace_deadline_ms,
            back_at + STARTUP_GRACE_MS
        );
        assert_eq!(
            f.connections[0].reconnection.last_reconnect_attempt_ms,
            back_at
        );
        let io = f.conn_io.get(&id).unwrap();
        assert_eq!(io.spec.link_id.as_ref().unwrap().as_str(), "path-a");
        assert_eq!(io.spec.iface.as_ref().unwrap().as_str(), "lo");
        assert!(
            f.reader_handles.contains_key(&id),
            "no reader on the socket"
        );
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut datagram),
        )
        .await
        .expect("the returning link must re-register")
        .unwrap();
        assert!(n >= srtla_protocol::MIN_CONTROL_PKT_LEN);
        assert_eq!(
            srtla_protocol::get_packet_type(&datagram[..n]),
            Some(srtla_protocol::SRTLA_TYPE_REG2)
        );
    }

    /// A rebind that an egress fault asked for, and the checked bind refused,
    /// must retire the link rather than leave the faulted socket in place.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_refused_rebind_after_an_egress_fault_retires_the_link() {
        use crate::net::{EgressLifecycle, SystemIfaceResolver};
        let (mut f, id, _assigned) = required_link(remote(1), false).await;
        let io = f.conn_io.get_mut(&id).unwrap();
        io.egress = EgressLifecycle::for_spec(io.spec.iface.as_ref());
        io.egress.resolve_for_bind(&SystemIfaceResolver).unwrap();
        io.egress
            .note_send_error(&std::io::Error::from_raw_os_error(libc::ENETUNREACH))
            .expect("an unreachable egress asks for a rebind");
        let socket = std::sync::Arc::downgrade(&io.socket);
        // Live and inside its window, so only the egress step can act on it.
        f.keep_all_uplinks_live(1_000_000);
        f.connections[0].reconnection.last_reconnect_attempt_ms = 0;

        f.tick(&mut RehomeGate::new(false), 1_000_000)
            .await
            .unwrap();

        assert!(!f.conn_io.contains_key(&id), "faulted socket retained");
        assert!(f.conn_io.is_retired(id));
        assert!(!f.reader_handles.contains_key(&id));
        assert!(socket.upgrade().is_none(), "faulted socket still open");
        assert!(!f.connections[0].connected);
    }

    /// Between ticks only required links are checked, and only failing ones
    /// are retired; a default link is never touched.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_between_ticks_check_retires_only_unverified_required_links() {
        let (mut f, id, assigned) = required_link(remote(1), true).await;
        f.connections.push(create_test_connection().await);
        let default = f.connections[1].conn_id;
        f.conn_io
            .insert(default, crate::test_helpers::create_test_conn_io());
        async fn check(f: &mut RehomeFixture) -> bool {
            retire_unverified_sources(
                &mut f.connections,
                &mut f.conn_io,
                &mut f.reader_handles,
                &mut f.seq_tracker,
            )
            .await
        }
        // `lo` holds 127.0.0.1, so the required link verifies and is kept.
        assert!(!check(&mut f).await);
        assert!(f.conn_io.contains_key(&id));
        // Its device now names one that does not exist.
        f.conn_io.get_mut(&id).unwrap().spec.iface =
            Some(crate::bind_map::IfaceName::parse("missing0").unwrap());
        let socket = std::sync::Arc::downgrade(&f.conn_io.get(&id).unwrap().socket);
        assert!(check(&mut f).await);
        assert!(f.conn_io.is_retired(id));
        assert!(!f.reader_handles.contains_key(&id));
        assert!(socket.upgrade().is_none(), "retired socket still open");
        assert!(
            f.conn_io.contains_key(&default),
            "a default link was retired"
        );
        assert!(!check(&mut f).await, "nothing left to retire");
        drop(assigned);
    }

    /// Registration must not wait on a link that has no socket: if the REG1
    /// target (the probing fallback is always the first link) is parked, the
    /// REG1 goes out on a link that can send. With no such link the target
    /// stays, so the parked one registers as soon as it is back.
    #[tokio::test]
    async fn the_group_registers_through_a_link_that_has_a_socket() {
        let now = now_ms();
        let mut f = RehomeFixture::new(remote(1)).await;
        f.reg.has_connected = false;
        super::super::uplink::retire_uplink(
            &mut f.connections[0],
            &mut f.conn_io,
            &mut f.reader_handles,
            &mut f.seq_tracker,
        )
        .await;
        f.connections[0].reconnection.last_reconnect_attempt_ms = now;
        let live = &mut f.connections[1];
        live.connected = false;
        live.last_received = None;
        live.reconnection.connection_established_ms = 0;
        live.reconnection.startup_grace_deadline_ms = now + STARTUP_GRACE_MS;
        f.reg.set_reg1_target_idx(Some(0));

        f.tick(&mut RehomeGate::new(false), now).await.unwrap();
        assert_eq!(
            f.reg.pending_reg2_idx(),
            Some(1),
            "REG1 must go out on the link with a socket"
        );

        // The target loses its source during this very tick: the REG1 still
        // goes out on the link that can send, not one tick later.
        let (mut h, required, _assigned) = required_link(remote(1), true).await;
        h.reg.has_connected = false;
        h.conn_io.get_mut(&required).unwrap().spec.iface =
            Some(crate::bind_map::IfaceName::parse("missing0").unwrap());
        h.connections.push(create_test_connection().await);
        let other = h.connections[1].conn_id;
        h.conn_io
            .insert(other, crate::test_helpers::create_test_conn_io());
        for conn in h.connections.iter_mut() {
            conn.connected = false;
            conn.last_received = None;
            conn.reconnection.connection_established_ms = 0;
            conn.reconnection.startup_grace_deadline_ms = now + STARTUP_GRACE_MS;
        }
        h.reg.set_reg1_target_idx(Some(0));
        h.tick(&mut RehomeGate::new(false), now).await.unwrap();
        assert!(h.conn_io.is_retired(required));
        assert_eq!(h.reg.pending_reg2_idx(), Some(1));

        // Nothing can send: the target is kept for the parked link.
        let mut g = RehomeFixture::new(remote(1)).await;
        g.connections.truncate(1);
        g.reg.has_connected = false;
        super::super::uplink::retire_uplink(
            &mut g.connections[0],
            &mut g.conn_io,
            &mut g.reader_handles,
            &mut g.seq_tracker,
        )
        .await;
        g.connections[0].reconnection.last_reconnect_attempt_ms = now + 60_000;
        g.reg.set_reg1_target_idx(Some(0));
        // Past the REG2 timeout: a REG1 that never left must not cost the target.
        for at in [now, now + 5_000] {
            g.tick(&mut RehomeGate::new(false), at).await.unwrap();
        }
        assert_eq!(g.reg.get_selected_connection_idx(), Some(0));
        assert!(g.conn_io.is_retired(g.connections[0].conn_id));
    }

    fn remote(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 5000)
    }

    /// The most important half of the policy: a bond with a live uplink is never
    /// re-homed, however far the receiver's DNS has drifted. The lookup must not
    /// even happen — GeoDNS answers change constantly on a healthy bond.
    #[tokio::test]
    async fn a_healthy_bond_is_never_re_homed_however_much_dns_drifts() {
        let old = remote(1);
        let mut fixture = RehomeFixture::new(old).await;
        let resolver = StubResolver::new(vec![Some(vec![remote(9)])]);
        let mut gate = RehomeGate::with_resolver(true, resolver.clone());

        // Both uplinks stay live, so the all-failed timer never arms.
        let t0 = now_ms();
        for now in [t0, t0 + GLOBAL_TIMEOUT_MS * 3] {
            fixture.keep_all_uplinks_live(now);
            fixture
                .tick(&mut gate, now)
                .await
                .expect("a healthy bond must not error");
        }

        assert_eq!(resolver.calls(), 0, "a live bond must not even re-resolve");
        assert_eq!(fixture.remotes(), vec![old]);
        assert_eq!(gate.rehome_count(), 0);
        assert!(fixture.all_failed_at.is_none());
    }

    /// A dead bond alone is not enough: the receiver hostname must actually have
    /// stopped answering with the address we are pinned to. Otherwise the
    /// ordinary all-failed error path stands and normal reconnects continue.
    #[tokio::test]
    async fn a_dead_bond_with_unchanged_dns_is_not_re_homed() {
        let old = remote(1);
        let mut fixture = RehomeFixture::new(old).await;
        // Answer with a reordered multi-A set that still lists our address.
        let resolver = StubResolver::new(vec![Some(vec![remote(7), old])]);
        let mut gate = RehomeGate::with_resolver(true, resolver.clone());

        let t0 = now_ms();
        fixture.kill_all_uplinks(t0);
        fixture
            .tick(&mut gate, t0)
            .await
            .expect("arming must not error");
        let fired = fixture
            .tick(&mut gate, t0 + GLOBAL_TIMEOUT_MS + 1_000)
            .await;

        assert_eq!(resolver.calls(), 1, "the probe runs, and answers 'no move'");
        assert_eq!(fixture.remotes(), vec![old], "the bond must stay put");
        assert_eq!(gate.rehome_count(), 0);
        assert!(
            fired.is_err(),
            "without drift the pre-existing all-failed error must still fire"
        );
    }

    /// A dead bond must not be re-homed before the existing all-failed window
    /// has elapsed — a blip where every modem drops for a second or two is
    /// exactly what that window exists to absorb.
    #[tokio::test]
    async fn a_dead_bond_inside_the_all_failed_window_is_not_probed() {
        let old = remote(1);
        let mut fixture = RehomeFixture::new(old).await;
        let resolver = StubResolver::new(vec![Some(vec![remote(9)])]);
        let mut gate = RehomeGate::with_resolver(true, resolver.clone());

        let t0 = now_ms();
        fixture.kill_all_uplinks(t0);
        fixture
            .tick(&mut gate, t0)
            .await
            .expect("arming must not error");
        fixture
            .tick(&mut gate, t0 + GLOBAL_TIMEOUT_MS - 1_000)
            .await
            .expect("inside the window nothing fires");

        assert_eq!(resolver.calls(), 0, "no probe inside the all-failed window");
        assert_eq!(fixture.remotes(), vec![old]);
    }

    /// The whole trigger, end to end: dead past the window plus real drift moves
    /// every uplink together, re-arms the all-failed timer instead of erroring,
    /// and is then rate-limited even though DNS still says the receiver moved.
    #[tokio::test]
    async fn a_dead_bond_with_drift_re_homes_once_then_is_rate_limited() {
        let old = remote(1);
        let new = remote(9);
        let mut fixture = RehomeFixture::new(old).await;
        let resolver = StubResolver::new(vec![Some(vec![new]), Some(vec![new])]);
        let mut gate = RehomeGate::with_resolver(true, resolver.clone());

        let t0 = now_ms();
        fixture.kill_all_uplinks(t0);
        fixture
            .tick(&mut gate, t0)
            .await
            .expect("arming must not error");

        let moved_at = t0 + GLOBAL_TIMEOUT_MS + 1_000;
        fixture
            .tick(&mut gate, moved_at)
            .await
            .expect("a successful re-home replaces the all-failed error");

        assert_eq!(fixture.remotes(), vec![new], "every uplink moved together");
        assert_eq!(gate.rehome_count(), 1);
        assert_eq!(
            fixture.all_failed_at,
            Some(moved_at),
            "the fresh registration gets a full window before the bond is declared unrecoverable \
             again"
        );
        assert!(
            fixture.reg.is_probing(),
            "the bond re-registers from scratch, starting with RTT probing"
        );

        // Still dead and still drifting, but inside the rate-limit window.
        fixture.kill_all_uplinks(moved_at);
        let fired = fixture
            .tick(&mut gate, moved_at + GLOBAL_TIMEOUT_MS + 1_000)
            .await;
        assert_eq!(resolver.calls(), 1, "the rate limit gates the lookup too");
        assert_eq!(gate.rehome_count(), 1);
        assert!(fired.is_err(), "the all-failed error path stands meanwhile");
    }

    /// `--no-rehome` restores the pre-existing behaviour exactly.
    #[tokio::test]
    async fn the_opt_out_leaves_a_dead_drifted_bond_where_it_is() {
        let old = remote(1);
        let mut fixture = RehomeFixture::new(old).await;
        let resolver = StubResolver::new(vec![Some(vec![remote(9)])]);
        let mut gate = RehomeGate::with_resolver(false, resolver.clone());

        let t0 = now_ms();
        fixture.kill_all_uplinks(t0);
        fixture
            .tick(&mut gate, t0)
            .await
            .expect("arming must not error");
        let fired = fixture
            .tick(&mut gate, t0 + GLOBAL_TIMEOUT_MS + 1_000)
            .await;

        assert_eq!(resolver.calls(), 0);
        assert_eq!(fixture.remotes(), vec![old]);
        assert!(
            fired.is_err(),
            "the pre-existing all-failed error must fire"
        );
    }
}
