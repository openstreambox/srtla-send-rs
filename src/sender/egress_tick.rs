//! The egress-binding step of a housekeeping tick.
//!
//! `SO_BINDTODEVICE` freezes an ifindex at bind time, and neither the kernel nor
//! the SRTLA protocol tells the sender when that index stops describing the
//! device. Nothing else in the tick would notice: the liveness timeout only
//! measures inbound silence, and a blackholed route produces no error at all. So
//! every tick re-resolves the interface by name and re-reads the route
//! invariant, which bounds detection to one housekeeping interval.
//!
//! Read-only with respect to the host: a name lookup and a route-table read. No
//! rule, route, or policy-routing table is ever installed.

use std::collections::HashMap;

use srtla_core::connection::SrtlaConnection;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

use super::connections::{reconnect_uplink, recover_connection};
use super::sequence::SequenceTracker;
use super::uplink::{ConnIo, ConnectionId, ReaderHandle, UplinkPacket, restart_reader_for};
use crate::net::{
    EgressPoll, RouteHealth, RouteTransition, SystemIfaceResolver, classify_route_transition,
    observe_default_route,
};

/// Whether the rest of the tick should still run for this link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickFlow {
    Continue,
    Retire,
    /// The link was removed or rebound; keepalives and registration would act on
    /// a socket that is gone or brand new.
    Skip,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_egress(
    conn: &mut SrtlaConnection,
    io: &mut ConnIo,
    reader_handles: &mut HashMap<ConnectionId, ReaderHandle>,
    packet_tx: &UnboundedSender<UplinkPacket>,
    seq_tracker: &mut SequenceTracker,
    receiver_host: &str,
    now_ms: u64,
) -> TickFlow {
    let route_before = io.route_health;
    match io.egress.poll(&SystemIfaceResolver) {
        EgressPoll::Unchanged => {}
        EgressPoll::Reenumerated { from, to } => warn!(
            "{}: egress interface re-enumerated (ifindex {from} -> {to}); rebinding rather than \
             reusing the stale socket",
            conn.label
        ),
        EgressPoll::Removed => warn!(
            "{}: egress interface is gone; link removed, awaiting a reload that names an \
             interface that exists",
            conn.label
        ),
    }
    io.route_health = observe_route(io);
    report_route_transition(&conn.label, route_before, io.route_health);

    // A removed link has no interface to bind to, so reconnecting it would only
    // burn the backoff. It waits for a reload, not a retry.
    if io.egress.is_removed() {
        return TickFlow::Skip;
    }

    if !(io.egress.needs_rebind() && conn.should_attempt_reconnect(now_ms)) {
        return TickFlow::Continue;
    }

    let label = conn.label.clone();
    conn.record_reconnect_attempt(now_ms);
    if let Err(e) = reconnect_uplink(conn, io, receiver_host, seq_tracker, now_ms).await {
        warn!("{label}: failed to rebind after an egress fault: {e}");
        recover_connection(conn, seq_tracker);
        if io.binder.requires_checked_device() {
            return TickFlow::Retire;
        }
    } else {
        restart_reader_for(conn, io.socket.clone(), reader_handles, packet_tx).await;
    }
    TickFlow::Skip
}

/// The route invariant for this link right now.
///
/// An unmapped link names no interface, so there is nothing to observe and the
/// answer stays `Unknown` — which asserts neither presence nor absence.
fn observe_route(io: &ConnIo) -> RouteHealth {
    io.egress.iface().map_or(RouteHealth::Unknown, |iface| {
        observe_default_route(iface.as_str())
    })
}

/// Announce a crossing of the route invariant the moment it happens.
///
/// The invariant is re-read every tick but only *printed* every status-log
/// interval, so without this a blackhole detected in one second could stay
/// unsaid for thirty — long enough for the operator to blame the bond instead
/// of the route.
fn report_route_transition(label: &str, before: RouteHealth, after: RouteHealth) {
    match classify_route_transition(before, after) {
        RouteTransition::Blackholed => warn!(
            "{label}: egress interface lost its default route; traffic pinned to it is silently \
             blackholed (sendto keeps succeeding) — link health is now route={}",
            after.as_str()
        ),
        RouteTransition::Restored => info!(
            "{label}: egress interface regained its default route (route={})",
            after.as_str()
        ),
        RouteTransition::Quiet => {}
    }
}
