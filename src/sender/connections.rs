use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use smallvec::SmallVec;
use srtla_core::connection::SrtlaConnection;
use srtla_core::utils::now_ms;
use tracing::{debug, info, warn};

use super::sequence::SequenceTracker;
use super::uplink::{ConnIo, ConnIoMap, RetiredUplink};
use crate::bind_map::EffectiveLink;
use crate::net::{
    BatchUdpSocket, EgressLifecycle, RouteHealth, SocketKey, SystemIfaceResolver, UplinkBinder,
    UplinkSpec, create_uplink_socket, resolve_remote, resolve_remote_all,
};

pub struct PendingConnectionChanges {
    pub new_links: Option<SmallVec<UplinkSpec, 4>>,
    pub receiver_host: String,
    pub receiver_port: u16,
}

/// Legacy shape: uplinks identified by source IP alone, no bind-map.
#[must_use]
pub fn specs_from_ips(ips: &[IpAddr], weights: &[u8]) -> SmallVec<UplinkSpec, 4> {
    ips.iter()
        .zip(
            weights
                .iter()
                .copied()
                .chain(std::iter::repeat(srtla_core::connection::LINK_WEIGHT_MIN)),
        )
        .map(|(&ip, weight)| UplinkSpec {
            weight,
            ..UplinkSpec::unmapped(ip)
        })
        .collect()
}

/// Turn a resolved bind-map decision into uplink specs, in file order.
#[must_use]
pub fn specs_from_effective_links(links: &[EffectiveLink]) -> SmallVec<UplinkSpec, 4> {
    links.iter().map(UplinkSpec::from).collect()
}

/// Apply a reloaded uplink set to the live connection pool.
///
/// The pool is rebuilt in **ips-file order**: a surviving uplink keeps its
/// existing socket and registration state (no re-handshake, no disconnect) but
/// is repositioned to match the file, and a removed uplink is torn down. The
/// telemetry `conn_id` is the link's index in this vector, so reordering the
/// file reorders `conn_id` consistently — the C sender's "reload reassigns by
/// file order" semantics.
///
/// Survival is decided by **identity**, not by socket key: a mapped link whose
/// `link_id` is unchanged survives even when its IP or interface moved — but it
/// survives as a *fresh socket*, because every piece of state the old socket
/// held is scoped to an ifindex that no longer describes it.
#[allow(clippy::too_many_arguments)]
pub async fn apply_connection_changes(
    connections: &mut SmallVec<SrtlaConnection, 4>,
    conn_io: &mut ConnIoMap,
    new_links: &[UplinkSpec],
    receiver_host: &str,
    receiver_port: u16,
    last_selected_idx: &mut Option<usize>,
    seq_tracker: &mut SequenceTracker,
    binder: &Arc<dyn UplinkBinder>,
) {
    // Dedup on the SOCKET KEY, not on the IP: that is what tells two twin
    // modems sharing 192.168.8.100 apart. Without a bind-map the key has no
    // interface and degenerates to the IP, which is the legacy behavior.
    let mut seen = HashSet::<SocketKey>::new();
    let desired: SmallVec<UplinkSpec, 4> = new_links
        .iter()
        .filter(|spec| seen.insert(spec.socket_key()))
        .cloned()
        .collect();

    let previous_order: SmallVec<u64, 4> = connections.iter().map(|c| c.conn_id).collect();
    let mut survivors = Survivors::take(connections, conn_io);

    // Two passes: claim every survivor first, so a link whose socket key moved
    // cannot be outbid by a later row that happens to want its old key.
    let claimed: SmallVec<Option<SrtlaConnection>, 4> =
        desired.iter().map(|spec| survivors.claim(spec)).collect();
    let attempted_new = claimed.iter().filter(|c| c.is_none()).count();

    let mut fresh = create_missing(
        &desired,
        &claimed,
        receiver_host,
        receiver_port,
        binder,
        conn_io,
    )
    .await;
    let added = fresh.len();

    // Drop the leaving links' sequence entries and I/O halves so a stale NAK
    // cannot be misattributed to whichever uplink later reuses that index.
    let removed = survivors.retire(seq_tracker, conn_io);

    for (spec, existing) in desired.iter().zip(claimed) {
        match existing {
            Some(mut conn) => {
                if conn.link_weight != spec.weight {
                    info!(
                        "uplink {} weight {} -> {}",
                        conn.label, conn.link_weight, spec.weight
                    );
                    conn.link_weight = spec.weight;
                }
                if let Some(io) = conn_io.get_mut(&conn.conn_id) {
                    io.spec = spec.clone();
                } else if let Some(retired) = conn_io.retired_mut(conn.conn_id) {
                    // Still down, but a reload is a reason to look again now
                    // rather than when the backoff next allows it.
                    retired.spec = spec.clone();
                    conn.reconnection.last_reconnect_attempt_ms = 0;
                }
                connections.push(conn);
            }
            None => {
                if let Some(conn) = fresh.remove(&spec.socket_key()) {
                    connections.push(conn);
                }
            }
        }
    }

    if removed > 0 {
        info!("removed {removed} stale connections");
    }
    if added > 0 {
        info!("added {added} new connections");
    } else if attempted_new > 0 {
        warn!("failed to add any new connections (attempted {attempted_new})");
    }

    // A reorder invalidates the cached selection index, not just a removal.
    let new_order: SmallVec<u64, 4> = connections.iter().map(|c| c.conn_id).collect();
    if previous_order != new_order {
        *last_selected_idx = None;
    }
}

/// The pre-reload pool, indexed both ways so a link can be matched by identity
/// first and by socket key second.
struct Survivors {
    by_link_id: HashMap<String, (SocketKey, SrtlaConnection)>,
    by_key: HashMap<SocketKey, SrtlaConnection>,
}

impl Survivors {
    fn take(connections: &mut SmallVec<SrtlaConnection, 4>, conn_io: &ConnIoMap) -> Self {
        let mut by_link_id = HashMap::new();
        let mut by_key = HashMap::new();
        for conn in std::mem::take(connections) {
            // A retired link has no socket, but it is still the link its spec
            // names: it keeps its place when the reload still lists it, and
            // housekeeping goes on retrying its checked bind.
            let spec = match conn_io.get(&conn.conn_id) {
                Some(io) => io.spec.clone(),
                None => match conn_io.retired(conn.conn_id) {
                    Some(retired) => retired.spec.clone(),
                    None => continue,
                },
            };
            let key = spec.socket_key();
            match spec.link_id {
                Some(id) => {
                    by_link_id.insert(id.as_str().to_string(), (key, conn));
                }
                None => {
                    by_key.insert(key, conn);
                }
            }
        }
        Self { by_link_id, by_key }
    }

    /// Claim the live connection that `spec` describes, if its socket is still
    /// the right one.
    ///
    /// A mapped link whose socket key moved is deliberately **not** returned:
    /// its window, packet log, in-flight count, and registration are all scoped
    /// to the interface it was bound to, so carrying them onto a new interface
    /// would credit the new link with the old one's history.
    fn claim(&mut self, spec: &UplinkSpec) -> Option<SrtlaConnection> {
        let key = spec.socket_key();
        let Some(id) = spec.link_id.as_ref() else {
            // Legacy identity: the socket key IS the link. A previously-mapped
            // survivor still matches on it, so falling back to legacy does not
            // needlessly tear down a bond that is otherwise unchanged.
            return self.by_key.remove(&key).or_else(|| {
                let matched = self
                    .by_link_id
                    .iter()
                    .find(|(_, (existing_key, _))| *existing_key == key)
                    .map(|(id, _)| id.clone())?;
                self.by_link_id.remove(&matched).map(|(_, conn)| conn)
            });
        };
        let (existing_key, _) = self.by_link_id.get(id.as_str())?;
        (*existing_key == key)
            .then(|| self.by_link_id.remove(id.as_str()))
            .flatten()
            .map(|(_, conn)| conn)
    }

    /// Retire everything left unclaimed, returning how many links left the pool.
    fn retire(self, seq_tracker: &mut SequenceTracker, conn_io: &mut ConnIoMap) -> usize {
        let leaving: SmallVec<u64, 4> = self
            .by_link_id
            .values()
            .map(|(_, conn)| conn)
            .chain(self.by_key.values())
            .map(|c| c.conn_id)
            .collect();
        for conn_id in &leaving {
            seq_tracker.remove_connection(*conn_id);
            conn_io.forget(*conn_id);
        }
        leaving.len()
    }
}

/// Dial every desired link that no survivor covers.
async fn create_missing(
    desired: &[UplinkSpec],
    claimed: &[Option<SrtlaConnection>],
    receiver_host: &str,
    receiver_port: u16,
    binder: &Arc<dyn UplinkBinder>,
    conn_io: &mut ConnIoMap,
) -> HashMap<SocketKey, SrtlaConnection> {
    let missing: SmallVec<UplinkSpec, 4> = desired
        .iter()
        .zip(claimed)
        .filter(|(_, existing)| existing.is_none())
        .map(|(spec, _)| spec.clone())
        .collect();
    if missing.is_empty() {
        return HashMap::new();
    }
    let created =
        create_connections_from_links(&missing, receiver_host, receiver_port, binder, conn_io)
            .await;
    created
        .into_iter()
        .map(|conn| {
            let key = match (conn_io.get(&conn.conn_id), conn_io.retired(conn.conn_id)) {
                (Some(io), _) => io.spec.socket_key(),
                (None, Some(parked)) => parked.spec.socket_key(),
                (None, None) => UplinkSpec::unmapped(conn.local_ip).socket_key(),
            };
            (key, conn)
        })
        .collect()
}

pub async fn create_connections_from_ips(
    ips: &[IpAddr],
    weights: &[u8],
    receiver_host: &str,
    receiver_port: u16,
    binder: &Arc<dyn UplinkBinder>,
    conn_io: &mut ConnIoMap,
) -> SmallVec<SrtlaConnection, 4> {
    create_connections_from_links(
        &specs_from_ips(ips, weights),
        receiver_host,
        receiver_port,
        binder,
        conn_io,
    )
    .await
}

pub async fn create_connections_from_links(
    links: &[UplinkSpec],
    receiver_host: &str,
    receiver_port: u16,
    binder: &Arc<dyn UplinkBinder>,
    conn_io: &mut ConnIoMap,
) -> SmallVec<SrtlaConnection, 4> {
    let mut connections = SmallVec::new();
    for spec in links {
        match connect_uplink(spec, receiver_host, receiver_port, binder).await {
            Ok(Dialled::Live(mut conn, io)) => {
                conn.link_weight = spec.weight;
                info!("added uplink {} (weight {})", conn.label, conn.link_weight);
                conn_io.insert(conn.conn_id, io);
                connections.push(conn);
            }
            Ok(Dialled::Parked(mut conn, uplink, e)) => {
                conn.link_weight = spec.weight;
                warn!(
                    "uplink {}: first bind refused ({e:#}); parked without a socket, retrying \
                     until its source is verified on its device",
                    conn.label
                );
                // Owns no socket, so it must never count as a live link.
                conn.mark_for_recovery();
                conn_io.park(conn.conn_id, uplink);
                connections.push(conn);
            }
            Err(e) => warn!(
                "failed to add uplink {} -> {}:{}: {}",
                spec.origin(),
                receiver_host,
                receiver_port,
                e
            ),
        }
    }
    connections
}

/// What dialling one uplink produced.
enum Dialled {
    /// A bound socket, ready to register.
    Live(SrtlaConnection, ConnIo),
    /// A required link whose checked bind was refused after the receiver had
    /// resolved. Its source is not (verifiably) on its device yet; that is the
    /// same transient loss as one that happens after the apply, so it is parked
    /// and retried rather than dropped.
    Parked(SrtlaConnection, RetiredUplink, anyhow::Error),
}

/// Open a UDP socket for `spec`, steered onto its egress, and pair it with a
/// fresh socket-free [`SrtlaConnection`]. The connection and its [`ConnIo`]
/// share a `conn_id` so the shell can key the I/O map by it.
///
/// A receiver that does not resolve is an error for every link: there is
/// nothing to retry against. A refused bind is an error only outside required
/// mode, where a link has always been dropped when it cannot bind.
async fn connect_uplink(
    spec: &UplinkSpec,
    receiver_host: &str,
    receiver_port: u16,
    binder: &Arc<dyn UplinkBinder>,
) -> Result<Dialled> {
    use rand::RngCore;

    let remote = resolve_remote(receiver_host, receiver_port).await?;
    let mut egress = EgressLifecycle::for_spec(spec.iface.as_ref());
    let link_binder = link_binder_for(spec, binder);
    let conn_id = rand::rng().next_u64();
    let label = spec.label(receiver_host, receiver_port);
    let conn = SrtlaConnection::new_registering(conn_id, label, spec.ip, now_ms());
    // Re-resolve the interface by NAME before every socket creation: a replug
    // leaves the old ifindex describing nothing, and SO_BINDTODEVICE freezes
    // whatever index it is handed at setsockopt time.
    let socket = egress
        .resolve_for_bind(&SystemIfaceResolver)
        .map_err(|fault| anyhow::anyhow!("egress unavailable ({})", fault.as_str()))
        .and_then(|_| open_bound_socket(spec.ip, link_binder.as_ref(), remote));
    match socket {
        Ok(socket) => {
            let route_health = observe_route_for(spec);
            let io = ConnIo {
                socket,
                binder: link_binder,
                remote,
                spec: spec.clone(),
                egress,
                route_health,
            };
            Ok(Dialled::Live(conn, io))
        }
        Err(e) if link_binder.requires_checked_device() => {
            let uplink = RetiredUplink {
                binder: link_binder,
                remote,
                spec: spec.clone(),
                egress,
            };
            Ok(Dialled::Parked(conn, uplink, e))
        }
        Err(e) => Err(e),
    }
}

/// IPv4-mapped receiver literals name IPv4 destinations. Required sockets must
/// send their canonical sockaddr even when DNS/literal parsing returned IPv6.
/// Keep the original remote identity for DNS drift/re-home comparisons.
fn send_peer(remote: SocketAddr, binder: &dyn UplinkBinder) -> SocketAddr {
    if binder.requires_checked_device()
        && let SocketAddr::V6(v6) = remote
        && let Some(ip) = v6.ip().to_ipv4_mapped()
    {
        SocketAddr::new(ip.into(), v6.port())
    } else {
        remote
    }
}

/// The binder this link's socket is created with.
///
/// A mapped link gets `SO_BINDTODEVICE` + `bind(ip, 0)`; an unmapped one keeps
/// the process-wide binder verbatim, which is what makes a run without
/// `--bind-map` byte-identical to the legacy one.
fn link_binder_for(spec: &UplinkSpec, default: &Arc<dyn UplinkBinder>) -> Arc<dyn UplinkBinder> {
    match spec.iface.as_ref() {
        None => default.clone(),
        #[cfg(target_os = "linux")]
        Some(iface) => {
            if default.requires_checked_device() {
                Arc::new(crate::net::DeviceBinder::checked(iface.as_str()))
            } else {
                Arc::new(crate::net::DeviceBinder::new(iface.as_str()))
            }
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => default.clone(),
    }
}

/// Read the route invariant for a mapped link. An unmapped link has no
/// interface to observe, so it stays `Unknown` rather than claiming anything.
fn observe_route_for(spec: &UplinkSpec) -> RouteHealth {
    spec.iface.as_ref().map_or(RouteHealth::Unknown, |iface| {
        crate::net::observe_default_route(iface.as_str())
    })
}

/// Put a link into recovery and drop the sequence ownership it can no longer
/// answer for.
///
/// [`SrtlaConnection::mark_for_recovery`] is a pure method: it clears the link's
/// own `packet_log`, but it cannot reach the shell's [`SequenceTracker`], which
/// still maps every sequence this link queued to its `conn_id`. A NAK arriving
/// after the reset would then be attributed to — and shrink the window of — a
/// link that has been wiped and cannot be responsible for that loss. The two
/// halves belong together, so every recovery site calls this instead of
/// `mark_for_recovery` directly.
pub fn recover_connection(conn: &mut SrtlaConnection, seq_tracker: &mut SequenceTracker) {
    conn.mark_for_recovery();
    seq_tracker.remove_connection(conn.conn_id);
}

/// Re-open this uplink's socket in place (same egress binding and remote) and
/// reset the connection's protocol state. The pure state reset lives on
/// [`SrtlaConnection::reset_for_reconnect`]; only the socket work is here. The
/// caller must respawn the reader from the new `io.socket`.
pub async fn reconnect_uplink(
    conn: &mut SrtlaConnection,
    io: &mut ConnIo,
    receiver_host: &str,
    seq_tracker: &mut SequenceTracker,
    now: u64,
) -> Result<()> {
    rebuild_uplink_socket(conn, io, seq_tracker, now)?;
    spawn_receiver_dns_drift_check(receiver_host, io.remote, now);
    Ok(())
}

/// Re-open this uplink's socket against whatever `io.remote` currently holds and
/// reset the connection's protocol state.
///
/// Shared by the per-uplink reconnect above and the whole-bond re-home in
/// [`super::rehome`], which repoints `io.remote` for *every* uplink first and
/// then rebuilds each socket through here. Re-home does not want the drift check
/// bolted onto `reconnect_uplink`: it has just re-resolved the hostname itself,
/// so re-asking would be a wasted lookup that could only warn about the address
/// it deliberately moved to.
pub(super) fn rebuild_uplink_socket(
    conn: &mut SrtlaConnection,
    io: &mut ConnIo,
    seq_tracker: &mut SequenceTracker,
    now: u64,
) -> Result<()> {
    // The interface is re-resolved by NAME here, never carried over: the socket
    // being replaced may be holding an ifindex that stopped describing the
    // device, which is the one failure `SO_BINDTODEVICE` cannot recover from.
    io.egress
        .resolve_for_bind(&SystemIfaceResolver)
        .map_err(|fault| anyhow::anyhow!("egress unavailable ({})", fault.as_str()))?;
    io.route_health = observe_route_for(&io.spec);
    io.socket = open_bound_socket(conn.local_ip, io.binder.as_ref(), io.remote)?;
    restart_on_new_socket(conn, seq_tracker, now);
    Ok(())
}

/// A fresh socket for `ip`, steered by `binder` and aimed at `remote`. For a
/// required link the binder is the checked one, so this refuses unless the
/// source is assigned to the mapped device right now.
fn open_bound_socket(
    ip: IpAddr,
    binder: &dyn UplinkBinder,
    remote: SocketAddr,
) -> Result<Arc<BatchUdpSocket>> {
    let sock = create_uplink_socket(ip)?;
    binder.bind(&sock, ip)?;
    sock.set_nonblocking(true)?;
    Ok(Arc::new(BatchUdpSocket::new(
        sock,
        send_peer(remote, binder),
    )?))
}

/// The protocol-state half of putting a link on a new socket.
fn restart_on_new_socket(conn: &mut SrtlaConnection, seq_tracker: &mut SequenceTracker, now: u64) {
    conn.reset_for_reconnect(now);
    // A reconnected link comes back with an empty packet log, so the tracker
    // must stop pointing already-queued sequences at it — same stale-ownership
    // problem `recover_connection` exists for, and a full socket reconnection is
    // the harder reset of the two.
    seq_tracker.remove_connection(conn.conn_id);
    conn.reconnection.reset_startup_grace(now);
}

/// Give a retired required link its socket back.
///
/// The bind goes through the link's own checked binder, exactly as its first
/// socket did: interface re-resolved by name, source required to be assigned to
/// that interface, bound address verified. Until all of that holds this returns
/// an error and the link stays parked without a socket, so a retry can never
/// transmit from a source that is not on its mapped device. The caller must
/// spawn the reader for the new `conn_io` entry.
pub(super) fn revive_uplink(
    conn: &mut SrtlaConnection,
    conn_io: &mut ConnIoMap,
    seq_tracker: &mut SequenceTracker,
    now: u64,
) -> Result<()> {
    let retired = conn_io
        .retired_mut(conn.conn_id)
        .ok_or_else(|| anyhow::anyhow!("link is not retired"))?;
    retired
        .egress
        .resolve_for_bind(&SystemIfaceResolver)
        .map_err(|fault| anyhow::anyhow!("egress unavailable ({})", fault.as_str()))?;
    let socket = open_bound_socket(conn.local_ip, retired.binder.as_ref(), retired.remote)?;
    let route_health = observe_route_for(&retired.spec);
    if let Some(retired) = conn_io.unpark(conn.conn_id) {
        conn_io.insert(
            conn.conn_id,
            ConnIo {
                socket,
                binder: retired.binder,
                remote: retired.remote,
                spec: retired.spec,
                egress: retired.egress,
                route_health,
            },
        );
    }
    restart_on_new_socket(conn, seq_tracker, now);
    Ok(())
}

/// At most one DNS-drift warning per minute across the whole process. Every
/// bonded uplink reconnects on its own schedule, so a receiver that really has
/// moved would otherwise print one line per link per retry.
const DNS_DRIFT_WARN_INTERVAL_MS: u64 = 60_000;
static LAST_DNS_DRIFT_WARN_MS: AtomicU64 = AtomicU64::new(0);

/// Claim the next drift-warning slot, or report that one was used recently.
///
/// `0` means "never warned", so the first drift always speaks up. The claim is
/// a compare-exchange: two uplinks reconnecting in the same millisecond produce
/// one warning, not two.
fn claim_dns_drift_warning(now: u64) -> bool {
    loop {
        let last = LAST_DNS_DRIFT_WARN_MS.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < DNS_DRIFT_WARN_INTERVAL_MS {
            return false;
        }
        // `now.max(1)` keeps 0 reserved for "never warned" on a clock that
        // could legitimately read 0.
        match LAST_DNS_DRIFT_WARN_MS.compare_exchange_weak(
            last,
            now.max(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(_) => continue,
        }
    }
}

/// Has the receiver's hostname stopped answering with the address this uplink is
/// pinned to? An empty answer is not drift — it is a lookup that told us nothing.
fn dns_drift_detected(cached: SocketAddr, fresh: &[SocketAddr]) -> bool {
    !fresh.is_empty() && !fresh.contains(&cached)
}

/// Bond-wide form of [`dns_drift_detected`], used by the re-home trigger.
///
/// True only when the hostname answered with something and *none* of the
/// addresses the bond is currently pinned to appear in that answer. Requiring
/// every uplink to have been dropped from DNS (rather than any one of them) is
/// the conservative reading: a GeoDNS or round-robin zone that still lists one
/// of our addresses has not moved the receiver, it has merely reordered its
/// answer, and re-homing on that would thrash the bond for nothing.
pub(super) fn receiver_moved(current: &[SocketAddr], fresh: &[SocketAddr]) -> bool {
    !current.is_empty() && current.iter().all(|c| dns_drift_detected(*c, fresh))
}

/// Detect-only check that the receiver's hostname still resolves to the address
/// this uplink is pinned to.
///
/// This **never** swaps `io.remote`, not even when the re-resolution succeeds
/// and hands back a perfectly good new address. SRTLA registration binds the
/// whole bond to a receiver-generated connection ID (REG1/REG2/REG3): the ID
/// only means anything to the receiver instance that minted it. Repointing a
/// single uplink at a fresh DNS answer would split the bond across two receiver
/// identities — the new instance would not know our group, so that link would
/// end up worse off than it is talking to a stale address, while the rest of the
/// bond stayed where it was.
///
/// Migrating the *whole* bond together does exist — see [`super::rehome`] — but
/// it is deliberately not reachable from here. This check fires on a single
/// uplink's reconnect, which happens constantly on a healthy bond as individual
/// modems flap; tearing down a working stream because one link reconnected while
/// GeoDNS happened to answer differently would be far worse than the stale
/// address. Re-home only runs once the bond is *entirely* dead, where there is
/// nothing left to protect. On a healthy bond the operator still just gets this
/// warning and decides.
///
/// Runs detached so a slow or hanging resolver cannot delay the reconnect it was
/// triggered by — the reconnect is on the housekeeping tick of the main event
/// loop, and this is diagnostics.
fn spawn_receiver_dns_drift_check(receiver_host: &str, cached: SocketAddr, now: u64) {
    let host = receiver_host.to_string();
    tokio::spawn(async move {
        // A failed lookup is not a reconnect failure: DNS is often the first
        // thing to break when an uplink flaps, and the cached address is still
        // the best guess we have. Log at debug and stay put.
        match resolve_remote_all(&host, cached.port()).await {
            Ok(fresh) => {
                if dns_drift_detected(cached, &fresh) && claim_dns_drift_warning(now) {
                    let answers: SmallVec<String, 4> =
                        fresh.iter().map(|a| a.to_string()).collect();
                    warn!(
                        "receiver DNS drift: {host} no longer resolves to {cached} (now {}); \
                         keeping the current address because the bond is registered against this \
                         receiver instance",
                        answers.join(", ")
                    );
                }
            }
            Err(e) => debug!("could not re-resolve {host} on reconnect ({e}); keeping {cached}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 5000)
    }

    #[test]
    fn dns_drift_needs_a_fresh_answer_that_excludes_the_cached_address() {
        // The receiver still answers with the address we are pinned to.
        assert!(!dns_drift_detected(addr(1), &[addr(1)]));
        // Multi-A record: ours is still one of them.
        assert!(!dns_drift_detected(addr(1), &[addr(2), addr(1)]));
        // Our address is gone from the answer — that is drift.
        assert!(dns_drift_detected(addr(1), &[addr(2)]));
        // An empty answer told us nothing; it must not be read as drift.
        assert!(!dns_drift_detected(addr(1), &[]));
    }

    #[test]
    fn dns_drift_warning_is_rate_limited_across_the_process() {
        // The static is process-wide, so drive it from a base far past any
        // stamp another test could have left, and never reset it.
        let base = LAST_DNS_DRIFT_WARN_MS
            .load(Ordering::Relaxed)
            .saturating_add(DNS_DRIFT_WARN_INTERVAL_MS * 10);

        assert!(claim_dns_drift_warning(base), "first drift must warn");
        assert!(
            !claim_dns_drift_warning(base + DNS_DRIFT_WARN_INTERVAL_MS - 1),
            "a second uplink reconnecting inside the window must stay quiet"
        );
        assert!(
            claim_dns_drift_warning(base + DNS_DRIFT_WARN_INTERVAL_MS),
            "the warning is due again once the window has passed"
        );
    }
}

#[cfg(test)]
mod retired_reload_tests {
    use super::*;
    use crate::test_helpers::{create_test_conn_io_map, create_test_connection};

    /// A reload that still lists a retired link keeps it — same connection,
    /// same identity, still without a socket — and makes its next bind retry
    /// due at once instead of after whatever backoff was left. A reload that
    /// no longer lists it drops it for good.
    #[tokio::test]
    async fn a_reload_keeps_a_listed_retired_link_and_makes_its_retry_due() {
        let now = now_ms();
        let mut connections: SmallVec<SrtlaConnection, 4> = SmallVec::new();
        connections.push(create_test_connection().await);
        let id = connections[0].conn_id;
        let mut conn_io = create_test_conn_io_map(&connections);
        let mut spec = UplinkSpec {
            iface: Some(crate::bind_map::IfaceName::parse("lo").unwrap()),
            link_id: Some(crate::bind_map::LinkId::parse("path-a").unwrap()),
            ..UplinkSpec::unmapped(connections[0].local_ip)
        };
        conn_io.get_mut(&id).unwrap().spec = spec.clone();
        let mut seq_tracker = SequenceTracker::new();
        recover_connection(&mut connections[0], &mut seq_tracker);
        assert!(conn_io.retire(id));
        connections[0].record_reconnect_attempt(now);
        assert!(!connections[0].should_attempt_reconnect(now));

        let binder: Arc<dyn UplinkBinder> = Arc::new(crate::net::RequiredBinding);
        spec.weight = 3;
        let mut last_selected = None;
        apply_connection_changes(
            &mut connections,
            &mut conn_io,
            std::slice::from_ref(&spec),
            "127.0.0.1",
            9,
            &mut last_selected,
            &mut seq_tracker,
            &binder,
        )
        .await;

        assert_eq!(connections.len(), 1, "the retired link left the pool");
        assert_eq!(connections[0].conn_id, id);
        assert!(
            !conn_io.contains_key(&id),
            "a reload must not conjure a socket"
        );
        assert_eq!(conn_io.retired(id).map(|r| &r.spec), Some(&spec));
        assert_eq!(connections[0].link_weight, 3);
        assert!(
            connections[0].should_attempt_reconnect(now),
            "a reload must make the retired link's retry due"
        );

        apply_connection_changes(
            &mut connections,
            &mut conn_io,
            &[],
            "127.0.0.1",
            9,
            &mut last_selected,
            &mut seq_tracker,
            &binder,
        )
        .await;
        assert!(connections.is_empty());
        assert!(!conn_io.is_retired(id), "a withdrawn link stayed parked");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod refused_first_bind_tests {
    use super::*;

    fn required_spec(ip: &str, link_id: &str) -> UplinkSpec {
        UplinkSpec {
            iface: Some(crate::bind_map::IfaceName::parse("lo").unwrap()),
            link_id: Some(crate::bind_map::LinkId::parse(link_id).unwrap()),
            ..UplinkSpec::unmapped(ip.parse().unwrap())
        }
    }

    /// A required row whose source is not on its device when the map is
    /// applied is the same transient loss as one that leaves later: it is
    /// parked under its identity, without a socket, and retried like any
    /// retired link — at start-up and when a reload adds it.
    #[tokio::test]
    async fn a_required_row_refused_at_its_first_bind_is_parked_not_dropped() {
        let required: Arc<dyn UplinkBinder> = Arc::new(crate::net::RequiredBinding);
        let mut conn_io = ConnIoMap::new();
        // TEST-NET-1 is never assigned to `lo`.
        let unassigned = required_spec("192.0.2.1", "path-a");
        let mut connections = create_connections_from_links(
            std::slice::from_ref(&unassigned),
            "127.0.0.1",
            9,
            &required,
            &mut conn_io,
        )
        .await;
        assert_eq!(connections.len(), 1, "the refused row was dropped");
        let id = connections[0].conn_id;
        assert!(!conn_io.contains_key(&id), "a refused row owns a socket");
        assert_eq!(conn_io.retired(id).map(|r| &r.spec), Some(&unassigned));
        assert!(
            connections[0].is_timed_out(now_ms()),
            "a parked row must not count as a live link"
        );
        assert!(connections[0].should_attempt_reconnect(now_ms()));

        // A reload adding a second refused row next to it keeps both.
        let added = required_spec("192.0.2.2", "path-b");
        apply_connection_changes(
            &mut connections,
            &mut conn_io,
            &[unassigned.clone(), added.clone()],
            "127.0.0.1",
            9,
            &mut None,
            &mut SequenceTracker::new(),
            &required,
        )
        .await;
        assert_eq!(
            connections.len(),
            2,
            "the row added by the reload was dropped"
        );
        assert_eq!(connections[0].conn_id, id, "the parked row was replaced");
        assert_eq!(
            conn_io.retired(connections[1].conn_id).map(|r| &r.spec),
            Some(&added)
        );
        assert!(conn_io.is_empty());
    }

    /// Without a receiver address there is nothing to retry against, and a
    /// default run keeps dropping a row it cannot bind, as it always has.
    #[tokio::test]
    async fn rows_are_still_dropped_on_lookup_failure_and_outside_required_mode() {
        let required: Arc<dyn UplinkBinder> = Arc::new(crate::net::RequiredBinding);
        let mut conn_io = ConnIoMap::new();
        let unresolvable = create_connections_from_links(
            &[required_spec("127.0.0.1", "path-a")],
            "receiver.invalid",
            9,
            &required,
            &mut conn_io,
        )
        .await;
        assert!(unresolvable.is_empty());

        let default: Arc<dyn UplinkBinder> = Arc::new(crate::net::SourceIpBinder);
        for spec in [
            UplinkSpec::unmapped("192.0.2.1".parse().unwrap()),
            required_spec("192.0.2.1", "path-a"),
        ] {
            let dropped =
                create_connections_from_links(&[spec], "127.0.0.1", 9, &default, &mut conn_io)
                    .await;
            assert!(dropped.is_empty(), "a default run parked a row");
        }
        assert!(conn_io.is_empty());
        assert!(!conn_io.is_retired(0));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod required_receiver_tests {
    use super::*;

    #[tokio::test]
    async fn mapped_receiver_forwards_before_and_after_required_socket_rebuild() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = SocketAddr::new(
            "::ffff:127.0.0.1".parse().unwrap(),
            receiver.local_addr().unwrap().port(),
        );
        let binder: Arc<dyn UplinkBinder> = Arc::new(crate::net::RequiredBinding);
        let spec = UplinkSpec {
            iface: Some(crate::bind_map::IfaceName::parse("lo").unwrap()),
            link_id: Some(crate::bind_map::LinkId::parse("path-a").unwrap()),
            ..UplinkSpec::unmapped("127.0.0.1".parse().unwrap())
        };
        let Dialled::Live(mut conn, mut io) =
            connect_uplink(&spec, "::ffff:127.0.0.1", remote.port(), &binder)
                .await
                .unwrap()
        else {
            panic!("a loopback source on lo must bind")
        };
        assert_eq!(io.remote, remote);
        assert_eq!(
            send_peer(remote, &crate::net::SourceIpBinder),
            remote,
            "default peer behavior must stay unchanged"
        );
        let mut seq = SequenceTracker::new();
        for rebuilt in [false, true] {
            if rebuilt {
                rebuild_uplink_socket(&mut conn, &mut io, &mut seq, now_ms()).unwrap();
            }
            assert_eq!(
                io.remote, remote,
                "canonical send must preserve DNS identity"
            );
            io.send_control_padded(b"probe").await.unwrap();
            let mut packet = [0; 64];
            let (n, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                receiver.recv_from(&mut packet),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&packet[..5], b"probe");
            assert_eq!(n, 32);
            assert_eq!(peer.ip(), spec.ip);
            assert!(io.binder.requires_checked_device());
        }
    }
}
