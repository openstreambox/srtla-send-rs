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
use super::uplink::{ConnIo, ConnIoMap};
use crate::bind_map::EffectiveLink;
use crate::net::{
    BatchUdpSocket, EgressLifecycle, RouteHealth, SocketKey, SystemIfaceResolver, UplinkBinder,
    UplinkSpec, create_uplink_socket, resolve_remote_all, resolve_remote_for_source,
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
            if !conn_io.contains_key(&conn.conn_id) {
                continue;
            }
            let spec = conn_io
                .get(&conn.conn_id)
                .map_or_else(|| UplinkSpec::unmapped(conn.local_ip), |io| io.spec.clone());
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
            conn_io.remove(conn_id);
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
            let key = conn_io
                .get(&conn.conn_id)
                .map_or_else(|| UplinkSpec::unmapped(conn.local_ip), |io| io.spec.clone())
                .socket_key();
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
            Ok((mut conn, io)) => {
                conn.link_weight = spec.weight;
                info!("added uplink {} (weight {})", conn.label, conn.link_weight);
                conn_io.insert(conn.conn_id, io);
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

/// Open a UDP socket for `spec`, steered onto its egress, and pair it with a
/// fresh socket-free [`SrtlaConnection`]. The connection and its [`ConnIo`]
/// share a `conn_id` so the shell can key the I/O map by it.
async fn connect_uplink(
    spec: &UplinkSpec,
    receiver_host: &str,
    receiver_port: u16,
    binder: &Arc<dyn UplinkBinder>,
) -> Result<(SrtlaConnection, ConnIo)> {
    use rand::RngCore;

    let remote = resolve_remote_for_source(receiver_host, receiver_port, spec.ip).await?;
    let mut egress = EgressLifecycle::for_spec(spec.iface.as_ref());
    // Re-resolve the interface by NAME before every socket creation: a replug
    // leaves the old ifindex describing nothing, and SO_BINDTODEVICE freezes
    // whatever index it is handed at setsockopt time.
    egress
        .resolve_for_bind(&SystemIfaceResolver)
        .map_err(|fault| anyhow::anyhow!("egress unavailable ({})", fault.as_str()))?;
    let link_binder = link_binder_for(spec, binder);

    let sock = create_uplink_socket(spec.ip)?;
    link_binder.bind(&sock, spec.ip)?;
    sock.set_nonblocking(true)?;
    let socket = Arc::new(BatchUdpSocket::new(sock, remote)?);

    let conn_id = rand::rng().next_u64();
    let label = spec.label(receiver_host, receiver_port);
    let conn = SrtlaConnection::new_registering(conn_id, label, spec.ip, now_ms());
    let route_health = observe_route_for(spec);
    let io = ConnIo {
        socket,
        binder: link_binder,
        remote,
        spec: spec.clone(),
        egress,
        route_health,
    };
    Ok((conn, io))
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
        Some(iface) => Arc::new(crate::net::DeviceBinder::new(iface.as_str())),
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
    anyhow::ensure!(
        conn.local_ip.is_ipv4() == io.remote.is_ipv4(),
        "receiver destination does not match source family; skipping {}",
        conn.local_ip
    );
    // The interface is re-resolved by NAME here, never carried over: the socket
    // being replaced may be holding an ifindex that stopped describing the
    // device, which is the one failure `SO_BINDTODEVICE` cannot recover from.
    io.egress
        .resolve_for_bind(&SystemIfaceResolver)
        .map_err(|fault| anyhow::anyhow!("egress unavailable ({})", fault.as_str()))?;
    io.route_health = observe_route_for(&io.spec);

    let sock = create_uplink_socket(conn.local_ip)?;
    io.binder.bind(&sock, conn.local_ip)?;
    sock.set_nonblocking(true)?;
    io.socket = Arc::new(BatchUdpSocket::new(sock, io.remote)?);

    conn.reset_for_reconnect(now);
    // A reconnected link comes back with an empty packet log, so the tracker
    // must stop pointing already-queued sequences at it — same stale-ownership
    // problem `recover_connection` exists for, and a full socket reconnection is
    // the harder reset of the two.
    seq_tracker.remove_connection(conn.conn_id);
    conn.reconnection.reset_startup_grace(now);
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
mod family_tests {
    use super::*;
    use crate::net::SourceIpBinder;

    #[tokio::test]
    async fn startup_skips_sources_without_a_receiver_family() {
        let binder: Arc<dyn UplinkBinder> = Arc::new(SourceIpBinder);
        for (host, expected) in [("127.0.0.1", "127.0.0.1"), ("::1", "::1")] {
            let mut io = ConnIoMap::new();
            let connections = create_connections_from_ips(
                &["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
                &[],
                host,
                9000,
                &binder,
                &mut io,
            )
            .await;
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].local_ip, expected.parse::<IpAddr>().unwrap());
            assert_eq!(io.len(), 1);
        }
    }

    #[tokio::test]
    async fn source_family_changes_and_reconnect_keep_destinations_in_source_family() {
        let binder: Arc<dyn UplinkBinder> = Arc::new(SourceIpBinder);
        let mut io = ConnIoMap::new();
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        let mut connections =
            create_connections_from_ips(&[v6], &[], "::1", 9000, &binder, &mut io).await;
        connections.extend(
            create_connections_from_ips(&[v4], &[], "127.0.0.1", 9000, &binder, &mut io).await,
        );
        assert_eq!(connections.len(), 2);
        let mut selected = None;
        let mut tracker = SequenceTracker::new();
        for sources in [vec![v4], vec![v6], vec![v4, v6]] {
            let host = if sources[0].is_ipv4() {
                "127.0.0.1"
            } else {
                "::1"
            };
            apply_connection_changes(
                &mut connections,
                &mut io,
                &specs_from_ips(&sources, &[]),
                host,
                9000,
                &mut selected,
                &mut tracker,
                &binder,
            )
            .await;
            assert_eq!(connections.len(), sources.len());
            for conn in &mut connections {
                let entry = io.get_mut(&conn.conn_id).unwrap();
                reconnect_uplink(conn, entry, host, &mut tracker, 10_000)
                    .await
                    .unwrap();
                assert_eq!(conn.local_ip.is_ipv4(), entry.remote.is_ipv4());
            }
        }
    }
}
