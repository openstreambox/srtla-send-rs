//! Follow a mapped link's source address when the host renumbers its interface.
//!
//! A mapped link (one with a bind-map row) is pinned to an interface and bound
//! to one source address on it. When the carrier hands that interface a new
//! address — a session reset, a new DHCP lease, an IPv6 prefix change or a
//! privacy-address rotation — the socket keeps sending from the old one and the
//! link goes silent. Until now only a reload (`SIGHUP` with a fresh IP list)
//! could move it.
//!
//! This module moves it on its own. On every address-table change and every
//! housekeeping tick it compares each mapped link's bound address with what its
//! interface holds now:
//!
//! * still there: nothing to do;
//! * gone, and the interface has exactly the kind of address that replaces it:
//!   after a short settle time the link's socket is re-created on the new
//!   address and re-joins the existing SRTLA group with a REG2, so the receiver
//!   keeps one session and the other links are not touched;
//! * gone with no replacement: the link is marked down and sends nothing until
//!   an address returns or a reload names one. It does not retry a bind that
//!   cannot succeed.
//!
//! A link without a bind-map row is left alone: its identity *is* its source
//! IP, so there is no "same link on a new address" to follow.
//!
//! The decision half ([`observe`], [`LinkFollow::step`]) is pure and unit
//! tested; [`follow_addresses`] applies it to the live pool.

use std::collections::HashMap;
use std::net::IpAddr;

use smallvec::SmallVec;
use srtla_core::connection::SrtlaConnection;
use srtla_core::registration::SrtlaRegistrationManager;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

use super::connections::{rebuild_uplink_socket, recover_connection};
use super::housekeeping::{RejoinSend, send_rejoin};
use super::sequence::SequenceTracker;
use super::uplink::{ConnIoMap, ConnectionId, ReaderHandle, UplinkPacket, restart_reader_for};
use crate::bind_map::IfaceName;
use crate::net::{AddrFlags, AddrTable, IfaceResolver, LocalAddr, SystemIfaceResolver};

/// How long a bound address must stay missing before the link acts on it.
///
/// Absorbs a delete-then-add renumbering, a brief DAD window and an address that
/// blinks out and back, so a flap shorter than this never touches the socket.
pub const ADDRESS_SETTLE_MS: u64 = 1_500;

/// Hold-down after a re-bind before the same link may re-bind again. Doubles for
/// every re-bind that comes less than [`FLAP_WINDOW_MS`] after the previous one,
/// up to [`REBIND_HOLD_MAX_MS`], so an address that keeps changing cannot make
/// the link churn its registration.
pub const REBIND_HOLD_BASE_MS: u64 = 2_000;
pub const REBIND_HOLD_MAX_MS: u64 = 30_000;
/// A link that has gone this long without a re-bind starts again from
/// [`REBIND_HOLD_BASE_MS`]. It is measured from the previous re-bind, not over
/// a sliding count, so a link flapping at the cap stays at the cap.
pub const FLAP_WINDOW_MS: u64 = 60_000;

// A link waiting out the longest hold-down re-binds well inside the window
// (with room for a late round), so sustained flapping never ages the back-off
// out.
const _: () = assert!(FLAP_WINDOW_MS >= REBIND_HOLD_MAX_MS + ADDRESS_SETTLE_MS + 10_000);

/// What the interface says about a link's bound address right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The interface still holds the bound address.
    Present(AddrFlags),
    /// The bound address is gone; this is the address that replaces it.
    Moved(IpAddr),
    /// The bound address is gone and nothing on the interface can replace it.
    Gone,
}

/// Compare a link's bound address with its interface's current addresses.
///
/// `claimed` lists the addresses other links on this interface (and unmapped
/// links) are bound to or are about to be, so two links on one interface never
/// pick the same replacement.
/// `was_temporary` is whether the bound address was last seen as an IPv6
/// privacy address; the replacement keeps the same kind when one exists.
#[must_use]
pub fn observe(
    bound: IpAddr,
    ifindex: u32,
    table: &AddrTable,
    claimed: &[IpAddr],
    was_temporary: bool,
) -> Observation {
    if let Some(addr) = table.find(ifindex, bound)
        && !addr.flags().dad_failed
    {
        return Observation::Present(addr.flags());
    }

    let mut candidates: SmallVec<&LocalAddr, 4> = table
        .on_iface(ifindex)
        .filter(|addr| addr.ip != bound && !claimed.contains(&addr.ip))
        .filter(|addr| can_replace(bound, addr))
        .collect();
    // Same kind first (privacy for privacy, stable for stable; a primary IPv4
    // address before a secondary one), then the lowest address, so the choice
    // is deterministic.
    candidates.sort_by_key(|addr| {
        let flags = addr.flags();
        (flags.temporary != was_temporary, flags.secondary, addr.ip)
    });
    candidates
        .first()
        .map_or(Observation::Gone, |addr| Observation::Moved(addr.ip))
}

/// Whether `addr` can stand in for the link's lost `bound` address: usable now,
/// same family and same scope (a link-local or loopback address only ever
/// replaces its own kind).
fn can_replace(bound: IpAddr, addr: &LocalAddr) -> bool {
    let flags = addr.flags();
    let usable = !flags.dad_failed && !flags.deprecated && (!flags.tentative || flags.optimistic);
    usable
        && bound.is_ipv4() == addr.ip.is_ipv4()
        && is_link_local(bound) == is_link_local(addr.ip)
        && bound.is_loopback() == addr.ip.is_loopback()
        && !addr.ip.is_multicast()
        && !addr.ip.is_unspecified()
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

/// What the live pool should do with one link this round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowAction {
    None,
    /// Re-create the socket on `to` and re-join the group. `to` may equal the
    /// bound address when a lost address came back.
    Rebind {
        to: IpAddr,
    },
    /// Stop using the link until an address returns.
    MarkDown,
}

/// Per-link debounce and flap state.
#[derive(Debug, Clone, Default)]
pub struct LinkFollow {
    bound: Option<IpAddr>,
    missing_since: Option<u64>,
    down: bool,
    was_temporary: bool,
    /// How many times the hold-down has doubled: re-binds in a row, each less
    /// than [`FLAP_WINDOW_MS`] after the one before.
    flap_level: u32,
    last_rebind: Option<u64>,
    hold_until: u64,
}

impl LinkFollow {
    #[must_use]
    pub fn is_down(&self) -> bool {
        self.down
    }

    /// The bound address is not on the interface right now: either still
    /// settling or already marked down. Reconnecting the link onto it cannot
    /// succeed, so housekeeping leaves it alone meanwhile.
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        self.down || self.missing_since.is_some()
    }

    #[must_use]
    pub fn was_temporary(&self) -> bool {
        self.was_temporary
    }

    /// When this link next needs a look even if the address table does not
    /// change: the end of its settle time, or of the hold-down it waits out.
    /// `None` when only a table change can move it.
    ///
    /// A down link still offers its settle time: after a failed re-bind the
    /// retry settles again, and that may end after the hold-down. A link that
    /// [`FollowAction::MarkDown`] took down settled long ago, so the `> now`
    /// filter drops its settle time anyway.
    #[must_use]
    pub fn wake_at(&self, now: u64) -> Option<u64> {
        let settle = self.missing_since.map(|since| since + ADDRESS_SETTLE_MS);
        let hold = (self.down || self.missing_since.is_some()).then_some(self.hold_until);
        [settle, hold]
            .into_iter()
            .flatten()
            .filter(|at| *at > now)
            .min()
    }

    /// Forget everything if the link is now bound somewhere this state did not
    /// put it (a reload re-created it, for instance).
    fn track(&mut self, bound: IpAddr) {
        if self.bound != Some(bound) {
            *self = Self {
                bound: Some(bound),
                ..Self::default()
            };
        }
    }

    /// Advance the state machine for one observation of `bound`.
    pub fn step(&mut self, bound: IpAddr, observation: Observation, now: u64) -> FollowAction {
        self.track(bound);
        match observation {
            Observation::Present(flags) => {
                self.was_temporary = flags.temporary;
                self.missing_since = None;
                if self.down && now >= self.hold_until {
                    // The address came back while the link was down: the link
                    // was taken out of service, so it needs a fresh socket and
                    // a REG2 exactly as for a new address.
                    self.note_rebind(bound, now);
                    return FollowAction::Rebind { to: bound };
                }
                FollowAction::None
            }
            Observation::Moved(to) => {
                if !self.settled(now) || now < self.hold_until {
                    return FollowAction::None;
                }
                self.note_rebind(to, now);
                FollowAction::Rebind { to }
            }
            Observation::Gone => {
                if self.down || !self.settled(now) {
                    return FollowAction::None;
                }
                self.down = true;
                FollowAction::MarkDown
            }
        }
    }

    fn settled(&mut self, now: u64) -> bool {
        let since = *self.missing_since.get_or_insert(now);
        now.saturating_sub(since) >= ADDRESS_SETTLE_MS
    }

    fn note_rebind(&mut self, to: IpAddr, now: u64) {
        let flapping = self
            .last_rebind
            .is_some_and(|at| now.saturating_sub(at) < FLAP_WINDOW_MS);
        self.flap_level = if flapping {
            (self.flap_level + 1).min(16)
        } else {
            0
        };
        self.last_rebind = Some(now);
        let hold = REBIND_HOLD_BASE_MS
            .saturating_mul(1 << self.flap_level)
            .min(REBIND_HOLD_MAX_MS);
        self.hold_until = now + hold;
        self.bound = Some(to);
        self.missing_since = None;
        self.down = false;
    }

    /// The re-bind the caller attempted failed, so the link is still bound to
    /// `bound`. It stays down until the next observation says otherwise, and
    /// the attempt still counts towards the back-off, so a bind that keeps
    /// failing is retried less and less often.
    fn rebind_failed(&mut self, bound: IpAddr) {
        self.bound = Some(bound);
        self.down = true;
    }
}

/// The follower's memory across rounds, keyed by `conn_id`.
#[derive(Debug, Default)]
pub struct AddressFollower {
    links: HashMap<ConnectionId, LinkFollow>,
    table: Option<std::sync::Arc<AddrTable>>,
}

impl AddressFollower {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adopt the latest address table from the watcher.
    pub fn set_table(&mut self, table: std::sync::Arc<AddrTable>) {
        self.table = Some(table);
    }

    /// The watcher is gone: with no table the follower lets go of every link
    /// on its next round, rather than keep acting on facts it can no longer
    /// refresh.
    pub fn clear_table(&mut self) {
        self.table = None;
    }

    /// The earliest time any link needs a look without a table change, so the
    /// caller can wake for a settle time ending between housekeeping ticks.
    #[must_use]
    pub fn next_wake(&self, now: u64) -> Option<u64> {
        self.table.as_ref()?;
        self.links.values().filter_map(|l| l.wake_at(now)).min()
    }

    #[must_use]
    pub fn link(&self, conn_id: ConnectionId) -> Option<&LinkFollow> {
        self.links.get(&conn_id)
    }
}

/// Slack added to the follower's wake-up so it never lands a millisecond before
/// the deadline it waits for (`now_ms` and the timer round differently).
pub(crate) const FOLLOW_WAKE_SLACK_MS: u64 = 5;

/// The follower's own wake-up between housekeeping ticks, so a settle time or
/// hold-down that ends mid-tick is acted on when it ends.
///
/// The sender's loop re-arms it after every follower round and awaits
/// [`FollowWake::fired`] in its `select!`.
pub(crate) struct FollowWake {
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
    armed: bool,
}

impl FollowWake {
    pub(crate) fn new() -> Self {
        Self {
            sleep: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            armed: false,
        }
    }

    /// Point the timer at the follower's next deadline, seen from `now`
    /// (`now_ms` time). With none pending it is disarmed, and only a table
    /// change or a housekeeping tick wakes the follower.
    pub(crate) fn rearm(&mut self, follower: &AddressFollower, now: u64) {
        self.armed = match follower.next_wake(now) {
            Some(at) => {
                let wait = at.saturating_sub(now) + FOLLOW_WAKE_SLACK_MS;
                self.sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_millis(wait));
                true
            }
            None => false,
        };
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }

    /// Resolves once the armed deadline passes, then stays pending until the
    /// next [`FollowWake::rearm`], so a fired timer never spins the loop. Never
    /// resolves while disarmed. Cancel-safe: dropping it keeps the deadline.
    pub(crate) async fn fired(&mut self) {
        if !self.armed {
            std::future::pending::<()>().await;
        }
        self.sleep.as_mut().await;
        self.armed = false;
    }
}

/// Apply the follower to the live pool: re-bind links whose address moved and
/// take down links whose address vanished.
#[allow(clippy::too_many_arguments)]
pub async fn follow_addresses(
    follower: &mut AddressFollower,
    connections: &mut [SrtlaConnection],
    conn_io: &mut ConnIoMap,
    reg: &mut SrtlaRegistrationManager,
    seq_tracker: &mut SequenceTracker,
    reader_handles: &mut HashMap<ConnectionId, ReaderHandle>,
    packet_tx: &UnboundedSender<UplinkPacket>,
    receiver_host: &str,
    now: u64,
) {
    follow_addresses_with(
        follower,
        &SystemIfaceResolver,
        connections,
        conn_io,
        reg,
        seq_tracker,
        reader_handles,
        packet_tx,
        receiver_host,
        now,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn follow_addresses_with(
    follower: &mut AddressFollower,
    resolver: &dyn IfaceResolver,
    connections: &mut [SrtlaConnection],
    conn_io: &mut ConnIoMap,
    reg: &mut SrtlaRegistrationManager,
    seq_tracker: &mut SequenceTracker,
    reader_handles: &mut HashMap<ConnectionId, ReaderHandle>,
    packet_tx: &UnboundedSender<UplinkPacket>,
    receiver_host: &str,
    now: u64,
) {
    follower
        .links
        .retain(|conn_id, _| connections.iter().any(|c| c.conn_id == *conn_id));
    let Some(table) = follower.table.clone() else {
        // No table (following is off, or the watcher ended): nothing here may
        // keep a link out of service.
        follower.links.clear();
        for io in conn_io.values_mut() {
            io.source_down = false;
        }
        return;
    };

    // Every address a link is bound to, with the interface it is pinned to. A
    // re-bind below adds its new address, so two links renumbered in the same
    // round never pick the same one.
    let mut claimed: SmallVec<Claim, 8> = connections
        .iter()
        .map(|c| Claim {
            iface: conn_io
                .get(&c.conn_id)
                .and_then(|io| io.egress.iface().cloned()),
            ip: c.local_ip,
        })
        .collect();

    for (idx, conn) in connections.iter_mut().enumerate() {
        let Some(io) = conn_io.get_mut(&conn.conn_id) else {
            continue;
        };
        // Only a mapped link has an interface to follow, and a link whose
        // interface is gone belongs to the egress lifecycle, not to us. Handing
        // it back means letting go entirely: housekeeping skips a link held
        // `source_down`, and housekeeping is what brings `Removed` back.
        let iface = match io.egress.iface().cloned() {
            Some(iface) if !io.egress.is_removed() => iface,
            _ => {
                release(follower, conn.conn_id, io);
                continue;
            }
        };
        let Some(ifindex) = resolver.ifindex(iface.as_str()) else {
            release(follower, conn.conn_id, io);
            continue;
        };

        let bound = conn.local_ip;
        let state = follower.links.entry(conn.conn_id).or_default();
        let others = claimed_on(&claimed, &iface, bound);
        let observation = observe(bound, ifindex, &table, &others, state.was_temporary());

        let action = state.step(bound, observation, now);
        // Hold reconnects from the first sighting of a missing address, not
        // only once it has settled: a bind to an address the host no longer
        // owns cannot succeed.
        io.source_down = state.is_unavailable();
        match action {
            FollowAction::None => {}
            FollowAction::MarkDown => {
                warn!(
                    "{}: source address {bound} left {} and nothing replaced it; link is down \
                     until an address returns or a reload names one",
                    conn.label,
                    iface.as_str()
                );
                recover_connection(conn, seq_tracker);
            }
            FollowAction::Rebind { to } => {
                let old_label = conn.label.clone();
                // The rebuild binds `conn.local_ip`, so the link points at the
                // new address for the attempt and is put back if it fails.
                conn.local_ip = to;
                io.spec.ip = to;
                conn.label = io.spec.label(receiver_host, io.remote.port());
                match rebuild_uplink_socket(conn, io, seq_tracker, now) {
                    Ok(()) => {
                        io.source_down = false;
                        restart_reader_for(conn, io.socket.clone(), reader_handles, packet_tx);
                        if to == bound {
                            info!(
                                "{}: source address {bound} is back on {}; link re-bound",
                                conn.label,
                                iface.as_str()
                            );
                        } else {
                            info!(
                                "{old_label}: source address moved {bound} -> {to} on {}; \
                                 re-bound this link without a reload",
                                iface.as_str()
                            );
                        }
                        let sent = send_rejoin(reg, idx, conn, io, now).await;
                        if sent == RejoinSend::Deferred {
                            info!(
                                "{}: another uplink is registering; re-joining once it is done",
                                conn.label
                            );
                        }
                        claimed.retain(|c| !c.is(&iface, bound));
                        claimed.push(Claim {
                            iface: Some(iface.clone()),
                            ip: to,
                        });
                    }
                    Err(e) => {
                        // The socket is still the old one, so the link must
                        // keep describing it: telemetry and the reload key
                        // report the address it is really bound to.
                        conn.local_ip = bound;
                        io.spec.ip = bound;
                        conn.label = old_label;
                        warn!(
                            "{}: could not re-bind to {to} on {}: {e}; link is down until the \
                             address settles",
                            conn.label,
                            iface.as_str()
                        );
                        recover_connection(conn, seq_tracker);
                        io.source_down = true;
                        state.rebind_failed(bound);
                    }
                }
            }
        }
    }
}

/// Stop holding a link: forget its follow state and let housekeeping (and the
/// egress lifecycle in it) look after it again.
fn release(follower: &mut AddressFollower, conn_id: ConnectionId, io: &mut super::uplink::ConnIo) {
    follower.links.remove(&conn_id);
    io.source_down = false;
}

/// One link's bound address and the interface it is pinned to (`None` for an
/// unmapped link, whose socket is not tied to any one interface).
#[derive(Debug, Clone)]
struct Claim {
    iface: Option<IfaceName>,
    ip: IpAddr,
}

impl Claim {
    fn is(&self, iface: &IfaceName, ip: IpAddr) -> bool {
        self.ip == ip && self.iface.as_ref() == Some(iface)
    }
}

/// The addresses a link on `iface`, bound to `bound`, must not move to: those
/// other links hold on the same interface, and any an unmapped link holds.
/// Twin modems may share one address on two interfaces, so a claim on another
/// interface does not block it here.
fn claimed_on(claimed: &[Claim], iface: &IfaceName, bound: IpAddr) -> SmallVec<IpAddr, 8> {
    claimed
        .iter()
        .filter(|c| !c.is(iface, bound))
        .filter(|c| c.iface.as_ref().is_none_or(|i| i == iface))
        .map(|c| c.ip)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const WWAN0: u32 = 4;
    const WWAN1: u32 = 5;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    fn addr(ifindex: u32, ip: IpAddr) -> LocalAddr {
        LocalAddr::new(ifindex, ip, AddrFlags::default())
    }

    fn addr_with(ifindex: u32, ip: IpAddr, flags: AddrFlags) -> LocalAddr {
        LocalAddr::new(ifindex, ip, flags)
    }

    fn temporary() -> AddrFlags {
        AddrFlags {
            temporary: true,
            ..AddrFlags::default()
        }
    }

    fn table(addrs: &[LocalAddr]) -> AddrTable {
        AddrTable::new(addrs.to_vec())
    }

    // ----- observe: the address diff -----

    #[test]
    fn a_bound_address_still_on_its_interface_is_present() {
        let t = table(&[addr(WWAN0, v4(10))]);
        assert!(matches!(
            observe(v4(10), WWAN0, &t, &[], false),
            Observation::Present(_)
        ));
    }

    #[test]
    fn a_renumbered_interface_reports_the_replacement() {
        let t = table(&[addr(WWAN0, v4(11))]);
        assert_eq!(
            observe(v4(10), WWAN0, &t, &[], false),
            Observation::Moved(v4(11))
        );
    }

    #[test]
    fn an_interface_with_no_address_left_reports_gone() {
        let t = table(&[addr(WWAN1, v4(20))]);
        assert_eq!(observe(v4(10), WWAN0, &t, &[], false), Observation::Gone);
    }

    #[test]
    fn the_same_address_on_another_interface_does_not_count() {
        // SO_BINDTODEVICE pins the link to wwan0; an address on wwan1 cannot
        // carry it, even the identical one.
        let t = table(&[addr(WWAN1, v4(10))]);
        assert_eq!(observe(v4(10), WWAN0, &t, &[], false), Observation::Gone);
    }

    #[test]
    fn a_replacement_must_be_the_same_family() {
        // A dual-stack modem lost its IPv4 lease; the IPv6 address belongs to
        // the IPv6 link, never to this one.
        let t = table(&[addr(WWAN0, v6("2001:db8::5"))]);
        assert_eq!(observe(v4(10), WWAN0, &t, &[], false), Observation::Gone);
    }

    #[test]
    fn two_links_on_one_interface_never_take_each_others_address() {
        // Given: links A (.10) and B (.30) share wwan0; A's address is
        // replaced by .20 while B keeps .30.
        let t = table(&[addr(WWAN0, v4(20)), addr(WWAN0, v4(30))]);

        // Then: A takes .20, not B's .30 (even though .30 is also unclaimed
        // by A itself), and B is unaffected.
        assert_eq!(
            observe(v4(10), WWAN0, &t, &[v4(30)], false),
            Observation::Moved(v4(20))
        );
        assert!(matches!(
            observe(v4(30), WWAN0, &t, &[v4(10)], false),
            Observation::Present(_)
        ));
    }

    #[test]
    fn two_links_renumbered_at_once_get_distinct_addresses() {
        // Both of wwan0's addresses changed. The pool processes A first and
        // adds its pick to `claimed`, so B gets the other one.
        let t = table(&[addr(WWAN0, v4(40)), addr(WWAN0, v4(50))]);
        let a = observe(v4(10), WWAN0, &t, &[v4(30)], false);
        assert_eq!(a, Observation::Moved(v4(40)));
        let b = observe(v4(30), WWAN0, &t, &[v4(40)], false);
        assert_eq!(b, Observation::Moved(v4(50)));
    }

    #[test]
    fn an_ipv6_privacy_link_follows_to_the_next_privacy_address() {
        // Given: the link was on a temporary address that has now expired;
        // the interface holds its stable address and a fresh temporary one.
        let t = table(&[
            addr(WWAN0, v6("2001:db8::1")),
            addr_with(WWAN0, v6("2001:db8::ffff:abcd"), temporary()),
        ]);
        assert_eq!(
            observe(v6("2001:db8::ffff:1234"), WWAN0, &t, &[], true),
            Observation::Moved(v6("2001:db8::ffff:abcd"))
        );
        // And a link on the stable address prefers the stable replacement.
        assert_eq!(
            observe(v6("2001:db8:1::1"), WWAN0, &t, &[], false),
            Observation::Moved(v6("2001:db8::1"))
        );
    }

    #[test]
    fn a_deprecated_privacy_address_is_still_present() {
        // A privacy address past its preferred lifetime still works for
        // existing traffic; the link stays on it until the kernel removes it.
        let flags = AddrFlags {
            temporary: true,
            deprecated: true,
            ..AddrFlags::default()
        };
        let t = table(&[addr_with(WWAN0, v6("2001:db8::ffff:1234"), flags)]);
        assert!(matches!(
            observe(v6("2001:db8::ffff:1234"), WWAN0, &t, &[], true),
            Observation::Present(_)
        ));
    }

    #[test]
    fn unusable_addresses_are_never_a_replacement() {
        let deprecated = AddrFlags {
            deprecated: true,
            ..AddrFlags::default()
        };
        let tentative = AddrFlags {
            tentative: true,
            ..AddrFlags::default()
        };
        let failed = AddrFlags {
            dad_failed: true,
            ..AddrFlags::default()
        };
        let t = table(&[
            addr_with(WWAN0, v6("2001:db8::2"), deprecated),
            addr_with(WWAN0, v6("2001:db8::3"), tentative),
            addr_with(WWAN0, v6("2001:db8::4"), failed),
            addr(WWAN0, v6("fe80::1")),
        ]);
        assert_eq!(
            observe(v6("2001:db8::1"), WWAN0, &t, &[], false),
            Observation::Gone
        );
    }

    #[test]
    fn an_optimistic_address_may_replace_while_dad_runs() {
        let optimistic = AddrFlags {
            tentative: true,
            optimistic: true,
            ..AddrFlags::default()
        };
        let t = table(&[addr_with(WWAN0, v6("2001:db8::9"), optimistic)]);
        assert_eq!(
            observe(v6("2001:db8::1"), WWAN0, &t, &[], false),
            Observation::Moved(v6("2001:db8::9"))
        );
    }

    #[test]
    fn a_bound_address_that_failed_dad_counts_as_gone() {
        let failed = AddrFlags {
            dad_failed: true,
            ..AddrFlags::default()
        };
        let t = table(&[addr_with(WWAN0, v6("2001:db8::1"), failed)]);
        assert_eq!(
            observe(v6("2001:db8::1"), WWAN0, &t, &[], false),
            Observation::Gone
        );
    }

    #[test]
    fn a_primary_ipv4_address_is_preferred_over_a_secondary_one() {
        let secondary = AddrFlags {
            secondary: true,
            ..AddrFlags::default()
        };
        let t = table(&[addr_with(WWAN0, v4(5), secondary), addr(WWAN0, v4(200))]);
        assert_eq!(
            observe(v4(10), WWAN0, &t, &[], false),
            Observation::Moved(v4(200))
        );
    }

    #[test]
    fn loopback_never_replaces_a_routable_address() {
        let t = table(&[addr(WWAN0, IpAddr::V4(Ipv4Addr::LOCALHOST))]);
        assert_eq!(observe(v4(10), WWAN0, &t, &[], false), Observation::Gone);
    }

    #[test]
    fn link_local_never_replaces_a_routable_address() {
        let t = table(&[addr(WWAN0, IpAddr::V4(Ipv4Addr::new(169, 254, 3, 4)))]);
        assert_eq!(observe(v4(10), WWAN0, &t, &[], false), Observation::Gone);
    }

    // ----- LinkFollow: debounce, flap and down handling -----

    #[test]
    fn a_move_waits_out_the_settle_time_then_rebinds_once() {
        let mut s = LinkFollow::default();
        let moved = Observation::Moved(v4(11));
        assert_eq!(s.step(v4(10), moved, 1_000), FollowAction::None);
        assert_eq!(
            s.step(v4(10), moved, 1_000 + ADDRESS_SETTLE_MS - 1),
            FollowAction::None
        );
        assert_eq!(
            s.step(v4(10), moved, 1_000 + ADDRESS_SETTLE_MS),
            FollowAction::Rebind { to: v4(11) }
        );
        // The caller is now bound to .11, which the interface holds.
        assert_eq!(
            s.step(
                v4(11),
                Observation::Present(AddrFlags::default()),
                3_000 + ADDRESS_SETTLE_MS
            ),
            FollowAction::None
        );
    }

    #[test]
    fn an_address_that_blinks_out_and_back_inside_the_settle_time_is_ignored() {
        let mut s = LinkFollow::default();
        let present = Observation::Present(AddrFlags::default());
        assert_eq!(s.step(v4(10), Observation::Gone, 0), FollowAction::None);
        assert_eq!(s.step(v4(10), present, 800), FollowAction::None);
        // The missing timer restarted: a fresh loss needs a full settle again.
        assert_eq!(s.step(v4(10), Observation::Gone, 900), FollowAction::None);
        assert_eq!(
            s.step(v4(10), Observation::Gone, 900 + ADDRESS_SETTLE_MS - 1),
            FollowAction::None
        );
        assert!(!s.is_down());
    }

    #[test]
    fn a_vanished_address_marks_the_link_down_once_and_never_spins() {
        let mut s = LinkFollow::default();
        assert_eq!(s.step(v4(10), Observation::Gone, 0), FollowAction::None);
        assert_eq!(
            s.step(v4(10), Observation::Gone, ADDRESS_SETTLE_MS),
            FollowAction::MarkDown
        );
        // Every later round while nothing changes is a no-op: no retry loop.
        for t in 1..100 {
            assert_eq!(
                s.step(v4(10), Observation::Gone, ADDRESS_SETTLE_MS + t * 1_000),
                FollowAction::None
            );
        }
        assert!(s.is_down());
    }

    #[test]
    fn a_down_link_comes_back_when_a_new_address_appears() {
        let mut s = LinkFollow::default();
        let _ = s.step(v4(10), Observation::Gone, 0);
        assert_eq!(
            s.step(v4(10), Observation::Gone, ADDRESS_SETTLE_MS),
            FollowAction::MarkDown
        );
        assert_eq!(
            s.step(v4(10), Observation::Moved(v4(12)), 10_000),
            FollowAction::Rebind { to: v4(12) }
        );
        assert!(!s.is_down());
    }

    #[test]
    fn a_down_link_comes_back_when_its_own_address_returns() {
        let mut s = LinkFollow::default();
        let _ = s.step(v4(10), Observation::Gone, 0);
        let _ = s.step(v4(10), Observation::Gone, ADDRESS_SETTLE_MS);
        assert!(s.is_down());
        assert_eq!(
            s.step(v4(10), Observation::Present(AddrFlags::default()), 9_000),
            FollowAction::Rebind { to: v4(10) }
        );
    }

    #[test]
    fn a_flapping_address_backs_off_instead_of_churning_the_registration() {
        // Given: an address that alternates between .10 and .11 every 2 s,
        // each time long enough to pass the settle time.
        let mut s = LinkFollow::default();
        let mut bound = v4(10);
        let mut rebind_times = Vec::new();
        let mut t = 0;
        while t < 40_000 {
            let other = if bound == v4(10) { v4(11) } else { v4(10) };
            if let FollowAction::Rebind { to } = s.step(bound, Observation::Moved(other), t) {
                rebind_times.push(t);
                bound = to;
            }
            t += 250;
        }
        // Then: the gaps between re-binds grow (2 s, 4 s, 8 s, 16 s ...)
        // rather than staying at the flap period.
        let gaps: Vec<u64> = rebind_times.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.len() >= 3, "expected several re-binds, got {gaps:?}");
        assert!(
            gaps.windows(2).all(|w| w[1] >= w[0]),
            "hold-down must not shrink while flapping: {gaps:?}"
        );
        assert!(gaps.last().unwrap() >= &8_000, "{gaps:?}");
        assert!(rebind_times.len() <= 6, "{rebind_times:?}");
    }

    #[test]
    fn the_hold_down_is_capped() {
        let mut s = LinkFollow::default();
        for i in 0..20 {
            s.note_rebind(v4(10), i * 100);
        }
        assert!(s.hold_until <= 1_900 + REBIND_HOLD_MAX_MS);
    }

    /// Re-bind times for a link whose address moves again as soon as it may,
    /// stepped every 250 ms for `until` ms.
    fn sustained_flap(until: u64) -> Vec<u64> {
        let mut s = LinkFollow::default();
        let mut bound = v4(10);
        let mut rebinds = Vec::new();
        let mut t = 0;
        while t < until {
            let other = if bound == v4(10) { v4(11) } else { v4(10) };
            if let FollowAction::Rebind { to } = s.step(bound, Observation::Moved(other), t) {
                rebinds.push(t);
                bound = to;
            }
            t += 250;
        }
        rebinds
    }

    #[test]
    fn sustained_flapping_stays_at_the_cap_instead_of_resetting() {
        // Given: an address that keeps moving for five minutes.
        let rebinds = sustained_flap(300_000);

        // Then: the hold-down grows to the cap and stays there; it never
        // drops back to the base while the flapping goes on.
        let gaps: Vec<u64> = rebinds.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(
            gaps.windows(2).all(|w| w[1] >= w[0]),
            "hold-down must not shrink while flapping: {gaps:?}"
        );
        let at_cap: Vec<u64> = gaps.iter().copied().skip(4).collect();
        assert!(!at_cap.is_empty());
        assert!(
            at_cap.iter().all(|gap| *gap >= REBIND_HOLD_MAX_MS),
            "{gaps:?}"
        );
        // 1.5, 3.5, 7.5, 15.5, 31.5 s, then every 30 s.
        assert!(rebinds.len() <= 14, "{rebinds:?}");
    }

    #[test]
    fn a_link_that_stays_put_for_the_flap_window_starts_again_from_the_base() {
        let mut s = LinkFollow::default();
        for i in 0..6 {
            s.note_rebind(v4(10), i * 1_000);
        }
        assert_eq!(s.hold_until, 5_000 + REBIND_HOLD_MAX_MS);
        // A minute without a move: the next move is held only briefly.
        s.note_rebind(v4(11), 5_000 + FLAP_WINDOW_MS);
        assert_eq!(s.hold_until, 5_000 + FLAP_WINDOW_MS + REBIND_HOLD_BASE_MS);
    }

    #[test]
    fn a_settling_link_asks_to_be_woken_when_its_settle_time_ends() {
        let mut s = LinkFollow::default();
        assert_eq!(s.wake_at(0), None, "nothing pending");
        let _ = s.step(v4(10), Observation::Moved(v4(11)), 1_000);
        assert_eq!(s.wake_at(1_000), Some(1_000 + ADDRESS_SETTLE_MS));
        let _ = s.step(v4(10), Observation::Gone, 1_200);
        assert_eq!(s.wake_at(1_200), Some(1_000 + ADDRESS_SETTLE_MS));
    }

    #[test]
    fn a_held_move_asks_to_be_woken_when_the_hold_down_ends() {
        // Given: a link that just re-bound, whose new address moves at once.
        let mut s = LinkFollow::default();
        s.note_rebind(v4(11), 0);
        s.note_rebind(v4(11), 10);
        let hold = s.hold_until;
        assert!(hold > ADDRESS_SETTLE_MS);
        let _ = s.step(v4(11), Observation::Moved(v4(12)), 20);

        // Then: it wakes at the settle time, and once that passed, at the
        // end of the hold-down, where the move happens.
        assert_eq!(s.wake_at(20), Some(20 + ADDRESS_SETTLE_MS));
        assert_eq!(
            s.step(v4(11), Observation::Moved(v4(12)), 20 + ADDRESS_SETTLE_MS),
            FollowAction::None
        );
        assert_eq!(s.wake_at(20 + ADDRESS_SETTLE_MS), Some(hold));
        assert_eq!(
            s.step(v4(11), Observation::Moved(v4(12)), hold),
            FollowAction::Rebind { to: v4(12) }
        );
    }

    #[test]
    fn a_link_marked_down_waits_for_a_table_change_not_a_timer() {
        let mut s = LinkFollow::default();
        let _ = s.step(v4(10), Observation::Gone, 0);
        let _ = s.step(v4(10), Observation::Gone, ADDRESS_SETTLE_MS);
        assert!(s.is_down());
        assert_eq!(s.wake_at(ADDRESS_SETTLE_MS), None);
    }

    #[test]
    fn a_failed_rebind_keeps_the_old_address_and_still_backs_off() {
        // Given: a move whose bind failed, so the link is still on .10.
        let mut s = LinkFollow::default();
        let moved = Observation::Moved(v4(11));
        let _ = s.step(v4(10), moved, 0);
        assert_eq!(
            s.step(v4(10), moved, ADDRESS_SETTLE_MS),
            FollowAction::Rebind { to: v4(11) }
        );
        s.rebind_failed(v4(10));
        assert!(s.is_down());

        // When: the next rounds still see .10 bound and .11 on offer.
        // Then: the state was not reset by `track`, so the next attempt waits
        // out a longer hold-down than the first.
        let first_hold = s.hold_until;
        let mut retry = None;
        for t in (ADDRESS_SETTLE_MS..60_000).step_by(250) {
            if let FollowAction::Rebind { .. } = s.step(v4(10), moved, t) {
                retry = Some(t);
                break;
            }
        }
        let retry = retry.expect("a later retry");
        assert_eq!(retry, first_hold, "retried once the hold-down ended");
        s.rebind_failed(v4(10));
        assert_eq!(s.hold_until - retry, 2 * REBIND_HOLD_BASE_MS, "doubled");
    }

    #[test]
    fn a_failed_rebind_is_retried_when_its_settle_time_ends_not_a_tick_later() {
        // Given: a move whose bind failed at the end of the settle time, and
        // the next housekeeping tick 900 ms later, so the retry's settle time
        // (from that tick) ends after the hold-down does.
        const TICK_MS: u64 = 1_000;
        let mut s = LinkFollow::default();
        let moved = Observation::Moved(v4(11));
        let _ = s.step(v4(10), moved, 0);
        let failed_at = ADDRESS_SETTLE_MS;
        assert_eq!(
            s.step(v4(10), moved, failed_at),
            FollowAction::Rebind { to: v4(11) }
        );
        s.rebind_failed(v4(10));
        let first_tick = failed_at + 900;
        assert_eq!(s.step(v4(10), moved, first_tick), FollowAction::None);
        assert!(
            s.hold_until < first_tick + ADDRESS_SETTLE_MS,
            "settle ends last"
        );

        // When: rounds run as the sender runs them, on every tick and on every
        // wake-up the link asks for, whichever comes first.
        let mut now = first_tick;
        let mut next_tick = first_tick + TICK_MS;
        let retry = loop {
            let wake = s.wake_at(now);
            now = wake.map_or(next_tick, |at| at.min(next_tick));
            if now == next_tick {
                next_tick += TICK_MS;
            }
            if let FollowAction::Rebind { .. } = s.step(v4(10), moved, now) {
                break now;
            }
            assert!(now < 60_000, "never retried");
        };

        // Then: the retry comes when its settle time ends, not on the tick
        // after.
        assert_eq!(retry, first_tick + ADDRESS_SETTLE_MS);
        assert!(retry < first_tick + 2 * TICK_MS);
    }

    #[test]
    fn twin_links_on_two_interfaces_may_share_one_address() {
        // Given: twin A on wwan0 bound to .100, twin B on wwan1 bound to .101;
        // A's interface is renumbered to .101 as well.
        let wwan0 = IfaceName::parse("wwan0").unwrap();
        let wwan1 = IfaceName::parse("wwan1").unwrap();
        let claimed = [
            Claim {
                iface: Some(wwan0.clone()),
                ip: v4(100),
            },
            Claim {
                iface: Some(wwan1.clone()),
                ip: v4(101),
            },
        ];
        let t = table(&[addr(WWAN0, v4(101)), addr(WWAN1, v4(101))]);

        // Then: B's claim is on another interface, so A follows to .101.
        let others = claimed_on(&claimed, &wwan0, v4(100));
        assert!(others.is_empty(), "{others:?}");
        assert_eq!(
            observe(v4(100), WWAN0, &t, &others, false),
            Observation::Moved(v4(101))
        );

        // And: on one interface, and for an unmapped link anywhere, a claim
        // still blocks the address.
        let same_iface = [Claim {
            iface: Some(wwan0.clone()),
            ip: v4(101),
        }];
        assert_eq!(&claimed_on(&same_iface, &wwan0, v4(100))[..], &[v4(101)]);
        let unmapped = [Claim {
            iface: None,
            ip: v4(101),
        }];
        assert_eq!(&claimed_on(&unmapped, &wwan0, v4(100))[..], &[v4(101)]);
    }

    #[test]
    fn a_link_reloaded_onto_another_address_starts_fresh() {
        let mut s = LinkFollow::default();
        let _ = s.step(v4(10), Observation::Gone, 0);
        let _ = s.step(v4(10), Observation::Gone, ADDRESS_SETTLE_MS);
        assert!(s.is_down());
        // A reload bound the same conn to .30: old debounce state is void.
        assert_eq!(
            s.step(v4(30), Observation::Present(AddrFlags::default()), 5_000),
            FollowAction::None
        );
        assert!(!s.is_down());
    }

    #[test]
    fn the_privacy_kind_is_remembered_from_the_last_sighting() {
        let mut s = LinkFollow::default();
        let addr = v6("2001:db8::ffff:1");
        let _ = s.step(addr, Observation::Present(temporary()), 0);
        assert!(s.was_temporary());
    }

    // ----- follow_addresses: applying a decision to the live pool -----

    // Linux only: the fixture renumbers a link across 127/8 on `lo`, which
    // other hosts neither name `lo` nor treat as wholly local.
    #[cfg(target_os = "linux")]
    mod live {
        use std::sync::Arc;
        use std::time::Duration;

        use socket2::{Domain, Protocol, Socket, Type};
        use srtla_protocol::{SRTLA_TYPE_REG2, get_packet_type};

        use super::super::*;
        use super::addr;
        use crate::bind_map::{IfaceName, LinkId};
        use crate::net::{
            BatchUdpSocket, EgressLifecycle, RouteHealth, SourceIpBinder, UplinkSpec,
        };
        use crate::sender::uplink::{ConnIo, create_uplink_channel, sync_readers};

        /// `lo` stands in for a modem interface: every 127/8 address is local,
        /// so a link can be "renumbered" onto 127.0.0.2 without privileges.
        const LO: u32 = 1;

        struct Lo;
        impl IfaceResolver for Lo {
            fn ifindex(&self, iface: &str) -> Option<u32> {
                (iface == "lo").then_some(LO)
            }
        }

        fn lo_ip(last: u8) -> IpAddr {
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, last))
        }

        fn mapped_link(
            conn_id: u64,
            ip: IpAddr,
            remote: std::net::SocketAddr,
        ) -> (SrtlaConnection, ConnIo) {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            socket
                .bind(&std::net::SocketAddr::new(ip, 0).into())
                .unwrap();
            socket.set_nonblocking(true).unwrap();
            let iface = IfaceName::parse("lo").unwrap();
            let mut egress = EgressLifecycle::for_iface(iface.clone());
            egress.resolve_for_bind(&SystemIfaceResolver).unwrap();
            let spec = UplinkSpec {
                ip,
                iface: Some(iface),
                link_id: Some(LinkId::parse(&format!("modem-{conn_id}")).unwrap()),
                weight: 1,
            };
            let label = spec.label("rec.test", remote.port());
            let mut conn = SrtlaConnection::new_registering(conn_id, label, ip, 0);
            conn.connected = true;
            let io = ConnIo {
                socket: Arc::new(BatchUdpSocket::new(socket, remote).unwrap()),
                binder: Arc::new(SourceIpBinder),
                remote,
                spec,
                egress,
                route_health: RouteHealth::Unknown,
                source_down: false,
            };
            (conn, io)
        }

        struct Pool {
            receiver: std::net::UdpSocket,
            connections: Vec<SrtlaConnection>,
            conn_io: ConnIoMap,
            reg: SrtlaRegistrationManager,
            seq: SequenceTracker,
            readers: HashMap<ConnectionId, ReaderHandle>,
            tx: UnboundedSender<UplinkPacket>,
            _rx: tokio::sync::mpsc::UnboundedReceiver<UplinkPacket>,
        }

        impl Pool {
            /// Two mapped links on `lo`, bound to 127.0.0.1 and 127.0.0.3.
            fn new() -> Self {
                let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                receiver
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let remote = receiver.local_addr().unwrap();
                let (a, a_io) = mapped_link(1, lo_ip(1), remote);
                let (b, b_io) = mapped_link(2, lo_ip(3), remote);
                let mut conn_io = ConnIoMap::new();
                conn_io.insert(1, a_io);
                conn_io.insert(2, b_io);
                let connections = vec![a, b];
                let (tx, rx) = create_uplink_channel();
                let mut readers = HashMap::new();
                sync_readers(&connections, &conn_io, &mut readers, &tx);
                Self {
                    receiver,
                    connections,
                    conn_io,
                    reg: SrtlaRegistrationManager::new(),
                    seq: SequenceTracker::new(),
                    readers,
                    tx,
                    _rx: rx,
                }
            }

            async fn follow(&mut self, follower: &mut AddressFollower, now: u64) {
                self.follow_via(follower, &Lo, now).await;
            }

            async fn follow_via(
                &mut self,
                follower: &mut AddressFollower,
                resolver: &dyn IfaceResolver,
                now: u64,
            ) {
                follow_addresses_with(
                    follower,
                    resolver,
                    &mut self.connections,
                    &mut self.conn_io,
                    &mut self.reg,
                    &mut self.seq,
                    &mut self.readers,
                    &self.tx,
                    "rec.test",
                    now,
                )
                .await;
            }
        }

        fn follower_with(addrs: &[IpAddr]) -> AddressFollower {
            let mut follower = AddressFollower::new();
            let table = AddrTable::new(addrs.iter().map(|ip| addr(LO, *ip)).collect());
            follower.set_table(Arc::new(table));
            follower
        }

        #[tokio::test]
        async fn a_renumbered_link_rebinds_alone_and_rejoins_the_group_with_reg2() {
            // Given: two mapped links on one interface; link 1's 127.0.0.1 is
            // replaced by 127.0.0.2 while link 2 keeps 127.0.0.3.
            let mut pool = Pool::new();
            let untouched = Arc::clone(&pool.conn_io[&2].socket);
            let group_id = pool.reg.srtla_id;
            let mut follower = follower_with(&[lo_ip(2), lo_ip(3)]);

            // When: the follower runs before and after the settle time.
            pool.follow(&mut follower, 10_000).await;
            assert_eq!(pool.connections[0].local_ip, lo_ip(1), "settle first");
            pool.follow(&mut follower, 10_000 + ADDRESS_SETTLE_MS).await;

            // Then: link 1 now sends from the new address under its old
            // identity, and its first frame is a REG2 carrying the group id.
            let io = &pool.conn_io[&1];
            assert_eq!(pool.connections[0].local_ip, lo_ip(2));
            assert_eq!(io.spec.ip, lo_ip(2));
            assert_eq!(io.spec.link_id.as_ref().unwrap().as_str(), "modem-1");
            assert!(pool.connections[0].label.contains("127.0.0.2"));
            assert!(!io.source_down);
            let mut buf = [0u8; 2048];
            let (n, from) = pool.receiver.recv_from(&mut buf).expect("REG2 on the wire");
            assert_eq!(from.ip(), lo_ip(2));
            assert_eq!(get_packet_type(&buf[..n]), Some(SRTLA_TYPE_REG2));
            assert_eq!(&buf[2..2 + group_id.len()], &group_id[..]);

            // And: the other link's socket and state were not touched.
            assert!(Arc::ptr_eq(&untouched, &pool.conn_io[&2].socket));
            assert!(pool.connections[1].connected);
            assert_eq!(pool.connections[1].local_ip, lo_ip(3));
        }

        /// The sender's loop, reduced to the follower: wait for the follower's
        /// own timer, run a round at that (virtual) time, re-arm. Returns the
        /// time the timer fired.
        async fn wait_and_follow(
            pool: &mut Pool,
            follower: &mut AddressFollower,
            wake: &mut FollowWake,
            clock: &impl Fn() -> u64,
        ) -> u64 {
            wake.fired().await;
            let now = clock();
            pool.follow(follower, now).await;
            wake.rearm(follower, now);
            now
        }

        #[tokio::test(start_paused = true)]
        async fn the_follow_timer_wakes_the_follower_when_its_deadlines_end() {
            // Given: virtual time, and link 1's 127.0.0.1 replaced by
            // 127.0.0.2 in the table the follower just saw.
            let start = tokio::time::Instant::now();
            let t0 = 10_000;
            let clock = || t0 + u64::try_from(start.elapsed().as_millis()).unwrap();
            let mut pool = Pool::new();
            let mut follower = follower_with(&[lo_ip(2), lo_ip(3)]);
            let mut wake = FollowWake::new();
            assert!(!wake.is_armed(), "nothing to wait for before a round");
            pool.follow(&mut follower, t0).await;
            wake.rearm(&follower, t0);

            // Then: the timer stays quiet until the settle time ends...
            assert!(wake.is_armed());
            let early = Duration::from_millis(ADDRESS_SETTLE_MS - 1);
            assert!(
                tokio::time::timeout(early, wake.fired()).await.is_err(),
                "fired before the settle time ended"
            );
            assert_eq!(pool.connections[0].local_ip, lo_ip(1));

            // ...and then fires within the slack, once: until it is re-armed
            // it stays quiet, so the loop cannot spin on it.
            let slack = Duration::from_millis(FOLLOW_WAKE_SLACK_MS + 1);
            tokio::time::timeout(slack, wake.fired())
                .await
                .expect("fires right after the settle time");
            let fired = clock();
            assert_eq!(fired, t0 + ADDRESS_SETTLE_MS + FOLLOW_WAKE_SLACK_MS);
            assert!(!wake.is_armed(), "a fired timer waits for the next re-arm");

            // And: the round it wakes re-binds the link.
            pool.follow(&mut follower, fired).await;
            wake.rearm(&follower, fired);
            assert_eq!(pool.connections[0].local_ip, lo_ip(2));

            // And: with nothing pending the timer is off; it does not fire
            // again on its old deadline.
            assert!(!wake.is_armed());
            let brief = Duration::from_millis(100);
            assert!(tokio::time::timeout(brief, wake.fired()).await.is_err());

            // When: the address moves again right after that re-bind, so the
            // new settle time ends before the hold-down does.
            let moved_at = clock();
            follower.set_table(Arc::new(AddrTable::new(vec![
                addr(LO, lo_ip(3)),
                addr(LO, lo_ip(4)),
            ])));
            pool.follow(&mut follower, moved_at).await;
            wake.rearm(&follower, moved_at);
            let hold_until = fired + REBIND_HOLD_BASE_MS;
            assert!(moved_at + ADDRESS_SETTLE_MS < hold_until);

            // Then: the timer wakes at the end of the settle time, where the
            // hold-down still holds the link...
            let settled = wait_and_follow(&mut pool, &mut follower, &mut wake, &clock).await;
            assert_eq!(settled, moved_at + ADDRESS_SETTLE_MS + FOLLOW_WAKE_SLACK_MS);
            assert_eq!(pool.connections[0].local_ip, lo_ip(2), "held");

            // ...and again at the end of the hold-down, which re-binds, with
            // no housekeeping tick involved.
            let released = wait_and_follow(&mut pool, &mut follower, &mut wake, &clock).await;
            assert_eq!(released, hold_until + FOLLOW_WAKE_SLACK_MS);
            assert_eq!(pool.connections[0].local_ip, lo_ip(4));
            assert!(!wake.is_armed());
            let hour = Duration::from_secs(3_600);
            assert!(tokio::time::timeout(hour, wake.fired()).await.is_err());
        }

        #[tokio::test]
        async fn a_vanished_address_takes_the_link_down_and_a_new_one_brings_it_back() {
            // Given: link 1's address leaves `lo` and nothing replaces it
            // (the only other address belongs to link 2).
            let mut pool = Pool::new();
            let mut follower = follower_with(&[lo_ip(3)]);

            pool.follow(&mut follower, 0).await;
            pool.follow(&mut follower, ADDRESS_SETTLE_MS).await;

            // Then: the link is out of service and will not be reconnected.
            assert!(pool.conn_io[&1].source_down);
            assert!(pool.connections[0].is_timed_out(ADDRESS_SETTLE_MS));
            assert!(!pool.conn_io[&2].source_down);
            let parked = Arc::clone(&pool.conn_io[&1].socket);
            for t in 2..10 {
                pool.follow(&mut follower, ADDRESS_SETTLE_MS + t * 1_000)
                    .await;
            }
            assert!(
                Arc::ptr_eq(&parked, &pool.conn_io[&1].socket),
                "a down link must not keep re-creating its socket"
            );

            // When: the carrier hands the interface a new address.
            follower.set_table(Arc::new(AddrTable::new(vec![
                addr(LO, lo_ip(3)),
                addr(LO, lo_ip(4)),
            ])));
            pool.follow(&mut follower, 20_000).await;

            // Then: the link comes back on it.
            assert!(!pool.conn_io[&1].source_down);
            assert_eq!(pool.connections[0].local_ip, lo_ip(4));
        }

        /// One housekeeping round as far as the egress lifecycle is concerned:
        /// housekeeping re-resolves a link's interface only while the follower
        /// is not holding it (`source_down`), and that re-resolve is the only
        /// way out of `Removed` short of a reload.
        fn egress_tick(pool: &mut Pool) {
            for io in pool.conn_io.values_mut() {
                if !io.source_down {
                    let _ = io.egress.poll(&Lo);
                }
            }
        }

        #[tokio::test]
        async fn a_link_whose_interface_vanishes_while_settling_is_not_parked_for_good() {
            // Given: link 1's address has just gone missing, so the follower
            // holds it in the settle window.
            let mut pool = Pool::new();
            let mut follower = follower_with(&[lo_ip(3)]);
            pool.follow(&mut follower, 0).await;
            assert!(pool.conn_io[&1].source_down, "settling");

            // When: a send fails with ENODEV (the modem re-enumerated), and
            // then the interface and the address come back.
            let enodev = std::io::Error::from_raw_os_error(libc::ENODEV);
            let _ = pool
                .conn_io
                .get_mut(&1)
                .unwrap()
                .egress
                .note_send_error(&enodev);
            assert!(pool.conn_io[&1].egress.is_removed());
            follower.set_table(Arc::new(AddrTable::new(vec![
                addr(LO, lo_ip(1)),
                addr(LO, lo_ip(3)),
            ])));
            for round in 1..30 {
                pool.follow(&mut follower, round * 1_000).await;
                egress_tick(&mut pool);
            }

            // Then: the link went back to the egress lifecycle, which brought
            // it back to active, instead of both sides waiting on each other.
            assert!(!pool.conn_io[&1].source_down);
            assert!(!pool.conn_io[&1].egress.is_removed());
        }

        /// An interface name that no longer resolves (the device vanished).
        struct NoIface;
        impl IfaceResolver for NoIface {
            fn ifindex(&self, _iface: &str) -> Option<u32> {
                None
            }
        }

        #[tokio::test]
        async fn a_link_whose_interface_stops_resolving_is_handed_back() {
            // Given: link 1 is held in the settle window.
            let mut pool = Pool::new();
            let mut follower = follower_with(&[lo_ip(3)]);
            pool.follow(&mut follower, 0).await;
            assert!(pool.conn_io[&1].source_down);

            // When: its interface name stops resolving before the egress
            // lifecycle has noticed.
            pool.follow_via(&mut follower, &NoIface, 500).await;

            // Then: the follower lets go, so housekeeping's egress check runs
            // for it again.
            assert!(!pool.conn_io[&1].source_down);
            assert!(follower.link(1).is_none());
        }

        #[tokio::test]
        async fn a_stopped_watcher_lets_go_of_every_link() {
            // Given: link 1 is marked down on the last table the watcher sent.
            let mut pool = Pool::new();
            let mut follower = follower_with(&[lo_ip(3)]);
            pool.follow(&mut follower, 0).await;
            pool.follow(&mut follower, ADDRESS_SETTLE_MS).await;
            assert!(pool.conn_io[&1].source_down);

            // When: the watcher ends, so that table can never be refreshed.
            follower.clear_table();
            pool.follow(&mut follower, ADDRESS_SETTLE_MS + 100).await;

            // Then: nothing holds the link any more, and no wake-up is pending.
            assert!(!pool.conn_io[&1].source_down);
            assert!(follower.link(1).is_none());
            assert_eq!(follower.next_wake(ADDRESS_SETTLE_MS + 100), None);
        }

        /// A binder that refuses every bind, so a rebuild fails after the
        /// interface resolved.
        struct RefuseBind;
        impl crate::net::UplinkBinder for RefuseBind {
            fn bind(&self, _sock: &Socket, ip: IpAddr) -> anyhow::Result<()> {
                anyhow::bail!("refused bind to {ip}")
            }
        }

        #[tokio::test]
        async fn a_failed_rebind_leaves_the_link_describing_the_socket_it_still_has() {
            // Given: link 1's address is replaced, but binding the new one fails.
            let mut pool = Pool::new();
            pool.conn_io.get_mut(&1).unwrap().binder = Arc::new(RefuseBind);
            let old_label = pool.connections[0].label.clone();
            let old_socket = Arc::clone(&pool.conn_io[&1].socket);
            let mut follower = follower_with(&[lo_ip(2), lo_ip(3)]);

            pool.follow(&mut follower, 0).await;
            pool.follow(&mut follower, ADDRESS_SETTLE_MS).await;

            // Then: the link still reports the address its socket is bound to.
            let io = &pool.conn_io[&1];
            assert!(Arc::ptr_eq(&old_socket, &io.socket));
            assert_eq!(pool.connections[0].local_ip, lo_ip(1));
            assert_eq!(io.spec.ip, lo_ip(1));
            assert_eq!(pool.connections[0].label, old_label);
            assert!(io.source_down);

            // And: the follower keeps its back-off for that address instead
            // of starting over as if a reload had moved the link.
            pool.follow(&mut follower, ADDRESS_SETTLE_MS + 250).await;
            assert!(follower.link(1).unwrap().is_down());
            assert!(pool.conn_io[&1].source_down);
        }

        #[tokio::test]
        async fn an_unmapped_link_is_never_moved() {
            // A link without a bind-map row has no interface identity: its
            // source IP is the link, so a different address is a different link.
            let mut pool = Pool::new();
            let remote = pool.conn_io[&1].remote;
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            socket
                .bind(
                    &"127.0.0.1:0"
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                        .into(),
                )
                .unwrap();
            pool.conn_io.insert(
                1,
                ConnIo::unmapped(
                    Arc::new(BatchUdpSocket::new(socket, remote).unwrap()),
                    Arc::new(SourceIpBinder),
                    remote,
                    lo_ip(1),
                ),
            );
            let mut follower = follower_with(&[lo_ip(2), lo_ip(3)]);
            pool.follow(&mut follower, 0).await;
            pool.follow(&mut follower, 10 * ADDRESS_SETTLE_MS).await;
            assert_eq!(pool.connections[0].local_ip, lo_ip(1));
            assert!(!pool.conn_io[&1].source_down);
        }
    }
}
