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
use crate::net::{AddrFlags, AddrTable, IfaceResolver, LocalAddr, SystemIfaceResolver};

/// How long a bound address must stay missing before the link acts on it.
///
/// Absorbs a delete-then-add renumbering, a brief DAD window and an address that
/// blinks out and back, so a flap shorter than this never touches the socket.
pub const ADDRESS_SETTLE_MS: u64 = 1_500;

/// Hold-down after a re-bind before the same link may re-bind again. Doubles for
/// every further re-bind inside [`FLAP_WINDOW_MS`], up to
/// [`REBIND_HOLD_MAX_MS`], so an address that keeps changing cannot make the
/// link churn its registration.
pub const REBIND_HOLD_BASE_MS: u64 = 2_000;
pub const REBIND_HOLD_MAX_MS: u64 = 30_000;
pub const FLAP_WINDOW_MS: u64 = 60_000;

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
/// `claimed` lists the addresses other links are bound to (or are about to be),
/// so two links on one interface never pick the same replacement.
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
    recent_rebinds: SmallVec<u64, 4>,
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
        self.recent_rebinds
            .retain(|at| now.saturating_sub(*at) < FLAP_WINDOW_MS);
        self.recent_rebinds.push(now);
        let doublings = (self.recent_rebinds.len() - 1).min(16) as u32;
        let hold = REBIND_HOLD_BASE_MS
            .saturating_mul(1 << doublings)
            .min(REBIND_HOLD_MAX_MS);
        self.hold_until = now + hold;
        self.bound = Some(to);
        self.missing_since = None;
        self.down = false;
    }

    /// The re-bind the caller attempted failed: the link stays down until the
    /// next observation says otherwise.
    fn rebind_failed(&mut self) {
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

    #[must_use]
    pub fn link(&self, conn_id: ConnectionId) -> Option<&LinkFollow> {
        self.links.get(&conn_id)
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
        return;
    };

    // Every address a link is bound to. A re-bind below adds its new address,
    // so two links renumbered in the same round never pick the same one.
    let mut claimed: SmallVec<IpAddr, 8> = connections.iter().map(|c| c.local_ip).collect();

    for (idx, conn) in connections.iter_mut().enumerate() {
        let Some(io) = conn_io.get_mut(&conn.conn_id) else {
            continue;
        };
        // Only a mapped link has an interface to follow, and a link whose
        // interface is gone belongs to the egress lifecycle, not to us.
        let Some(iface) = io.egress.iface().cloned() else {
            continue;
        };
        if io.egress.is_removed() {
            follower.links.remove(&conn.conn_id);
            continue;
        }
        let Some(ifindex) = resolver.ifindex(iface.as_str()) else {
            continue;
        };

        let bound = conn.local_ip;
        let state = follower.links.entry(conn.conn_id).or_default();
        let others: SmallVec<IpAddr, 8> =
            claimed.iter().copied().filter(|ip| *ip != bound).collect();
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
                        claimed.retain(|ip| *ip != bound);
                        claimed.push(to);
                    }
                    Err(e) => {
                        warn!(
                            "{}: could not re-bind to {to} on {}: {e}; link is down until the \
                             address settles",
                            conn.label,
                            iface.as_str()
                        );
                        recover_connection(conn, seq_tracker);
                        io.source_down = true;
                        state.rebind_failed();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const WWAN0: u32 = 4;
    const WWAN1: u32 = 5;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 64, 0, last))
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
                follow_addresses_with(
                    follower,
                    &Lo,
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
