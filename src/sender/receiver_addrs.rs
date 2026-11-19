//! Per-link receiver address failover for a hostname that answers with more
//! than one address.
//!
//! # The problem
//!
//! Every uplink resolves the receiver hostname when it is first dialed and,
//! before this module, stayed on that answer for the life of the process. A name
//! with two A records where one is stale (a moved server, a leftover record)
//! could put one uplink on the dead address for the whole session: it never
//! registers, carries nothing, and the bond silently runs on fewer links than it
//! has. Nobody notices until the links that did land on the live address go
//! down, and then the outage is total although a working path is right there.
//! The whole-bond re-home in [`super::rehome`] does not help: it only fires
//! once *every* address the bond is on has left DNS, and a stale record that
//! stays published never leaves.
//!
//! # The policy
//!
//! The address book keeps the hostname's current answers fresh (a lookup every
//! [`REFRESH_INTERVAL_MS`], sooner after a link runs out of addresses to try)
//! without ever blocking the housekeeping tick on DNS. Each time a failing link
//! is about to rebuild its socket (the existing timed-out reconnect path), it
//! picks the address to rebuild against, within its own address family:
//!
//! 1. If other uplinks are registered (REG3) on an address, that is where the
//!    bond lives. A link not already there moves to it straight away, whether
//!    or not DNS still lists it. Registration binds the bond to one receiver
//!    instance, so this is also what keeps two receiver instances behind one
//!    name from splitting the bond.
//! 2. Otherwise (no uplink is registered in this family), the link gives its
//!    current address [`ADDRESS_TRIAL_MS`] to answer and then tries the next
//!    answer in the order DNS gave them, wrapping around. An address that has
//!    left DNS is replaced by the first current answer.
//!
//! A registered link is never touched, and nothing here sends anything: a moved
//! link goes through the same socket rebuild and REG1/REG2 resend it would have
//! made against its old address. A receiver given as an IP literal is left
//! exactly as before, as is everything under `--no-rehome`.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use smallvec::SmallVec;
use srtla_core::connection::SrtlaConnection;
use tokio::sync::oneshot;
use tracing::{debug, info};

use super::rehome::{ReceiverResolver, ResolvedAddrs};
use super::uplink::ConnIoMap;
use crate::net::same_family;

/// How long a link may sit on an address without registering before it tries
/// the next one, when no other uplink has proven an address in its family.
/// Long enough for a REG2/REG3 round trip over a slow cellular link, short
/// enough that a two-address name settles well inside the all-links-failed
/// window.
pub const ADDRESS_TRIAL_MS: u64 = 5_000;

/// Routine re-resolution interval. A fixed interval rather than the record TTL:
/// `getaddrinfo` does not report one, and the system resolver cache honours it
/// for us anyway.
pub const REFRESH_INTERVAL_MS: u64 = 30_000;

/// Floor between lookups asked for because a link ran out of addresses to try.
pub const URGENT_REFRESH_MIN_MS: u64 = 5_000;

/// Where a failing link should rebuild its socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteChoice {
    /// Keep the current address.
    Stay,
    /// Move to an address other uplinks are registered on.
    Proven(SocketAddr),
    /// The current address had its chance; try this answer next.
    Next(SocketAddr),
}

/// Pure address choice for one failing link. `proven` lists the addresses other
/// uplinks are registered on, most-used first; `answers` is the latest DNS
/// answer in resolver order.
pub(super) fn choose_remote(
    current: SocketAddr,
    since_ms: u64,
    source: IpAddr,
    proven: &[SocketAddr],
    answers: &[SocketAddr],
    now: u64,
) -> RemoteChoice {
    let mut proven_here = proven.iter().copied().filter(|a| same_family(*a, source));
    if proven.contains(&current) {
        return RemoteChoice::Stay;
    }
    if let Some(best) = proven_here.next() {
        return RemoteChoice::Proven(best);
    }

    if now.saturating_sub(since_ms) < ADDRESS_TRIAL_MS {
        return RemoteChoice::Stay;
    }
    let candidates: SmallVec<SocketAddr, 4> = answers
        .iter()
        .copied()
        .filter(|a| same_family(*a, source))
        .collect();
    let next = match candidates.iter().position(|a| *a == current) {
        Some(i) => candidates[(i + 1) % candidates.len()],
        None => match candidates.first() {
            Some(first) => *first,
            None => return RemoteChoice::Stay,
        },
    };
    if next == current {
        RemoteChoice::Stay
    } else {
        RemoteChoice::Next(next)
    }
}

/// Every uplink that is registered and not timed out, with its address.
pub(super) fn registered_remotes(
    connections: &[SrtlaConnection],
    conn_io: &ConnIoMap,
    now: u64,
) -> SmallVec<(u64, SocketAddr), 4> {
    connections
        .iter()
        .filter(|c| c.connected && !c.is_timed_out(now))
        .filter_map(|c| conn_io.get(&c.conn_id).map(|io| (c.conn_id, io.remote)))
        .collect()
}

/// Addresses that uplinks other than `conn_id` are registered on, most-used
/// first (ties keep connection order). A link never counts as proof for
/// itself.
pub(super) fn proven_for(
    registered: &[(u64, SocketAddr)],
    conn_id: u64,
) -> SmallVec<SocketAddr, 4> {
    let mut counts: SmallVec<(SocketAddr, usize), 4> = SmallVec::new();
    for (_, remote) in registered.iter().filter(|(id, _)| *id != conn_id) {
        match counts.iter_mut().find(|(a, _)| a == remote) {
            Some((_, n)) => *n += 1,
            None => counts.push((*remote, 1)),
        }
    }
    // Stable sort: equal counts keep first-seen order.
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    counts.into_iter().map(|(a, _)| a).collect()
}

type Lookup = oneshot::Receiver<Option<ResolvedAddrs>>;

/// The receiver hostname's latest answers, refreshed off the housekeeping tick.
pub struct ReceiverAddresses {
    enabled: bool,
    resolver: Arc<dyn ReceiverResolver>,
    answers: ResolvedAddrs,
    last_lookup_ms: Option<u64>,
    refresh_wanted: bool,
    pending: Option<Lookup>,
    moves: u64,
}

impl ReceiverAddresses {
    pub fn new(enabled: bool, resolver: Arc<dyn ReceiverResolver>) -> Self {
        Self {
            enabled,
            resolver,
            answers: SmallVec::new(),
            last_lookup_ms: None,
            refresh_wanted: false,
            pending: None,
            moves: 0,
        }
    }

    /// Whether failover applies to `host` at all: never for an IP literal, and
    /// never under `--no-rehome`.
    pub fn applies_to(&self, host: &str) -> bool {
        self.enabled && host.parse::<IpAddr>().is_err()
    }

    /// Once per housekeeping tick: collect a finished lookup and start the next
    /// one when it is due. Never waits on DNS.
    pub fn poll(&mut self, host: &str, port: u16, now: u64) {
        if !self.applies_to(host) {
            return;
        }
        if let Some(rx) = self.pending.as_mut() {
            match rx.try_recv() {
                Ok(answer) => {
                    self.pending = None;
                    if let Some(fresh) = answer {
                        if fresh != self.answers {
                            info!(
                                "receiver {host} resolves to {}",
                                fresh
                                    .iter()
                                    .map(|a| a.to_string())
                                    .collect::<SmallVec<String, 4>>()
                                    .join(", ")
                            );
                        }
                        self.answers = fresh;
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => return,
                Err(oneshot::error::TryRecvError::Closed) => self.pending = None,
            }
        }
        let due = match self.last_lookup_ms {
            None => true,
            Some(last) => {
                let age = now.saturating_sub(last);
                age >= REFRESH_INTERVAL_MS || (self.refresh_wanted && age >= URGENT_REFRESH_MIN_MS)
            }
        };
        if !due {
            return;
        }
        self.last_lookup_ms = Some(now);
        self.refresh_wanted = false;
        let (tx, rx) = oneshot::channel();
        let lookup: Pin<Box<dyn Future<Output = Option<ResolvedAddrs>> + Send>> =
            self.resolver.resolve(host.to_string(), port);
        tokio::spawn(async move {
            let _ = tx.send(lookup.await);
        });
        self.pending = Some(rx);
    }

    /// The latest successful answer (empty until the first lookup lands).
    pub fn answers(&self) -> &[SocketAddr] {
        &self.answers
    }

    /// Pick the address a failing link rebuilds against. Returns the new
    /// address when the link should move, `None` to stay.
    pub(super) fn choose_for(
        &mut self,
        label: &str,
        current: SocketAddr,
        since_ms: u64,
        source: IpAddr,
        proven: &[SocketAddr],
        now: u64,
    ) -> Option<SocketAddr> {
        let choice = choose_remote(current, since_ms, source, proven, &self.answers, now);
        let trial_over = now.saturating_sub(since_ms) >= ADDRESS_TRIAL_MS;
        match choice {
            RemoteChoice::Stay => {
                if trial_over && !proven.iter().any(|a| same_family(*a, source)) {
                    // Nothing else to try (or nothing resolved yet): ask DNS
                    // again sooner than the routine refresh.
                    self.refresh_wanted = true;
                }
                debug!("{label}: staying on receiver address {current}");
                None
            }
            RemoteChoice::Proven(addr) => {
                self.moves = self.moves.saturating_add(1);
                info!(
                    "{label}: not registered on receiver address {current}; moving to {addr}, \
                     where other uplinks are registered"
                );
                Some(addr)
            }
            RemoteChoice::Next(addr) => {
                self.moves = self.moves.saturating_add(1);
                self.refresh_wanted = true;
                info!(
                    "{label}: no registration from receiver address {current} in {}ms; trying \
                     {addr}",
                    now.saturating_sub(since_ms)
                );
                Some(addr)
            }
        }
    }

    /// Links moved to another address so far. Log-only, like the re-home count.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn move_count(&self) -> u64 {
        self.moves
    }

    #[cfg(any(test, feature = "test-internals"))]
    pub fn lookup_pending(&self) -> bool {
        self.pending.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::sender::rehome::StubResolver;

    fn a(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 5000)
    }
    fn v6(last: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)),
            5000,
        )
    }
    const SRC4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    fn src6() -> IpAddr {
        "2001:db8:1::2".parse().unwrap()
    }

    const T: u64 = 100_000;

    #[test]
    fn a_link_on_an_address_others_proved_stays() {
        assert_eq!(
            choose_remote(a(1), 0, SRC4, &[a(1)], &[a(1), a(2)], T),
            RemoteChoice::Stay
        );
    }

    #[test]
    fn a_link_moves_to_the_proven_address_at_once() {
        // Even inside its trial window, and even if DNS no longer lists it.
        assert_eq!(
            choose_remote(a(2), T, SRC4, &[a(1)], &[a(2)], T),
            RemoteChoice::Proven(a(1))
        );
        // Most-used proven address first.
        assert_eq!(
            choose_remote(a(3), 0, SRC4, &[a(1), a(2)], &[a(1), a(2), a(3)], T),
            RemoteChoice::Proven(a(1))
        );
    }

    #[test]
    fn a_proven_address_in_the_other_family_does_not_count() {
        // The v4 bond proves nothing an IPv6 link can dial.
        assert_eq!(
            choose_remote(v6(1), 0, src6(), &[a(1)], &[a(1), v6(1), v6(2)], T),
            RemoteChoice::Next(v6(2))
        );
        // And the v4 link does not jump to an IPv6 address someone proved.
        assert_eq!(
            choose_remote(a(2), T, SRC4, &[v6(1)], &[v6(1), a(2)], T),
            RemoteChoice::Stay
        );
    }

    #[test]
    fn without_proof_the_current_address_gets_its_trial_window() {
        let since = T - ADDRESS_TRIAL_MS + 1;
        assert_eq!(
            choose_remote(a(1), since, SRC4, &[], &[a(1), a(2)], T),
            RemoteChoice::Stay
        );
        assert_eq!(
            choose_remote(a(1), since - 1, SRC4, &[], &[a(1), a(2)], T),
            RemoteChoice::Next(a(2))
        );
    }

    #[test]
    fn rotation_follows_dns_order_and_wraps() {
        let answers = [a(1), a(2), a(3)];
        assert_eq!(
            choose_remote(a(1), 0, SRC4, &[], &answers, T),
            RemoteChoice::Next(a(2))
        );
        assert_eq!(
            choose_remote(a(3), 0, SRC4, &[], &answers, T),
            RemoteChoice::Next(a(1))
        );
        // An address that left DNS is replaced by the first current answer.
        assert_eq!(
            choose_remote(a(9), 0, SRC4, &[], &answers, T),
            RemoteChoice::Next(a(1))
        );
    }

    #[test]
    fn rotation_stays_within_the_link_family() {
        let answers = [v6(1), a(1), v6(2), a(2)];
        assert_eq!(
            choose_remote(a(1), 0, SRC4, &[], &answers, T),
            RemoteChoice::Next(a(2))
        );
        assert_eq!(
            choose_remote(v6(2), 0, src6(), &[], &answers, T),
            RemoteChoice::Next(v6(1))
        );
        let mapped: IpAddr = "::ffff:10.0.0.2".parse().unwrap();
        assert_eq!(
            choose_remote(a(2), 0, mapped, &[], &answers, T),
            RemoteChoice::Next(a(1))
        );
    }

    #[test]
    fn nothing_to_rotate_to_means_stay() {
        assert_eq!(
            choose_remote(a(1), 0, SRC4, &[], &[a(1)], T),
            RemoteChoice::Stay
        );
        assert_eq!(
            choose_remote(a(1), 0, SRC4, &[], &[], T),
            RemoteChoice::Stay
        );
        assert_eq!(
            choose_remote(a(1), 0, SRC4, &[], &[v6(1)], T),
            RemoteChoice::Stay
        );
    }

    #[tokio::test]
    async fn ip_literals_and_the_opt_out_never_resolve() {
        let resolver = StubResolver::new(vec![Some(vec![a(1)])]);
        let mut book = ReceiverAddresses::new(true, resolver.clone());
        book.poll("203.0.113.1", 5000, T);
        book.poll("2001:db8::1", 5000, T);
        assert_eq!(resolver.calls(), 0);
        assert!(!book.applies_to("203.0.113.1"));

        let mut off = ReceiverAddresses::new(false, resolver.clone());
        off.poll("rec.example.com", 5000, T);
        assert_eq!(resolver.calls(), 0);
        assert!(!off.applies_to("rec.example.com"));
    }

    async fn settle(book: &mut ReceiverAddresses, now: u64) {
        for _ in 0..100 {
            if !book.lookup_pending() {
                return;
            }
            tokio::task::yield_now().await;
            book.poll("rec.example.com", 5000, now);
        }
        panic!("lookup never finished");
    }

    #[tokio::test]
    async fn lookups_are_paced_and_a_failed_lookup_keeps_the_last_answer() {
        let resolver = StubResolver::new(vec![Some(vec![a(1), a(2)]), None, Some(vec![a(3)])]);
        let mut book = ReceiverAddresses::new(true, resolver.clone());

        book.poll("rec.example.com", 5000, T);
        settle(&mut book, T).await;
        assert_eq!(book.answers(), &[a(1), a(2)]);
        assert_eq!(resolver.calls(), 1);

        book.poll("rec.example.com", 5000, T + REFRESH_INTERVAL_MS - 1);
        assert_eq!(resolver.calls(), 1, "no lookup before the refresh interval");

        let t1 = T + REFRESH_INTERVAL_MS;
        book.poll("rec.example.com", 5000, t1);
        settle(&mut book, t1).await;
        assert_eq!(resolver.calls(), 2);
        assert_eq!(
            book.answers(),
            &[a(1), a(2)],
            "a failed lookup tells us nothing and keeps the last answer"
        );

        // A link that ran out of addresses asks for an early refresh, which is
        // still floored.
        let _ = book.choose_for("l", a(2), 0, SRC4, &[], t1);
        book.poll("rec.example.com", 5000, t1 + URGENT_REFRESH_MIN_MS - 1);
        assert_eq!(resolver.calls(), 2);
        book.poll("rec.example.com", 5000, t1 + URGENT_REFRESH_MIN_MS);
        settle(&mut book, t1 + URGENT_REFRESH_MIN_MS).await;
        assert_eq!(resolver.calls(), 3);
        assert_eq!(book.answers(), &[a(3)]);
    }

    #[tokio::test]
    async fn proof_ranks_by_registered_links_and_never_counts_the_link_itself() {
        let mut connections = srtla_core::test_helpers::create_test_connections(4).await;
        let mut conn_io = crate::test_helpers::create_test_conn_io_map(&connections);
        let now = srtla_core::utils::now_ms();
        let remotes = [a(2), a(1), a(1), a(3)];
        for (conn, remote) in connections.iter_mut().zip(remotes) {
            conn.connected = true;
            conn.last_received = Some(now);
            conn_io.get_mut(&conn.conn_id).unwrap().remote = remote;
        }
        // The fourth link is registered but has gone silent: no proof.
        connections[3].last_received = Some(now - 60_000);
        let registered = registered_remotes(&connections, &conn_io, now);
        assert_eq!(registered.len(), 3);

        let outsider = 0;
        assert_eq!(proven_for(&registered, outsider).as_slice(), &[a(1), a(2)]);
        // Link 0 is the only one on a(2); its own registration is not proof.
        assert_eq!(
            proven_for(&registered, connections[0].conn_id).as_slice(),
            &[a(1)]
        );

        connections[1].connected = false;
        connections[2].connected = false;
        let registered = registered_remotes(&connections, &conn_io, now);
        assert_eq!(proven_for(&registered, outsider).as_slice(), &[a(2)]);
    }
}
