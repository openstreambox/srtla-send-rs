//! The host's local addresses, as the kernel reports them, and a watcher that
//! publishes a fresh table whenever they change.
//!
//! A cellular modem can be handed a new source address under an unchanged
//! interface: a carrier session reset, a DHCP renewal with a new lease, an IPv6
//! prefix change or a privacy-address rotation. Nothing on the sending socket
//! reports that. The socket stays bound to an address the host no longer owns
//! and every datagram it sends is lost. This module is how the sender sees the
//! change on its own instead of waiting for a reload.
//!
//! Two sources feed the same table:
//!
//! * an `RTM_NEWADDR`/`RTM_DELADDR` subscription on a netlink route socket,
//!   which wakes the watcher within milliseconds of a change, and
//! * a periodic full dump ([`ADDRESS_POLL_INTERVAL_MS`]), which covers a missed
//!   or overflowed notification and hosts where the subscription is refused.
//!
//! Notifications are only a wake-up: the watcher never trusts their contents
//! and always re-reads the whole table, so a burst of events or a dropped one
//! cannot leave it with a partial picture.
//!
//! Read-only with respect to the host. Non-Linux targets have no watcher; the
//! follower that consumes the table is then inert.

use std::net::IpAddr;

/// How often the watcher re-reads the table even without a notification.
pub const ADDRESS_POLL_INTERVAL_MS: u64 = 2_000;

/// After a notification, how long the watcher waits for the rest of the burst
/// before it re-reads the table. A renumbering is usually a delete followed by
/// an add within a few milliseconds.
pub const ADDRESS_EVENT_COALESCE_MS: u64 = 100;

/// Consecutive failed table reads (about ten seconds' worth at the poll
/// interval) after which the watcher gives up and following stops.
pub const ADDRESS_DUMP_FAILURES_MAX: u32 = 5;

/// The per-address state bits the follower needs.
///
/// The kernel's `IFA_F_SECONDARY` (IPv4) and `IFA_F_TEMPORARY` (IPv6) share one
/// bit, so they are decoded per family into separate fields here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AddrFlags {
    /// IPv6 privacy (RFC 8981) address.
    pub temporary: bool,
    /// IPv4 address that is not the first one in its subnet on the interface.
    pub secondary: bool,
    /// Preferred lifetime ran out: still valid, but not to be chosen for new use.
    pub deprecated: bool,
    /// Duplicate address detection is still running.
    pub tentative: bool,
    /// Optimistic DAD: usable while detection runs.
    pub optimistic: bool,
    /// Duplicate address detection failed.
    pub dad_failed: bool,
}

impl AddrFlags {
    const KERNEL_SECONDARY_OR_TEMPORARY: u32 = 0x01;
    const KERNEL_OPTIMISTIC: u32 = 0x04;
    const KERNEL_DADFAILED: u32 = 0x08;
    const KERNEL_DEPRECATED: u32 = 0x20;
    const KERNEL_TENTATIVE: u32 = 0x40;

    /// Decode the kernel's `ifa_flags`/`IFA_FLAGS` bits for an address of the
    /// given family.
    #[must_use]
    pub fn from_kernel(bits: u32, is_ipv6: bool) -> Self {
        let shared = bits & Self::KERNEL_SECONDARY_OR_TEMPORARY != 0;
        Self {
            temporary: is_ipv6 && shared,
            secondary: !is_ipv6 && shared,
            deprecated: bits & Self::KERNEL_DEPRECATED != 0,
            tentative: bits & Self::KERNEL_TENTATIVE != 0,
            optimistic: bits & Self::KERNEL_OPTIMISTIC != 0,
            dad_failed: bits & Self::KERNEL_DADFAILED != 0,
        }
    }
}

/// One local address on one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalAddr {
    pub ifindex: u32,
    pub ip: IpAddr,
    pub flags: AddrFlagsOrd,
}

/// [`AddrFlags`] with a total order, so a table can be sorted and compared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddrFlagsOrd(u8);

impl From<AddrFlags> for AddrFlagsOrd {
    fn from(flags: AddrFlags) -> Self {
        let bits = [
            flags.temporary,
            flags.secondary,
            flags.deprecated,
            flags.tentative,
            flags.optimistic,
            flags.dad_failed,
        ]
        .iter()
        .enumerate()
        .fold(0u8, |acc, (bit, set)| acc | (u8::from(*set) << bit));
        Self(bits)
    }
}

impl From<AddrFlagsOrd> for AddrFlags {
    fn from(packed: AddrFlagsOrd) -> Self {
        let bit = |n: u8| packed.0 & (1 << n) != 0;
        Self {
            temporary: bit(0),
            secondary: bit(1),
            deprecated: bit(2),
            tentative: bit(3),
            optimistic: bit(4),
            dad_failed: bit(5),
        }
    }
}

impl LocalAddr {
    #[must_use]
    pub fn new(ifindex: u32, ip: IpAddr, flags: AddrFlags) -> Self {
        Self {
            ifindex,
            ip,
            flags: flags.into(),
        }
    }

    #[must_use]
    pub fn flags(&self) -> AddrFlags {
        self.flags.into()
    }
}

/// Every local address on the host at one instant, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddrTable {
    addrs: Vec<LocalAddr>,
}

impl AddrTable {
    #[must_use]
    pub fn new(mut addrs: Vec<LocalAddr>) -> Self {
        addrs.sort_unstable();
        addrs.dedup();
        Self { addrs }
    }

    #[must_use]
    pub fn addrs(&self) -> &[LocalAddr] {
        &self.addrs
    }

    /// The entry for `ip` on `ifindex`, if the interface currently holds it.
    #[must_use]
    pub fn find(&self, ifindex: u32, ip: IpAddr) -> Option<&LocalAddr> {
        self.addrs
            .iter()
            .find(|addr| addr.ifindex == ifindex && addr.ip == ip)
    }

    /// Every address currently on `ifindex`.
    pub fn on_iface(&self, ifindex: u32) -> impl Iterator<Item = &LocalAddr> {
        self.addrs
            .iter()
            .filter(move |addr| addr.ifindex == ifindex)
    }
}

#[cfg(target_os = "linux")]
pub use linux::{dump_addresses, spawn_address_watch};

/// Without netlink there is no table to watch; the follower stays inert.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn spawn_address_watch() -> Option<tokio::sync::watch::Receiver<std::sync::Arc<AddrTable>>> {
    None
}

#[cfg(target_os = "linux")]
mod linux {
    //! Hand-rolled `NETLINK_ROUTE` address dump and subscription.
    //!
    //! Only `RTM_GETADDR`/`RTM_NEWADDR` are spoken, so a few dozen lines of
    //! parsing replace a dependency. Layouts are the stable kernel UAPI
    //! (`linux/netlink.h`, `linux/rtnetlink.h`, `linux/if_addr.h`).

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::watch;
    use tracing::{debug, info};

    use super::{
        ADDRESS_DUMP_FAILURES_MAX, ADDRESS_EVENT_COALESCE_MS, ADDRESS_POLL_INTERVAL_MS, AddrFlags,
        AddrTable, LocalAddr,
    };

    const NLMSG_HDRLEN: usize = 16;
    const IFADDRMSG_LEN: usize = 8;
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    const RTM_NEWADDR: u16 = 20;
    const RTM_GETADDR: u16 = 22;
    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_DUMP: u16 = 0x300;
    /// Set on a dump message when the table changed while it was being read.
    const NLM_F_DUMP_INTR: u16 = 0x10;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_FLAGS: u16 = 8;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV6_IFADDR: u32 = 0x100;
    const RECV_BUF_LEN: usize = 32 * 1024;

    fn align4(len: usize) -> usize {
        (len + 3) & !3
    }

    fn open_route_socket(groups: u32, nonblocking: bool) -> io::Result<OwnedFd> {
        let mut kind = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
        if nonblocking {
            kind |= libc::SOCK_NONBLOCK;
        }
        // SAFETY: plain socket(2) call; the result is checked before use.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, kind, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by socket(2) and is owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero sockaddr_nl is a valid value (nl_pid 0 lets the
        // kernel assign the port id).
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = groups;
        // SAFETY: `addr` is a fully initialized sockaddr_nl and the length
        // passed matches its size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// A dump the kernel marked as interrupted is re-read this many times
    /// before it counts as a failure.
    const DUMP_ATTEMPTS: usize = 3;

    /// Read every local address the kernel holds right now.
    ///
    /// Blocking, bounded by a one-second receive timeout so a misbehaving
    /// kernel answer can never wedge the caller. A dump that raced a change
    /// (`NLM_F_DUMP_INTR`) may be inconsistent, so it is read again.
    pub fn dump_addresses() -> io::Result<AddrTable> {
        let mut last = None;
        for _ in 0..DUMP_ATTEMPTS {
            match dump_once() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => last = Some(e),
                other => return other,
            }
        }
        Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::Interrupted)))
    }

    fn dump_once() -> io::Result<AddrTable> {
        let fd = open_route_socket(0, false)?;
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        // SAFETY: `timeout` is a valid timeval and the length matches it.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(timeout).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let seq: u32 = 1;
        let mut request = [0u8; NLMSG_HDRLEN + IFADDRMSG_LEN];
        let len = request.len() as u32;
        request[0..4].copy_from_slice(&len.to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
        request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request[8..12].copy_from_slice(&seq.to_ne_bytes());
        // ifaddrmsg: family AF_UNSPEC (0) asks for both families; rest zero.
        // SAFETY: `request` is a valid buffer of the given length.
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut addrs = Vec::new();
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let mut interrupted = false;
        loop {
            // SAFETY: `buf` is a valid writable buffer of the given length.
            let n = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "netlink dump ended without NLMSG_DONE",
                ));
            }
            match parse_messages(&buf[..n as usize], &mut addrs, &mut interrupted)? {
                DumpProgress::Done if interrupted => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "address table changed during the dump",
                    ));
                }
                DumpProgress::Done => return Ok(AddrTable::new(addrs)),
                DumpProgress::More => {}
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum DumpProgress {
        More,
        Done,
    }

    /// Parse one datagram of netlink messages, appending every address found.
    /// `interrupted` is set when any message says the dump raced a change.
    pub(super) fn parse_messages(
        mut buf: &[u8],
        out: &mut Vec<LocalAddr>,
        interrupted: &mut bool,
    ) -> io::Result<DumpProgress> {
        while buf.len() >= NLMSG_HDRLEN {
            let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(buf[6..8].try_into().unwrap());
            *interrupted |= flags & NLM_F_DUMP_INTR != 0;
            if len < NLMSG_HDRLEN || len > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated netlink message",
                ));
            }
            let payload = &buf[NLMSG_HDRLEN..len];
            match kind {
                NLMSG_DONE => return Ok(DumpProgress::Done),
                NLMSG_ERROR => {
                    let errno = payload
                        .get(0..4)
                        .map_or(0, |b| i32::from_ne_bytes(b.try_into().unwrap()));
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(-errno));
                    }
                }
                RTM_NEWADDR => {
                    if let Some(addr) = parse_ifaddr(payload) {
                        out.push(addr);
                    }
                }
                _ => {}
            }
            buf = &buf[align4(len).min(buf.len())..];
        }
        Ok(DumpProgress::More)
    }

    /// Decode one `RTM_NEWADDR` payload (`ifaddrmsg` plus attributes).
    pub(super) fn parse_ifaddr(payload: &[u8]) -> Option<LocalAddr> {
        if payload.len() < IFADDRMSG_LEN {
            return None;
        }
        let family = i32::from(payload[0]);
        let mut flags = u32::from(payload[2]);
        let ifindex = u32::from_ne_bytes(payload[4..8].try_into().ok()?);
        let is_ipv6 = match family {
            libc::AF_INET => false,
            libc::AF_INET6 => true,
            _ => return None,
        };

        let mut local = None;
        let mut address = None;
        let mut attrs = &payload[IFADDRMSG_LEN..];
        while attrs.len() >= 4 {
            let rta_len = usize::from(u16::from_ne_bytes(attrs[0..2].try_into().ok()?));
            let rta_type = u16::from_ne_bytes(attrs[2..4].try_into().ok()?);
            if rta_len < 4 || rta_len > attrs.len() {
                break;
            }
            let value = &attrs[4..rta_len];
            match rta_type {
                IFA_LOCAL => local = parse_ip(value, is_ipv6),
                IFA_ADDRESS => address = parse_ip(value, is_ipv6),
                // The 32-bit attribute supersedes the 8-bit header field.
                IFA_FLAGS if value.len() >= 4 => {
                    flags = u32::from_ne_bytes(value[0..4].try_into().ok()?);
                }
                _ => {}
            }
            attrs = &attrs[align4(rta_len).min(attrs.len())..];
        }

        // On a point-to-point link IFA_ADDRESS is the peer and IFA_LOCAL is
        // ours; elsewhere only IFA_ADDRESS may be present.
        let ip = local.or(address)?;
        Some(LocalAddr::new(
            ifindex,
            ip,
            AddrFlags::from_kernel(flags, is_ipv6),
        ))
    }

    fn parse_ip(value: &[u8], is_ipv6: bool) -> Option<IpAddr> {
        if is_ipv6 {
            let octets: [u8; 16] = value.get(0..16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            let octets: [u8; 4] = value.get(0..4)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
    }

    /// The address-change subscription. Readable means "something changed";
    /// the contents are drained and ignored.
    struct AddrEvents {
        fd: AsyncFd<OwnedFd>,
    }

    impl AddrEvents {
        fn open() -> io::Result<Self> {
            let fd = open_route_socket(RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, true)?;
            // SAFETY: `fd` is an open socket we own outright; the `AsyncFd`
            // takes ownership of it, nothing else can close it, and `as_raw_fd`
            // on an `OwnedFd` always returns that same descriptor.
            let fd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
                .map_err(|e| e.into_parts().1)?;
            Ok(Self { fd })
        }

        /// Wait until at least one notification (or a receive-queue overflow,
        /// which also means "re-read everything") has arrived, then drain.
        async fn changed(&self) -> io::Result<()> {
            let mut buf = vec![0u8; RECV_BUF_LEN];
            loop {
                let mut guard = self.fd.readable().await?;
                let mut got_any = false;
                loop {
                    // SAFETY: `buf` is a valid writable buffer of the given length.
                    let n = unsafe {
                        libc::recv(
                            self.fd.get_ref().as_raw_fd(),
                            buf.as_mut_ptr().cast::<libc::c_void>(),
                            buf.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if n >= 0 {
                        got_any = true;
                        continue;
                    }
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EAGAIN) => break,
                        Some(libc::EINTR) => continue,
                        // The kernel dropped notifications: the table must be
                        // re-read, which is exactly what a change triggers.
                        Some(libc::ENOBUFS) => {
                            got_any = true;
                            continue;
                        }
                        _ => return Err(err),
                    }
                }
                guard.clear_ready();
                if got_any {
                    return Ok(());
                }
            }
        }
    }

    async fn read_table() -> Result<AddrTable, String> {
        match tokio::task::spawn_blocking(dump_addresses).await {
            Ok(Ok(table)) => Ok(table),
            Ok(Err(e)) => Err(e.to_string()),
            Err(e) => Err(format!("dump task failed: {e}")),
        }
    }

    /// Start the watcher. Returns `None` when even the first dump fails: the
    /// host gives no address table, so there is nothing to follow.
    #[must_use]
    pub fn spawn_address_watch() -> Option<watch::Receiver<Arc<AddrTable>>> {
        let initial = match dump_addresses() {
            Ok(table) => table,
            Err(e) => {
                info!("source-address follow unavailable: cannot read local addresses ({e})");
                return None;
            }
        };
        let (tx, rx) = watch::channel(Arc::new(initial));
        let events = match AddrEvents::open() {
            Ok(events) => Some(events),
            Err(e) => {
                info!(
                    "address change notifications unavailable ({e}); checking local addresses \
                     every {ADDRESS_POLL_INTERVAL_MS} ms instead"
                );
                None
            }
        };
        tokio::spawn(watch_loop(tx, events));
        Some(rx)
    }

    async fn watch_loop(tx: watch::Sender<Arc<AddrTable>>, mut events: Option<AddrEvents>) {
        let mut failures = 0u32;
        let mut poll = tokio::time::interval(Duration::from_millis(ADDRESS_POLL_INTERVAL_MS));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = poll.tick() => {}
                res = async {
                    match events.as_ref() {
                        Some(ev) => ev.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Err(e) = res {
                        info!(
                            "address change notifications stopped ({e}); checking local \
                             addresses every {ADDRESS_POLL_INTERVAL_MS} ms instead"
                        );
                        events = None;
                        continue;
                    }
                    tokio::time::sleep(Duration::from_millis(ADDRESS_EVENT_COALESCE_MS)).await;
                }
            }
            if tx.is_closed() {
                return;
            }
            match read_table().await {
                Ok(table) => {
                    failures = 0;
                    tx.send_if_modified(|current| {
                        if **current == table {
                            false
                        } else {
                            *current = Arc::new(table);
                            true
                        }
                    });
                }
                Err(e) => {
                    failures += 1;
                    if failures < ADDRESS_DUMP_FAILURES_MAX {
                        debug!("local address dump failed ({failures} in a row): {e}");
                        continue;
                    }
                    // Acting on an address table that can no longer be
                    // refreshed would hold links down on stale facts. Ending
                    // the watcher makes the follower let go of every link,
                    // which is the behaviour without address following.
                    info!(
                        "source-address follow stopped: local addresses could not be read \
                         {failures} times in a row ({e})"
                    );
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn nlmsg(kind: u16, payload: &[u8]) -> Vec<u8> {
            let len = NLMSG_HDRLEN + payload.len();
            let mut out = Vec::new();
            out.extend_from_slice(&(len as u32).to_ne_bytes());
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(&0u16.to_ne_bytes());
            out.extend_from_slice(&0u32.to_ne_bytes());
            out.extend_from_slice(&0u32.to_ne_bytes());
            out.extend_from_slice(payload);
            out.resize(align4(out.len()), 0);
            out
        }

        fn rta(kind: u16, value: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(value);
            out.resize(align4(out.len()), 0);
            out
        }

        fn ifaddrmsg(family: u8, flags: u8, ifindex: u32) -> Vec<u8> {
            let mut out = vec![family, 24, flags, 0];
            out.extend_from_slice(&ifindex.to_ne_bytes());
            out
        }

        #[test]
        fn a_point_to_point_address_reports_the_local_side_not_the_peer() {
            // Given: a PPP-style record where IFA_ADDRESS is the peer.
            let mut payload = ifaddrmsg(libc::AF_INET as u8, 0, 7);
            payload.extend(rta(IFA_ADDRESS, &[192, 0, 2, 1]));
            payload.extend(rta(IFA_LOCAL, &[192, 0, 2, 34]));
            let msg = nlmsg(RTM_NEWADDR, &payload);

            // When: the datagram is parsed.
            let mut out = Vec::new();
            let progress = parse_messages(&msg, &mut out, &mut false).unwrap();

            // Then: our own address is the one recorded.
            assert_eq!(progress, DumpProgress::More);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].ifindex, 7);
            assert_eq!(out[0].ip, "192.0.2.34".parse::<IpAddr>().unwrap());
        }

        #[test]
        fn the_32_bit_flags_attribute_overrides_the_header_and_is_decoded_per_family() {
            // Given: an IPv6 temporary, deprecated address whose flags only the
            // IFA_FLAGS attribute carries in full.
            let mut payload = ifaddrmsg(libc::AF_INET6 as u8, 0, 3);
            payload.extend(rta(
                IFA_ADDRESS,
                &"2001:db8::1234".parse::<Ipv6Addr>().unwrap().octets(),
            ));
            payload.extend(rta(IFA_FLAGS, &(0x01u32 | 0x20).to_ne_bytes()));
            let mut msg = nlmsg(RTM_NEWADDR, &payload);
            msg.extend(nlmsg(NLMSG_DONE, &[0, 0, 0, 0]));

            let mut out = Vec::new();
            let progress = parse_messages(&msg, &mut out, &mut false).unwrap();

            assert_eq!(progress, DumpProgress::Done);
            let flags = out[0].flags();
            assert!(flags.temporary && flags.deprecated);
            assert!(!flags.secondary, "the shared bit means temporary on IPv6");
        }

        #[test]
        fn a_netlink_error_reply_is_reported_not_swallowed() {
            let msg = nlmsg(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
            let mut out = Vec::new();
            let err = parse_messages(&msg, &mut out, &mut false).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        }

        #[test]
        fn a_dump_that_raced_a_change_is_flagged_as_interrupted() {
            // Given: a dump whose messages carry NLM_F_DUMP_INTR.
            let mut msg = nlmsg(RTM_NEWADDR, &ifaddrmsg(libc::AF_INET as u8, 0, 1));
            msg[6..8].copy_from_slice(&NLM_F_DUMP_INTR.to_ne_bytes());
            msg.extend(nlmsg(NLMSG_DONE, &[0, 0, 0, 0]));

            let mut out = Vec::new();
            let mut interrupted = false;
            let progress = parse_messages(&msg, &mut out, &mut interrupted).unwrap();

            // Then: the caller learns it must read the table again.
            assert_eq!(progress, DumpProgress::Done);
            assert!(interrupted);

            let clean = nlmsg(NLMSG_DONE, &[0, 0, 0, 0]);
            let mut interrupted = false;
            let _ = parse_messages(&clean, &mut Vec::new(), &mut interrupted).unwrap();
            assert!(!interrupted);
        }

        #[test]
        fn a_truncated_message_is_rejected() {
            let mut msg = nlmsg(RTM_NEWADDR, &ifaddrmsg(libc::AF_INET as u8, 0, 1));
            msg[0..4].copy_from_slice(&999u32.to_ne_bytes());
            let mut out = Vec::new();
            assert!(parse_messages(&msg, &mut out, &mut false).is_err());
        }

        #[test]
        fn a_live_dump_succeeds_and_is_well_formed() {
            // The host's real table varies (a test sandbox may hold nothing
            // but a downed `lo`), so only the dump itself is asserted.
            let table = dump_addresses().expect("netlink dump");
            for addr in table.addrs() {
                assert_ne!(addr.ifindex, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_reads_the_shared_bit_as_secondary_and_ipv6_as_temporary() {
        let v4 = AddrFlags::from_kernel(0x01, false);
        let v6 = AddrFlags::from_kernel(0x01, true);
        assert!(v4.secondary && !v4.temporary);
        assert!(v6.temporary && !v6.secondary);
    }

    #[test]
    fn flags_survive_the_packed_round_trip() {
        let flags = AddrFlags {
            temporary: true,
            deprecated: true,
            optimistic: true,
            ..AddrFlags::default()
        };
        let addr = LocalAddr::new(2, "2001:db8::1".parse().unwrap(), flags);
        assert_eq!(addr.flags(), flags);
    }

    #[test]
    fn a_table_compares_equal_regardless_of_dump_order() {
        let a = LocalAddr::new(2, "10.0.0.1".parse().unwrap(), AddrFlags::default());
        let b = LocalAddr::new(3, "10.0.1.1".parse().unwrap(), AddrFlags::default());
        assert_eq!(AddrTable::new(vec![a, b]), AddrTable::new(vec![b, a, b]));
    }
}
