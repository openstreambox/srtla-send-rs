//! Required-mode source validation. Default binders do not use these checks.
use std::net::IpAddr;

use anyhow::{Result, ensure};

pub fn validate_source(ip: IpAddr, iface: &str) -> Result<()> {
    HostAddrs::read().validate(ip, iface)
}

pub fn require_assigned_source(ip: IpAddr, iface: &str) -> Result<()> {
    HostAddrs::read().require_assigned(ip, iface)
}

/// One reading of the host's interface addresses.
///
/// Housekeeping checks every required link against the same reading, so a tick
/// costs one `getifaddrs` however many links the bond has. A reading that
/// failed is kept as a failure: assignment then cannot be proven, and every
/// check against it refuses, naming the inspection rather than the address.
pub struct HostAddrs {
    #[cfg(target_os = "linux")]
    rows: Option<Vec<HostAddr>>,
}

#[cfg(target_os = "linux")]
struct HostAddr {
    iface: Vec<u8>,
    addr: Option<IpAddr>,
    netmask: Option<IpAddr>,
    broadcast_capable: bool,
}

impl HostAddrs {
    #[must_use]
    pub fn read() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            rows: read_host_addrs(),
        }
    }

    /// Concrete unicast, and not a directed broadcast on `iface`.
    pub fn validate(&self, ip: IpAddr, iface: &str) -> Result<()> {
        let ip = ip.to_canonical();
        ensure!(
            !ip.is_unspecified() && !ip.is_multicast(),
            "source must be concrete unicast"
        );
        if let IpAddr::V4(v4) = ip {
            ensure!(!v4.is_broadcast(), "source must not be broadcast");
        }
        #[cfg(target_os = "linux")]
        ensure!(
            !self.source_facts(ip, iface)?.1,
            "source must not be directed broadcast"
        );
        #[cfg(not(target_os = "linux"))]
        let _ = iface;
        Ok(())
    }

    /// [`validate`](Self::validate), and assigned to `iface` in this reading.
    pub fn require_assigned(&self, ip: IpAddr, iface: &str) -> Result<()> {
        self.validate(ip, iface)?;
        #[cfg(target_os = "linux")]
        {
            ensure!(
                self.source_facts(ip.to_canonical(), iface)?.0,
                "source is not assigned to device {iface}"
            );
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("required binding needs Linux")
        }
    }

    /// Whether a source is assigned to this device, and whether it is a directed
    /// broadcast there. /31 and /32 have no directed broadcast.
    #[cfg(target_os = "linux")]
    fn source_facts(&self, ip: IpAddr, iface: &str) -> Result<(bool, bool)> {
        let Some(rows) = self.rows.as_ref() else {
            anyhow::bail!("cannot inspect interface addresses");
        };
        let mut assigned = false;
        let mut broadcast = false;
        for row in rows.iter().filter(|row| row.iface == iface.as_bytes()) {
            assigned |= row.addr == Some(ip);
            if row.broadcast_capable
                && let (Some(IpAddr::V4(addr)), Some(IpAddr::V4(mask)), IpAddr::V4(source)) =
                    (row.addr, row.netmask, ip)
            {
                broadcast |= directed_broadcast(addr, mask, source);
            }
        }
        Ok((assigned, broadcast))
    }
}

/// `None` when the host would not list its addresses.
#[cfg(target_os = "linux")]
fn read_host_addrs() -> Option<Vec<HostAddr>> {
    struct Addrs(*mut libc::ifaddrs);
    impl Drop for Addrs {
        fn drop(&mut self) {
            // SAFETY: owned list returned by getifaddrs, freed exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: head is writable; successful list remains alive until Addrs drops.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let list = Addrs(head);
    let mut cur = list.0;
    let mut rows = Vec::new();
    while !cur.is_null() {
        // SAFETY: cur belongs to the live getifaddrs list.
        let row = unsafe { &*cur };
        if !row.ifa_name.is_null() {
            rows.push(HostAddr {
                // SAFETY: getifaddrs supplies a terminated interface name.
                iface: unsafe { std::ffi::CStr::from_ptr(row.ifa_name) }
                    .to_bytes()
                    .to_vec(),
                // SAFETY: optional sockaddr pointers belong to the same live row.
                addr: unsafe { address(row.ifa_addr) },
                // SAFETY: optional netmask belongs to this row.
                netmask: unsafe { address(row.ifa_netmask) },
                broadcast_capable: row.ifa_flags & libc::IFF_BROADCAST as u32 != 0,
            });
        }
        cur = row.ifa_next;
    }
    Some(rows)
}

#[cfg(target_os = "linux")]
fn directed_broadcast(
    addr: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
    source: std::net::Ipv4Addr,
) -> bool {
    let host = !u32::from(mask);
    host > 1 && u32::from(source) == (u32::from(addr) | host)
}

#[cfg(target_os = "linux")]
unsafe fn address(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: caller provides a live sockaddr; family determines its size.
    match i32::from(unsafe { (*sa).sa_family }) {
        libc::AF_INET => {
            // SAFETY: family is AF_INET; unaligned read tolerates list packing.
            let v = unsafe { std::ptr::read_unaligned(sa.cast::<libc::sockaddr_in>()) };
            Some(std::net::Ipv4Addr::from(u32::from_be(v.sin_addr.s_addr)).into())
        }
        libc::AF_INET6 => {
            // SAFETY: family is AF_INET6.
            let v = unsafe { std::ptr::read_unaligned(sa.cast::<libc::sockaddr_in6>()) };
            Some(std::net::Ipv6Addr::from(v.sin6_addr.s6_addr).into())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_non_unicast_sources_are_refused() {
        for ip in [
            "0.0.0.0",
            "::",
            "255.255.255.255",
            "224.0.0.1",
            "239.255.255.255",
            "ff02::1",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
        ] {
            assert!(validate_source(ip.parse().unwrap(), "lo").is_err(), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "::1",
            "169.254.1.2",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(validate_source(ip.parse().unwrap(), "lo").is_ok(), "{ip}");
        }
    }

    /// A reading that failed proves nothing, so it refuses — and says that
    /// the inspection failed, not that the address is gone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_address_reading_refuses_and_names_the_inspection() {
        let ip = "127.0.0.1".parse().unwrap();
        assert!(HostAddrs::read().require_assigned(ip, "lo").is_ok());
        let err = HostAddrs { rows: None }
            .require_assigned(ip, "lo")
            .unwrap_err();
        assert_eq!(err.to_string(), "cannot inspect interface addresses");
        let err = HostAddrs::read()
            .require_assigned(ip, "missing0")
            .unwrap_err();
        assert_eq!(err.to_string(), "source is not assigned to device missing0");
    }

    /// One reading answers for every link checked against it.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_reading_serves_every_link_of_a_tick() {
        let addrs = HostAddrs::read();
        for source in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(
                addrs
                    .require_assigned(source.parse().unwrap(), "lo")
                    .is_ok(),
                "{source}"
            );
        }
        assert!(
            addrs
                .require_assigned("192.0.2.1".parse().unwrap(), "lo")
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directed_broadcast_uses_the_selected_interface_prefix() {
        let addr = "192.0.2.1".parse().unwrap();
        assert!(directed_broadcast(
            addr,
            "255.255.255.0".parse().unwrap(),
            "192.0.2.255".parse().unwrap()
        ));
        assert!(!directed_broadcast(
            addr,
            "255.255.255.0".parse().unwrap(),
            "192.0.2.2".parse().unwrap()
        ));
        assert!(!directed_broadcast(
            addr,
            "255.255.255.254".parse().unwrap(),
            addr
        ));
        assert!(!directed_broadcast(
            addr,
            "255.255.255.255".parse().unwrap(),
            addr
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checked_binder_verifies_assignment_and_exact_local_address() {
        use crate::net::{DeviceBinder, UplinkBinder, create_uplink_socket};
        for source in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            let ip = source.parse().unwrap();
            let sock = create_uplink_socket(ip).unwrap();
            DeviceBinder::checked("lo").bind(&sock, ip).unwrap();
            assert_eq!(
                sock.local_addr()
                    .unwrap()
                    .as_socket()
                    .unwrap()
                    .ip()
                    .to_canonical(),
                ip.to_canonical()
            );
        }
        for source in ["192.0.2.1", "224.0.0.1", "255.255.255.255"] {
            let ip = source.parse().unwrap();
            let sock = create_uplink_socket(ip).unwrap();
            assert!(
                DeviceBinder::checked("lo").bind(&sock, ip).is_err(),
                "{source}"
            );
        }
    }
}
