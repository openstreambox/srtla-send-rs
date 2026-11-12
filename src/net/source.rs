//! Required-mode source validation. Default binders do not use these checks.
use std::net::IpAddr;

use anyhow::{Result, ensure};

pub fn validate_source(ip: IpAddr, iface: &str) -> Result<()> {
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
        !source_facts(ip, iface)?.1,
        "source must not be directed broadcast"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = iface;
    Ok(())
}

pub fn require_assigned_source(ip: IpAddr, iface: &str) -> Result<()> {
    validate_source(ip, iface)?;
    #[cfg(target_os = "linux")]
    {
        ensure!(
            source_facts(ip.to_canonical(), iface)?.0,
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
fn source_facts(ip: IpAddr, iface: &str) -> Result<(bool, bool)> {
    struct Addrs(*mut libc::ifaddrs);
    impl Drop for Addrs {
        fn drop(&mut self) {
            // SAFETY: owned list returned by getifaddrs, freed exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: head is writable; successful list remains alive until Addrs drops.
    ensure!(
        unsafe { libc::getifaddrs(&mut head) } == 0,
        "cannot inspect interface addresses"
    );
    let list = Addrs(head);
    let mut cur = list.0;
    let mut assigned = false;
    let mut broadcast = false;
    while !cur.is_null() {
        // SAFETY: cur belongs to the live getifaddrs list.
        let row = unsafe { &*cur };
        // SAFETY: getifaddrs supplies a terminated interface name.
        if !row.ifa_name.is_null()
            && unsafe { std::ffi::CStr::from_ptr(row.ifa_name) }.to_bytes() == iface.as_bytes()
        {
            // SAFETY: optional sockaddr pointers belong to the same live row.
            let addr = unsafe { address(row.ifa_addr) };
            assigned |= addr == Some(ip);
            if row.ifa_flags & libc::IFF_BROADCAST as u32 != 0 {
                // SAFETY: optional netmask belongs to this row.
                if let (Some(IpAddr::V4(addr)), Some(IpAddr::V4(mask)), IpAddr::V4(source)) =
                    (addr, unsafe { address(row.ifa_netmask) }, ip)
                {
                    broadcast |= directed_broadcast(addr, mask, source);
                }
            }
        }
        cur = row.ifa_next;
    }
    Ok((assigned, broadcast))
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
