use std::net::{IpAddr, SocketAddr};
// The raw-fd binder below is a unix concept: it exists for Android, where the
// host steers a socket onto a radio via `Network.bindSocket` on its fd. Windows
// has no fd, and no such host integration, so the whole binder is unix-only.
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{Context, Result};
use smallvec::SmallVec;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::warn;

/// Strategy for steering a freshly created uplink socket onto a specific egress
/// path.
///
/// On a multi-homed Linux host each uplink owns a source IP, and source-based
/// routing makes binding that source IP sufficient to pick the egress
/// (`SourceIpBinder`). On platforms where the kernel selects the egress by a
/// network handle rather than by source address (notably Android, where the app
/// must call `Network.bindSocket` on the wifi or cellular `Network`), the host
/// supplies a `CallbackBinder` that operates on the raw fd instead.
///
/// The uplink identity stays keyed on `IpAddr` in both cases; only the act of
/// steering the socket differs.
pub trait UplinkBinder: Send + Sync {
    /// Steer `sock` (already created with buffers set, no traffic yet) onto the
    /// egress identified by `ip`.
    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()>;
}

/// Default binder. Binds the socket to the uplink source IP on an ephemeral
/// port, the behavior the CLI (`ips_file`) relies on.
pub struct SourceIpBinder;

impl UplinkBinder for SourceIpBinder {
    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()> {
        let addr = SocketAddr::new(ip, 0);
        sock.bind(&addr.into()).context("bind socket")
    }
}

/// Linux egress steering via `SO_BINDTODEVICE` **and** a source-address bind.
///
/// Selected only for a link the bind-map names (`--bind-map`); an unmapped link
/// keeps [`SourceIpBinder`] verbatim, which is what makes a run without the flag
/// byte-identical to the legacy one.
///
/// Both halves are load-bearing and neither substitutes for the other:
///
/// * `SO_BINDTODEVICE` decides which interface the packet physically leaves by,
///   overriding the routing table. On its own it leaves the **source address**
///   to the kernel, which picks one from the chosen interface — so two modems
///   presenting the same address, or an interface holding several, would put a
///   non-deterministic source on the wire and the receiver would see the bond's
///   links blur together.
/// * `bind(ip, 0)` pins that source address. On its own it steers nothing
///   without host source routing, which is exactly what a modem bond cannot
///   rely on.
///
/// The device binding is applied **first** so the subsequent `bind(2)` is
/// evaluated against the interface this link is already pinned to.
#[cfg(target_os = "linux")]
pub struct DeviceBinder {
    pub ifname: String,
}

#[cfg(target_os = "linux")]
impl DeviceBinder {
    #[must_use]
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }
}

#[cfg(target_os = "linux")]
impl UplinkBinder for DeviceBinder {
    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()> {
        // The socket2 method is `bind_device` (NOT `set_bind_device`); passing
        // `None` would clear the binding rather than set it.
        sock.bind_device(Some(self.ifname.as_bytes()))
            .with_context(|| format!("bind socket to device {}", self.ifname))?;
        let addr = SocketAddr::new(ip, 0);
        sock.bind(&addr.into())
            .with_context(|| format!("bind socket to {ip} on {}", self.ifname))
    }
}

/// Binder that delegates to a host-supplied closure over the raw fd. The Android
/// integration wires this to `ConnectivityManager` / `Network.bindSocket`,
/// keying on the same `IpAddr` used as the uplink identity. The closure must
/// steer the fd onto the intended radio before the socket carries traffic.
///
/// Exported for library consumers; the CLI binary never constructs it.
#[cfg(unix)]
pub struct CallbackBinder<F>(pub F)
where
    F: Fn(RawFd, IpAddr) -> std::io::Result<()> + Send + Sync;

#[cfg(unix)]
impl<F> UplinkBinder for CallbackBinder<F>
where
    F: Fn(RawFd, IpAddr) -> std::io::Result<()> + Send + Sync,
{
    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()> {
        (self.0)(sock.as_raw_fd(), ip).context("host bindSocket callback")
    }
}

/// Create a UDP socket with the standard nonblocking and buffer configuration.
///
/// The caller applies an [`UplinkBinder`] and then hands the socket to
/// `BatchUdpSocket::new` together with the receiver address. The socket is never
/// connected; see that constructor for why.
pub fn create_uplink_socket(domain_for: IpAddr) -> Result<Socket> {
    let domain = match domain_for {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create socket")?;
    sock.set_nonblocking(true).context("set nonblocking")?;

    // Set send buffer size (100MB)
    const SEND_BUF_SIZE: usize = 100 * 1024 * 1024;
    if let Err(e) = sock.set_send_buffer_size(SEND_BUF_SIZE) {
        warn!("Failed to set send buffer size to {}: {}", SEND_BUF_SIZE, e);
        if let Ok(actual_size) = sock.send_buffer_size() {
            warn!("Effective send buffer size: {}", actual_size);
        }
    }

    // Set receive buffer size to handle large SRT packets (100MB)
    const RECV_BUF_SIZE: usize = 100 * 1024 * 1024;
    if let Err(e) = sock.set_recv_buffer_size(RECV_BUF_SIZE) {
        warn!(
            "Failed to set receive buffer size to {}: {}",
            RECV_BUF_SIZE, e
        );
        if let Ok(actual_size) = sock.recv_buffer_size() {
            warn!("Effective receive buffer size: {}", actual_size);
        }
    }

    Ok(sock)
}

/// Every address the receiver's hostname currently answers with.
///
/// [`resolve_remote_for_source`] picks the first compatible address to dial.
/// The reconnect and whole-bond re-home paths compare pinned addresses against
/// this fresh answer set to detect receiver DNS drift (see
/// `sender::connections`).
pub async fn resolve_remote_all(host: &str, port: u16) -> Result<SmallVec<SocketAddr, 4>> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .context("dns lookup")?;
    Ok(addrs.collect())
}

pub async fn resolve_remote(host: &str, port: u16) -> Result<SocketAddr> {
    resolve_remote_all(host, port)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("no DNS result for {}", host))
}

/// Select the first answer compatible with the source socket's address family.
/// A missing family is an unavailable uplink, never a cross-family send attempt.
pub fn select_remote_for_source(addrs: &[SocketAddr], source: IpAddr) -> Result<SocketAddr> {
    addrs
        .iter()
        .copied()
        .find(|addr| addr.is_ipv4() == source.is_ipv4())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "receiver offers no {} destination; skipping source {}",
                if source.is_ipv4() { "IPv4" } else { "IPv6" },
                source
            )
        })
}

pub async fn resolve_remote_for_source(
    host: &str,
    port: u16,
    source: IpAddr,
) -> Result<SocketAddr> {
    select_remote_for_source(&resolve_remote_all(host, port).await?, source)
}

#[cfg(test)]
mod family_tests {
    use super::*;

    #[test]
    fn resolution_selects_each_source_family_in_answer_order() {
        let v4: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let v6: SocketAddr = "[::1]:9000".parse().unwrap();
        let answers = [v6, v4];
        assert_eq!(select_remote_for_source(&answers, v4.ip()).unwrap(), v4);
        assert_eq!(select_remote_for_source(&answers, v6.ip()).unwrap(), v6);
        assert!(select_remote_for_source(&[v6], v4.ip()).is_err());
        assert!(select_remote_for_source(&[v4], v6.ip()).is_err());
        assert!(select_remote_for_source(&[], v4.ip()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv4_socket_reproduces_eafnosupport_then_sends_to_matching_answer() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let v4 = receiver.local_addr().unwrap();
        let v6 = SocketAddr::new("::1".parse().unwrap(), v4.port());
        let sock = create_uplink_socket(v4.ip()).unwrap();
        SourceIpBinder.bind(&sock, v4.ip()).unwrap();
        let error = sock.send_to(b"family", &v6.into()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EAFNOSUPPORT));
        let remote = select_remote_for_source(&[v6, v4], v4.ip()).unwrap();
        sock.send_to(b"family", &remote.into()).unwrap();
        let mut bytes = [0; 16];
        assert_eq!(receiver.recv(&mut bytes).unwrap(), 6);
    }
}
