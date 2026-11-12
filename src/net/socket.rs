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
    /// Required mode must select the checked device binder.
    fn requires_checked_device(&self) -> bool {
        false
    }

    /// Steer `sock` (already created with buffers set, no traffic yet) onto the
    /// egress identified by `ip`.
    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()>;
}

/// Required-mode marker: an unmapped socket is always refused.
pub struct RequiredBinding;
impl UplinkBinder for RequiredBinding {
    fn requires_checked_device(&self) -> bool {
        true
    }
    fn bind(&self, _sock: &Socket, _ip: IpAddr) -> Result<()> {
        anyhow::bail!("required binding needs a device");
    }
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
    pub fn checked(ifname: impl Into<String>) -> CheckedDeviceBinder {
        CheckedDeviceBinder(Self::new(ifname))
    }

    #[must_use]
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }
}

/// Required-mode device binder, preserving the default binder's public shape.
#[cfg(target_os = "linux")]
pub struct CheckedDeviceBinder(DeviceBinder);

#[cfg(target_os = "linux")]
impl UplinkBinder for DeviceBinder {
    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()> {
        self.bind_inner(sock, ip, false)
    }
}

#[cfg(target_os = "linux")]
impl UplinkBinder for CheckedDeviceBinder {
    fn requires_checked_device(&self) -> bool {
        true
    }

    fn bind(&self, sock: &Socket, ip: IpAddr) -> Result<()> {
        self.0.bind_inner(sock, ip, true)
    }
}

#[cfg(target_os = "linux")]
impl DeviceBinder {
    fn bind_inner(&self, sock: &Socket, ip: IpAddr, checked: bool) -> Result<()> {
        if checked {
            super::source::require_assigned_source(ip, &self.ifname)?;
        }
        // The socket2 method is `bind_device` (NOT `set_bind_device`); passing
        // `None` would clear the binding rather than set it.
        sock.bind_device(Some(self.ifname.as_bytes()))
            .with_context(|| format!("bind socket to device {}", self.ifname))?;
        let mut addr = SocketAddr::new(ip, 0);
        if checked
            && let SocketAddr::V6(v6) = &mut addr
            && v6.ip().is_unicast_link_local()
        {
            let name = std::ffi::CString::new(self.ifname.as_str())?;
            // SAFETY: name is a valid terminated string.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            anyhow::ensure!(index != 0, "device disappeared before bind");
            v6.set_scope_id(index);
        }
        sock.bind(&addr.into())
            .with_context(|| format!("bind socket to {ip} on {}", self.ifname))?;
        if checked {
            let local = sock
                .local_addr()?
                .as_socket()
                .context("local address is not IP")?;
            anyhow::ensure!(
                local.ip().to_canonical() == ip.to_canonical(),
                "bound local address differs from mapped source"
            );
            if let (SocketAddr::V6(expected), SocketAddr::V6(actual)) = (addr, local)
                && expected.ip().is_unicast_link_local()
            {
                anyhow::ensure!(
                    expected.scope_id() == actual.scope_id(),
                    "bound source scope differs"
                );
            }
        }
        Ok(())
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
/// [`resolve_remote`] picks the first of these to dial. The full set matters
/// only to the reconnect path, which compares the address an uplink is pinned
/// to against a fresh answer to detect that the receiver's DNS has drifted (see
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
