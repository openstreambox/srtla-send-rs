use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use smallvec::SmallVec;
use srtla_core::connection::SrtlaConnection;
use srtla_protocol::MIN_CONTROL_PKT_LEN;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::warn;

use crate::net::{
    BatchUdpSocket, EgressLifecycle, RecvMmsgBuffer, RouteHealth, UplinkBinder, UplinkSpec,
};

pub type ConnectionId = u64;

/// The I/O half of an uplink, lifted out of the pure [`SrtlaConnection`] so the
/// connection owns no socket. Held shell-side in a [`ConnIoMap`] keyed by
/// `conn_id` — the same stable-id lifecycle as [`ReaderHandle`]s, so no index
/// stays in lockstep with the connections vec. `binder`/`remote` are retained
/// for reconnect, which re-creates the socket in place.
///
/// `spec`, `egress`, and `route_health` are the ADR-003 half. They live here
/// rather than on [`SrtlaConnection`] because they are interface facts about
/// the socket, not protocol state: the pure core is deliberately unaware that
/// an uplink can be pinned to a device at all.
pub struct ConnIo {
    pub socket: Arc<BatchUdpSocket>,
    pub binder: Arc<dyn UplinkBinder>,
    pub remote: SocketAddr,
    /// Identity (`link_id`) plus current socket key (`ip`, `iface`).
    pub spec: UplinkSpec,
    /// Ifindex staleness for a device-bound link; inert for an unmapped one.
    pub egress: EgressLifecycle,
    /// Last observed per-interface default-route invariant. Distinct from ACK
    /// liveness: a link can be ACK-live and route-blackholed at the same time.
    pub route_health: RouteHealth,
}

impl ConnIo {
    /// The I/O half of a legacy, unmapped uplink: source-IP bound, no identity,
    /// and no interface to re-resolve or observe a route on.
    ///
    /// The ADR-003 half is inert in this shape, which is what lets the tests and
    /// every `--bind-map`-less run share the pre-ADR-003 code path exactly.
    pub fn unmapped(
        socket: Arc<BatchUdpSocket>,
        binder: Arc<dyn UplinkBinder>,
        remote: SocketAddr,
        ip: std::net::IpAddr,
    ) -> Self {
        Self {
            socket,
            binder,
            remote,
            spec: UplinkSpec::unmapped(ip),
            egress: EgressLifecycle::unmapped(),
            route_health: RouteHealth::Unknown,
        }
    }

    /// Send a control-plane frame, zero-padding it to [`MIN_CONTROL_PKT_LEN`]
    /// when it is smaller.
    ///
    /// Mirrors the C `pad_sendto` (`srtla/src/protocol/pad_sendto.h`): frames
    /// already at or above the minimum go out unchanged; smaller ones go out as
    /// a 32-byte frame with trailing zeros. Every control-plane sender
    /// (keepalive, REG1/REG2, REG2 probes) routes through here; the DATA path
    /// (`net::send_all_datagrams`, `sendmmsg`-based) deliberately bypasses it.
    pub async fn send_control_padded(&self, pkt: &[u8]) -> std::io::Result<usize> {
        if pkt.len() >= MIN_CONTROL_PKT_LEN {
            self.socket.send(pkt).await
        } else {
            let mut padded = [0u8; MIN_CONTROL_PKT_LEN];
            padded[..pkt.len()].copy_from_slice(pkt);
            self.socket.send(&padded).await
        }
    }
}

/// Shell-owned map from `conn_id` to its [`ConnIo`]. Lives entirely inside the
/// single event-loop task and is only ever accessed serially, so a plain
/// `HashMap` (not a concurrent map) is both correct and cheapest.
pub type ConnIoMap = HashMap<ConnectionId, ConnIo>;

pub struct UplinkPacket {
    pub conn_id: ConnectionId,
    pub bytes: SmallVec<u8, 64>,
}

pub struct ReaderHandle {
    pub handle: JoinHandle<()>,
}

/// Spawn a reader task for a connection.
///
/// On Unix: Uses `recvmmsg` via `BatchUdpSocket` to batch receive up to 32 packets
/// per syscall, significantly reducing syscall overhead at high packet rates.
///
/// On non-Unix: Falls back to tokio's async recv_from (one packet per call).
pub fn spawn_reader(
    conn_id: ConnectionId,
    label: String,
    socket: Arc<BatchUdpSocket>,
    packet_tx: UnboundedSender<UplinkPacket>,
) -> ReaderHandle {
    let handle = tokio::spawn(async move {
        // Allocate batch receive buffer on heap (large structure ~50KB on Unix)
        let mut recv_buffer = RecvMmsgBuffer::new();

        loop {
            // Wait for and receive packets (batched on Unix, single on other platforms)
            match socket.recv_batch(&mut recv_buffer).await {
                Ok(count) if count > 0 => {
                    // Process all received packets
                    for (_addr, data) in recv_buffer.iter() {
                        if data.is_empty() {
                            continue;
                        }
                        let packet = SmallVec::from_slice_copy(data);
                        if packet_tx
                            .send(UplinkPacket {
                                conn_id,
                                bytes: packet,
                            })
                            .is_err()
                        {
                            return; // Channel closed, exit task
                        }
                    }
                }
                Ok(_) => {
                    // No packets received (shouldn't happen after await returns)
                }
                Err(err) => {
                    warn!("{}: uplink recv error: {}", label, err);
                    // Send empty packet to signal error to handler
                    if packet_tx
                        .send(UplinkPacket {
                            conn_id,
                            bytes: SmallVec::new(),
                        })
                        .is_err()
                    {
                        return;
                    }
                    // Pause before retrying to avoid CPU-intensive tight error loops.
                    // 100ms is long enough to prevent spinning but short enough to
                    // recover quickly when the error resolves.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    ReaderHandle { handle }
}

pub async fn sync_readers(
    connections: &[SrtlaConnection],
    conn_io: &ConnIoMap,
    readers: &mut HashMap<ConnectionId, ReaderHandle>,
    packet_tx: &UnboundedSender<UplinkPacket>,
) {
    let mut active_ids = HashSet::with_capacity(connections.len());
    for conn in connections {
        active_ids.insert(conn.conn_id);
        // The socket now lives in the I/O map; a connection with no ConnIo
        // entry (should not happen — they are created together) simply gets no
        // reader until one exists.
        if let Some(io) = conn_io.get(&conn.conn_id) {
            readers.entry(conn.conn_id).or_insert_with(|| {
                spawn_reader(
                    conn.conn_id,
                    conn.label.clone(),
                    io.socket.clone(),
                    packet_tx.clone(),
                )
            });
        }
    }

    let removed: Vec<_> = readers
        .keys()
        .filter(|id| !active_ids.contains(id))
        .copied()
        .collect();
    for id in removed {
        if let Some(reader) = readers.remove(&id) {
            reader.handle.abort();
            let _ = reader.handle.await;
        }
    }
}

pub async fn restart_reader_for(
    conn: &SrtlaConnection,
    socket: Arc<BatchUdpSocket>,
    readers: &mut HashMap<ConnectionId, ReaderHandle>,
    packet_tx: &UnboundedSender<UplinkPacket>,
) {
    if let Some(reader) = readers.remove(&conn.conn_id) {
        reader.handle.abort();
        let _ = reader.handle.await;
    }
    readers.insert(
        conn.conn_id,
        spawn_reader(conn.conn_id, conn.label.clone(), socket, packet_tx.clone()),
    );
}

pub fn create_uplink_channel() -> (
    UnboundedSender<UplinkPacket>,
    UnboundedReceiver<UplinkPacket>,
) {
    unbounded_channel::<UplinkPacket>()
}

#[cfg(test)]
mod reader_retirement_tests {
    use super::*;
    #[tokio::test]
    async fn removing_a_reader_joins_its_socket_owner_before_returning() {
        use crate::net::{SourceIpBinder, UplinkBinder, create_uplink_socket};
        let ip = "127.0.0.1".parse().unwrap();
        let sock = create_uplink_socket(ip).unwrap();
        SourceIpBinder.bind(&sock, ip).unwrap();
        let socket = Arc::new(BatchUdpSocket::new(sock, "127.0.0.1:9".parse().unwrap()).unwrap());
        let weak = Arc::downgrade(&socket);
        let (tx, _rx) = create_uplink_channel();
        let mut readers = HashMap::new();
        readers.insert(1, spawn_reader(1, "path-a".into(), socket, tx.clone()));
        tokio::task::yield_now().await;
        sync_readers(&[], &HashMap::new(), &mut readers, &tx).await;
        assert!(readers.is_empty());
        assert!(
            weak.upgrade().is_none(),
            "cancelled reader still owns the socket"
        );
    }
}
