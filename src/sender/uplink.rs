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

/// What a required-mode link keeps while it holds no socket.
///
/// A required link is retired the moment its mapped source stops being
/// assigned to its mapped device, or a checked socket rebuild fails: its socket
/// is closed and its reader joined, so nothing can be sent from it. What stays
/// is everything needed to bind it again through the same checked path, and the
/// identity telemetry reports it under while it is down.
pub struct RetiredUplink {
    pub binder: Arc<dyn UplinkBinder>,
    pub remote: SocketAddr,
    pub spec: UplinkSpec,
    pub egress: EgressLifecycle,
}

/// Shell-owned map from `conn_id` to its [`ConnIo`]. Lives entirely inside the
/// single event-loop task and is only ever accessed serially, so a plain
/// `HashMap` (not a concurrent map) is both correct and cheapest.
///
/// Dereferences to that map of LIVE sockets, which is what every send and
/// receive path consults: a link with no entry there cannot transmit. Retired
/// required links are parked beside it, never inside it, so no send path can
/// reach one by accident.
#[derive(Default)]
pub struct ConnIoMap {
    live: HashMap<ConnectionId, ConnIo>,
    retired: HashMap<ConnectionId, RetiredUplink>,
}

impl ConnIoMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Close this link's socket and park what is needed to bind it again.
    /// Returns false when the link owned no socket.
    pub fn retire(&mut self, conn_id: ConnectionId) -> bool {
        let Some(io) = self.live.remove(&conn_id) else {
            return false;
        };
        self.retired.insert(
            conn_id,
            RetiredUplink {
                binder: io.binder,
                remote: io.remote,
                spec: io.spec,
                egress: io.egress,
            },
        );
        true
    }

    #[must_use]
    pub fn is_retired(&self, conn_id: ConnectionId) -> bool {
        self.retired.contains_key(&conn_id)
    }

    #[must_use]
    pub fn retired(&self, conn_id: ConnectionId) -> Option<&RetiredUplink> {
        self.retired.get(&conn_id)
    }

    pub fn retired_mut(&mut self, conn_id: ConnectionId) -> Option<&mut RetiredUplink> {
        self.retired.get_mut(&conn_id)
    }

    /// Every parked link, for the passes that must reach the whole bond.
    pub fn retired_values_mut(&mut self) -> impl Iterator<Item = &mut RetiredUplink> {
        self.retired.values_mut()
    }

    /// Hand a parked link back to its caller, which now owns its socket-less
    /// state: either to pair it with a fresh socket or to drop it.
    pub fn unpark(&mut self, conn_id: ConnectionId) -> Option<RetiredUplink> {
        self.retired.remove(&conn_id)
    }

    /// Drop everything held for a link that left the pool, live or retired.
    pub fn forget(&mut self, conn_id: ConnectionId) {
        self.live.remove(&conn_id);
        self.retired.remove(&conn_id);
    }
}

impl std::ops::Deref for ConnIoMap {
    type Target = HashMap<ConnectionId, ConnIo>;

    fn deref(&self) -> &Self::Target {
        &self.live
    }
}

impl std::ops::DerefMut for ConnIoMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.live
    }
}

impl FromIterator<(ConnectionId, ConnIo)> for ConnIoMap {
    fn from_iter<T: IntoIterator<Item = (ConnectionId, ConnIo)>>(iter: T) -> Self {
        Self {
            live: iter.into_iter().collect(),
            retired: HashMap::new(),
        }
    }
}

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

/// Strict apply drains even surviving readers before replacing any sockets.
pub async fn drain_readers(readers: &mut HashMap<ConnectionId, ReaderHandle>) {
    for (_, reader) in readers.drain() {
        reader.handle.abort();
        let _ = reader.handle.await;
    }
}

/// Remove every owner of an unusable socket before any later send or snapshot.
///
/// The link stays in the pool, parked: housekeeping retries its checked bind on
/// the reconnect backoff, so it returns by itself once its source is assigned
/// to its device again.
pub async fn retire_uplink(
    conn: &mut SrtlaConnection,
    conn_io: &mut ConnIoMap,
    readers: &mut HashMap<ConnectionId, ReaderHandle>,
    seq_tracker: &mut super::sequence::SequenceTracker,
) {
    super::connections::recover_connection(conn, seq_tracker);
    conn_io.retire(conn.conn_id);
    if let Some(reader) = readers.remove(&conn.conn_id) {
        reader.handle.abort();
        let _ = reader.handle.await;
    }
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
        for strict in [false, true] {
            use crate::net::{SourceIpBinder, UplinkBinder, create_uplink_socket};
            let ip = "127.0.0.1".parse().unwrap();
            let sock = create_uplink_socket(ip).unwrap();
            SourceIpBinder.bind(&sock, ip).unwrap();
            let socket =
                Arc::new(BatchUdpSocket::new(sock, "127.0.0.1:9".parse().unwrap()).unwrap());
            let weak = Arc::downgrade(&socket);
            let (tx, _rx) = create_uplink_channel();
            let mut readers = HashMap::new();
            readers.insert(1, spawn_reader(1, "path-a".into(), socket, tx.clone()));
            tokio::task::yield_now().await;
            if strict {
                drain_readers(&mut readers).await;
            } else {
                sync_readers(&[], &ConnIoMap::new(), &mut readers, &tx).await;
            }
            assert!(readers.is_empty());
            assert!(
                weak.upgrade().is_none(),
                "cancelled reader still owns the socket"
            );
        }
    }
}
