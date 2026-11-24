//! A datagram queued by an uplink's previous socket must not count after the
//! socket was rebuilt. A replacement keeps the link's `conn_id`, and aborting
//! the old reader does not drain what it already queued. The reader tags every
//! datagram with its socket's generation; the receive path drops the ones from
//! a retired socket.

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use smallvec::SmallVec;
    use srtla_core::connection::SrtlaConnection;
    use srtla_core::registration::SrtlaRegistrationManager;
    use srtla_core::test_helpers::create_test_connection;
    use srtla_core::utils::now_ms;
    use srtla_protocol::{SRTLA_TYPE_REG3, create_ack_packet};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc::unbounded_channel;

    use crate::config::DynamicConfig;
    use crate::sender::{
        ClientDedup, ConnIoMap, SequenceTracker, UplinkPacket, handle_uplink_packet,
    };
    use crate::test_helpers::{create_test_conn_io_for, create_test_conn_io_map};

    struct Rx {
        reg: SrtlaRegistrationManager,
        dedup: ClientDedup,
        listener: UdpSocket,
        seq_tracker: SequenceTracker,
        config: DynamicConfig,
    }

    impl Rx {
        async fn new() -> Self {
            Self {
                reg: SrtlaRegistrationManager::new(),
                dedup: ClientDedup::new(),
                listener: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                seq_tracker: SequenceTracker::new(),
                config: DynamicConfig::new(),
            }
        }

        /// Hand one datagram, tagged with `generation`, to the receive path.
        async fn receive(
            &mut self,
            connections: &mut [SrtlaConnection],
            conn_io: &ConnIoMap,
            generation: u64,
            bytes: &[u8],
        ) {
            let (instant_tx, _instant_rx) = unbounded_channel::<(SocketAddr, SmallVec<u8, 64>)>();
            let packet = UplinkPacket {
                conn_id: connections[0].conn_id,
                generation,
                bytes: SmallVec::from_slice_copy(bytes),
            };
            handle_uplink_packet(
                packet,
                connections,
                conn_io,
                &mut self.reg,
                &instant_tx,
                &mut self.dedup,
                None,
                &self.listener,
                &self.seq_tracker,
                &self.config.snapshot(),
                &self.config,
            )
            .await;
        }
    }

    fn send(conn: &mut SrtlaConnection, seqs: std::ops::Range<u32>) {
        for seq in seqs {
            conn.queue_data_packet(&[0u8; 200], Some(seq), now_ms());
        }
    }

    /// An SRTLA ACK the old socket's reader queued before the replacement
    /// arrives afterwards. It must neither stamp a fresh ACK age on the new
    /// socket nor clear the packets it has sent since.
    #[tokio::test]
    async fn an_srtla_ack_from_a_retired_socket_is_not_delivery_evidence() {
        let mut connections = vec![create_test_connection().await];
        let conn_id = connections[0].conn_id;
        let mut conn_io = create_test_conn_io_map(&connections);
        let old_generation = conn_io[&conn_id].socket.generation();
        let mut rx = Rx::new().await;

        // The old socket delivers one batch.
        send(&mut connections[0], 0..10);
        rx.receive(
            &mut connections,
            &conn_io,
            old_generation,
            &create_ack_packet(&(0..10).collect::<Vec<_>>()),
        )
        .await;
        assert_eq!(connections[0].srtla_acked_packets_total(), 10);
        send(&mut connections[0], 10..20);

        // The socket is replaced; a second ACK from the old socket is still
        // queued.
        connections[0].reset_for_reconnect(now_ms());
        conn_io.insert(conn_id, create_test_conn_io_for(connections[0].local_ip));
        let new_generation = conn_io[&conn_id].socket.generation();
        assert_ne!(old_generation, new_generation);
        send(&mut connections[0], 20..24);

        rx.receive(
            &mut connections,
            &conn_io,
            old_generation,
            &create_ack_packet(&(10..20).collect::<Vec<_>>()),
        )
        .await;
        let c = &connections[0];
        assert_eq!(
            c.srtla_acked_packets_total(),
            10,
            "the stale ACK is not counted"
        );
        assert_eq!(
            c.last_srtla_ack_age_ms(now_ms()),
            None,
            "no fresh age from a retired socket"
        );
        assert_eq!(
            c.packets_since_srtla_ack(),
            4,
            "the new socket's gap stands"
        );

        // An ACK on the new socket counts.
        rx.receive(
            &mut connections,
            &conn_io,
            new_generation,
            &create_ack_packet(&(20..30).collect::<Vec<_>>()),
        )
        .await;
        let c = &connections[0];
        assert_eq!(c.srtla_acked_packets_total(), 20);
        assert!(c.last_srtla_ack_age_ms(now_ms()).is_some());
        assert_eq!(c.packets_since_srtla_ack(), 0);
    }

    /// A late REG3 answering a REG2 sent from the old socket must not mark the
    /// link registered: the receiver knows only the old source port.
    #[tokio::test]
    async fn a_reg3_from_a_retired_socket_does_not_register_the_link() {
        let mut connections = vec![create_test_connection().await];
        connections[0].connected = false;
        let conn_id = connections[0].conn_id;
        let conn_io = create_test_conn_io_map(&connections);
        let live_generation = conn_io[&conn_id].socket.generation();
        let mut rx = Rx::new().await;

        for (generation, registers) in [(live_generation + 1_000, false), (live_generation, true)] {
            // A REG2 went out on this link, so a REG3 for it is in phase.
            let _ = rx.reg.build_reg2(0);
            rx.receive(
                &mut connections,
                &conn_io,
                generation,
                &SRTLA_TYPE_REG3.to_be_bytes(),
            )
            .await;
            assert_eq!(
                connections[0].connected, registers,
                "generation {generation} (live socket {live_generation})"
            );
        }
    }
}
