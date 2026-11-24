//! Delivery evidence (`payload_report` >= 2): per link, what the receiver
//! confirmed, in `get_stats` and in the stats file.
//!
//! `srtla_rec` sends one SRTLA ACK per 10 data packets that arrive on a link
//! (`RECV_ACK_INT`), back on that link. A host that wants to know whether a
//! link still delivers, and not only whether the scheduler routes to it, reads
//! `packets_since_srtla_ack` and `last_srtla_ack_age_ms` from one sample.
//!
//! The tests read stats as JSON, and drive the sender through functions that
//! exist without the evidence fields, so they compile against a sender without
//! them and fail there on the missing keys.

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use srtla_core::connection::{SrtlaConnection, SrtlaIncoming};
    use srtla_core::mode::SchedulingMode;
    use srtla_core::priority::CriticalWindow;
    use srtla_core::utils::now_ms;

    use crate::config::{ConfigSnapshot, STALL_MIN_IN_FLIGHT_PACKETS};
    use crate::sender::{ConnIoMap, SequenceTracker, handle_srt_packet, process_connection_events};
    use crate::stats::SharedStats;
    use crate::telemetry_doc::build_telemetry_json_from_stats;
    use crate::test_helpers::{create_test_conn_io_map, create_test_connections};

    /// `srtla_rec`'s `RECV_ACK_INT`: data packets per SRTLA ACK and link.
    const RECV_ACK_INT: u64 = 10;
    /// The packet threshold of `delivering(L)` in the consumer contract:
    /// three ACK intervals.
    const N_DELIVERING: u64 = 3 * RECV_ACK_INT;
    /// The time bound of `delivering(L)`: the last ACK is at most this old at
    /// the snapshot build.
    const D_DELIVERING_MS: u64 = 5_000;
    const PAYLOAD_LEN: usize = 200;

    fn enhanced() -> ConfigSnapshot {
        ConfigSnapshot {
            mode: SchedulingMode::Enhanced,
            quality_enabled: true,
            ..ConfigSnapshot::default()
        }
    }

    /// The ACK clauses of `delivering(L)`: a recent SRTLA ACK and a short gap
    /// since it (report age is checked separately as freshness).
    fn ack_evidence(report: &serde_json::Value, row: &serde_json::Value) -> bool {
        let Some(version) = report["payload_report"].as_u64() else {
            return false;
        };
        let (Some(age), Some(since)) = (
            row["last_srtla_ack_age_ms"].as_u64(),
            row["packets_since_srtla_ack"].as_u64(),
        ) else {
            return false;
        };
        version >= 2 && age <= D_DELIVERING_MS && since < N_DELIVERING
    }

    /// The consumer's `delivering(L)` on one row of a snapshot, as the
    /// contract states it: the ACK evidence, and the scheduler still counts
    /// the link as a healthy sibling and does not hold it out of payload.
    fn delivering(report: &serde_json::Value, row: &serde_json::Value) -> bool {
        ack_evidence(report, row)
            && row["routing_healthy"].as_bool() == Some(true)
            && row["payload_held_out"].as_bool() == Some(false)
    }

    /// Make a loaded link silent: nothing received for a second with a full
    /// backlog, so the next scheduling pass engages its silence pull. Its
    /// SRT-level delivery proof stays fresh, so the slower stall latch does
    /// not engage: the pull alone acts.
    fn go_silent(conn: &mut SrtlaConnection, now: u64) {
        conn.last_received = Some(now.saturating_sub(1_000));
        conn.in_flight_packets = conn.in_flight_packets.max(STALL_MIN_IN_FLIGHT_PACKETS);
        conn.last_ack_or_rtt_sample_ms = now;
    }

    /// A link that keeps speaking (something arrives on it all the time).
    fn keep_speaking(conn: &mut SrtlaConnection, now: u64) {
        conn.last_received = Some(now);
        conn.last_ack_or_rtt_sample_ms = now;
    }

    fn stats_json(conns: &[SrtlaConnection]) -> serde_json::Value {
        let stats = SharedStats::new();
        stats.update(conns, &enhanced(), None, None, None);
        serde_json::from_str(&stats.to_json()).expect("get_stats is valid JSON")
    }

    /// Deliver one SRTLA ACK listing `seqs` on `link`, through the sender's
    /// incoming-event path.
    async fn srtla_ack_on(conns: &mut [SrtlaConnection], link: usize, seqs: &[u32]) {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let incoming = SrtlaIncoming {
            srtla_ack_numbers: seqs.iter().copied().collect(),
            read_any: true,
            ..Default::default()
        };
        process_connection_events(
            link,
            conns,
            None,
            &listener,
            &SequenceTracker::new(),
            false,
            incoming,
        )
        .await
        .unwrap();
    }

    /// One full receiver batch: `RECV_ACK_INT` sequence numbers.
    fn batch(first: u32) -> Vec<u32> {
        (first..first + RECV_ACK_INT as u32).collect()
    }

    /// Fresh delivery proof as the sender's own stall detector sees it, so
    /// the stall latch stays off. SRT's cumulative ACKs can arrive over any
    /// link, so this proof can stay fresh for a link whose packets no longer
    /// arrive: the window before the latch engages, which is the case the
    /// consumer rule must survive.
    fn keep_unlatched(conn: &mut SrtlaConnection, now: u64) {
        conn.last_ack_or_rtt_sample_ms = now;
    }

    fn srt_data(seq: u32) -> [u8; PAYLOAD_LEN] {
        let mut pkt = [0u8; PAYLOAD_LEN];
        pkt[..4].copy_from_slice(&(seq & 0x7fff_ffff).to_be_bytes());
        pkt
    }

    struct Path {
        conn_io: ConnIoMap,
        last_selected_idx: Option<usize>,
        seq_tracker: SequenceTracker,
        last_client_addr: Option<SocketAddr>,
        critical_window: CriticalWindow,
        next_seq: u32,
    }

    impl Path {
        fn new(conns: &[SrtlaConnection]) -> Self {
            Self {
                conn_io: create_test_conn_io_map(conns),
                last_selected_idx: None,
                seq_tracker: SequenceTracker::new(),
                last_client_addr: None,
                critical_window: CriticalWindow::new(),
                next_seq: 1,
            }
        }

        /// One SRT data packet through the production send path. Returns its
        /// sequence number and the link it was routed to as payload.
        async fn send_one(&mut self, conns: &mut [SrtlaConnection]) -> (u32, Option<usize>) {
            let before: Vec<u64> = conns.iter().map(|c| c.payload_packets_total()).collect();
            let seq = self.next_seq;
            let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
            let mut buf = srt_data(self.next_seq);
            self.next_seq += 1;
            handle_srt_packet(
                Ok((PAYLOAD_LEN, client)),
                &mut buf,
                conns,
                &mut self.conn_io,
                &mut self.last_selected_idx,
                &mut self.seq_tracker,
                &mut self.last_client_addr,
                true,
                &enhanced(),
                &self.critical_window,
            )
            .await;
            let link = conns
                .iter()
                .zip(&before)
                .position(|(c, b)| c.payload_packets_total() > *b);
            (seq, link)
        }

        /// One SRT control datagram (an SRT ACK from the caller: top bit set,
        /// so no sequence number) through the production send path.
        async fn send_control(&mut self, conns: &mut [SrtlaConnection]) {
            let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
            let mut buf = [0u8; 44];
            buf[..4].copy_from_slice(&0x8002_0000u32.to_be_bytes());
            handle_srt_packet(
                Ok((buf.len(), client)),
                &mut buf,
                conns,
                &mut self.conn_io,
                &mut self.last_selected_idx,
                &mut self.seq_tracker,
                &mut self.last_client_addr,
                true,
                &enhanced(),
                &self.critical_window,
            )
            .await;
        }
    }

    /// The receiver side of the model, as `srtla_rec` does it: each packet
    /// that arrives on a link goes into that link's batch, and a full batch of
    /// `RECV_ACK_INT` goes back as one SRTLA ACK on the same link. Packets
    /// routed to a black-holed link never arrive.
    struct Receiver {
        pending: Vec<Vec<u32>>,
        acked: Vec<u64>,
        black_holed: Vec<bool>,
    }

    impl Receiver {
        fn new(links: usize) -> Self {
            Self {
                pending: vec![Vec::new(); links],
                acked: vec![0; links],
                black_holed: vec![false; links],
            }
        }

        async fn arrive(&mut self, conns: &mut [SrtlaConnection], seq: u32, link: Option<usize>) {
            let Some(link) = link else { return };
            if self.black_holed[link] {
                return;
            }
            self.pending[link].push(seq);
            if self.pending[link].len() as u64 == RECV_ACK_INT {
                let seqs = std::mem::take(&mut self.pending[link]);
                srtla_ack_on(conns, link, &seqs).await;
                self.acked[link] += RECV_ACK_INT;
            }
        }
    }

    /// Two links carry payload. Link 1 black-holes: its packets stop arriving,
    /// so its SRTLA ACKs stop, while the scheduler keeps routing to it (the
    /// sender's own stall detector has not fired, as when SRT ACKs come back
    /// over the sibling). Per-link attribution must show link 0 delivering and
    /// link 1 carrying but not delivering.
    #[tokio::test]
    async fn a_black_holed_link_carries_payload_but_does_not_deliver() {
        let mut conns = create_test_connections(2).await;
        let mut path = Path::new(&conns);
        let mut rx = Receiver::new(2);

        // Both links deliver for a while.
        for _ in 0..200 {
            let now = now_ms();
            keep_unlatched(&mut conns[0], now);
            keep_unlatched(&mut conns[1], now);
            let (seq, link) = path.send_one(&mut conns).await;
            rx.arrive(&mut conns, seq, link).await;
        }
        assert!(
            rx.acked[1] >= RECV_ACK_INT,
            "precondition: link 1 delivered at least one batch before the black hole"
        );
        let link1_acked_before = rx.acked[1];
        let link1_routed_at_hole = conns[1].payload_packets_total();

        // Link 1 black-holes. The scheduler keeps routing to both links.
        rx.black_holed[1] = true;
        for _ in 0..400 {
            let now = now_ms();
            keep_unlatched(&mut conns[0], now);
            keep_unlatched(&mut conns[1], now);
            let (seq, link) = path.send_one(&mut conns).await;
            rx.arrive(&mut conns, seq, link).await;
        }
        let routed_since_hole = conns[1].payload_packets_total() - link1_routed_at_hole;
        assert!(
            routed_since_hole >= N_DELIVERING,
            "precondition: the scheduler kept routing to link 1 ({routed_since_hole} packets)"
        );

        let v = stats_json(&conns);
        let (l0, l1) = (&v["links"][0], &v["links"][1]);

        // Both links carry payload: routing alone cannot tell them apart.
        assert!(l0["payload_age_ms"].as_u64().is_some_and(|a| a < 1_000));
        assert!(l1["payload_age_ms"].as_u64().is_some_and(|a| a < 1_000));

        // Link 0: every full batch acknowledged on link 0, the gap below one
        // batch.
        assert_eq!(
            l0["srtla_acked_packets_total"], rx.acked[0],
            "link 0's ACKs count on link 0 only: {l0}"
        );
        assert_eq!(l0["packets_since_srtla_ack"], rx.pending[0].len() as u64);
        assert!(l0["last_srtla_ack_age_ms"].as_u64().is_some());
        assert!(delivering(&v, l0), "link 0 delivers: {l0}");

        // Link 1: the ACKs stopped at the black hole and nothing from link 0
        // was credited to it; everything routed since its last ACK is in the
        // gap.
        assert_eq!(
            l1["srtla_acked_packets_total"], link1_acked_before,
            "no ACK after the black hole, and none of link 0's: {l1}"
        );
        let l1_routed = l1["payload_packets_total"].as_u64().unwrap();
        assert_eq!(
            l1["packets_since_srtla_ack"],
            l1_routed - link1_acked_before,
            "packets sent since link 1's last ACK: {l1}"
        );
        assert!(l1["packets_since_srtla_ack"].as_u64().unwrap() >= N_DELIVERING);
        assert!(l1["last_srtla_ack_age_ms"].as_u64().is_some());
        assert!(
            !delivering(&v, l1),
            "link 1 carries but does not deliver: {l1}"
        );
    }

    /// Review case: witness M dies while its sibling K keeps speaking. The
    /// silence pull takes M out of payload within max(250 ms, 2 x SRTT); from
    /// then on M gets only duplicate probes, so its gap stays far below the
    /// threshold and its last ACK is recent. On the ACK clauses alone M still
    /// reads carrying and delivering until the ACK ages past D. The report
    /// must show that the scheduler no longer counts M as healthy.
    #[tokio::test]
    async fn a_silence_pulled_witness_is_not_delivering_although_its_gap_is_short() {
        let mut conns = create_test_connections(2).await;
        let mut path = Path::new(&conns);
        let mut rx = Receiver::new(2);
        for _ in 0..200 {
            let now = now_ms();
            keep_speaking(&mut conns[0], now);
            keep_speaking(&mut conns[1], now);
            let (seq, link) = path.send_one(&mut conns).await;
            rx.arrive(&mut conns, seq, link).await;
        }
        assert!(rx.acked[0] >= RECV_ACK_INT, "precondition: M delivered");

        // M dies: nothing arrives on it any more, its packets are lost.
        rx.black_holed[0] = true;
        for _ in 0..25 {
            let now = now_ms();
            go_silent(&mut conns[0], now);
            keep_speaking(&mut conns[1], now);
            let (seq, link) = path.send_one(&mut conns).await;
            rx.arrive(&mut conns, seq, link).await;
        }

        let v = stats_json(&conns);
        let (m, k) = (&v["links"][0], &v["links"][1]);
        assert!(
            m["payload_age_ms"].as_u64().is_some_and(|a| a < 1_000),
            "precondition: M carried payload within the window: {m}"
        );
        assert!(
            ack_evidence(&v, m),
            "precondition: on the ACK clauses alone M still reads delivering: {m}"
        );
        assert_eq!(m["routing_healthy"], false, "M is silence-pulled: {m}");
        assert_eq!(m["payload_held_out"], true);
        assert!(!delivering(&v, m), "M is no witness: {m}");
        assert_eq!(k["routing_healthy"], true, "K keeps speaking: {k}");
        assert!(delivering(&v, k), "K delivers: {k}");
    }

    /// With no healthy link left the stall gate lifts and a pulled link
    /// carries payload again, so `payload_held_out` reads false. The
    /// scheduler still does not count the link as healthy, and the report must
    /// say so.
    #[tokio::test]
    async fn a_pulled_link_carrying_for_want_of_a_healthy_one_is_not_healthy() {
        let mut conns = create_test_connections(1).await;
        let mut path = Path::new(&conns);
        let mut rx = Receiver::new(1);
        for _ in 0..20 {
            keep_speaking(&mut conns[0], now_ms());
            let (seq, link) = path.send_one(&mut conns).await;
            rx.arrive(&mut conns, seq, link).await;
        }
        rx.black_holed[0] = true;
        for _ in 0..5 {
            go_silent(&mut conns[0], now_ms());
            let (seq, link) = path.send_one(&mut conns).await;
            rx.arrive(&mut conns, seq, link).await;
        }
        let v = stats_json(&conns);
        let m = &v["links"][0];
        assert_eq!(
            m["payload_held_out"], false,
            "precondition: the gate lifted: {m}"
        );
        assert!(
            ack_evidence(&v, m),
            "precondition: gap and age still look fine: {m}"
        );
        assert_eq!(m["routing_healthy"], false, "{m}");
        assert!(!delivering(&v, m));
    }

    /// SRT control datagrams the caller sends (SRT ACKs, NAKs, keepalives) are
    /// forwarded over a link like data, but carry no sequence number, so the
    /// receiver never lists them in an SRTLA ACK. They must not grow the gap
    /// or the sent total, or control traffic alone could push a delivering
    /// link past the threshold.
    #[tokio::test]
    async fn forwarded_srt_control_does_not_count_toward_the_gap() {
        let mut conns = create_test_connections(1).await;
        let mut path = Path::new(&conns);
        for _ in 0..3 {
            keep_unlatched(&mut conns[0], now_ms());
            path.send_one(&mut conns).await;
        }
        let bytes_after_data = stats_json(&conns)["links"][0]["bytes_sent_total"]
            .as_u64()
            .unwrap();
        for _ in 0..40 {
            keep_unlatched(&mut conns[0], now_ms());
            path.send_control(&mut conns).await;
        }
        let v = stats_json(&conns);
        let row = &v["links"][0];
        assert!(
            row["bytes_sent_total"].as_u64().unwrap() > bytes_after_data,
            "precondition: the control datagrams went out on the link: {row}"
        );
        assert_eq!(row["payload_packets_total"], 3);
        assert_eq!(
            row["packets_sent_total"], 3,
            "control is not counted: {row}"
        );
        assert_eq!(
            row["packets_since_srtla_ack"], 3,
            "control does not grow the gap: {row}"
        );
    }

    /// Duplicate probes count as packets sent on the link: a held-out link
    /// that keeps getting probes and no ACK grows its gap, and an ACK of the
    /// probes clears it.
    #[tokio::test]
    async fn probes_count_toward_the_gap_and_their_acks_clear_it() {
        let mut conns = create_test_connections(1).await;
        let now = now_ms();
        for seq in 0..12 {
            conns[0].queue_probe_packet(&srt_data(seq), seq, now);
        }
        let v = stats_json(&conns);
        assert_eq!(v["links"][0]["packets_sent_total"], 12);
        assert_eq!(v["links"][0]["payload_packets_total"], 0);
        assert_eq!(v["links"][0]["packets_since_srtla_ack"], 12);

        srtla_ack_on(&mut conns, 0, &batch(0)).await;
        let v = stats_json(&conns);
        assert_eq!(v["links"][0]["packets_since_srtla_ack"], 0);
        assert_eq!(v["links"][0]["srtla_acked_packets_total"], 10);
    }

    /// The totals are per sender connection and survive recovery and socket
    /// replacement. The evidence (ACK age and gap) belongs to the established
    /// path: recovery follows a silent link, and a replaced socket starts a
    /// fresh ACK batch at the receiver, so both clear it until the next ACK.
    #[tokio::test]
    async fn totals_survive_a_reconnect_and_the_evidence_starts_over() {
        let mut conns = create_test_connections(1).await;
        let now = now_ms();
        for seq in 0..25 {
            conns[0].queue_data_packet(&srt_data(seq), Some(seq), now);
        }
        srtla_ack_on(&mut conns, 0, &batch(0)).await;
        srtla_ack_on(&mut conns, 0, &batch(10)).await;
        for seq in 25..30 {
            conns[0].queue_data_packet(&srt_data(seq), Some(seq), now);
        }
        let v = stats_json(&conns);
        let row = &v["links"][0];
        assert_eq!(row["packets_sent_total"], 30);
        assert_eq!(row["srtla_acked_packets_total"], 20);
        assert_eq!(
            row["packets_since_srtla_ack"], 5,
            "the gap counts packets sent after the last ACK arrived"
        );
        assert!(row["last_srtla_ack_age_ms"].as_u64().is_some());

        // Socket replacement.
        conns[0].reset_for_reconnect(now_ms());
        let v = stats_json(&conns);
        let row = &v["links"][0];
        assert_eq!(
            row["packets_sent_total"], 30,
            "the totals are per connection"
        );
        assert_eq!(row["srtla_acked_packets_total"], 20);
        assert_eq!(row["payload_packets_total"], 30);
        assert_eq!(row["packets_since_srtla_ack"], 0);
        assert!(
            row.get("last_srtla_ack_age_ms").is_none(),
            "an ACK on the old socket proves nothing about the new one: {row}"
        );
        assert!(!ack_evidence(&v, row));

        // The new socket sends and earns its first ACK.
        for seq in 30..33 {
            conns[0].queue_data_packet(&srt_data(seq), Some(seq), now_ms());
        }
        let v = stats_json(&conns);
        assert_eq!(v["links"][0]["packets_since_srtla_ack"], 3);
        srtla_ack_on(&mut conns, 0, &batch(30)).await;
        let v = stats_json(&conns);
        let row = &v["links"][0];
        assert_eq!(row["srtla_acked_packets_total"], 30);
        assert_eq!(row["packets_since_srtla_ack"], 0);
        assert!(
            ack_evidence(&v, row),
            "ACK evidence again after a fresh ACK: {row}"
        );

        // Recovery (same socket, link went silent) clears the evidence too.
        conns[0].mark_for_recovery();
        let v = stats_json(&conns);
        let row = &v["links"][0];
        assert_eq!(row["srtla_acked_packets_total"], 30);
        assert!(row.get("last_srtla_ack_age_ms").is_none());
        assert_eq!(row["packets_since_srtla_ack"], 0);
    }

    /// The stats file carries the same evidence as `get_stats`, under the same
    /// names, promised by `payload_report` 2.
    #[tokio::test]
    async fn the_stats_file_projects_the_delivery_evidence() {
        let mut conns = create_test_connections(2).await;
        let now = now_ms();
        for seq in 0..10 {
            conns[0].queue_data_packet(&srt_data(seq), Some(seq), now);
        }
        srtla_ack_on(&mut conns, 0, &batch(0)).await;
        for seq in 10..13 {
            conns[0].queue_data_packet(&srt_data(seq), Some(seq), now);
        }
        conns[1].queue_probe_packet(&srt_data(100), 100, now);

        let stats = SharedStats::new();
        stats.update(&conns, &enhanced(), None, None, None);
        let snapshot = stats.get();
        let api: serde_json::Value = serde_json::to_value(&snapshot).unwrap();
        let file: serde_json::Value = serde_json::from_str(&build_telemetry_json_from_stats(
            1_749_556_546_000,
            &snapshot,
        ))
        .unwrap();

        assert_eq!(file["schema_version"], 1, "the required shape is unchanged");
        assert_eq!(file["payload_report"], 2);
        assert_eq!(api["payload_report"], 2);
        for key in [
            "packets_sent_total",
            "srtla_acked_packets_total",
            "packets_since_srtla_ack",
            "last_srtla_ack_age_ms",
            "routing_healthy",
        ] {
            for i in 0..2 {
                assert_eq!(
                    file["connections"][i].get(key),
                    api["links"][i].get(key),
                    "`{key}` of link {i} in the file equals get_stats"
                );
            }
        }
        let (c0, c1) = (&file["connections"][0], &file["connections"][1]);
        assert_eq!(c0["packets_sent_total"], 13);
        assert_eq!(c0["srtla_acked_packets_total"], 10);
        assert_eq!(c0["packets_since_srtla_ack"], 3);
        assert!(c0["last_srtla_ack_age_ms"].as_u64().is_some());
        assert_eq!(c1["packets_sent_total"], 1);
        assert_eq!(c1["srtla_acked_packets_total"], 0);
        assert_eq!(c1["packets_since_srtla_ack"], 1);
        assert!(
            c1.get("last_srtla_ack_age_ms").is_none(),
            "absent before the first ACK, never null or 0: {c1}"
        );
    }
}
