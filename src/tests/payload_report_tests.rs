//! The payload routing report: per-link `payload_*` fields in `get_stats` and
//! the telemetry file that say what the scheduler routed, independent of what
//! the gates say.
//!
//! The case that motivates it: the stall latch (`stall_gated` in stats) stays
//! set on a link after the routing gate has been lifted because no healthy
//! sibling remained, so the link carries the whole stream while its stats say
//! it is gated. A host that tears down "gated" links would cut the last
//! carrier. Duplicate probes also move `bytes_sent_total` on a held-out link,
//! so that counter cannot tell a carrier from a probed link either.
//!
//! The routing tests read the stats as JSON rather than through Rust accessors,
//! so they compile against a sender without the report and fail there on the
//! missing keys.

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use srtla_core::connection::SrtlaConnection;
    use srtla_core::mode::SchedulingMode;
    use srtla_core::priority::CriticalWindow;
    use srtla_core::utils::now_ms;

    use crate::config::{ConfigSnapshot, STALL_ACK_STALE_MS, STALL_MIN_IN_FLIGHT_PACKETS};
    use crate::sender::{ConnIoMap, SequenceTracker, handle_srt_packet};
    use crate::stats::SharedStats;
    use crate::telemetry_doc::build_current_telemetry_json;
    use crate::test_helpers::{create_test_conn_io_map, create_test_connections};

    const PAYLOAD_LEN: usize = 200;

    fn enhanced() -> ConfigSnapshot {
        ConfigSnapshot {
            mode: SchedulingMode::Enhanced,
            quality_enabled: true,
            ..ConfigSnapshot::default()
        }
    }

    /// A black-holed link: a backlog at the stall threshold whose last delivery
    /// proof is older than the staleness window, so the stall latch engages.
    fn make_stalled(conn: &mut SrtlaConnection, now: u64) {
        conn.in_flight_packets = STALL_MIN_IN_FLIGHT_PACKETS;
        conn.last_ack_or_rtt_sample_ms = now.saturating_sub(STALL_ACK_STALE_MS + 1000);
    }

    /// A healthy link with fresh delivery proof.
    fn make_healthy(conn: &mut SrtlaConnection, now: u64) {
        conn.in_flight_packets = 0;
        conn.last_ack_or_rtt_sample_ms = now;
    }

    /// An SRT data packet (top bit clear) with sequence number `seq`.
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

        /// Push `count` SRT data packets through the production send path:
        /// selection, the unique copy, and the duplicate probes.
        async fn send(&mut self, conns: &mut [SrtlaConnection], count: u32) {
            let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);
            let config = enhanced();
            for _ in 0..count {
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
                    &config,
                    &self.critical_window,
                )
                .await;
            }
        }
    }

    fn stats_json(conns: &[SrtlaConnection]) -> serde_json::Value {
        let stats = SharedStats::new();
        stats.update(conns, &enhanced(), None, None, None);
        serde_json::from_str(&stats.to_json()).expect("get_stats is valid JSON")
    }

    /// Review case r4: the last link is latched, the gate is lifted because no
    /// healthy sibling remains, payload is routed to it, and the latch flag
    /// still says gated. The report must say the link is not held out and is
    /// carrying payload.
    #[tokio::test]
    async fn a_latched_last_link_that_carries_payload_is_reported_as_carrying() {
        let mut conns = create_test_connections(2).await;
        let mut path = Path::new(&conns);
        let now = now_ms();
        make_stalled(&mut conns[0], now);
        make_healthy(&mut conns[1], now);

        // While link 1 is healthy, link 0 is latched and gated.
        path.send(&mut conns, 1).await;
        assert!(conns[0].stall_latched(), "precondition: link 0 latched");
        assert!(conns[0].is_stall_gated(), "precondition: link 0 gated");

        // Link 1 drops out (the sender puts it into recovery, which times it
        // out). No healthy sibling remains, so the gate lifts and link 0
        // carries the stream with its latch still engaged.
        conns[1].mark_for_recovery();
        assert!(conns[1].is_timed_out(now_ms()), "precondition: link 1 gone");
        path.send(&mut conns, 5).await;
        assert!(conns[0].stall_latched(), "precondition: latch still set");
        assert!(!conns[0].is_stall_gated(), "precondition: gate lifted");

        let v = stats_json(&conns);
        let link = &v["links"][0];
        assert_eq!(
            link["stall_gated"], true,
            "stall_gated reports the latch and is unchanged"
        );
        assert_eq!(
            link["payload_held_out"], false,
            "a link the scheduler routes payload to must not read held out"
        );
        assert_eq!(
            link["payload_packets_total"], 5,
            "every packet routed after the gate lifted is payload on link 0"
        );
        assert_eq!(link["payload_bytes_total"], 5 * PAYLOAD_LEN as u64);
        let age = link["payload_age_ms"]
            .as_u64()
            .expect("a link that carried payload reports its age");
        assert!(age < 1_000, "payload was routed just now, got {age} ms");
    }

    /// A held-out link receives duplicate probes. They move `bytes_sent_total`
    /// but are not payload, so the report must keep the link at zero payload.
    #[tokio::test]
    async fn probes_to_a_held_out_link_are_not_payload() {
        let mut conns = create_test_connections(2).await;
        let mut path = Path::new(&conns);
        let now = now_ms();
        make_stalled(&mut conns[0], now);
        make_healthy(&mut conns[1], now);

        // Two probe periods: link 0 gets two duplicate probes, link 1 every
        // unique copy.
        let sent = 2 * srtla_core::config_snapshot::STALL_PROBE_ONE_IN_N;
        path.send(&mut conns, sent).await;
        assert!(conns[0].is_stall_gated(), "precondition: link 0 gated");

        let v = stats_json(&conns);
        let held = &v["links"][0];
        let carrier = &v["links"][1];
        assert!(
            held["bytes_sent_total"].as_u64().unwrap() > 0,
            "precondition: the probes moved bytes_sent_total on the held-out link"
        );
        assert_eq!(held["payload_held_out"], true);
        assert_eq!(held["payload_packets_total"], 0, "probes are not payload");
        assert!(
            held.get("payload_age_ms").is_none(),
            "a link that never carried payload omits its age"
        );
        assert_eq!(carrier["payload_held_out"], false);
        assert_eq!(carrier["payload_packets_total"], u64::from(sent));
    }

    /// The report is versioned at the top level of `get_stats` and of the
    /// telemetry file, and the snapshot carries its own age.
    #[tokio::test]
    async fn the_report_is_versioned_in_get_stats_and_the_file() {
        let mut conns = create_test_connections(1).await;
        let mut path = Path::new(&conns);
        make_healthy(&mut conns[0], now_ms());
        path.send(&mut conns, 3).await;

        let stats = SharedStats::new();
        stats.update(&conns, &enhanced(), None, None, None);
        let snapshot = stats.get();

        let v: serde_json::Value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(v["payload_report"], 1);
        assert!(v["snapshot_age_ms"].as_u64().is_some());

        let file: serde_json::Value =
            serde_json::from_str(&build_current_telemetry_json(&snapshot)).unwrap();
        assert_eq!(file["schema_version"], 1, "the required shape is unchanged");
        assert_eq!(file["payload_report"], 1);
        assert!(file["snapshot_age_ms"].as_u64().is_some());
        let conn = &file["connections"][0];
        assert_eq!(conn["payload_packets_total"], 3);
        assert_eq!(conn["payload_bytes_total"], 3 * PAYLOAD_LEN as u64);
        assert_eq!(conn["payload_held_out"], false);
        assert!(conn["payload_age_ms"].as_u64().is_some());
    }

    /// Before the first build there is no snapshot to age.
    #[test]
    fn an_unbuilt_snapshot_has_no_age() {
        let v: serde_json::Value = serde_json::from_str(&SharedStats::new().to_json()).unwrap();
        assert!(v.get("snapshot_age_ms").is_none());
    }
}
