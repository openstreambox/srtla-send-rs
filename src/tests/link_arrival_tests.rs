//! Per-link arrival reports: how many sequence entries the receiver listed in
//! SRTLA ACKs on each link. The receiver sends an SRTLA ACK only on the link
//! the packets arrived on, so the entries belong to the arrival link, whatever
//! the sender's packet logs still hold.

#[cfg(test)]
mod tests {
    use srtla_core::connection::{SrtlaConnection, SrtlaIncoming};
    use srtla_core::utils::now_ms;

    use crate::config::ConfigSnapshot;
    use crate::sender::{SequenceTracker, process_connection_events};
    use crate::stats::SharedStats;
    use crate::test_helpers::create_test_connections;

    async fn ack_on(conns: &mut [SrtlaConnection], link: usize, seqs: &[u32]) {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let seq_tracker = SequenceTracker::new();
        let incoming = SrtlaIncoming {
            srtla_ack_numbers: seqs.iter().copied().collect(),
            read_any: true,
            ..Default::default()
        };
        process_connection_events(link, conns, None, &listener, &seq_tracker, false, incoming)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn entries_count_for_the_link_the_ack_arrived_on() {
        let mut conns = create_test_connections(2).await;
        let now = now_ms();
        // Link 0 sent these; a NAK and a resend could have moved or cleared
        // them since. The receiver reports them as arrived on link 1.
        for s in [10, 11, 12] {
            conns[0].register_packet(s, now);
        }
        ack_on(&mut conns, 1, &[10, 11, 12]).await;
        assert_eq!(conns[1].srtla_ack_entries_total(), 3);
        assert_eq!(conns[0].srtla_ack_entries_total(), 0);
        assert!(conns[1].last_srtla_ack_age_ms(now_ms()).is_some());
        assert_eq!(conns[0].last_srtla_ack_age_ms(now_ms()), None);
    }

    #[tokio::test]
    async fn entries_no_log_holds_still_count() {
        let mut conns = create_test_connections(2).await;
        ack_on(&mut conns, 0, &[1, 2, 3, 4, 5]).await;
        ack_on(&mut conns, 0, &[6, 7]).await;
        assert_eq!(conns[0].srtla_ack_entries_total(), 7);
    }

    #[tokio::test]
    async fn nothing_counts_before_registration() {
        let mut conns = create_test_connections(1).await;
        conns[0].connected = false;
        ack_on(&mut conns, 0, &[1, 2, 3]).await;
        assert_eq!(conns[0].srtla_ack_entries_total(), 0);
        assert_eq!(conns[0].last_srtla_ack_age_ms(now_ms()), None);
    }

    #[tokio::test]
    async fn only_srt_data_counts_as_queued() {
        let mut conns = create_test_connections(1).await;
        let now = now_ms();
        let c = &mut conns[0];
        c.queue_data_packet(&[0u8; 1316], Some(1), now);
        // Forwarded SRT control (no sequence) is not data.
        c.queue_data_packet(&[0u8; 64], None, now);
        c.queue_probe_packet(&[0u8; 1316], 3, now);
        assert_eq!(c.data_packets_queued_total(), 2);
    }

    #[tokio::test]
    async fn a_socket_replacement_starts_a_new_epoch_and_clears_the_age() {
        let mut conns = create_test_connections(1).await;
        let now = now_ms();
        conns[0].note_srtla_ack_arrival(10, now);
        let before = conns[0].srtla_ack_epoch();
        conns[0].reset_for_reconnect(now + 1);
        assert_ne!(conns[0].srtla_ack_epoch(), before);
        assert_eq!(conns[0].last_srtla_ack_age_ms(now + 2), None);
        // The totals belong to the connection object and survive.
        assert_eq!(conns[0].srtla_ack_entries_total(), 10);
    }

    #[tokio::test]
    async fn a_link_created_again_never_repeats_an_epoch() {
        let first = create_test_connections(1).await;
        let again = create_test_connections(1).await;
        assert_ne!(first[0].srtla_ack_epoch(), again[0].srtla_ack_epoch());
        assert_eq!(again[0].srtla_ack_entries_total(), 0);
    }

    #[tokio::test]
    async fn get_stats_and_metrics_report_the_arrival_counters() {
        let mut conns = create_test_connections(2).await;
        let now = now_ms();
        conns[0].queue_data_packet(&[0u8; 1316], Some(1), now);
        ack_on(&mut conns, 0, &[1]).await;
        let stats = SharedStats::new();
        stats.update(&conns, &ConfigSnapshot::default(), None, None, None);
        let v: serde_json::Value = serde_json::from_str(&stats.to_json()).unwrap();
        let links = v["links"].as_array().unwrap();
        assert_eq!(links[0]["data_packets_queued_total"], 1);
        assert_eq!(links[0]["srtla_ack_entries_total"], 1);
        assert!(links[0]["last_srtla_ack_age_ms"].is_u64());
        assert_eq!(links[0]["srtla_ack_epoch"], conns[0].srtla_ack_epoch());
        assert!(
            links[1].get("last_srtla_ack_age_ms").is_none(),
            "absent before the first ACK, never null: {}",
            links[1]
        );
        let text = crate::metrics::render(
            &stats,
            &crate::config::DynamicConfig::new(),
            &srtla_core::priority::CriticalWindow::new(),
        );
        assert!(
            text.contains(r#"srtla_send_link_srtla_ack_entries_total{ip="192.168.1.10"} 1"#),
            "{text}"
        );
        assert!(text.contains(r#"srtla_send_link_data_packets_queued_total{ip="192.168.1.10"} 1"#));
    }
}
