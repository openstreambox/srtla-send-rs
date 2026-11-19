//! Per-link delivery counters: how many packets the receiver says arrived on
//! each link. `srtla_rec` sends an SRTLA ACK on a link only for packets it
//! received on that link, so the count belongs to the arrival link, whatever
//! the sender's packet logs still hold.

#[cfg(test)]
mod tests {
    use srtla_core::connection::SrtlaIncoming;
    use srtla_core::utils::now_ms;

    use crate::config::ConfigSnapshot;
    use crate::sender::{SequenceTracker, process_connection_events};
    use crate::stats::SharedStats;
    use crate::test_helpers::create_test_connections;

    async fn ack_on(
        conns: &mut [srtla_core::connection::SrtlaConnection],
        link: usize,
        seqs: &[u32],
    ) {
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
    async fn an_srtla_ack_counts_for_the_link_it_arrived_on() {
        let mut conns = create_test_connections(2).await;
        let now = now_ms();
        // Link 0 sent these; a NAK and a retransmit could have moved or cleared
        // them since. The receiver still reports them as received on link 1.
        for s in [10, 11, 12] {
            conns[0].register_packet(s, now);
        }
        ack_on(&mut conns, 1, &[10, 11, 12]).await;
        assert_eq!(conns[1].srtla_acked_packets_total(), 3);
        assert_eq!(conns[0].srtla_acked_packets_total(), 0);
        assert!(conns[1].last_srtla_ack_age_ms(now_ms()).is_some());
        assert_eq!(conns[0].last_srtla_ack_age_ms(now_ms()), None);
    }

    #[tokio::test]
    async fn sequences_missing_from_every_log_still_count() {
        // A cumulative SRT ACK over a sibling pruned the log first: delivery
        // over this path happened all the same.
        let mut conns = create_test_connections(2).await;
        ack_on(&mut conns, 0, &[1, 2, 3, 4, 5]).await;
        ack_on(&mut conns, 0, &[6, 7]).await;
        assert_eq!(conns[0].srtla_acked_packets_total(), 7);
    }

    #[tokio::test]
    async fn incoming_traffic_without_an_srtla_ack_counts_nothing() {
        let mut conns = create_test_connections(1).await;
        ack_on(&mut conns, 0, &[]).await;
        assert_eq!(conns[0].srtla_acked_packets_total(), 0);
        assert_eq!(conns[0].last_srtla_ack_age_ms(now_ms()), None);
    }

    #[tokio::test]
    async fn sent_and_acked_counts_survive_a_socket_replacement() {
        let mut conns = create_test_connections(1).await;
        let now = now_ms();
        let c = &mut conns[0];
        c.queue_data_packet(&[0u8; 1316], Some(1), now);
        c.queue_data_packet(&[0u8; 1316], Some(2), now);
        c.queue_probe_packet(&[0u8; 1316], 3, now);
        c.note_srtla_ack_arrival(2, now);
        assert_eq!(c.packets_sent_total(), 3);
        c.reset_for_reconnect(now + 1);
        assert_eq!(c.packets_sent_total(), 3);
        assert_eq!(c.srtla_acked_packets_total(), 2);
    }

    #[tokio::test]
    async fn get_stats_reports_the_counters_per_link() {
        let mut conns = create_test_connections(2).await;
        let now = now_ms();
        conns[0].queue_data_packet(&[0u8; 1316], Some(1), now);
        ack_on(&mut conns, 0, &[1]).await;
        let stats = SharedStats::new();
        stats.update(&conns, &ConfigSnapshot::default(), None, None, None);
        let v: serde_json::Value = serde_json::from_str(&stats.to_json()).unwrap();
        let links = v["links"].as_array().unwrap();
        assert_eq!(links[0]["packets_sent_total"], 1);
        assert_eq!(links[0]["srtla_acked_packets_total"], 1);
        assert!(links[0]["last_srtla_ack_age_ms"].is_u64());
        assert_eq!(links[1]["srtla_acked_packets_total"], 0);
        assert!(
            links[1].get("last_srtla_ack_age_ms").is_none(),
            "absent before the first ACK, never null: {}",
            links[1]
        );
    }
}
