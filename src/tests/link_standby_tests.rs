//! Host-requested link standby (`set_link_standby`): a standby link stays
//! registered and keeps its keepalives, but gets no payload while another link
//! can carry. It never blacks out the stream, and it expires by itself.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::Value;
    use srtla_core::mode::SchedulingMode;
    use srtla_core::selection::select_connection_idx;
    use srtla_core::utils::now_ms;

    use crate::config::{
        ConfigSnapshot, DynamicConfig, LINK_STANDBY_TTL_MS_DEFAULT, LINK_STANDBY_TTL_MS_MAX,
        LINK_STANDBY_TTL_MS_MIN, StandbyKey,
    };
    use crate::control::dispatch;
    use crate::stats::{LinkIdentity, SharedStats};
    use crate::test_helpers::create_test_connections;

    fn snap(mode: SchedulingMode, stall_deselect: bool) -> ConfigSnapshot {
        ConfigSnapshot {
            mode,
            quality_enabled: true,
            stall_deselect,
            ..ConfigSnapshot::default()
        }
    }

    /// How often each link is picked over `n` selections.
    fn picks(
        conns: &mut [srtla_core::connection::SrtlaConnection],
        now: u64,
        cfg: &ConfigSnapshot,
        n: usize,
    ) -> Vec<usize> {
        let mut count = vec![0; conns.len()];
        let mut last = None;
        for _ in 0..n {
            if let Some(i) = select_connection_idx(conns, last, now, cfg) {
                count[i] += 1;
                last = Some(i);
            }
        }
        count
    }

    #[test]
    fn a_standby_link_gets_no_payload_while_another_can_carry() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        for mode in [SchedulingMode::Classic, SchedulingMode::Enhanced] {
            for stall_deselect in [true, false] {
                let mut conns = rt.block_on(create_test_connections(2));
                let now = now_ms();
                // Link 0 would win on capacity; standby must override that.
                conns[1].in_flight_packets = 20;
                conns[0].standby_until_ms = now + 10_000;
                let count = picks(&mut conns, now, &snap(mode, stall_deselect), 50);
                assert_eq!(count[0], 0, "{mode:?} deselect={stall_deselect}: {count:?}");
                assert_eq!(count[1], 50);
                assert!(conns[0].connected, "standby must not touch liveness");
            }
        }
    }

    #[test]
    fn the_only_usable_link_carries_even_in_standby() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(1));
        let now = now_ms();
        conns[0].standby_until_ms = now + 10_000;
        let count = picks(&mut conns, now, &snap(SchedulingMode::Enhanced, true), 10);
        assert_eq!(count, vec![10]);
    }

    #[test]
    fn standby_yields_when_every_other_link_is_timed_out() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        let now = now_ms();
        conns[0].standby_until_ms = now + 10_000;
        conns[1].last_received = Some(now.saturating_sub(60_000));
        assert!(conns[1].is_timed_out(now));
        let count = picks(&mut conns, now, &snap(SchedulingMode::Enhanced, true), 10);
        assert_eq!(count[0], 10, "{count:?}");
    }

    #[test]
    fn standby_ends_by_itself() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        let now = now_ms();
        conns[1].in_flight_packets = 20;
        conns[0].standby_until_ms = now + 1_000;
        let later = now + 1_001;
        let count = picks(&mut conns, later, &snap(SchedulingMode::Classic, true), 10);
        assert_eq!(count[0], 10, "{count:?}");
        assert!(!conns[0].is_stall_gated());
    }

    #[test]
    fn the_table_reaches_links_by_source_address_and_expires() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        let config = DynamicConfig::new();
        let now = now_ms();
        let ip0 = conns[0].local_ip;
        let before = config.standby_generation();
        assert_eq!(
            config.set_link_standby(StandbyKey::Ip(ip0), true, 5_000, now),
            5_000
        );
        assert_ne!(config.standby_generation(), before);
        config.apply_link_standby(&mut conns, |_| None, now);
        assert!(conns[0].in_standby(now));
        assert!(!conns[1].in_standby(now));
        // Expired entries are dropped on the next application.
        config.apply_link_standby(&mut conns, |_| None, now + 5_000);
        assert_eq!(conns[0].standby_until_ms, 0);
        // Release.
        config.set_link_standby(StandbyKey::Ip(ip0), true, 5_000, now);
        assert_eq!(
            config.set_link_standby(StandbyKey::Ip(ip0), false, 0, now),
            0
        );
        config.apply_link_standby(&mut conns, |_| None, now);
        assert!(!conns[0].in_standby(now));
    }

    #[test]
    fn a_link_id_holds_one_twin_and_an_ip_shared_by_twins_holds_neither() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        // A bind-map pair on one source IP, as two radios leasing the same
        // address from two routers would be.
        conns[1].local_ip = conns[0].local_ip;
        let first = conns[0].conn_id;
        let id_of = move |c: &srtla_core::connection::SrtlaConnection| {
            Some(
                if c.conn_id == first {
                    "radio-a"
                } else {
                    "radio-b"
                }
                .to_string(),
            )
        };
        let config = DynamicConfig::new();
        let now = now_ms();
        config.set_link_standby(StandbyKey::LinkId("radio-b".into()), true, 5_000, now);
        config.apply_link_standby(&mut conns, id_of, now);
        assert!(!conns[0].in_standby(now));
        assert!(conns[1].in_standby(now));
        // An IP both twins carry names two links: the entry is dropped and
        // holds neither, instead of silently holding both.
        let config = DynamicConfig::new();
        config.set_link_standby(StandbyKey::Ip(conns[0].local_ip), true, 5_000, now);
        config.apply_link_standby(&mut conns, id_of, now);
        assert!(!conns[0].in_standby(now) && !conns[1].in_standby(now));
    }

    #[test]
    fn a_hold_ends_with_its_link_and_never_moves_to_a_successor() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        let config = DynamicConfig::new();
        let now = now_ms();
        config.set_link_standby(StandbyKey::Ip(conns[1].local_ip), true, 10_000, now);
        // The link is removed by a reload: the next application drops the hold.
        let mut remaining = vec![conns.remove(0)];
        config.apply_link_standby(&mut remaining, |_| None, now);
        // A new link later takes the old address: it must not inherit the hold.
        let held_ip = conns[0].local_ip;
        let mut successor = rt.block_on(create_test_connections(1));
        successor[0].local_ip = held_ip;
        config.apply_link_standby(&mut successor, |_| None, now);
        assert!(!successor[0].in_standby(now));
    }

    fn call(config: &DynamicConfig, stats: Option<&SharedStats>, params: &str) -> Value {
        let req =
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"set_link_standby","params":{params}}}"#);
        let resp = dispatch(config, stats, None, &req).unwrap();
        serde_json::from_str(&resp.to_json()).unwrap()
    }

    /// Live links 192.168.1.10 (link_id "radio-a") and 192.168.1.11, plus a
    /// twin pair on 192.168.1.20 ("radio-b", "radio-c").
    fn live_stats() -> SharedStats {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(4));
        let twin_ip: std::net::IpAddr = "192.168.1.20".parse().unwrap();
        conns[2].local_ip = twin_ip;
        conns[3].local_ip = twin_ip;
        let mut ids = HashMap::new();
        for (c, id) in conns
            .iter()
            .zip([Some("radio-a"), None, Some("radio-b"), Some("radio-c")])
        {
            ids.insert(
                c.conn_id,
                LinkIdentity {
                    iface: None,
                    link_id: id.map(str::to_string),
                },
            );
        }
        let stats = SharedStats::new();
        stats.update(&conns, &ConfigSnapshot::default(), None, None, Some(&ids));
        stats
    }

    #[test]
    fn the_control_method_names_exactly_one_live_link() {
        let config = DynamicConfig::new();
        let stats = live_stats();
        let v = call(
            &config,
            Some(&stats),
            r#"{"link_id":"radio-b","standby":true}"#,
        );
        assert_eq!(v["result"]["matched"], 1, "{v}");
        assert_eq!(v["result"]["link_id"], "radio-b");
        let v = call(
            &config,
            Some(&stats),
            r#"{"ip":"192.168.1.11","standby":true}"#,
        );
        assert_eq!(v["result"]["matched"], 1, "{v}");
        let v = call(
            &config,
            Some(&stats),
            r#"{"ip":"192.168.1.20","standby":true}"#,
        );
        assert_eq!(v["error"]["code"], -32602, "{v}");
        assert_eq!(v["error"]["data"]["matched"], 2);
        let v = call(
            &config,
            Some(&stats),
            r#"{"ip":"192.0.2.99","standby":true}"#,
        );
        assert_eq!(v["error"]["data"]["matched"], 0, "{v}");
        let v = call(
            &config,
            Some(&stats),
            r#"{"link_id":"gone","standby":true}"#,
        );
        assert_eq!(v["error"]["code"], -32602, "{v}");
        // Releasing what is not there is a harmless no-op that says so.
        let v = call(
            &config,
            Some(&stats),
            r#"{"link_id":"gone","standby":false}"#,
        );
        assert_eq!(v["result"]["matched"], 0, "{v}");
    }

    #[test]
    fn the_control_method_clamps_the_ttl_and_validates_its_params() {
        let config = DynamicConfig::new();
        let stats = live_stats();
        let s = Some(&stats);
        let v = call(&config, s, r#"{"link_id":"radio-a","standby":true}"#);
        assert_eq!(v["result"]["ttl_ms"], LINK_STANDBY_TTL_MS_DEFAULT);
        let v = call(
            &config,
            s,
            r#"{"link_id":"radio-a","standby":true,"ttl_ms":5}"#,
        );
        assert_eq!(v["result"]["ttl_ms"], LINK_STANDBY_TTL_MS_MIN);
        let v = call(
            &config,
            s,
            r#"{"link_id":"radio-a","standby":true,"ttl_ms":3600000}"#,
        );
        assert_eq!(v["result"]["ttl_ms"], LINK_STANDBY_TTL_MS_MAX);
        let v = call(
            &config,
            s,
            r#"{"link_id":"radio-a","standby":false,"ttl_ms":0}"#,
        );
        assert_eq!(v["result"]["standby"], false);
        assert_eq!(v["result"]["ttl_ms"], 0);
        for bad in [
            r#"{"standby":true}"#,
            r#"{"ip":"not-an-ip","standby":true}"#,
            r#"{"link_id":"","standby":true}"#,
            r#"{"link_id":"radio-a","ip":"192.168.1.10","standby":true}"#,
            r#"{"link_id":"radio-a"}"#,
            r#"{"link_id":"radio-a","standby":true,"ttl_ms":0}"#,
            r#"{"link_id":"radio-a","standby":true,"ttl_ms":"long"}"#,
        ] {
            let v = call(&config, s, bad);
            assert_eq!(v["error"]["code"], -32602, "{bad}: {v}");
        }
    }

    #[test]
    fn get_capabilities_lists_the_method() {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"get_capabilities"}"#;
        let v: Value =
            serde_json::from_str(&dispatch(&config, None, None, req).unwrap().to_json()).unwrap();
        let methods: Vec<&str> = v["result"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(methods.contains(&"set_link_standby"), "{methods:?}");
    }

    #[test]
    fn get_stats_shows_the_standby() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        let now = now_ms();
        conns[0].standby_until_ms = now + 10_000;
        let stats = SharedStats::new();
        stats.update(&conns, &ConfigSnapshot::default(), None, None, None);
        let v: Value = serde_json::from_str(&stats.to_json()).unwrap();
        assert_eq!(v["links"][0]["standby"], true);
        assert_eq!(v["links"][1]["standby"], false);
    }

    #[test]
    fn a_held_link_is_reported_as_held_not_as_stalled() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut conns = rt.block_on(create_test_connections(2));
        let now = now_ms();
        conns[0].standby_until_ms = now + 10_000;
        let _ = select_connection_idx(&mut conns, None, now, &snap(SchedulingMode::Enhanced, true));
        assert!(conns[0].standby_gated);
        let stats = SharedStats::new();
        stats.update(&conns, &ConfigSnapshot::default(), None, None, None);
        let v: Value = serde_json::from_str(&stats.to_json()).unwrap();
        assert_eq!(v["links"][0]["standby_gated"], true);
        assert_eq!(v["links"][0]["stall_gated"], false);
        let text = crate::metrics::render(
            &stats,
            &DynamicConfig::new(),
            &srtla_core::priority::CriticalWindow::new(),
        );
        assert!(
            text.contains(r#"srtla_send_link_standby_gated{ip="192.168.1.10"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"srtla_send_link_stall_gated{ip="192.168.1.10"} 0"#),
            "{text}"
        );
        // The only carrier left: held, it still carries and is not gated.
        conns.truncate(1);
        let _ = select_connection_idx(&mut conns, None, now, &snap(SchedulingMode::Enhanced, true));
        assert!(!conns[0].standby_gated);
    }
}
