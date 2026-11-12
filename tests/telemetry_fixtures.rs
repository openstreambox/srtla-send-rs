//! The telemetry fixture matrix (producer half).
//!
//! Each fixture is built with the real production serializer and compared
//! against committed bytes, so a drift in the ADR-001 document is a failing
//! test rather than a silent change under a consumer. Paths are anchored at
//! `CARGO_MANIFEST_DIR`, inside this repo.
//!
//! Regenerate deliberately:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test --test telemetry_fixtures
//! ```
//!
//! `telemetry-legacy-producer` is the one fixture that is NEVER regenerated: it
//! is the frozen bytes of the shipped pre-ADR-003 producer, and it is only
//! useful as long as it keeps predating the additive keys.
//!
//! The matrix, and what each case exists to prove:
//!
//! | Fixture | Proves |
//! |---|---|
//! | `telemetry-legacy-producer` | An OLD producer's document (none of the four additive keys) is still a valid ADR-001 snapshot. |
//! | `telemetry-golden` | The current producer's unmapped/legacy output. |
//! | `telemetry-mapped` | Twin modems on ONE IP are two links, told apart by `link_id`. |
//! | `telemetry-reordered` | A SIGHUP reorder moves `conn_id` but never `link_id`. |
//! | `telemetry-reconnect` | An interface change keeps `link_id` and does not regress `bytes_sent_total`. |
//! | `telemetry-degraded-startup` | `startup_collision_excluded` names the group it broke up. |
//! | `telemetry-degraded-reload` | `retained_last_valid` says degraded AND still pinned. |
//! | `telemetry-unknown-fields` | A FUTURE producer's extra keys do not break today's reader. |

use std::path::PathBuf;

use srtla_send::bind_map::{
    BindMapDisposition, BindMapReport, BindMapStatus, CollisionGroup, DegradedReason,
};
use srtla_send::telemetry_file::{TelemetryConn, TelemetryInputs, build_telemetry_json};

/// Fixed publish timestamp baked into every fixture so the serialized ms never
/// depends on when the suite ran.
const FIXED_MS: u64 = 1_749_556_546_000;

/// The four optional identity/operating-mode keys. Every one is OPTIONAL; the
/// legacy fixture asserts their total absence.
const ADDITIVE_KEYS: [&str; 4] = ["iface", "link_id", "bind_map_status", "disposition"];

fn crate_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.json"))
}

/// Assert the committed fixture equals `produced`, or rewrite it when
/// `UPDATE_GOLDEN` is set.
fn assert_fixture(name: &str, produced: &str) {
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        let path = crate_fixture(name);
        std::fs::create_dir_all(path.parent().expect("fixture dirs are nested"))
            .expect("fixture directory is writable");
        std::fs::write(&path, produced).expect("fixture is writable");
    }

    let committed = std::fs::read_to_string(crate_fixture(name)).unwrap_or_else(|e| {
        panic!("fixture `{name}` missing ({e}); regenerate with UPDATE_GOLDEN=1")
    });
    assert_eq!(
        committed, produced,
        "producer output drifted from the committed `{name}` fixture"
    );
    assert!(
        !committed.contains('\n'),
        "fixture `{name}` must be the newline-free atomic-publish document"
    );
}

fn conn(conn_id: u32, link_id: Option<&str>, iface: Option<&str>) -> TelemetryConn {
    TelemetryConn {
        conn_id,
        rtt_ms: 42,
        nak_count: 3,
        weight_percent: 50,
        window: 8192,
        in_flight: 100,
        bitrate_bytes_per_sec: 312_500,
        bytes_sent_total: Some(812_000_000),
        iface: iface.map(ToString::to_string),
        link_id: link_id.map(ToString::to_string),
    }
}

fn document(conns: &[TelemetryConn], bind_map: &BindMapReport) -> String {
    build_telemetry_json(
        FIXED_MS,
        &TelemetryInputs {
            conns,
            session_bytes_sent: Some(1_620_000_000),
            bind_map: Some(bind_map),
        },
    )
}

fn active() -> BindMapReport {
    BindMapReport::new(BindMapStatus::Active, BindMapDisposition::Mapped, &[])
}

fn parse(name: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(crate_fixture(name)).expect("fixture is committed");
    serde_json::from_str(&text).expect("fixture is valid JSON")
}

fn value(document: &str) -> serde_json::Value {
    serde_json::from_str(document).expect("the producer emits valid JSON")
}

/// The mapped twin-modem link set. Built rather than read back from the mapped
/// fixture so the reorder/reconnect cases cannot depend on another test having
/// run first.
fn mapped_conns() -> [TelemetryConn; 2] {
    [
        conn(0, Some("modem-a"), Some("wwan0")),
        conn(1, Some("modem-b"), Some("wwan1")),
    ]
}

// ---- The legacy fixture: an OLD producer's bytes ---------------------------

#[test]
fn the_legacy_fixture_carries_none_of_the_additive_keys() {
    // Given: the exact document the shipped pre-ADR-003 producer emitted,
    // committed verbatim. It is NOT regenerated — it is the frozen "before"
    // side of the old-consumer-reads-new-file / new-consumer-reads-old-file
    // pair.
    let text = std::fs::read_to_string(crate_fixture("telemetry-legacy-producer"))
        .expect("the legacy fixture is committed, never regenerated");

    // When/Then: it contains not one of the four additive fields, so a consumer
    // test that parses it is genuinely exercising the old shape.
    for key in ADDITIVE_KEYS {
        assert!(
            !text.contains(key),
            "the legacy fixture must predate `{key}`; it is the frozen old shape"
        );
    }
    // And it is still a well-formed ADR-001 snapshot.
    let doc: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(
        doc["connections"].as_array().expect("connections[]").len(),
        2
    );
}

// ---- The current producer's own output -------------------------------------

#[test]
fn the_golden_fixture_matches_the_current_producer() {
    // Given: the ADR-001 canonical two-link snapshot on a legacy (unmapped) run.
    let conns = [
        TelemetryConn {
            weight_percent: 85,
            ..conn(0, None, None)
        },
        TelemetryConn {
            conn_id: 1,
            rtt_ms: 73,
            nak_count: 11,
            weight_percent: 55,
            window: 4096,
            in_flight: 240,
            bitrate_bytes_per_sec: 150_000,
            bytes_sent_total: Some(808_000_000),
            ..conn(1, None, None)
        },
    ];

    // When/Then: the committed bytes are the producer's bytes.
    let produced = document(&conns, &BindMapReport::default());
    assert_fixture("telemetry-golden", &produced);

    // An unmapped run must not grow per-link identity keys.
    assert!(!produced.contains("\"link_id\""));
    assert!(produced.contains("\"bind_map_status\":{\"state\":\"absent\"}"));
}

#[test]
fn the_mapped_fixture_tells_twin_modems_apart() {
    // Given: two HiLink modems that both present 192.168.8.100 — the case the
    // legacy source-IP identity silently collapsed into one link.
    let produced = document(&mapped_conns(), &active());
    assert_fixture("telemetry-mapped", &produced);

    // Then: two distinct identities reach the consumer.
    let doc = parse("telemetry-mapped");
    assert_eq!(doc["connections"][0]["link_id"], "modem-a");
    assert_eq!(doc["connections"][1]["link_id"], "modem-b");
    assert_eq!(doc["bind_map_status"]["state"], "active");
    assert_eq!(doc["disposition"]["state"], "mapped");
}

#[test]
fn a_reorder_moves_conn_id_but_never_link_id() {
    // Given: the same two modems after a SIGHUP that reordered the ips file.
    // conn_id follows the FILE; link_id follows the MODEM.
    let conns = [
        conn(0, Some("modem-b"), Some("wwan1")),
        conn(1, Some("modem-a"), Some("wwan0")),
    ];

    assert_fixture("telemetry-reordered", &document(&conns, &active()));

    // Then: read against the pre-reorder fixture, conn_id 0 names a different
    // modem while each link_id still names the same interface. This is why a UI
    // must key on link_id — conn_id is positional and transient.
    let before = value(&document(&mapped_conns(), &active()));
    let after = parse("telemetry-reordered");
    assert_eq!(
        before["connections"][0]["conn_id"],
        after["connections"][0]["conn_id"]
    );
    assert_ne!(
        before["connections"][0]["link_id"], after["connections"][0]["link_id"],
        "the reorder fixture must actually swap the modems"
    );
    assert_eq!(
        before["connections"][0]["link_id"],
        after["connections"][1]["link_id"]
    );
    assert_eq!(
        before["connections"][0]["iface"],
        after["connections"][1]["iface"]
    );
}

#[test]
fn a_reconnect_keeps_the_identity_across_a_new_interface() {
    // Given: modem-a replugged onto wwan3 — a NEW socket under an UNCHANGED
    // identity — with its cumulative byte count carried across, not reset.
    let conns = [
        TelemetryConn {
            iface: Some("wwan3".to_string()),
            bytes_sent_total: Some(900_000_000),
            rtt_ms: 55,
            in_flight: 0,
            ..conn(0, Some("modem-a"), None)
        },
        conn(1, Some("modem-b"), Some("wwan1")),
    ];

    assert_fixture("telemetry-reconnect", &document(&conns, &active()));

    let before = value(&document(&mapped_conns(), &active()));
    let after = parse("telemetry-reconnect");
    assert_eq!(
        before["connections"][0]["link_id"], after["connections"][0]["link_id"],
        "a reconnect must not mint a new identity"
    );
    assert_ne!(
        before["connections"][0]["iface"], after["connections"][0]["iface"],
        "the reconnect fixture must actually move the interface"
    );
    let (was, now) = (
        before["connections"][0]["bytes_sent_total"]
            .as_u64()
            .expect("cumulative bytes"),
        after["connections"][0]["bytes_sent_total"]
            .as_u64()
            .expect("cumulative bytes"),
    );
    assert!(
        now > was,
        "ADR-002 bytes must not regress across a reconnect"
    );
}

// ---- Degraded operating modes ----------------------------------------------

#[test]
fn the_degraded_startup_fixture_names_the_excluded_group() {
    // Given: startup degraded with two modems on one IP; one representative
    // runs and the other is excluded AND reported.
    let report = BindMapReport::new(
        BindMapStatus::Degraded(DegradedReason::RetryExhausted),
        BindMapDisposition::StartupCollisionExcluded,
        &[CollisionGroup {
            ip: "192.168.8.100".parse().expect("fixture IP"),
            effective_index: 0,
            excluded_indices: vec![1],
        }],
    );

    assert_fixture(
        "telemetry-degraded-startup",
        &document(&[conn(0, None, None)], &report),
    );

    // Then: a UI can explain "you plugged in two modems and see one link"
    // entirely from typed data.
    let doc = parse("telemetry-degraded-startup");
    assert_eq!(doc["bind_map_status"]["reason"], "retry_exhausted");
    assert_eq!(doc["disposition"]["state"], "startup_collision_excluded");
    assert_eq!(doc["disposition"]["collisions"][0]["ip"], "192.168.8.100");
    assert_eq!(doc["disposition"]["collisions"][0]["effective_index"], 0);
    assert_eq!(
        doc["disposition"]["collisions"][0]["excluded_indices"],
        serde_json::json!([1])
    );
}

#[test]
fn the_degraded_reload_fixture_still_reports_a_pinned_bond() {
    // Given: a live mapped bond whose reload degraded. The links keep their
    // identities because the last valid pool is what is still running.
    let report = BindMapReport::degraded(
        DegradedReason::HashMismatch,
        BindMapDisposition::RetainedLastValid,
    );
    assert_fixture(
        "telemetry-degraded-reload",
        &document(&mapped_conns(), &report),
    );

    // Then: degraded AND still pinned — the two facts a single field could not
    // carry, and the reason startup and reload degradation are distinguishable.
    let doc = parse("telemetry-degraded-reload");
    assert_eq!(doc["bind_map_status"]["state"], "degraded");
    assert_eq!(doc["bind_map_status"]["reason"], "hash_mismatch");
    assert_eq!(doc["disposition"]["state"], "retained_last_valid");
    assert!(doc["disposition"].get("collisions").is_none());
    assert_eq!(doc["connections"][0]["link_id"], "modem-a");
}

// ---- Forward tolerance: a FUTURE producer's extra keys ---------------------

#[test]
fn the_unknown_field_fixture_is_a_superset_of_a_valid_document() {
    // Given: today's document with keys a LATER build might add, at both the
    // document and the per-connection level.
    let base = document(&[conn(0, Some("modem-a"), Some("wwan0"))], &active());
    let mut doc: serde_json::Value = serde_json::from_str(&base).expect("producer emits JSON");
    doc["future_top_level_field"] = serde_json::json!("ignored-by-todays-reader");
    doc["connections"][0]["future_link_field"] = serde_json::json!(1234);
    doc["bind_map_status"]["future_status_field"] = serde_json::json!(true);
    let produced = serde_json::to_string(&doc).expect("still serializable");

    assert_fixture("telemetry-unknown-fields", &produced);

    // Then: every field today's reader requires is still present and unchanged,
    // so a failure to parse it can only be intolerance of the unknown keys.
    let committed = parse("telemetry-unknown-fields");
    assert_eq!(committed["schema_version"], 1);
    assert_eq!(committed["last_updated_ms"], FIXED_MS);
    assert_eq!(committed["connections"][0]["conn_id"], "0");
    assert_eq!(committed["connections"][0]["bitrate_bps"], 2_500_000);
    assert_eq!(
        committed["future_top_level_field"],
        "ignored-by-todays-reader"
    );
}

#[test]
fn required_binding_refusal_publishes_fresh_empty_connections() {
    let report = BindMapReport::degraded(
        DegradedReason::UnknownIface,
        BindMapDisposition::RequiredBindingRefused,
    );
    let produced = document(&[], &report);
    assert_fixture("telemetry-required-binding-refused", &produced);
    let doc = value(&produced);
    assert_eq!(doc["last_updated_ms"], FIXED_MS);
    assert_eq!(doc["connections"], serde_json::json!([]));
    assert_eq!(doc["disposition"]["state"], "required_binding_refused");
}

#[test]
fn pending_apply_is_not_an_empty_withdrawal_acknowledgement() {
    let report = BindMapReport::new(BindMapStatus::Active, BindMapDisposition::PendingApply, &[]);
    let produced = document(&[], &report);
    assert_fixture("telemetry-pending-apply", &produced);
    let doc = value(&produced);
    assert_eq!(doc["disposition"]["state"], "pending_apply");
    assert_ne!(doc["disposition"]["state"], "mapped");
}
