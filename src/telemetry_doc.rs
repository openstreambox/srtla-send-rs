//! The ADR-001 telemetry document: its model, its units, and its serializer.
//!
//! Split from [`crate::telemetry_file`], which owns only the publish mechanics
//! (temp sibling -> fsync -> `rename(2)`). Everything that decides what the
//! document *says* lives here, so the schema has one home.
//!
//! # Schema
//!
//! A single newline-free JSON object:
//!
//! ```json
//! {"schema_version":1,"last_updated_ms":1749556546000,"connections":[
//!   {"conn_id":"0","rtt_ms":42,"nak_count":3,"weight_percent":85,
//!    "window":8192,"in_flight":100,"bitrate_bps":2500000,
//!    "bytes_sent_total":812000000,"iface":"wwan0","link_id":"modem-a"}],
//!  "bytes_sent_total":1620000000,
//!  "bind_map_status":{"state":"active"},"disposition":{"state":"mapped"}}
//! ```
//!
//! Seven per-connection keys are REQUIRED and frozen: `conn_id`, `rtt_ms`,
//! `nak_count`, `weight_percent`, `window`, `in_flight`, `bitrate_bps`. Four
//! more are OPTIONAL and omitted entirely (never `null`, never `""`) when they
//! do not apply: `bytes_sent_total` (ADR-002), `iface` and `link_id` (ADR-003),
//! and `binding_state`, present only as `"retired"` on a required link that
//! holds no socket (ADR-003 §9.4).
//! The top level carries the same three-optional pattern: `bytes_sent_total`,
//! `bind_map_status`, `disposition`.
//!
//! ## `schema_version` handling
//!
//! `schema_version` stays **1**. It names the shape of the *required* fields,
//! not the set of fields present: the schema grows only by ADDITION, and an
//! added field is always OPTIONAL. A consumer therefore keeps parsing a newer
//! document, and a producer that omits an added field (an older build) still
//! validates. The version is reserved for a change no old consumer could
//! survive: renaming, retyping, or REMOVING a required field, or changing a
//! unit.
//!
//! ## Identity: `conn_id` vs `link_id`
//!
//! `conn_id` is the uplink's 0-based index in IP-list order and is
//! **TRANSIENT**: a SIGHUP reload that reorders the file reorders it, so the
//! same physical modem can answer to a different `conn_id` across a reload. It
//! is retained for compatibility and for positional correlation within one
//! snapshot. **UI identity must use `link_id`**, the sidecar's writer-assigned
//! opaque id, which survives reloads, reconnects, IP changes, and interface
//! changes. The sender only ever echoes it and never invents one, so an unmapped
//! link has none.
//!
//! ## Units
//!
//! `bitrate_bps` is wire bytes/s x 8 — the mandated bits/s conversion has its
//! single home in [`ConnRecord::from`]. `bytes_sent_total` is BYTES and is
//! **not** multiplied: it is a count, not a rate, and it sits directly beside
//! the one field a consumer is most likely to confuse it with.

use serde::Serialize;
use srtla_core::utils::wall_clock_ms;

use crate::bind_map::{BindMapIdentity, BindMapReport, BindMapStatusRecord, DispositionRecord};
use crate::stats::{BindingState, StatsSnapshot};

/// JSON schema version. See the module docs for what does and does not bump it.
pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;

/// One per-uplink telemetry record in wire units.
///
/// `bitrate_bytes_per_sec` is the wire byte rate; the mandated x8 -> bits/s
/// conversion happens only at serialization, in [`ConnRecord::from`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TelemetryConn {
    pub conn_id: u32,
    pub rtt_ms: u32,
    pub nak_count: u32,
    pub weight_percent: u8,
    pub window: i32,
    pub in_flight: i32,
    pub bitrate_bytes_per_sec: u32,
    /// Cumulative wire BYTES for this uplink (ADR-002). Serialized verbatim —
    /// unlike `bitrate_bytes_per_sec` there is no x8, because this is a byte
    /// count and not a rate.
    pub bytes_sent_total: Option<u64>,
    /// Egress interface this uplink is bound to; `None` when unmapped.
    pub iface: Option<String>,
    /// The sidecar's writer-assigned identity, echoed; `None` when unmapped.
    pub link_id: Option<String>,
    /// `retired` while a required link holds no socket; `None` otherwise.
    pub binding_state: Option<BindingState>,
}

/// Serialized per-connection record. `conn_id` is a string and `bitrate_bps` is
/// bits/s (the x8 conversion). Field order is fixed to mirror the C golden
/// fixture; the optional fields come last and are omitted entirely when absent.
#[derive(Serialize)]
struct ConnRecord {
    conn_id: String,
    rtt_ms: u32,
    nak_count: u32,
    weight_percent: u8,
    window: i32,
    in_flight: i32,
    bitrate_bps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_sent_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_state: Option<BindingState>,
}

impl From<&TelemetryConn> for ConnRecord {
    fn from(c: &TelemetryConn) -> Self {
        Self {
            conn_id: c.conn_id.to_string(),
            rtt_ms: c.rtt_ms,
            nak_count: c.nak_count,
            weight_percent: c.weight_percent,
            window: c.window,
            in_flight: c.in_flight,
            // The single, testable home of the mandated bytes/s -> bits/s x8.
            bitrate_bps: u64::from(c.bitrate_bytes_per_sec) * 8,
            // No x8: a cumulative byte COUNT, not a rate.
            bytes_sent_total: c.bytes_sent_total,
            iface: c.iface.clone(),
            link_id: c.link_id.clone(),
            binding_state: c.binding_state,
        }
    }
}

/// Whole-document shape. `schema_version` first so the on-disk object leads with
/// the version tag; the rest mirrors the C golden field order, with the ADR-003
/// operating-mode pair on the end.
#[derive(Serialize)]
struct TelemetryDoc<'a> {
    schema_version: u32,
    last_updated_ms: u64,
    connections: Vec<ConnRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_sent_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind_map_status: Option<&'a BindMapStatusRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disposition: Option<&'a DispositionRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind_map_applied: Option<&'a BindMapIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind_map_pending: Option<&'a BindMapIdentity>,
}

/// Everything a snapshot document is built from, other than its timestamp.
///
/// `session_bytes_sent` is the bond-level ADR-002 cumulative byte count. It is
/// passed in rather than summed from `conns` because the sum of the LIVE links
/// regresses when a link is torn down.
///
/// Both optional inputs mean "this build has nothing to say here", which
/// serializes as an ABSENT key rather than a zero or a null: `None` for
/// `session_bytes_sent` is UNKNOWN, which is a different claim from `Some(0)`.
#[derive(Default)]
pub struct TelemetryInputs<'a> {
    pub conns: &'a [TelemetryConn],
    pub session_bytes_sent: Option<u64>,
    pub bind_map: Option<&'a BindMapReport>,
}

/// Serialize one snapshot to the exact ADR-001 JSON object (compact,
/// newline-free). This is the single place the bytes/s -> bits/s x8 conversion
/// lives, so the mandated unit transform has one testable home.
#[must_use]
pub fn build_telemetry_json(last_updated_ms: u64, inputs: &TelemetryInputs<'_>) -> String {
    let doc = TelemetryDoc {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        last_updated_ms,
        connections: inputs.conns.iter().map(ConnRecord::from).collect(),
        bytes_sent_total: inputs.session_bytes_sent,
        bind_map_status: inputs.bind_map.map(|r| &r.bind_map_status),
        disposition: inputs.bind_map.map(|r| &r.disposition),
        bind_map_applied: inputs.bind_map.and_then(|r| r.bind_map_applied.as_ref()),
        bind_map_pending: inputs.bind_map.and_then(|r| r.bind_map_pending.as_ref()),
    };
    // The doc is plain scalars / strings, so serialization cannot fail; fall back
    // to an empty object defensively rather than panicking on the hot path.
    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Serialize a whole [`StatsSnapshot`] into the publishable telemetry document.
///
/// Every sink goes through here, so the per-link projection and the top-level
/// fields can never be paired inconsistently.
#[must_use]
pub fn build_telemetry_json_from_stats(last_updated_ms: u64, stats: &StatsSnapshot) -> String {
    build_telemetry_json(
        last_updated_ms,
        &TelemetryInputs {
            conns: &conns_from_stats(stats),
            session_bytes_sent: Some(stats.session_bytes_sent),
            bind_map: Some(&stats.bind_map),
        },
    )
}

/// The document a `--stats-file` publish writes right now, stamped with the
/// WALL clock.
///
/// `last_updated_ms` is the one value in this crate that must NOT come from the
/// monotonic `now_ms()`: a consumer diffs it against its own `Date.now()` to
/// judge staleness, and the monotonic clock drifts away from the wall clock
/// permanently after any step.
#[must_use]
pub fn build_current_telemetry_json(stats: &StatsSnapshot) -> String {
    build_telemetry_json_from_stats(wall_clock_ms(), stats)
}

/// Project the shared stats snapshot into per-uplink telemetry records.
///
/// `conn_id` is the link's 0-based position in IP-list order. `weight_percent`
/// is the link's share of total selection weight (`base_score x quality`) among
/// active links, normalized to 100; inactive links report 0. Active links with
/// no capacity signal yet fall back to an equal share so a freshly-registered
/// group is not reported as all-zero.
#[must_use]
pub fn conns_from_stats(stats: &StatsSnapshot) -> Vec<TelemetryConn> {
    let weights: Vec<f64> = stats
        .links
        .iter()
        .map(|l| {
            if l.connected && !l.timed_out {
                f64::from(l.base_score.max(0)) * l.quality_multiplier
            } else {
                0.0
            }
        })
        .collect();
    let total: f64 = weights.iter().sum();
    let active = stats
        .links
        .iter()
        .filter(|l| l.connected && !l.timed_out)
        .count();

    stats
        .links
        .iter()
        .enumerate()
        .map(|(idx, l)| {
            let is_active = l.connected && !l.timed_out;
            let weight_percent = if !is_active {
                0
            } else if total > 0.0 {
                weight_share_percent(weights[idx], total)
            } else {
                equal_share_percent(active)
            };
            TelemetryConn {
                conn_id: idx as u32,
                rtt_ms: l.rtt_ms,
                nak_count: l.nak_count.max(0) as u32,
                weight_percent,
                window: l.window,
                in_flight: l.in_flight,
                // LinkStats carries wire bytes/s; the x8 to bits/s is applied
                // once, at JSON serialization.
                bitrate_bytes_per_sec: l.bitrate_bytes_per_sec,
                // ADR-002: a byte COUNT, passed through with no x8.
                bytes_sent_total: Some(l.bytes_sent_total),
                // ADR-003: echoed, never invented. An unmapped link carries
                // neither, and the key is then omitted rather than emptied.
                iface: l.iface.clone(),
                link_id: l.link_id.clone(),
                // ADR-003 §9.4: present only on a retired required link, so
                // every other document is byte-identical to what it was.
                binding_state: l.binding_state,
            }
        })
        .collect()
}

/// One link's percentage of the total selection weight, rounded and clamped to
/// the schema's `0..=100` range.
fn weight_share_percent(weight: f64, total: f64) -> u8 {
    let pct = (weight / total * 100.0).round();
    pct.clamp(0.0, 100.0) as u8
}

/// Equal share among `active` links (the no-capacity-signal fallback).
fn equal_share_percent(active: usize) -> u8 {
    100usize
        .checked_div(active)
        .map_or(0, |share| share.min(100) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind_map::{BindMapDisposition, BindMapStatus, CollisionGroup, DegradedReason};
    use crate::stats::LinkStats;

    /// The ADR-001 canonical 312500 B/s -> 2_500_000 bps example link.
    fn sample_conn() -> TelemetryConn {
        TelemetryConn {
            conn_id: 0,
            rtt_ms: 42,
            nak_count: 3,
            weight_percent: 85,
            window: 8192,
            in_flight: 100,
            bitrate_bytes_per_sec: 312_500,
            bytes_sent_total: Some(812_000_000),
            iface: None,
            link_id: None,
            binding_state: None,
        }
    }

    fn json(conns: &[TelemetryConn]) -> String {
        build_telemetry_json(
            1,
            &TelemetryInputs {
                conns,
                ..TelemetryInputs::default()
            },
        )
    }

    fn link(score: i32, active: bool, bytes_per_sec: u32) -> LinkStats {
        LinkStats {
            connected: active,
            timed_out: !active,
            window: 100,
            rtt_ms: 20,
            bitrate_bytes_per_sec: bytes_per_sec,
            base_score: score,
            ..LinkStats::default()
        }
    }

    // ---- Schema serialization: field names + types ------------------------

    #[test]
    fn schema_version_is_integer_one() {
        let doc = json(&[]);
        assert!(doc.contains("\"schema_version\":1"), "got {doc}");
        assert!(!doc.contains("\"schema_version\":\"1\""));
    }

    #[test]
    fn document_is_newline_free() {
        let doc = json(&[sample_conn()]);
        assert!(
            !doc.contains('\n'),
            "telemetry must be a single line: {doc}"
        );
    }

    #[test]
    fn empty_connections_serialize_to_array() {
        let doc = build_telemetry_json(
            1_749_556_546_000,
            &TelemetryInputs {
                conns: &[],
                ..TelemetryInputs::default()
            },
        );
        assert!(doc.contains("\"connections\":[]"), "got {doc}");
        assert!(doc.contains("\"last_updated_ms\":1749556546000"));
    }

    #[test]
    fn conn_id_is_stringified() {
        assert!(json(&[sample_conn()]).contains("\"conn_id\":\"0\""));
    }

    #[test]
    fn all_schema_fields_present_and_typed() {
        let doc = json(&[sample_conn()]);
        for needle in [
            "\"rtt_ms\":42",
            "\"nak_count\":3",
            "\"weight_percent\":85",
            "\"window\":8192",
            "\"in_flight\":100",
            "\"bitrate_bps\":2500000",
        ] {
            assert!(doc.contains(needle), "missing {needle} in {doc}");
        }
    }

    // ---- The mandated x8 bytes/s -> bits/s conversion ---------------------

    #[test]
    fn bitrate_is_bytes_times_eight_bits_per_second() {
        // 312500 B/s -> 2500000 bps (the ADR-001 canonical example).
        let doc = json(&[sample_conn()]);
        assert!(doc.contains("\"bitrate_bps\":2500000"), "got {doc}");
        assert!(!doc.contains("312500"), "raw bytes/s leaked: {doc}");
    }

    #[test]
    fn bitrate_conversion_is_exactly_times_eight() {
        let cases = [
            (0u32, 0u64),
            (1, 8),
            (150_000, 1_200_000),
            (312_500, 2_500_000),
        ];
        for (bytes, bits) in cases {
            let conn = TelemetryConn {
                bitrate_bytes_per_sec: bytes,
                ..sample_conn()
            };
            let record = ConnRecord::from(&conn);
            assert_eq!(record.bitrate_bps, bits, "{bytes} B/s should be {bits} bps");
        }
    }

    // ---- Optional fields are ABSENT, never null or empty ------------------

    #[test]
    fn an_unmapped_link_omits_iface_and_link_id_entirely() {
        // Given: a legacy uplink, which has neither an interface binding nor a
        // writer-assigned identity.
        // When/Then: the keys are ABSENT, not null and not empty-string — an old
        // consumer must see the document it has always seen.
        let doc = json(&[sample_conn()]);
        assert!(
            !doc.contains("iface"),
            "unmapped link leaked an iface: {doc}"
        );
        assert!(
            !doc.contains("link_id"),
            "unmapped link leaked a link_id: {doc}"
        );
    }

    #[test]
    fn an_unknown_byte_count_omits_the_key_rather_than_claiming_zero() {
        // Given: a build with no cumulative-byte accounting wired in.
        let conn = TelemetryConn {
            bytes_sent_total: None,
            ..sample_conn()
        };

        // When/Then: absent, because "unknown" and "nothing was sent" are
        // different claims and a consumer must be able to tell them apart.
        let doc = json(&[conn]);
        assert!(!doc.contains("bytes_sent_total"), "got {doc}");
        assert!(!doc.contains("null"), "got {doc}");
    }

    #[test]
    fn a_mapped_link_echoes_the_writer_assigned_identity() {
        // Given: a link the sidecar named. The id is the WRITER's; the sender
        // must reproduce it byte-for-byte rather than deriving anything.
        let conn = TelemetryConn {
            iface: Some("wwan1".to_string()),
            link_id: Some("modem-b".to_string()),
            ..sample_conn()
        };

        // When: serialized.
        let doc = json(&[conn]);

        // Then: both fields ride along verbatim.
        assert!(doc.contains("\"iface\":\"wwan1\""), "got {doc}");
        assert!(doc.contains("\"link_id\":\"modem-b\""), "got {doc}");
    }

    #[test]
    fn twin_modems_on_one_ip_are_told_apart_by_link_id_not_conn_id() {
        // Given: the HiLink twin case — two uplinks that legacy identity would
        // have collapsed into one.
        let conns = vec![
            TelemetryConn {
                conn_id: 0,
                iface: Some("wwan0".to_string()),
                link_id: Some("modem-a".to_string()),
                ..sample_conn()
            },
            TelemetryConn {
                conn_id: 1,
                iface: Some("wwan1".to_string()),
                link_id: Some("modem-b".to_string()),
                ..sample_conn()
            },
        ];

        // When: serialized.
        let doc = json(&conns);

        // Then: both identities are present and distinct, so a UI keying on
        // link_id renders two links rather than one.
        assert!(doc.contains("\"link_id\":\"modem-a\""), "got {doc}");
        assert!(doc.contains("\"link_id\":\"modem-b\""), "got {doc}");
    }

    // ---- Top-level operating mode (ADR-003 §6.4) --------------------------

    #[test]
    fn a_legacy_report_reports_absent_and_legacy_unique_only() {
        let report = BindMapReport::default();
        let doc = build_telemetry_json(
            1,
            &TelemetryInputs {
                conns: &[],
                bind_map: Some(&report),
                ..TelemetryInputs::default()
            },
        );
        assert!(
            doc.contains("\"bind_map_status\":{\"state\":\"absent\"}"),
            "got {doc}"
        );
        assert!(
            doc.contains("\"disposition\":{\"state\":\"legacy_unique_only\"}"),
            "got {doc}"
        );
    }

    #[test]
    fn a_degraded_startup_publishes_the_collision_group_it_excluded() {
        // Given: the sender fell open at startup and dropped one of two modems
        // sharing an IP.
        let report = BindMapReport::new(
            BindMapStatus::Degraded(DegradedReason::RetryExhausted),
            BindMapDisposition::StartupCollisionExcluded,
            &[CollisionGroup {
                ip: "192.168.8.100".parse().expect("fixture IP"),
                effective_index: 0,
                excluded_indices: vec![1],
            }],
        );

        // When: a snapshot is published.
        let doc = build_telemetry_json(
            1,
            &TelemetryInputs {
                conns: &[],
                bind_map: Some(&report),
                ..TelemetryInputs::default()
            },
        );

        // Then: the UI has everything it needs to explain "two modems, one
        // link" without reading a log line.
        assert!(
            doc.contains(
                "\"bind_map_status\":{\"state\":\"degraded\",\"reason\":\"retry_exhausted\"}"
            ),
            "got {doc}"
        );
        assert!(
            doc.contains("\"state\":\"startup_collision_excluded\""),
            "got {doc}"
        );
        assert!(doc.contains("\"ip\":\"192.168.8.100\""), "got {doc}");
        assert!(doc.contains("\"excluded_indices\":[1]"), "got {doc}");
    }

    #[test]
    fn the_operating_mode_pair_comes_after_the_frozen_fields() {
        // The ADR-001 prefix must stay byte-stable so a byte-diff of two
        // documents localizes a change to the additive tail.
        let report = BindMapReport::default();
        let doc = build_telemetry_json(
            1,
            &TelemetryInputs {
                conns: &[],
                session_bytes_sent: Some(0),
                bind_map: Some(&report),
            },
        );
        let frozen_end = doc
            .find("\"bytes_sent_total\"")
            .expect("frozen tail present");
        let additive = doc
            .find("\"bind_map_status\"")
            .expect("additive tail present");
        assert!(
            frozen_end < additive,
            "the additive pair must follow the frozen fields: {doc}"
        );
        assert!(
            doc.starts_with("{\"schema_version\":1,\"last_updated_ms\":"),
            "got {doc}"
        );
    }

    // ---- ADR-001 contract pins -------------------------------------------

    #[test]
    fn telemetry_json_shape_and_bitrate_x8() {
        // One snapshot with the ADR-001 canonical 312500 B/s link asserts the
        // whole shape at once: the schema tag, every required field, the x8
        // bitrate, and the single-line invariant the atomic publish depends on.
        let doc = build_telemetry_json(
            1_749_556_546_000,
            &TelemetryInputs {
                conns: &[sample_conn()],
                ..TelemetryInputs::default()
            },
        );

        assert!(doc.starts_with("{\"schema_version\":1,"), "got {doc}");
        assert!(!doc.contains("\"schema_version\":\"1\""));
        assert!(doc.contains("\"bitrate_bps\":2500000"), "got {doc}");
        assert!(!doc.contains("312500"), "raw bytes/s leaked: {doc}");

        for needle in [
            "\"last_updated_ms\":1749556546000",
            "\"conn_id\":\"0\"",
            "\"rtt_ms\":42",
            "\"nak_count\":3",
            "\"weight_percent\":85",
            "\"window\":8192",
            "\"in_flight\":100",
            "\"bitrate_bps\":2500000",
        ] {
            assert!(doc.contains(needle), "missing {needle} in {doc}");
        }

        assert!(!doc.contains('\n'), "telemetry must be one line: {doc}");
    }

    #[test]
    fn telemetry_idle_connections_empty() {
        // "running but idle": a live process with no active uplinks still
        // serializes an empty array (distinct from an absent file), keeping the
        // schema tag and timestamp so a reader can tell idle from stale.
        let doc = build_telemetry_json(
            1_749_556_546_000,
            &TelemetryInputs {
                conns: &[],
                ..TelemetryInputs::default()
            },
        );
        assert!(doc.contains("\"connections\":[]"), "got {doc}");
        assert!(doc.contains("\"schema_version\":1"), "got {doc}");
        assert!(
            doc.contains("\"last_updated_ms\":1749556546000"),
            "got {doc}"
        );
        assert!(!doc.contains('\n'), "telemetry must be one line: {doc}");
    }

    // ---- Weight normalization --------------------------------------------

    #[test]
    fn weight_share_normalizes_to_one_hundred() {
        assert_eq!(weight_share_percent(5.0, 10.0), 50);
        assert_eq!(weight_share_percent(10.0, 10.0), 100);
        // 2:1 split rounds to 67 / 33.
        assert_eq!(weight_share_percent(2.0, 3.0), 67);
        assert_eq!(weight_share_percent(1.0, 3.0), 33);
    }

    #[test]
    fn equal_share_fallback_distributes_evenly() {
        assert_eq!(equal_share_percent(0), 0);
        assert_eq!(equal_share_percent(1), 100);
        assert_eq!(equal_share_percent(2), 50);
        assert_eq!(equal_share_percent(4), 25);
    }

    #[test]
    fn conns_from_stats_indexes_and_normalizes() {
        let snap = StatsSnapshot {
            // two equal active links + one timed-out link
            links: vec![link(10, true, 100), link(10, true, 200), link(0, false, 0)],
            ..Default::default()
        };
        let conns = conns_from_stats(&snap);

        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].conn_id, 0);
        assert_eq!(conns[1].conn_id, 1);
        assert_eq!(conns[2].conn_id, 2);
        // Two equal active links split 50/50; the inactive link reports 0.
        assert_eq!(conns[0].weight_percent, 50);
        assert_eq!(conns[1].weight_percent, 50);
        assert_eq!(conns[2].weight_percent, 0);
        // Wire bytes/s carried through verbatim (x8 applied only at serialization).
        assert_eq!(conns[1].bitrate_bytes_per_sec, 200);
    }

    #[test]
    fn conns_from_stats_equal_share_when_no_capacity_signal() {
        // Active links whose base_score is 0 still get a non-zero equal share.
        let snap = StatsSnapshot {
            links: vec![link(0, true, 0), link(0, true, 0)],
            ..Default::default()
        };
        let conns = conns_from_stats(&snap);
        assert_eq!(conns[0].weight_percent, 50);
        assert_eq!(conns[1].weight_percent, 50);
    }

    #[test]
    fn an_unmapped_run_reports_the_absent_mode_and_no_per_link_identity() {
        // Given: a live snapshot from a run with no `--bind-map`, which is what
        // `SharedStats::get` composes when nothing ever called `set_bind_map`.
        let snap = StatsSnapshot {
            links: vec![link(10, true, 100)],
            ..Default::default()
        };

        // When: the whole-snapshot serializer runs, which is what the
        // `--stats-file` sink calls.
        let doc = build_telemetry_json_from_stats(1_749_556_546_000, &snap);

        // Then: the operating mode is stated POSITIVELY — a UI must be able to
        // read "no bind-map" as a fact rather than infer it from two missing
        // keys.
        assert!(
            doc.contains(r#""bind_map_status":{"state":"absent"}"#),
            "got {doc}"
        );
        assert!(
            doc.contains(r#""disposition":{"state":"legacy_unique_only"}"#),
            "got {doc}"
        );

        // And: the per-link identity keys do NOT materialize, neither as `null`
        // nor as an empty string, because the sender never invents one.
        for absent in ["iface", "link_id"] {
            assert!(!doc.contains(absent), "unexpected `{absent}` in {doc}");
        }
        assert!(doc.contains("\"bitrate_bps\":800"), "got {doc}");
    }

    #[test]
    fn a_mapped_link_echoes_its_interface_and_identity() {
        // Given: a snapshot whose link carries the ADR-003 echo, i.e. a run
        // with a coherent `--bind-map`.
        let snap = StatsSnapshot {
            links: vec![LinkStats {
                iface: Some("wwan0".to_string()),
                link_id: Some("modem-a".to_string()),
                ..link(10, true, 100)
            }],
            bind_map: BindMapReport::new(BindMapStatus::Active, BindMapDisposition::Mapped, &[]),
            ..Default::default()
        };

        // When: the sink serializes it.
        let doc = build_telemetry_json_from_stats(1_749_556_546_000, &snap);

        // Then: both identity fields ride along verbatim, and the mode says the
        // map is in force.
        assert!(doc.contains(r#""iface":"wwan0""#), "got {doc}");
        assert!(doc.contains(r#""link_id":"modem-a""#), "got {doc}");
        assert!(
            doc.contains(r#""bind_map_status":{"state":"active"}"#),
            "got {doc}"
        );
        assert!(
            doc.contains(r#""disposition":{"state":"mapped"}"#),
            "got {doc}"
        );
    }

    // ---- ADR-002: the runtime feed populates BOTH scopes ------------------

    #[test]
    fn the_runtime_projection_reports_cumulative_bytes_at_both_scopes() {
        // Given: a live snapshot whose bond accumulator already EXCEEDS the sum
        // of its live links — the state a SIGHUP teardown leaves behind.
        let snap = StatsSnapshot {
            links: vec![LinkStats {
                bytes_sent_total: 777_000,
                ..link(10, true, 100)
            }],
            session_bytes_sent: 1_500_000,
            ..Default::default()
        };

        // When: projected and serialized through the `--stats-file` path.
        let conns = conns_from_stats(&snap);
        let doc = build_telemetry_json_from_stats(1_749_556_546_000, &snap);

        // Then: both counters ship verbatim, and the serializer does NOT
        // "helpfully" recompute the bond figure from the live links.
        assert_eq!(conns[0].bytes_sent_total, Some(777_000));
        assert!(doc.contains("\"bytes_sent_total\":777000"), "got {doc}");
        assert!(doc.contains("\"bytes_sent_total\":1500000"), "got {doc}");
    }

    #[test]
    fn a_link_that_has_sent_nothing_reports_zero_rather_than_omitting_the_key() {
        // Given: a live link with the counter wired but no traffic yet.
        // When/Then: `Some(0)` is a positive claim ("nothing sent"), distinct
        // from the absent key that means "this build cannot tell you".
        let snap = StatsSnapshot {
            links: vec![link(10, true, 0)],
            ..Default::default()
        };
        let doc = build_telemetry_json_from_stats(1_749_556_546_000, &snap);
        assert!(doc.contains("\"bytes_sent_total\":0"), "got {doc}");
        assert!(!doc.contains("null"), "got {doc}");
    }

    #[test]
    fn the_current_document_is_stamped_from_the_wall_clock() {
        // Given/When: a publish-time document.
        let doc = build_current_telemetry_json(&StatsSnapshot::default());
        let value: serde_json::Value = serde_json::from_str(&doc).expect("valid JSON");
        let stamped = value["last_updated_ms"].as_u64().expect("u64 ms");

        // Then: it agrees with an independent wall-clock read, so a consumer
        // diffing it against its own Date.now() measures real staleness.
        assert!(
            stamped.abs_diff(wall_clock_ms()) < 5_000,
            "last_updated_ms must be wall-clock: {stamped}"
        );
    }
}
