//! The telemetry-facing projection of an ADR-003 bind-map decision (§6.4).
//!
//! Telemetry needs only the *observable* part of that decision — is the map in
//! force, what is actually running, and which same-IP group had to be broken up
//! — in a shape a UI can render without inferring anything from log text.
//!
//! Nothing here re-derives state. Every value is read straight off the
//! [`BindMapStatus`] / [`BindMapDisposition`] / [`CollisionGroup`] tokens, so a
//! UI and a log line can never disagree about what the sender is doing. The
//! resolver's own [`Resolution`] funnels through [`BindMapReport::new`] rather
//! than re-deriving anything of its own.

use serde::Serialize;

use super::resolve::Resolution;
use super::status::{BindMapDisposition, BindMapStatus, CollisionGroup, DegradedReason};

/// Is the map in force, and if not, why not?
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindMapStatusRecord {
    /// `active` | `absent` | `degraded`.
    pub state: &'static str,
    /// One of the seven degraded reasons; absent unless `state` is `degraded`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl Default for BindMapStatusRecord {
    /// No `--bind-map` was supplied, which is the shipped default.
    fn default() -> Self {
        Self::from(BindMapStatus::Absent)
    }
}

impl From<BindMapStatus> for BindMapStatusRecord {
    fn from(status: BindMapStatus) -> Self {
        Self {
            state: status.state_str(),
            reason: status.reason().map(DegradedReason::as_str),
        }
    }
}

/// One same-IP group that a degraded startup could not disambiguate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollisionRecord {
    pub ip: String,
    pub effective_index: usize,
    pub excluded_indices: Vec<usize>,
}

impl From<&CollisionGroup> for CollisionRecord {
    fn from(group: &CollisionGroup) -> Self {
        Self {
            ip: group.ip.to_string(),
            effective_index: group.effective_index,
            excluded_indices: group.excluded_indices.clone(),
        }
    }
}

/// What is the sender actually running, and at whose expense?
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispositionRecord {
    /// `mapped` | `retained_last_valid` | `legacy_unique_only` | `startup_collision_excluded` | `pending_apply`.
    pub state: &'static str,
    /// The groups a `startup_collision_excluded` disposition cost. Empty for
    /// every other disposition, and omitted from the JSON when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub collisions: Vec<CollisionRecord>,
}

impl Default for DispositionRecord {
    /// Legacy behavior with no ambiguity, which is the shipped default.
    fn default() -> Self {
        Self {
            state: BindMapDisposition::LegacyUniqueOnly.as_str(),
            collisions: Vec::new(),
        }
    }
}

/// The pair of typed fields telemetry publishes at the top level of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct BindMapReport {
    pub bind_map_status: BindMapStatusRecord,
    pub disposition: DispositionRecord,
}

impl BindMapReport {
    #[must_use]
    pub fn new(
        status: BindMapStatus,
        disposition: BindMapDisposition,
        excluded: &[CollisionGroup],
    ) -> Self {
        Self {
            bind_map_status: BindMapStatusRecord::from(status),
            disposition: DispositionRecord {
                state: disposition.as_str(),
                collisions: excluded.iter().map(CollisionRecord::from).collect(),
            },
        }
    }

    /// A degradation that never reached a resolution — the outer failure arm of
    /// a pair read, where `BIND_IPS_FILE` itself was unusable so there was no
    /// link set to resolve against.
    #[must_use]
    pub fn degraded(reason: DegradedReason, disposition: BindMapDisposition) -> Self {
        Self::new(BindMapStatus::Degraded(reason), disposition, &[])
    }
}

impl From<&Resolution> for BindMapReport {
    fn from(resolution: &Resolution) -> Self {
        Self::new(
            resolution.status,
            resolution.disposition,
            &resolution.excluded,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(report: &BindMapReport) -> String {
        serde_json::to_string(report).expect("the report is plain scalars")
    }

    #[test]
    fn the_default_report_is_the_legacy_unmapped_run() {
        assert_eq!(
            json(&BindMapReport::default()),
            r#"{"bind_map_status":{"state":"absent"},"disposition":{"state":"legacy_unique_only"}}"#
        );
    }

    #[test]
    fn a_non_degraded_status_omits_the_reason_key_entirely() {
        let active = BindMapReport::new(BindMapStatus::Active, BindMapDisposition::Mapped, &[]);
        assert!(
            !json(&active).contains("reason"),
            "an active map must not carry a degraded reason"
        );
    }

    #[test]
    fn a_degraded_reload_says_degraded_and_still_pinned() {
        let report = BindMapReport::degraded(
            DegradedReason::HashMismatch,
            BindMapDisposition::RetainedLastValid,
        );
        assert_eq!(
            json(&report),
            r#"{"bind_map_status":{"state":"degraded","reason":"hash_mismatch"},"disposition":{"state":"retained_last_valid"}}"#
        );
    }

    #[test]
    fn a_degraded_startup_publishes_the_group_it_broke_up() {
        // Given: two modems on one IP that the degraded read could not tell
        // apart, so the second line was excluded.
        let group = CollisionGroup {
            ip: "192.168.8.100".parse().expect("fixture IP"),
            effective_index: 0,
            excluded_indices: vec![1],
        };

        // When: projected for telemetry.
        let report = BindMapReport::new(
            BindMapStatus::Degraded(DegradedReason::RetryExhausted),
            BindMapDisposition::StartupCollisionExcluded,
            std::slice::from_ref(&group),
        );

        // Then: the excluded IP-list line positions ride along, so a UI can
        // explain "two modems, one link" without reading a log.
        let doc = json(&report);
        assert!(
            doc.contains(r#""state":"startup_collision_excluded""#),
            "{doc}"
        );
        assert!(doc.contains(r#""ip":"192.168.8.100""#), "{doc}");
        assert!(doc.contains(r#""effective_index":0"#), "{doc}");
        assert!(doc.contains(r#""excluded_indices":[1]"#), "{doc}");
    }
}
