//! The frozen ADR-003 §6.4 operating-mode vocabulary.
//!
//! These tokens are a wire contract, not internal naming: they are echoed
//! verbatim into the ADR-001 telemetry document so a UI renders what the sender
//! is actually doing from typed data instead of scraping a log line. Each token
//! is spelled exactly once, here, so the log and the snapshot can never drift.
//!
//! The types the resolver produces around them (`EffectiveLink`, `Resolution`,
//! the sidecar reader) land with the rest of ADR-003; only the vocabulary and
//! the collision group it reports are needed to serialize a document.

use std::fmt;
use std::net::IpAddr;

/// The operator-visible reason a configured bind-map is not in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedReason {
    /// The sidecar's digest did not name the `BIND_IPS_FILE` content on disk.
    HashMismatch,
    /// Bad JSON, bad header, bad row, bad correspondence, or a stale generation.
    Malformed,
    /// A row names an interface that does not exist on this host.
    UnknownIface,
    /// A hash mismatch persisted past the bounded retry budget.
    RetryExhausted,
    /// The sidecar path does not exist.
    MissingFile,
    /// I/O error, symlink, non-regular file, or unsafe permissions.
    Unreadable,
    /// A `schema_version` this build does not implement.
    Unsupported,
}

impl DegradedReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash_mismatch",
            Self::Malformed => "malformed",
            Self::UnknownIface => "unknown_iface",
            Self::RetryExhausted => "retry_exhausted",
            Self::MissingFile => "missing_file",
            Self::Unreadable => "unreadable",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for DegradedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Is a configured bind-map in force?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMapStatus {
    /// A coherent, valid pair is applied.
    Active,
    /// `--bind-map` was not supplied.
    Absent,
    /// The map is configured but not in force.
    Degraded(DegradedReason),
}

impl BindMapStatus {
    #[must_use]
    pub const fn state_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Absent => "absent",
            Self::Degraded(_) => "degraded",
        }
    }

    #[must_use]
    pub const fn reason(self) -> Option<DegradedReason> {
        match self {
            Self::Degraded(reason) => Some(reason),
            Self::Active | Self::Absent => None,
        }
    }
}

/// What is the sender actually running, and at whose expense?
///
/// Orthogonal to [`BindMapStatus`]: a degraded RELOAD keeps the last valid
/// mapped pool alive, while a degraded STARTUP has nothing to retain and
/// excludes the ambiguous rows instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMapDisposition {
    /// The map is in force.
    Mapped,
    /// A degraded reload was rejected; the last valid mapped pool still runs.
    RetainedLastValid,
    /// Legacy behavior; no collision groups were present.
    LegacyUniqueOnly,
    /// Degraded at startup with at least one collision group.
    StartupCollisionExcluded,
    /// Required binding has no valid mapping; no uplinks run.
    RequiredBindingRefused,
    /// A required-mode reload request is being read or applied.
    PendingApply,
}

impl BindMapDisposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequiredBindingRefused => "required_binding_refused",
            Self::PendingApply => "pending_apply",
            Self::Mapped => "mapped",
            Self::RetainedLastValid => "retained_last_valid",
            Self::LegacyUniqueOnly => "legacy_unique_only",
            Self::StartupCollisionExcluded => "startup_collision_excluded",
        }
    }
}

/// An ambiguous same-IP group that degraded startup could not disambiguate.
///
/// The indices are `BIND_IPS_FILE` line positions, **not** telemetry `conn_id`s:
/// an excluded line never becomes a connection, so the two numberings diverge
/// exactly when this record is non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionGroup {
    pub ip: IpAddr,
    /// Index of the row that runs — always the first occurrence in file order.
    pub effective_index: usize,
    /// Indices of the rows that do not run.
    pub excluded_indices: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seven_degraded_reasons_are_the_frozen_adr_003_tokens() {
        let tokens: Vec<&str> = [
            DegradedReason::HashMismatch,
            DegradedReason::Malformed,
            DegradedReason::UnknownIface,
            DegradedReason::RetryExhausted,
            DegradedReason::MissingFile,
            DegradedReason::Unreadable,
            DegradedReason::Unsupported,
        ]
        .iter()
        .map(|r| r.as_str())
        .collect();
        assert_eq!(
            tokens,
            [
                "hash_mismatch",
                "malformed",
                "unknown_iface",
                "retry_exhausted",
                "missing_file",
                "unreadable",
                "unsupported"
            ]
        );
    }

    #[test]
    fn only_a_degraded_status_carries_a_reason() {
        assert_eq!(BindMapStatus::Active.state_str(), "active");
        assert_eq!(BindMapStatus::Absent.state_str(), "absent");
        assert_eq!(BindMapStatus::Active.reason(), None);
        assert_eq!(BindMapStatus::Absent.reason(), None);

        let degraded = BindMapStatus::Degraded(DegradedReason::HashMismatch);
        assert_eq!(degraded.state_str(), "degraded");
        assert_eq!(degraded.reason(), Some(DegradedReason::HashMismatch));
    }

    #[test]
    fn the_four_dispositions_are_the_frozen_adr_003_tokens() {
        assert_eq!(BindMapDisposition::Mapped.as_str(), "mapped");
        assert_eq!(
            BindMapDisposition::RetainedLastValid.as_str(),
            "retained_last_valid"
        );
        assert_eq!(
            BindMapDisposition::LegacyUniqueOnly.as_str(),
            "legacy_unique_only"
        );
        assert_eq!(
            BindMapDisposition::StartupCollisionExcluded.as_str(),
            "startup_collision_excluded"
        );
    }
}
