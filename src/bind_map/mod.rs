//! Optional versioned bind-map sidecar (ADR-003).
//!
//! `srtla_send` has always identified an uplink by its local source IP. That is
//! not enough on a real modem bond: two identical HiLink modems both present
//! `192.168.8.100`, and the pool builder silently collapses the second into the
//! first. This module adds the missing channel — a **separate, optional** JSON
//! sidecar (`--bind-map <path>`) that describes `BIND_IPS_FILE` positionally,
//! naming each row's stable `link_id` and its egress interface.
//!
//! Two properties are load-bearing:
//!
//! * **`BIND_IPS_FILE` stays byte-unchanged.** Without `--bind-map` this module
//!   is never entered and behavior is byte-identical to before.
//! * **Degradation never guesses.** An unusable map falls open (the stream keeps
//!   running) but never blindly collapses an ambiguous same-IP group — the
//!   ambiguity is reported instead.

mod coherence;
mod error;
mod parser;
mod report;
mod resolve;
mod retry;
mod status;

use std::path::Path;

pub use coherence::{IfaceOracle, StaticIfaces, SystemIfaces, ValidateCtx, validate_pair};
pub use error::BindMapError;
pub use parser::{
    BIND_MAP_SCHEMA_VERSION, BindMapDoc, BindMapRow, IfaceName, IpsFile, LinkId, MappedPool,
    parse_sidecar,
};
pub use report::{
    BindMapIdentity, BindMapReport, BindMapStatusRecord, CollisionRecord, DispositionRecord,
};
pub use resolve::{
    EffectiveLink, Resolution, ResolvePhase, resolve, resolve_absent, resolve_required,
    validate_required_pool,
};
pub use retry::{
    BIND_MAP_RETRY_ATTEMPTS, BIND_MAP_RETRY_BUDGET_MS, BIND_MAP_RETRY_DELAY_MS, BindMapPaths,
    PairRead, read_pair,
};
pub use status::{BindMapDisposition, BindMapStatus, CollisionGroup, DegradedReason};

/// Validate both files for `--dry-run`, returning the mapping that would apply.
///
/// `--dry-run` is the one place a degraded map is an error rather than a
/// fallback: the operator asked whether the configuration is valid, so answering
/// "it will limp" with exit 0 would defeat the flag.
pub async fn dry_run_validate(ips_file: &str, sidecar: &str) -> Result<MappedPool, BindMapError> {
    let oracle = SystemIfaces;
    let pair = read_pair(
        BindMapPaths {
            ips_file: Path::new(ips_file),
            sidecar: Path::new(sidecar),
        },
        ValidateCtx {
            ifaces: &oracle,
            prior: None,
        },
    )
    .await?;
    pair.map
}

/// Required binding depends on Linux device-and-source socket binding.
pub fn ensure_required_binding_supported() -> anyhow::Result<()> {
    anyhow::ensure!(cfg!(target_os = "linux"), "required binding needs Linux");
    Ok(())
}

#[cfg(test)]
mod required_platform_tests {
    #[test]
    fn required_binding_support_matches_the_platform() {
        assert_eq!(
            super::ensure_required_binding_supported().is_ok(),
            cfg!(target_os = "linux")
        );
    }
}
