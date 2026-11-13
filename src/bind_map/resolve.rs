//! Fail-open, duplicate-safe resolution (ADR-003 §6).
//!
//! Fail-open means "keep streaming". It does not mean "guess". The naive
//! fallback — no map, so collapse duplicate IPs and carry on — is exactly the
//! silent-collapse bug this contract exists to fix, so degradation never
//! blindly collapses an ambiguous group.
//!
//! Startup and reload get different answers because they have different
//! material: startup has nothing to retain, reload has a known-good pool.
//!
//! The vocabulary this module decides in ([`BindMapStatus`],
//! [`BindMapDisposition`], [`CollisionGroup`]) is spelled once in
//! [`super::status`]; nothing here re-declares it.

use std::collections::HashMap;
use std::net::IpAddr;

use super::error::BindMapError;
use super::parser::{IfaceName, IpsFile, LinkId, MappedPool};
use super::status::{BindMapDisposition, BindMapStatus, CollisionGroup, DegradedReason};

/// One uplink the sender should actually run.
///
/// `iface` and `link_id` are `None` whenever the sender had to fall back — a
/// degraded read never invents a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveLink {
    pub ip: IpAddr,
    pub iface: Option<IfaceName>,
    pub link_id: Option<LinkId>,
}

/// Which side of the "have we ever applied a valid map?" line we are on.
pub enum ResolvePhase<'a> {
    /// No valid map has been applied yet.
    Startup,
    /// A valid map is already running.
    Reload { last_valid: &'a MappedPool },
}

/// The typed decision: what runs, under what status, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub status: BindMapStatus,
    pub disposition: BindMapDisposition,
    pub links: Vec<EffectiveLink>,
    pub excluded: Vec<CollisionGroup>,
    /// The pool the caller must remember. `Some` iff `status == Active`.
    pub applied: Option<MappedPool>,
}

/// `--bind-map` was not supplied: byte-identical legacy behavior.
///
/// Every accepted IP is handed on in file order, **duplicates included** —
/// deduplication is the legacy pool builder's job, and filtering here would
/// change shipped behavior.
#[must_use]
pub fn resolve_absent(ips: &IpsFile) -> Resolution {
    Resolution {
        status: BindMapStatus::Absent,
        disposition: BindMapDisposition::LegacyUniqueOnly,
        links: ips
            .accepted()
            .iter()
            .map(|ip| EffectiveLink {
                ip: *ip,
                iface: None,
                link_id: None,
            })
            .collect(),
        excluded: Vec::new(),
        applied: None,
    }
}

/// Turn a read outcome into the sender's operating decision.
#[must_use]
pub fn resolve(
    outcome: Result<MappedPool, BindMapError>,
    ips: &IpsFile,
    phase: ResolvePhase<'_>,
) -> Resolution {
    match outcome {
        Ok(pool) => Resolution {
            status: BindMapStatus::Active,
            disposition: BindMapDisposition::Mapped,
            links: pool
                .rows
                .iter()
                .map(|row| EffectiveLink {
                    ip: row.ip,
                    iface: Some(row.iface.clone()),
                    link_id: Some(row.link_id.clone()),
                })
                .collect(),
            excluded: Vec::new(),
            applied: Some(pool),
        },
        Err(err) => degrade(err.reason(), ips, phase),
    }
}

/// Validate the concrete-source contract shared by runtime and dry-run.
pub fn validate_required_pool(pool: MappedPool) -> Result<MappedPool, BindMapError> {
    if pool.generation > 9_007_199_254_740_991 {
        return Err(BindMapError::InvalidHeader {
            field: "generation",
            detail: "required binding needs a positive safe-integer generation".into(),
        });
    }
    let mut sources = std::collections::HashSet::new();
    for (index, row) in pool.rows.iter().enumerate() {
        if !sources.insert((row.ip.to_canonical(), row.iface.clone())) {
            return Err(BindMapError::DuplicatePair {
                index,
                ip: row.ip,
                iface: row.iface.as_str().to_string(),
            });
        }
        crate::net::source::validate_source(row.ip, row.iface.as_str()).map_err(|err| {
            BindMapError::InvalidRow {
                index,
                field: "ip",
                detail: format!("required binding needs a concrete source address: {err}"),
            }
        })?;
    }
    Ok(pool)
}

/// Required-binding variant: a degraded first read never creates source-only links.
/// Once a valid mapping exists, reload retains its source and device bindings.
#[must_use]
pub fn resolve_required(
    outcome: Result<MappedPool, BindMapError>,
    ips: &IpsFile,
    phase: ResolvePhase<'_>,
) -> Resolution {
    let outcome = outcome.and_then(validate_required_pool);
    if let (Err(err), ResolvePhase::Startup) = (&outcome, &phase) {
        return Resolution {
            status: BindMapStatus::Degraded(err.reason()),
            disposition: BindMapDisposition::RequiredBindingRefused,
            links: Vec::new(),
            excluded: Vec::new(),
            applied: None,
        };
    }
    resolve(outcome, ips, phase)
}

fn degrade(reason: DegradedReason, ips: &IpsFile, phase: ResolvePhase<'_>) -> Resolution {
    match phase {
        // A live bond already has interface bindings. Falling back to legacy
        // would silently un-bind every one of them, which is worse than running
        // the last known-good mapping until a coherent pair arrives.
        ResolvePhase::Reload { last_valid } => Resolution {
            status: BindMapStatus::Degraded(reason),
            disposition: BindMapDisposition::RetainedLastValid,
            links: last_valid
                .rows
                .iter()
                .map(|row| EffectiveLink {
                    ip: row.ip,
                    iface: Some(row.iface.clone()),
                    link_id: Some(row.link_id.clone()),
                })
                .collect(),
            excluded: Vec::new(),
            applied: None,
        },
        ResolvePhase::Startup => {
            let (links, excluded) = exclude_collisions(ips.accepted());
            let disposition = if excluded.is_empty() {
                BindMapDisposition::LegacyUniqueOnly
            } else {
                BindMapDisposition::StartupCollisionExcluded
            };
            Resolution {
                status: BindMapStatus::Degraded(reason),
                disposition,
                links,
                excluded,
                applied: None,
            }
        }
    }
}

/// Keep one deterministic representative per IP — the first occurrence in file
/// order — and report every row that therefore does not run.
///
/// The *effective* link set here equals what legacy would have produced. The
/// difference is that the ambiguity is named instead of silently swallowed: an
/// operator with two modems and one visible link gets told why.
fn exclude_collisions(accepted: &[IpAddr]) -> (Vec<EffectiveLink>, Vec<CollisionGroup>) {
    let mut first_seen: HashMap<IpAddr, usize> = HashMap::new();
    let mut links = Vec::new();
    let mut groups: Vec<CollisionGroup> = Vec::new();

    for (index, ip) in accepted.iter().enumerate() {
        match first_seen.get(ip) {
            None => {
                first_seen.insert(*ip, index);
                links.push(EffectiveLink {
                    ip: *ip,
                    iface: None,
                    link_id: None,
                });
            }
            Some(&effective_index) => match groups.iter_mut().find(|g| g.ip == *ip) {
                Some(group) => group.excluded_indices.push(index),
                None => groups.push(CollisionGroup {
                    ip: *ip,
                    effective_index,
                    excluded_indices: vec![index],
                }),
            },
        }
    }

    (links, groups)
}

#[cfg(test)]
mod required_tests {
    use super::*;

    #[test]
    fn degraded_startup_never_returns_source_only_links() {
        for bytes in [b"10.0.0.9\n".as_slice(), b"10.0.0.9\n10.0.0.9\n".as_slice()] {
            let ips = IpsFile::from_bytes(bytes).unwrap();
            for error in [
                BindMapError::MissingFile { path: "map".into() },
                BindMapError::UnknownIface {
                    index: 0,
                    iface: "wwan0".into(),
                },
                BindMapError::RetryExhausted { attempts: 5 },
                BindMapError::MalformedJson("invalid".into()),
            ] {
                let reason = error.reason();
                let result = resolve_required(Err(error), &ips, ResolvePhase::Startup);
                assert_eq!(result.status, BindMapStatus::Degraded(reason));
                assert_eq!(
                    result.disposition,
                    BindMapDisposition::RequiredBindingRefused
                );
                assert!(result.links.is_empty());
                assert!(result.applied.is_none());
            }
        }
    }
}
