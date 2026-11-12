//! Where the sender's uplink set comes from, across startup and every reload.
//!
//! Two sources, and only one of them is new. Without `--bind-map` the sender
//! reads `BIND_IPS_FILE` exactly as it always has and every uplink is unmapped —
//! no hashing, no sidecar, no new failure mode. With `--bind-map` the same IP
//! file is read through the ADR-003 pair protocol, and the resolution decides
//! whether the mapping is in force, whether the last valid one is retained, or
//! whether the sender falls open to legacy behavior with the ambiguity named.
//!
//! This type owns the one piece of state that decision needs: the last mapping
//! actually applied. That is what distinguishes a startup degradation (nothing
//! to retain, so collisions are excluded and reported) from a reload degradation
//! (a live bond is already interface-pinned, so it is kept running).

use anyhow::Result;
use smallvec::SmallVec;
use tracing::{info, warn};

use super::connections::{specs_from_effective_links, specs_from_ips};
use crate::bind_map::{
    BindMapDisposition, BindMapError, BindMapPaths, BindMapReport, BindMapStatus, MappedPool,
    PairRead, ResolvePhase, SystemIfaces, ValidateCtx, read_pair, resolve, resolve_required,
};
use crate::net::UplinkSpec;
use crate::sender::read_ip_list;

/// The two file paths the sender's link set is derived from.
#[derive(Debug, Clone, Copy)]
pub struct SenderPaths<'a> {
    pub ips_file: &'a str,
    /// `None` means legacy: the bind-map module is never entered.
    pub bind_map: Option<&'a str>,
}

/// The outcome of one bind-map pair read: the IP file that was hashed, plus the
/// mapping derived from exactly those bytes.
///
/// Unix-only because its sole consumer is the `SIGHUP` reload channel, and
/// `SIGHUP` does not exist on Windows.
#[cfg(unix)]
pub type PairReadResult = Result<PairRead, BindMapError>;

/// Read the `(ips_file, sidecar)` pair off disk.
///
/// Free-standing and owning its arguments so a `SIGHUP` can run it on a spawned
/// task: the read is bounded but not instant (a hash mismatch is retried for up
/// to 2 s), and stalling the packet-forwarding loop for that long would be a
/// worse regression than a slightly later reload.
pub async fn read_bind_map(
    ips_file: String,
    sidecar: String,
    prior: Option<MappedPool>,
) -> Result<PairRead, BindMapError> {
    let oracle = SystemIfaces;
    read_pair(
        BindMapPaths {
            ips_file: std::path::Path::new(&ips_file),
            sidecar: std::path::Path::new(&sidecar),
        },
        ValidateCtx {
            ifaces: &oracle,
            prior: prior.as_ref(),
        },
    )
    .await
}

pub struct LinkSource {
    ips_file: String,
    sidecar: Option<String>,
    // Highest accepted candidate, including a queued candidate not yet applied.
    last_valid: Option<MappedPool>,
    applied: Option<MappedPool>,
    pending: Option<MappedPool>,
    require_bind_map: bool,
    report: BindMapReport,
}

impl LinkSource {
    #[must_use]
    pub fn new(paths: &SenderPaths<'_>) -> Self {
        Self {
            ips_file: paths.ips_file.to_string(),
            sidecar: paths.bind_map.map(ToString::to_string),
            last_valid: None,
            applied: None,
            pending: None,
            require_bind_map: false,
            // A legacy run never resolves, so the default is what it reports for
            // its whole lifetime: absent, running legacy, nothing excluded.
            report: BindMapReport::default(),
        }
    }

    /// Refuse all source-only fallback paths. A sidecar is mandatory.
    pub fn require_bind_map(&mut self) -> Result<()> {
        anyhow::ensure!(self.sidecar.is_some(), "required binding needs --bind-map");
        crate::bind_map::ensure_required_binding_supported()?;
        self.require_bind_map = true;
        Ok(())
    }

    #[must_use]
    pub fn is_mapped(&self) -> bool {
        self.sidecar.is_some()
    }

    /// The last resolution's telemetry projection (ADR-003 §6.4).
    #[must_use]
    pub fn report(&self) -> &BindMapReport {
        &self.report
    }

    /// The actual published pending projection, with applied state retained.
    #[must_use]
    pub fn pending_report(&self) -> BindMapReport {
        let mut report = self.report.clone();
        report.disposition.state = BindMapDisposition::PendingApply.as_str();
        report
    }

    /// Start a new required reload: invalidate queued application, retaining
    /// actual applied state and the monotonic accepted-generation watermark.
    pub fn begin_reload(&mut self) {
        if self.require_bind_map {
            self.pending = None;
            self.report.disposition.state = BindMapDisposition::PendingApply.as_str();
            self.report.bind_map_applied = self.applied.as_ref().map(Into::into);
            self.report.bind_map_pending = None;
        }
    }

    /// Call only after sockets/readers match the pending target (or at startup).
    pub fn finish_apply(&mut self) {
        if self.require_bind_map {
            if let Some(pool) = self.pending.take() {
                self.applied = Some(pool);
            }
            self.report.bind_map_applied = self.applied.as_ref().map(Into::into);
            self.report.bind_map_pending = None;
        }
    }

    fn retained_pool(&self) -> Option<&MappedPool> {
        if self.require_bind_map {
            self.applied.as_ref()
        } else {
            self.last_valid.as_ref()
        }
    }

    /// What a degradation leaves running: a live bond keeps its last valid
    /// mapped pool, a startup that never had one falls open to legacy.
    fn retention(&self) -> BindMapDisposition {
        if self.retained_pool().is_some() {
            BindMapDisposition::RetainedLastValid
        } else if self.require_bind_map {
            BindMapDisposition::RequiredBindingRefused
        } else {
            BindMapDisposition::LegacyUniqueOnly
        }
    }

    /// Only a validated empty mapping in required mode authorizes withdrawal.
    /// A degraded read (including an unreadable IP file) always retains.
    #[must_use]
    pub fn accepts_empty_reload(&self) -> bool {
        self.require_bind_map
            && self.report.bind_map_status.state == BindMapStatus::Active.state_str()
            && self
                .last_valid
                .as_ref()
                .is_some_and(|pool| pool.rows.is_empty())
    }

    /// The arguments a spawned reload read needs.
    #[must_use]
    pub fn read_args(&self) -> Option<(String, String, Option<MappedPool>)> {
        let sidecar = self.sidecar.clone()?;
        Some((self.ips_file.clone(), sidecar, self.last_valid.clone()))
    }

    /// The uplink set to start with.
    ///
    /// The `Err` arm is reserved for an unreadable `BIND_IPS_FILE`, matching the
    /// legacy contract: an empty start is not fatal, it waits for a `SIGHUP`.
    pub async fn startup(&mut self) -> Result<SmallVec<UplinkSpec, 4>> {
        let Some((ips_file, sidecar, prior)) = self.read_args() else {
            return Ok(specs_from_ips(&read_ip_list(&self.ips_file).await?));
        };
        let read = read_bind_map(ips_file, sidecar, prior).await;
        Ok(self.adopt(read))
    }

    /// Turn a completed pair read into the uplink set, remembering the mapping
    /// when it was valid.
    pub fn adopt(&mut self, read: Result<PairRead, BindMapError>) -> SmallVec<UplinkSpec, 4> {
        let pair = match read {
            Ok(pair) => pair,
            Err(err) => {
                warn!("bind-map read failed: {err}");
                // The outer Err means BIND_IPS_FILE itself was unusable, so no
                // resolution ran. Report the degradation anyway — leaving the
                // previous status standing would tell a UI the map is still
                // active while the sender is running on nothing new.
                self.report = BindMapReport::degraded(err.reason(), self.retention());
                self.report.bind_map_applied = self.applied.as_ref().map(Into::into);
                self.pending = None;
                return SmallVec::new();
            }
        };
        let mut outcome = pair.map;
        if self.require_bind_map
            && let (Ok(pool), Some(prior)) = (&outcome, &self.last_valid)
            && (pool.generation < prior.generation
                || (pool.generation == prior.generation && pool != prior))
        {
            outcome = Err(BindMapError::StaleGeneration {
                generation: pool.generation,
            });
        }
        let phase = match self.retained_pool() {
            Some(last_valid) => ResolvePhase::Reload { last_valid },
            None => ResolvePhase::Startup,
        };
        let resolution = if self.require_bind_map {
            resolve_required(outcome, &pair.ips, phase)
        } else {
            resolve(outcome, &pair.ips, phase)
        };
        self.report = BindMapReport::from(&resolution);
        log_outcome(resolution.status, resolution.disposition);
        for group in &resolution.excluded {
            warn!(
                "bind-map unusable: source IP {} is claimed by {} uplink(s); running line {} and \
                 excluding line(s) {:?} — the excluded modem(s) will carry no traffic until a \
                 coherent bind-map is published",
                group.ip,
                group.excluded_indices.len() + 1,
                group.effective_index,
                group.excluded_indices
            );
        }
        let specs = specs_from_effective_links(&resolution.links);
        self.pending = None;
        if let Some(applied) = resolution.applied {
            if self.require_bind_map {
                self.pending = Some(applied.clone());
            }
            self.last_valid = Some(applied);
        }
        if self.require_bind_map {
            self.report.bind_map_applied = self.applied.as_ref().map(Into::into);
            self.report.bind_map_pending = self.pending.as_ref().map(Into::into);
        }
        specs
    }
}

fn log_outcome(status: BindMapStatus, disposition: BindMapDisposition) {
    let disposition = disposition.as_str();
    match status {
        BindMapStatus::Active => info!("bind-map active ({disposition})"),
        BindMapStatus::Absent => info!("bind-map absent ({disposition})"),
        BindMapStatus::Degraded(reason) => {
            warn!("bind-map degraded: {reason} ({disposition})");
        }
    }
}
