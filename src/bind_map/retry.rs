//! Reading the pair off disk: symlink-safe sidecar access and the bounded retry
//! that absorbs the writer's publication window (ADR-003 §4.2, §5).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use tracing::{debug, warn};

use super::coherence::{ValidateCtx, validate_pair};
use super::error::BindMapError;
use super::parser::{IpsFile, MappedPool, parse_sidecar};
use super::status::DegradedReason;

/// Total read attempts: one initial read plus four retries.
pub const BIND_MAP_RETRY_ATTEMPTS: u32 = 5;
/// Pause between attempts.
pub const BIND_MAP_RETRY_DELAY_MS: u64 = 400;
/// Hard ceiling on the whole retry schedule. Startup and `SIGHUP` both run this
/// path, so an unbounded wait would hold the stream hostage to a writer bug.
pub const BIND_MAP_RETRY_BUDGET_MS: u64 = 2000;

/// The two paths a bind-map read needs.
#[derive(Debug, Clone, Copy)]
pub struct BindMapPaths<'a> {
    pub ips_file: &'a Path,
    pub sidecar: &'a Path,
}

/// One completed read: the IP file that was hashed, plus the mapping outcome
/// derived from exactly those bytes.
///
/// The IP file comes back even on failure so the caller can fail open against
/// the same content the digest was compared with.
#[derive(Debug)]
pub struct PairRead {
    pub ips: IpsFile,
    pub map: Result<MappedPool, BindMapError>,
    pub explicit_links: bool,
}

/// Read and validate the pair, retrying only a hash mismatch.
///
/// A mismatch is the one failure the writer's own publication window can
/// produce; every other rejection is a genuine content error that re-reading
/// cannot fix, so retrying it would only delay the report.
///
/// The outer `Err` is reserved for an unreadable `BIND_IPS_FILE` — at that point
/// the legacy path has nothing to run either.
pub async fn read_pair(
    paths: BindMapPaths<'_>,
    ctx: ValidateCtx<'_>,
) -> Result<PairRead, BindMapError> {
    let mut attempt = 1;
    loop {
        // Hash and parse the SAME bytes from the SAME read: reading twice would
        // let the file change in between and yield a digest describing content
        // the sender did not parse.
        let ips_bytes = std::fs::read(paths.ips_file).map_err(|e| BindMapError::Unreadable {
            path: paths.ips_file.display().to_string(),
            detail: e.to_string(),
        })?;
        let ips = IpsFile::from_bytes(&ips_bytes)?;

        let doc = read_sidecar_bytes(paths.sidecar).and_then(|bytes| parse_sidecar(&bytes));
        let explicit_links = doc.as_ref().is_ok_and(|doc| doc.explicit_links);
        let map = doc.and_then(|doc| validate_pair(&ips, doc, ctx));

        if matches!(map, Err(BindMapError::HashMismatch { .. })) {
            if attempt < BIND_MAP_RETRY_ATTEMPTS {
                debug!(
                    attempt,
                    "bind-map {} on attempt {attempt}; re-reading after \
                     {BIND_MAP_RETRY_DELAY_MS}ms",
                    DegradedReason::HashMismatch,
                );
                tokio::time::sleep(Duration::from_millis(BIND_MAP_RETRY_DELAY_MS)).await;
                attempt += 1;
                continue;
            }
            // Name the check that actually failed, not just the give-up class.
            // `retry_exhausted` alone would leave an operator guessing which of
            // the ten validation steps never converged, and this one has a
            // specific fix: the writer must publish the ips file BEFORE the
            // sidecar that names its digest.
            warn!(
                "bind-map {} persisted across all {attempt} attempt(s) \
                 (>{BIND_MAP_RETRY_BUDGET_MS}ms budget); degrading as {} and falling open",
                DegradedReason::HashMismatch,
                DegradedReason::RetryExhausted,
            );
            return Ok(PairRead {
                ips,
                explicit_links: false,
                map: Err(BindMapError::RetryExhausted { attempts: attempt }),
            });
        }

        return Ok(PairRead {
            ips,
            map,
            explicit_links,
        });
    }
}

/// Read the sidecar, refusing anything that is not a plainly-owned regular file.
///
/// The mapping decides where device traffic egresses, so a symlinked or
/// world-writable sidecar is refused rather than trusted. These checks apply to
/// the sidecar only — `BIND_IPS_FILE` keeps its existing, unchanged read path.
fn read_sidecar_bytes(path: &Path) -> Result<Vec<u8>, BindMapError> {
    let unreadable = |detail: String| BindMapError::Unreadable {
        path: path.display().to_string(),
        detail,
    };

    let mut file = open_no_follow(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => BindMapError::MissingFile {
            path: path.display().to_string(),
        },
        // O_NOFOLLOW reports a symlinked final component as ELOOP.
        _ => unreadable(e.to_string()),
    })?;

    let meta = file
        .metadata()
        .map_err(|e| unreadable(format!("stat failed: {e}")))?;
    if !meta.is_file() {
        return Err(unreadable("not a regular file".to_string()));
    }
    check_permissions(&meta).map_err(unreadable)?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| unreadable(e.to_string()))?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn check_permissions(meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(format!(
            "mode {:04o} is group- or world-writable; the mapping must be owned by the service \
             that writes it",
            mode & 0o7777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_meta: &std::fs::Metadata) -> Result<(), String> {
    Ok(())
}
