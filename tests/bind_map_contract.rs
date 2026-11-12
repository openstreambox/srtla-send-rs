//! Filesystem- and process-level halves of the bind-map contract (ADR-003).
//!
//! The in-crate suites cover the pure parser and the fail-open state machine.
//! What can only be proven here: the writer's two-rename publication window, the
//! bounded retry that absorbs it, the sidecar's symlink/permission refusals, and
//! — at the real process boundary — that a run *without* `--bind-map` produces
//! byte-identical output to the pre-ADR-003 binary.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use srtla_send::bind_map::{
    BIND_MAP_RETRY_BUDGET_MS, BindMapError, BindMapPaths, IpsFile, StaticIfaces, ValidateCtx,
    read_pair,
};

const IPS_A: &str = "192.168.8.100\n192.168.8.100\n";
const IPS_B: &str = "192.168.8.100\n192.168.8.100\n10.0.0.9\n";

fn sha_of(contents: &str) -> String {
    IpsFile::from_bytes(contents.as_bytes())
        .expect("fixture parses")
        .sha256()
        .to_string()
}

fn sidecar_for(contents: &str, generation: u64) -> String {
    let rows: Vec<String> = IpsFile::from_bytes(contents.as_bytes())
        .expect("fixture parses")
        .accepted()
        .iter()
        .enumerate()
        .map(|(i, ip)| format!(r#"{{"link_id":"link-{i}","ip":"{ip}","iface":"wwan{i}"}}"#))
        .collect();
    format!(
        r#"{{"schema_version":1,"generation":{generation},"ips_file_sha256":"{}","links":[{}]}}"#,
        sha_of(contents),
        rows.join(",")
    )
}

fn oracle() -> StaticIfaces {
    StaticIfaces::new(["wwan0", "wwan1", "wwan2"])
}

/// Publish a file the way the ADR requires: unique temp sibling, then rename.
fn publish(target: &Path, contents: &str) {
    let tmp = target.with_extension(format!("{}.0.tmp", std::process::id()));
    std::fs::write(&tmp, contents).expect("write temp sibling");
    std::fs::rename(&tmp, target).expect("atomic rename into place");
}

async fn read(
    dir: &Path,
) -> Result<Result<srtla_send::bind_map::MappedPool, BindMapError>, BindMapError> {
    let ifaces = oracle();
    let pair = read_pair(
        BindMapPaths {
            ips_file: &dir.join("srtla_ips"),
            sidecar: &dir.join("bind_map.json"),
        },
        ValidateCtx {
            ifaces: &ifaces,
            prior: None,
        },
    )
    .await?;
    Ok(pair.map)
}

// ---- the publication window ------------------------------------------

#[tokio::test]
async fn a_coherently_published_pair_reads_as_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    publish(&dir.path().join("srtla_ips"), IPS_A);
    publish(&dir.path().join("bind_map.json"), &sidecar_for(IPS_A, 1));

    let pool = read(dir.path())
        .await
        .expect("ips file is readable")
        .expect("a coherent pair is valid");
    assert_eq!(pool.generation, 1);
    assert_eq!(pool.rows.len(), 2);
    assert_eq!(pool.rows[0].iface.as_str(), "wwan0");
    assert_eq!(
        pool.rows[1].iface.as_str(),
        "wwan1",
        "the twin rows are told apart positionally, not by IP"
    );
}

#[tokio::test]
async fn the_bounded_retry_absorbs_the_window_between_the_two_renames() {
    // The writer commits the ips file first, so a reader landing between the two
    // renames sees NEW ips bytes + OLD sidecar. That is a DETECTABLE transient
    // mismatch, and absorbing it is the entire reason the retry exists.
    let dir = tempfile::tempdir().expect("tempdir");
    let ips = dir.path().join("srtla_ips");
    let sidecar = dir.path().join("bind_map.json");

    publish(&ips, IPS_A);
    publish(&sidecar, &sidecar_for(IPS_A, 1));
    publish(&ips, IPS_B); // first rename lands; the sidecar still names IPS_A

    let path = sidecar.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        publish(&path, &sidecar_for(IPS_B, 2)); // the COMMIT POINT
    });

    let started = Instant::now();
    let pool = read(dir.path())
        .await
        .expect("ips file is readable")
        .expect("the retry must absorb the publication window");

    assert_eq!(pool.generation, 2);
    assert_eq!(pool.rows.len(), 3, "the reader converged on the NEW pair");
    assert!(
        started.elapsed().as_millis() as u64 <= BIND_MAP_RETRY_BUDGET_MS,
        "the retry must stay inside its budget"
    );
}

#[tokio::test]
async fn a_mismatch_that_outlives_the_budget_reports_retry_exhausted() {
    let dir = tempfile::tempdir().expect("tempdir");
    publish(&dir.path().join("srtla_ips"), IPS_B);
    // A sidecar that permanently names different content — a writer bug, not a window.
    publish(&dir.path().join("bind_map.json"), &sidecar_for(IPS_A, 1));

    let started = Instant::now();
    let err = read(dir.path())
        .await
        .expect("ips file is readable")
        .expect_err("a permanent mismatch is not a transient window");

    assert!(
        matches!(err, BindMapError::RetryExhausted { .. }),
        "expected retry exhaustion, got {err:?}"
    );
    let elapsed = started.elapsed().as_millis() as u64;
    assert!(
        elapsed <= BIND_MAP_RETRY_BUDGET_MS,
        "the retry schedule ran {elapsed}ms, past its {BIND_MAP_RETRY_BUDGET_MS}ms ceiling"
    );
}

// ---- sidecar read safety ---------------------------------------------

#[tokio::test]
async fn an_absent_sidecar_reports_missing_file_rather_than_a_parse_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    publish(&dir.path().join("srtla_ips"), IPS_A);

    let err = read(dir.path())
        .await
        .expect("ips file is readable")
        .expect_err("no sidecar means no mapping");
    assert!(
        matches!(err, BindMapError::MissingFile { .. }),
        "expected missing-file, got {err:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_sidecar_is_refused() {
    // The mapping decides where device traffic egresses, so the path must not be
    // redirectable at a file the service never wrote.
    let dir = tempfile::tempdir().expect("tempdir");
    publish(&dir.path().join("srtla_ips"), IPS_A);

    let real = dir.path().join("elsewhere.json");
    std::fs::write(&real, sidecar_for(IPS_A, 1)).expect("write link target");
    std::os::unix::fs::symlink(&real, dir.path().join("bind_map.json")).expect("symlink");

    let err = read(dir.path())
        .await
        .expect("ips file is readable")
        .expect_err("a symlinked sidecar must be refused");
    assert!(
        matches!(err, BindMapError::Unreadable { .. }),
        "expected unreadable, got {err:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_world_writable_sidecar_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    publish(&dir.path().join("srtla_ips"), IPS_A);
    let sidecar = dir.path().join("bind_map.json");
    publish(&sidecar, &sidecar_for(IPS_A, 1));
    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o666))
        .expect("loosen perms");

    let err = read(dir.path())
        .await
        .expect("ips file is readable")
        .expect_err("an anyone-writable mapping must be refused");
    assert!(
        matches!(err, BindMapError::Unreadable { .. }),
        "expected unreadable, got {err:?}"
    );

    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o644))
        .expect("restore perms");
    read(dir.path())
        .await
        .expect("ips file is readable")
        .expect("service-owned perms read fine");
}

// ---- the parity guarantee, at the process boundary -------------------

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");

#[test]
fn a_legacy_invocation_without_bind_map_produces_byte_identical_output() {
    // Four positionals + an IP-only file. Any deviation here is a parity break,
    // so the expected stdout is pinned literally rather than pattern-matched.
    let ips = tempfile::NamedTempFile::new().expect("temp ips file");
    std::fs::write(ips.path(), "10.0.0.1\n10.0.1.2\n").expect("write ips");

    let out = Command::new(BIN)
        .args([
            "5000",
            "127.0.0.1",
            "5001",
            ips.path().to_str().unwrap(),
            "--dry-run",
        ])
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn srtla_send");

    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "dry-run: configuration valid; no sockets bound\nreceiver 127.0.0.1:5001 resolves to 1 \
         address(es):\n\x20 127.0.0.1:5001\nsource uplink IPs (2):\n\x20 10.0.0.1\n\x20 10.0.1.2\n",
        "the legacy dry-run output must not gain a single byte from the bind-map work"
    );
}

#[test]
fn dry_run_validates_the_sidecar_too_and_refuses_an_unusable_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ips = dir.path().join("srtla_ips");
    let sidecar = dir.path().join("bind_map.json");
    std::fs::write(&ips, "10.0.0.1\n").expect("write ips");
    std::fs::write(&sidecar, r#"{"schema_version":1,"generation":1}"#).expect("write sidecar");

    let out = Command::new(BIN)
        .args([
            "5000",
            "127.0.0.1",
            "5001",
            ips.to_str().unwrap(),
            "--dry-run",
            "--bind-map",
            sidecar.to_str().unwrap(),
        ])
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn srtla_send");

    assert!(
        !out.status.success(),
        "--dry-run exists to answer 'is this configuration valid?'; a broken map is a no"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bind-map") && stderr.contains("unusable"),
        "the failure must name the sidecar; got: {stderr}"
    );
    assert!(
        stderr.contains("malformed"),
        "the ADR-003 degraded reason must be reported verbatim; got: {stderr}"
    );
}

// Required-binding startup and reload use the same pair validator as production.
#[tokio::test]
async fn required_binding_refuses_unique_and_duplicate_sources_without_a_map() {
    use srtla_send::bind_map::{BindMapDisposition, BindMapReport, ResolvePhase, resolve_required};
    for contents in ["10.0.0.9\n", IPS_A] {
        let dir = tempfile::tempdir().unwrap();
        publish(&dir.path().join("srtla_ips"), contents);
        let pair = read_pair(
            BindMapPaths {
                ips_file: &dir.path().join("srtla_ips"),
                sidecar: &dir.path().join("missing.json"),
            },
            ValidateCtx {
                ifaces: &oracle(),
                prior: None,
            },
        )
        .await
        .unwrap();
        let resolution = resolve_required(pair.map, &pair.ips, ResolvePhase::Startup);
        assert!(resolution.links.is_empty());
        assert!(resolution.applied.is_none());
        assert_eq!(
            resolution.disposition,
            BindMapDisposition::RequiredBindingRefused
        );
        let report = BindMapReport::from(&resolution);
        assert_eq!(report.bind_map_status.state, "degraded");
        assert_eq!(report.bind_map_status.reason, Some("missing_file"));
    }
}

#[tokio::test]
async fn required_binding_missing_device_then_appears_and_degraded_reload_retains_twins() {
    use srtla_send::bind_map::{BindMapDisposition, ResolvePhase, resolve_required};
    let dir = tempfile::tempdir().unwrap();
    publish(&dir.path().join("srtla_ips"), IPS_A);
    publish(&dir.path().join("bind_map.json"), &sidecar_for(IPS_A, 1));
    let absent = StaticIfaces::new(["wwan0"]);
    let paths = BindMapPaths {
        ips_file: &dir.path().join("srtla_ips"),
        sidecar: &dir.path().join("bind_map.json"),
    };
    let pair = read_pair(
        paths,
        ValidateCtx {
            ifaces: &absent,
            prior: None,
        },
    )
    .await
    .unwrap();
    let refused = resolve_required(pair.map, &pair.ips, ResolvePhase::Startup);
    assert!(
        refused.links.is_empty(),
        "one missing device refuses the entire pair"
    );
    assert_eq!(refused.status.reason().unwrap().as_str(), "unknown_iface");
    // Device arrival alone does not publish a map: a fresh read (SIGHUP) does.
    let pair = read_pair(
        paths,
        ValidateCtx {
            ifaces: &oracle(),
            prior: None,
        },
    )
    .await
    .unwrap();
    let active = resolve_required(pair.map, &pair.ips, ResolvePhase::Startup);
    assert_eq!(active.links.len(), 2);
    assert_eq!(active.links[0].ip, active.links[1].ip);
    assert_ne!(active.links[0].iface, active.links[1].iface);
    assert!(
        active
            .links
            .iter()
            .all(|link| link.iface.is_some() && link.link_id.is_some())
    );
    let prior = active.applied.unwrap();
    let pair = read_pair(
        paths,
        ValidateCtx {
            ifaces: &absent,
            prior: Some(&prior),
        },
    )
    .await
    .unwrap();
    let retained = resolve_required(
        pair.map,
        &pair.ips,
        ResolvePhase::Reload { last_valid: &prior },
    );
    assert_eq!(retained.disposition, BindMapDisposition::RetainedLastValid);
    assert_eq!(retained.links, active.links);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn required_link_source_stays_empty_until_a_valid_pair_is_published() {
    use srtla_send::sender::{LinkSource, SenderPaths};
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips");
    let map = dir.path().join("map");
    let mut source = LinkSource::new(&SenderPaths {
        ips_file: ips.to_str().unwrap(),
        bind_map: Some(map.to_str().unwrap()),
    });
    source.require_bind_map().unwrap();
    assert!(source.startup().await.unwrap().is_empty());
    assert_eq!(
        source.report().disposition.state,
        "required_binding_refused"
    );
    publish(&ips, "127.0.0.1\n");
    assert!(source.startup().await.unwrap().is_empty());
    publish(&map, &sidecar_for("127.0.0.1\n", 1).replace("wwan0", "lo"));
    let links = source.startup().await.unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(source.report().disposition.state, "mapped");
}
#[tokio::test]
async fn required_binding_refuses_wildcard_sources() {
    use srtla_send::bind_map::{ResolvePhase, resolve_required};
    for contents in ["0.0.0.0\n", "::\n"] {
        let dir = tempfile::tempdir().unwrap();
        publish(&dir.path().join("srtla_ips"), contents);
        publish(&dir.path().join("bind_map.json"), &sidecar_for(contents, 1));
        let pair = read_pair(
            BindMapPaths {
                ips_file: &dir.path().join("srtla_ips"),
                sidecar: &dir.path().join("bind_map.json"),
            },
            ValidateCtx {
                ifaces: &oracle(),
                prior: None,
            },
        )
        .await
        .unwrap();
        let resolution = resolve_required(pair.map, &pair.ips, ResolvePhase::Startup);
        assert!(resolution.links.is_empty());
        assert_eq!(resolution.status.reason().unwrap().as_str(), "malformed");
    }
}
