#![cfg(target_os = "linux")]
use std::path::Path;

use srtla_send::bind_map::{
    BindMapDisposition, BindMapPaths, BindMapReport, BindMapStatus, IpsFile, PairRead,
    StaticIfaces, ValidateCtx, read_pair,
};
use srtla_send::config::ConfigSnapshot;
use srtla_send::sender::{LinkSource, SenderPaths};
use srtla_send::stats::SharedStats;

fn publish(root: &Path, content: &str, generation: u64) {
    use std::os::unix::fs::PermissionsExt;
    let rows = if content.is_empty() {
        serde_json::json!([])
    } else {
        serde_json::json!([{"link_id":"path-a","ip":content,"iface":"lo"}])
    };
    for (name, data) in [
        ("ips", content.to_owned()),
        (
            "map",
            serde_json::json!({
        "schema_version":1,"generation":generation,
        "ips_file_sha256":IpsFile::from_bytes(content.as_bytes()).unwrap().sha256(),"links":rows})
            .to_string(),
        ),
    ] {
        let path = root.join(name);
        std::fs::write(&path, data).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
async fn read(root: &Path) -> PairRead {
    read_pair(
        BindMapPaths {
            ips_file: &root.join("ips"),
            sidecar: &root.join("map"),
        },
        ValidateCtx {
            ifaces: &StaticIfaces::new(["lo"]),
            prior: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn startup_identity_covers_nonempty_and_empty_exact_file_bytes() {
    for content in ["127.0.0.1", ""] {
        let dir = tempfile::tempdir().unwrap();
        publish(dir.path(), content, 1);
        let ips = dir.path().join("ips");
        let map = dir.path().join("map");
        let mut source = LinkSource::new(&SenderPaths {
            ips_file: ips.to_str().unwrap(),
            bind_map: Some(map.to_str().unwrap()),
        });
        source.require_bind_map().unwrap();
        source.startup().await.unwrap();
        assert!(source.report().bind_map_applied.is_none());
        source.finish_apply();
        let applied = source.report().bind_map_applied.as_ref().unwrap();
        assert_eq!(applied.generation, 1);
        assert_eq!(
            applied.ips_file_sha256,
            IpsFile::from_bytes(content.as_bytes()).unwrap().sha256()
        );
        assert!(source.report().bind_map_pending.is_none());
    }
}

#[tokio::test]
async fn late_generation_and_writer_counter_reset_cannot_recreate_withdrawn_pool() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = LinkSource::new(&SenderPaths {
        ips_file: "ips",
        bind_map: Some("map"),
    });
    source.require_bind_map().unwrap();
    publish(dir.path(), "127.0.0.1", 1);
    source.adopt(Ok(read(dir.path()).await));
    source.finish_apply();
    publish(dir.path(), "127.0.0.1", 2);
    let old = read(dir.path()).await;
    source.begin_reload();
    publish(dir.path(), "", 3);
    source.adopt(Ok(read(dir.path()).await));
    assert_eq!(
        source
            .pending_report()
            .bind_map_pending
            .as_ref()
            .unwrap()
            .generation,
        3
    );
    source.finish_apply();
    assert!(source.adopt(Ok(old)).is_empty());
    assert_eq!(
        source
            .report()
            .bind_map_applied
            .as_ref()
            .unwrap()
            .generation,
        3
    );
    assert!(source.report().bind_map_pending.is_none());
    publish(dir.path(), "127.0.0.1", 1);
    assert!(source.adopt(Ok(read(dir.path()).await)).is_empty());
    assert_eq!(
        source
            .report()
            .bind_map_applied
            .as_ref()
            .unwrap()
            .generation,
        3
    );
    publish(dir.path(), "127.0.0.1", 3);
    assert!(
        source.adopt(Ok(read(dir.path()).await)).is_empty(),
        "same-generation changed hash must be refused"
    );
    assert_eq!(
        source
            .report()
            .bind_map_applied
            .as_ref()
            .unwrap()
            .generation,
        3
    );
    // A newer request cancels an accepted-but-unapplied target; degradation
    // retains the actual empty pool, never the canceled candidate.
    publish(dir.path(), "127.0.0.1", 4);
    source.adopt(Ok(read(dir.path()).await));
    source.begin_reload();
    source.adopt(Err(srtla_send::bind_map::BindMapError::MissingFile {
        path: "map".into(),
    }));
    assert_eq!(
        source
            .report()
            .bind_map_applied
            .as_ref()
            .unwrap()
            .generation,
        3
    );
}

#[test]
fn same_generation_noop_cannot_clear_newer_unknown_pending_or_publish_after_join() {
    let stats = SharedStats::new();
    let mut applied = BindMapReport::new(BindMapStatus::Active, BindMapDisposition::Mapped, &[]);
    applied.bind_map_applied = Some(srtla_send::bind_map::BindMapIdentity {
        generation: 1,
        ips_file_sha256: IpsFile::from_bytes(b"").unwrap().sha256().into(),
    });
    stats.update_with_bind_map(
        &[],
        &ConfigSnapshot::default(),
        None,
        None,
        None,
        Some(&applied),
    );
    let noop = stats.begin_reload_request();
    let mut queued_noop = applied.clone();
    queued_noop.disposition.state = "pending_apply";
    queued_noop.bind_map_pending = applied.bind_map_applied.clone();
    assert!(stats.set_bind_map_if_current(queued_noop, noop));
    let newer = stats.begin_reload_request();
    assert!(newer > noop);
    let accepted = std::cell::Cell::new(false);
    assert!(
        stats
            .with_reload_request(noop, || accepted.set(true))
            .is_none()
    );
    assert!(
        !accepted.get(),
        "superseded no-op must not mutate accepted generation state"
    );

    assert!(!stats.set_bind_map_if_current(applied.clone(), noop));
    assert!(!stats.update_for_reload(
        &[],
        &ConfigSnapshot::default(),
        None,
        None,
        None,
        Some(&applied),
        Some(noop)
    ));
    let snapshot = stats.get();
    assert_eq!(snapshot.bind_map.disposition.state, "pending_apply");
    assert_eq!(snapshot.bind_map.bind_map_applied, applied.bind_map_applied);
    assert!(snapshot.bind_map.bind_map_pending.is_none());
}

#[tokio::test]
async fn unsafe_generation_is_not_applied_and_a_later_writer_lifetime_is_separate() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = LinkSource::new(&SenderPaths {
        ips_file: "ips",
        bind_map: Some("map"),
    });
    source.require_bind_map().unwrap();
    publish(dir.path(), "", 9_007_199_254_740_992);
    source.adopt(Ok(read(dir.path()).await));
    source.finish_apply();
    assert!(source.report().bind_map_applied.is_none());
    assert_eq!(source.report().bind_map_status.state, "degraded");
}

#[tokio::test]
async fn a_freshly_serialized_old_snapshot_cannot_acknowledge_a_new_publication() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = LinkSource::new(&SenderPaths {
        ips_file: "ips",
        bind_map: Some("map"),
    });
    source.require_bind_map().unwrap();
    publish(dir.path(), "", 1);
    source.adopt(Ok(read(dir.path()).await));
    source.finish_apply();
    let stats = SharedStats::new();
    stats.update_with_bind_map(
        &[],
        &ConfigSnapshot::default(),
        None,
        None,
        None,
        Some(source.report()),
    );
    let old = stats.get();
    source.begin_reload();
    publish(dir.path(), "127.0.0.1", 2);
    source.adopt(Ok(read(dir.path()).await));
    source.finish_apply();
    let fresh_json = srtla_send::telemetry_file::build_current_telemetry_json(&old);
    let v: serde_json::Value = serde_json::from_str(&fresh_json).unwrap();
    assert!(v["last_updated_ms"].as_u64().unwrap() > 0);
    assert!(v["connections"].as_array().unwrap().is_empty());
    assert_eq!(v["bind_map_applied"]["generation"], 1);
    assert_ne!(
        v["bind_map_applied"]["generation"],
        source
            .report()
            .bind_map_applied
            .as_ref()
            .unwrap()
            .generation
    );
}

#[tokio::test]
async fn strict_duplicate_check_uses_canonical_source_and_device() {
    let dir = tempfile::tempdir().unwrap();
    publish(dir.path(), "127.0.0.1", 1);
    let bytes = b"127.0.0.1\n::ffff:127.0.0.1";
    std::fs::write(dir.path().join("ips"), bytes).unwrap();
    let map = serde_json::json!({"schema_version":1,"generation":1,
        "ips_file_sha256":IpsFile::from_bytes(bytes).unwrap().sha256(),
        "links":[{"link_id":"a","ip":"127.0.0.1","iface":"lo"},
                 {"link_id":"b","ip":"::ffff:127.0.0.1","iface":"lo"}]});
    std::fs::write(dir.path().join("map"), map.to_string()).unwrap();
    let pair = read(dir.path()).await;
    assert!(
        pair.map
            .and_then(srtla_send::bind_map::validate_required_pool)
            .is_err()
    );
}
