//! Native families, translation and same-process source replacement.
//!
//! Uses only synthetic interfaces in fresh PID, mount and network namespaces.
//! External receiver/translator binaries are explicit prerequisites; ordinary
//! unit-test environments self-skip without them.

use std::process::Command;

#[test]
fn native_and_mixed_family_destinations() {
    if !cfg!(target_os = "linux") {
        eprintln!("Skipping: Linux namespaces required");
        return;
    }
    for name in ["SRTLA_RECEIVER", "SRTLA_IPV4_RECEIVER", "TAYGA_BIN"] {
        if std::env::var_os(name).is_none() {
            eprintln!("Skipping: set {name} to the acceptance binary path");
            return;
        }
    }
    if !Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("Skipping: passwordless sudo required");
        return;
    }
    let output = tempfile::tempdir().expect("acceptance output directory");
    let status = Command::new("sudo")
        .args(["-n", "env"])
        .arg(format!("SRTLA_SEND={}", env!("CARGO_BIN_EXE_srtla_send")))
        .arg(format!("PROOF_OUTPUT={}", output.path().display()))
        .args(
            ["SRTLA_RECEIVER", "SRTLA_IPV4_RECEIVER", "TAYGA_BIN"].map(|name| {
                format!(
                    "{name}={}",
                    std::env::var(name).expect("checked prerequisite")
                )
            }),
        )
        .args([
            "unshare",
            "--mount",
            "--pid",
            "--net",
            "--fork",
            "--mount-proc",
            "python3",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netns_family.py"
        ))
        .status()
        .expect("run family acceptance");
    if !status.success() {
        for entry in std::fs::read_dir(output.path()).unwrap().flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "log") {
                eprintln!(
                    "{}:\n{}",
                    entry.file_name().to_string_lossy(),
                    std::fs::read_to_string(entry.path()).unwrap_or_default()
                );
            }
        }
    }
    assert!(status.success(), "family acceptance failed: {status}");
}
