//! Pins the `--capabilities-json` pre-spawn probe contract.
//!
//! A supervisor runs the installed binary with this flag *before* it spawns a
//! stream, to decide which optional flags it may pass. Three properties are
//! load-bearing for that caller and are asserted here against the real binary:
//!
//! - exit `0` and **one line** of JSON on stdout, with nothing else mixed in
//!   (the probe answers before logging is initialized, so `RUST_LOG` cannot
//!   contaminate the parse);
//! - **no side effects** — no socket bound, no file written, even when the
//!   invocation also names a control socket and a stats file;
//! - a **non-zero exit** for anything the binary does not understand, which is
//!   the "no support" answer an older binary gives by accident and a newer one
//!   must keep giving on purpose.

use std::net::UdpSocket;
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");

/// clap's exit code for a usage error.
const USAGE_ERROR_CODE: i32 = 2;

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn srtla_send")
}

fn probe_document() -> Value {
    let out = run(&["--capabilities-json"]);
    assert_eq!(out.status.code(), Some(0));
    serde_json::from_slice(&out.stdout).expect("probe stdout parses as JSON")
}

#[test]
fn probe_exits_zero_with_a_single_json_line() {
    let out = run(&["--capabilities-json"]);
    assert_eq!(out.status.code(), Some(0), "probe must exit 0");

    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(stdout.ends_with('\n'), "one terminated line");
    assert_eq!(
        stdout.trim_end_matches('\n').lines().count(),
        1,
        "exactly one line: {stdout:?}"
    );
    serde_json::from_str::<Value>(stdout.trim()).expect("the line parses as JSON");
}

#[test]
fn probe_writes_nothing_to_stderr() {
    let out = run(&["--capabilities-json"]);
    assert!(
        out.stderr.is_empty(),
        "logging must not be initialized before the probe answers: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn probe_carries_the_frozen_document_shape() {
    let v = probe_document();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["binary"], "srtla_send");
    assert!(v["version"].is_string());

    let caps = v["capabilities"].as_object().expect("capabilities object");
    let mut keys: Vec<&str> = caps.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "bind_map",
            "bind_map_contract",
            "bind_map_required",
            "bind_map_required_empty_reload",
            "conn_timeout_ms",
            "control_socket_jsonrpc",
            "dry_run",
            "modes",
            "stats_file",
        ]
    );
    assert_eq!(caps["modes"], serde_json::json!(["classic", "enhanced"]));
}

#[cfg(target_os = "linux")]
#[test]
fn probe_claims_bind_map_on_linux() {
    assert_eq!(probe_document()["capabilities"]["bind_map"], true);
}

/// The probe must not bind the local SRT listener even when a port is named on
/// the same command line. Holding the port first makes a bind attempt fail
/// loudly instead of passing unnoticed.
#[test]
fn probe_binds_no_listener() {
    let held = UdpSocket::bind("127.0.0.1:0").expect("bind probe port");
    let port = held.local_addr().unwrap().port().to_string();

    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips.txt");
    std::fs::write(&ips, "127.0.0.1\n").unwrap();
    let sock = dir.path().join("control.sock");
    let stats = dir.path().join("stats.json");

    let out = run(&[
        "--capabilities-json",
        "--control-socket",
        sock.to_str().unwrap(),
        "--stats-file",
        stats.to_str().unwrap(),
        &port,
        "127.0.0.1",
        "5000",
        ips.to_str().unwrap(),
    ]);

    assert_eq!(out.status.code(), Some(0));
    assert!(
        !sock.exists(),
        "the control socket must not be created by a probe"
    );
    assert!(
        !stats.exists(),
        "the telemetry file must not be created by a probe"
    );
    drop(held);
}

/// The failure half of the contract: anything the binary does not understand
/// is a usage error, which is exactly the answer a binary predating the flag
/// gives. A caller must treat *any* non-zero exit as "no support" rather than
/// matching a code or a message.
#[test]
fn an_unknown_flag_alongside_the_probe_is_a_usage_error() {
    let out = run(&["--capabilities-json", "--not-a-real-flag"]);
    assert_eq!(out.status.code(), Some(USAGE_ERROR_CODE));
    assert!(out.stdout.is_empty(), "no document on a usage error");
    assert!(!out.stderr.is_empty(), "usage error explains itself");
}

#[test]
fn required_binding_capability_is_platform_honest() {
    assert_eq!(
        probe_document()["capabilities"]["bind_map_required"],
        cfg!(target_os = "linux")
    );
}

#[test]
fn required_binding_flag_requires_a_sidecar() {
    let out = run(&["5000", "127.0.0.1", "5001", "ips.txt", "--require-bind-map"]);
    assert_eq!(out.status.code(), Some(USAGE_ERROR_CODE));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--bind-map"));
}

#[test]
fn required_empty_reload_capability_is_platform_honest() {
    assert_eq!(
        probe_document()["capabilities"]["bind_map_required_empty_reload"],
        cfg!(target_os = "linux")
    );
}

#[test]
fn probe_advertises_the_verified_required_binding_contract_revision() {
    let v = probe_document();
    assert_eq!(
        v["capabilities"]["bind_map_contract"].as_u64(),
        Some(if cfg!(target_os = "linux") { 1 } else { 0 })
    );
}
