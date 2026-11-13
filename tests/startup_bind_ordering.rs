//! Startup bind-ordering regression tests.
//!
//! An encoder is typically pointed at the local SRT listen port the moment
//! `srtla_send` is spawned, with no readiness handshake in between. If the
//! listener is not bound by then the handshake goes unanswered and the operator
//! sees a hard stream-start failure. These tests pin the ordering that closes
//! that window: the local SRT listener is bound before any uplink is dialed, so
//! the wait for uplink setup (a sequential per-link resolve + bind + connect)
//! can never delay it.
//!
//! They spawn the real binary and self-skip nothing: no privileges, no external
//! tools, no reachable receiver required.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");
const START_TIMEOUT: Duration = Duration::from_secs(10);

const LISTENING_LOG: &str = "listening for SRT";
const ADDED_UPLINK_LOG: &str = "added uplink";
const FAILED_UPLINK_LOG: &str = "failed to add uplink";

/// Source IPs from TEST-NET-1 (RFC 5737), which is reserved for documentation
/// and therefore never locally configured. Binding an uplink to one fails, so
/// they stand in for the extra bonded modems of a real multi-link deployment
/// without needing any host network setup.
const UNCONFIGURED_SOURCE_IPS: [&str; 4] = ["192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"];

/// Grab an ephemeral UDP port for the local SRT listener, then release it so the
/// spawned binary can bind it (a small TOCTOU race is acceptable for a test).
fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
    sock.local_addr().unwrap().port()
}

struct SenderProc {
    child: Child,
    logs: Arc<Mutex<String>>,
}

impl SenderProc {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn srtla_send");

        // Both needles are `info!` records on stdout, so a single reader thread
        // preserves their relative order in the buffer. stderr is pumped into
        // the same buffer only so a panic/anyhow message shows up in assertion
        // output.
        let logs = Arc::new(Mutex::new(String::new()));
        let streams: [Box<dyn std::io::Read + Send>; 2] = [
            Box::new(child.stdout.take().expect("capture stdout")),
            Box::new(child.stderr.take().expect("capture stderr")),
        ];
        for stream in streams {
            let sink = logs.clone();
            thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let mut buf = sink.lock().unwrap();
                    buf.push_str(&line);
                    buf.push('\n');
                }
            });
        }

        Self { child, logs }
    }

    fn logs(&self) -> String {
        self.logs.lock().unwrap().clone()
    }

    fn wait_for_log(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.logs().contains(needle) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

impl Drop for SenderProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the sender against a throwaway ips file. Positional arguments only —
/// note `-v` on this CLI is `--version`, not a verbosity flag, so log level is
/// set through `RUST_LOG` in [`SenderProc::spawn`] instead.
fn spawn_with_ips(dir: &std::path::Path, contents: &str, port: u16) -> SenderProc {
    let ips = dir.join("ips.txt");
    std::fs::write(&ips, contents).expect("write ips file");
    SenderProc::spawn(&[
        &port.to_string(),
        "127.0.0.1",
        "9999",
        ips.to_str().unwrap(),
    ])
}

/// Byte offset of `needle` in `logs`, or a failure naming what was missing.
fn log_position(logs: &str, needle: &str) -> usize {
    logs.find(needle)
        .unwrap_or_else(|| panic!("expected '{needle}' in the sender log; logs:\n{logs}"))
}

#[test]
fn local_srt_listener_is_bound_before_the_first_uplink_connect() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_udp_port();
    let proc = spawn_with_ips(dir.path(), "127.0.0.1\n", port);

    assert!(
        proc.wait_for_log(ADDED_UPLINK_LOG, START_TIMEOUT),
        "the uplink never connected; logs:\n{}",
        proc.logs()
    );

    let logs = proc.logs();
    assert!(
        log_position(&logs, LISTENING_LOG) < log_position(&logs, ADDED_UPLINK_LOG),
        "the local SRT listener must be bound before the first uplink is dialed, otherwise the \
         encoder's immediate SRT connect races the bind; logs:\n{logs}"
    );
}

#[test]
fn the_bound_port_is_really_taken_once_the_listener_is_logged() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_udp_port();
    let proc = spawn_with_ips(dir.path(), "127.0.0.1\n", port);

    assert!(
        proc.wait_for_log(LISTENING_LOG, START_TIMEOUT),
        "the sender never reported a bound listener; logs:\n{}",
        proc.logs()
    );

    // The listen log is emitted after the bind resolves, so the same address the
    // sender binds must now be unavailable to anyone else.
    let err = std::net::UdpSocket::bind(("::", port))
        .expect_err("the sender must already hold the local SRT port when it logs the listener");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AddrInUse,
        "unexpected bind error: {err}"
    );
}

#[test]
fn listener_bind_precedes_every_uplink_of_a_multi_link_bond() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_udp_port();
    // One workable uplink plus four that cannot bind: the sequential connect
    // loop walks all five, which is the multi-modem shape that widens the race.
    let mut ips = String::from("127.0.0.1\n");
    for ip in UNCONFIGURED_SOURCE_IPS {
        ips.push_str(ip);
        ips.push('\n');
    }
    let proc = spawn_with_ips(dir.path(), &ips, port);

    let last_ip = UNCONFIGURED_SOURCE_IPS[UNCONFIGURED_SOURCE_IPS.len() - 1];
    assert!(
        proc.wait_for_log(last_ip, START_TIMEOUT),
        "the connect loop never reached the last uplink; logs:\n{}",
        proc.logs()
    );

    let logs = proc.logs();
    let listening_at = log_position(&logs, LISTENING_LOG);
    assert!(
        listening_at < log_position(&logs, ADDED_UPLINK_LOG),
        "the bind must precede the successful uplink; logs:\n{logs}"
    );
    assert!(
        listening_at < log_position(&logs, FAILED_UPLINK_LOG),
        "the bind must precede even a failing uplink attempt — a link that stalls or errors must \
         not hold the local listener closed; logs:\n{logs}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sighup_during_strict_startup_is_queued_and_first_document_is_pending() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips");
    let map = dir.path().join("map");
    let stats = dir.path().join("stats");
    std::fs::write(&ips, "127.0.0.1").unwrap();
    let sidecar = |generation, hash: &str| {
        serde_json::json!({
            "schema_version":1,"generation":generation,"ips_file_sha256":hash,
            "links":[{"link_id":"path-a","ip":"127.0.0.1","iface":"lo"}]
        })
        .to_string()
    };
    std::fs::write(&map, sidecar(1, &"0".repeat(64))).unwrap();
    for path in [&ips, &map] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut sender = SenderProc::spawn(&[
        &free_udp_port().to_string(),
        "127.0.0.1",
        "9999",
        ips.to_str().unwrap(),
        "--bind-map",
        map.to_str().unwrap(),
        "--require-bind-map",
        "--stats-file",
        stats.to_str().unwrap(),
        "--stats-file-interval",
        "50",
    ]);
    assert!(sender.wait_for_log(LISTENING_LOG, START_TIMEOUT));
    thread::sleep(Duration::from_millis(200));
    let first: serde_json::Value = serde_json::from_slice(&std::fs::read(&stats).unwrap()).unwrap();
    // Deliver while the mismatched startup pair is still retrying.
    assert!(
        Command::new("kill")
            .args(["-HUP", &sender.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    thread::sleep(Duration::from_millis(100));
    assert!(
        sender.child.try_wait().unwrap().is_none(),
        "startup SIGHUP killed sender"
    );
    assert_eq!(first["disposition"]["state"], "pending_apply");
    let hash = srtla_send::bind_map::IpsFile::from_bytes(b"127.0.0.1")
        .unwrap()
        .sha256()
        .to_string();
    std::fs::write(&map, sidecar(2, &hash)).unwrap();
    assert!(
        sender.wait_for_log("connection changes applied successfully", START_TIMEOUT),
        "queued signal lost: {}",
        sender.logs()
    );
}
