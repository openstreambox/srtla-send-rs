//! Signal & startup parity integration tests (Unix).
//!
//! These spawn the real `srtla_send` binary and drive it with POSIX signals to
//! pin the CeraLive signal/startup contract CeraUI depends on:
//!   * a missing / empty `BIND_IPS_FILE` at startup yields an EMPTY uplink pool
//!     (listener still bound), not a crash;
//!   * a SIGHUP that follows the empty start adds the newly listed uplinks;
//!   * SIGTERM and SIGINT exit cleanly (code 0) well inside CeraUI's 10s
//!     SIGKILL window.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");
const START_TIMEOUT: Duration = Duration::from_secs(5);
const LOG_TIMEOUT: Duration = Duration::from_secs(5);
const KILL_WINDOW: Duration = Duration::from_secs(10);
/// Clean shutdown must be prompt: the contract says "well within" CeraUI's 10s
/// SIGKILL window. Poll up to `KILL_WINDOW` so a slow exit is reported as a
/// too-slow failure, and additionally assert this tighter bound.
const PROMPT_EXIT: Duration = Duration::from_secs(2);

const EMPTY_START_LOG: &str = "no valid source IPs at startup";

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
        Self::spawn_with_env(args, &[])
    }

    fn spawn_with_env(args: &[&str], vars: &[(&str, &str)]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .env("RUST_LOG", "info")
            .envs(vars.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn srtla_send");

        // tracing writes to stdout; panics/anyhow errors land on stderr. Pump both
        // into one buffer so log assertions see everything the binary emitted.
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
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn signal(&self, sig: &str) {
        let status = Command::new("kill")
            .args([format!("-{sig}"), self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{sig} failed");
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => return None,
            }
        }
        None
    }
}

impl Drop for SenderProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a sender against `ips`, bound to `127.0.0.1`, and return the process
/// plus the ips-file path so a test can rewrite it before signalling.
fn spawn(dir: &std::path::Path, ips_contents: &str) -> (SenderProc, std::path::PathBuf) {
    let ips = dir.join("ips.txt");
    std::fs::write(&ips, ips_contents).expect("write ips file");
    let port = free_udp_port().to_string();
    let proc = SenderProc::spawn(&[
        port.as_str(),
        "127.0.0.1",
        "9999",
        ips.to_str().unwrap(),
        "--verbose",
    ]);
    (proc, ips)
}

#[test]
fn empty_ip_file_at_startup_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    // The file exists but resolves to zero valid IPs (blank lines only).
    let (mut proc, _ips) = spawn(dir.path(), "\n   \n\n");

    assert!(
        proc.wait_for_log(EMPTY_START_LOG, START_TIMEOUT),
        "an empty ips file must start an empty pool with the empty-start log; logs:\n{}",
        proc.logs()
    );
    assert!(
        proc.wait_for_log("listening for SRT", START_TIMEOUT),
        "the listener must be bound even with no uplinks; logs:\n{}",
        proc.logs()
    );
    thread::sleep(Duration::from_secs(1));
    assert!(
        proc.is_alive(),
        "empty-start must keep running (no crash-loop); logs:\n{}",
        proc.logs()
    );

    proc.signal("TERM");
    assert_eq!(
        proc.wait_exit(KILL_WINDOW),
        Some(0),
        "SIGTERM after an empty start must still exit 0; logs:\n{}",
        proc.logs()
    );
}

#[test]
fn missing_ips_file_at_startup_starts_empty_and_reloads_on_sighup() {
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips.txt"); // intentionally not created
    let port = free_udp_port().to_string();
    let mut proc = SenderProc::spawn(&[
        port.as_str(),
        "127.0.0.1",
        "9999",
        ips.to_str().unwrap(),
        "--verbose",
    ]);

    assert!(
        proc.wait_for_log(EMPTY_START_LOG, START_TIMEOUT),
        "a missing ips file must yield an empty pool, not an error exit; logs:\n{}",
        proc.logs()
    );
    assert!(
        proc.wait_for_log("listening for SRT", START_TIMEOUT),
        "the sender must bind the listener even with no uplinks; logs:\n{}",
        proc.logs()
    );
    thread::sleep(Duration::from_secs(1));
    assert!(
        proc.is_alive(),
        "sender must not crash on a missing ips file"
    );

    // Writing the file and signalling must populate the pool.
    std::fs::write(&ips, "127.0.0.1\n").unwrap();
    proc.signal("HUP");
    assert!(
        proc.wait_for_log("added uplink", LOG_TIMEOUT),
        "SIGHUP after writing the file must add the uplink; logs:\n{}",
        proc.logs()
    );
    assert!(proc.is_alive());

    proc.signal("TERM");
    assert_eq!(
        proc.wait_exit(KILL_WINDOW),
        Some(0),
        "SIGTERM after the reload must still exit 0; logs:\n{}",
        proc.logs()
    );
}

#[test]
fn sigterm_exits_cleanly_and_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let (mut proc, _ips) = spawn(dir.path(), "127.0.0.1\n");

    assert!(
        proc.wait_for_log("listening for SRT", START_TIMEOUT),
        "sender never started; logs:\n{}",
        proc.logs()
    );

    let t0 = Instant::now();
    proc.signal("TERM");
    let code = proc.wait_exit(KILL_WINDOW);
    let elapsed = t0.elapsed();

    assert_eq!(code, Some(0), "SIGTERM must exit 0; logs:\n{}", proc.logs());
    assert!(
        elapsed < PROMPT_EXIT,
        "SIGTERM must exit promptly (< {PROMPT_EXIT:?}); took {elapsed:?}"
    );
}

#[test]
fn sigint_exits_cleanly_and_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let (mut proc, _ips) = spawn(dir.path(), "127.0.0.1\n");

    assert!(
        proc.wait_for_log("listening for SRT", START_TIMEOUT),
        "sender never started; logs:\n{}",
        proc.logs()
    );

    let t0 = Instant::now();
    proc.signal("INT");
    let code = proc.wait_exit(KILL_WINDOW);
    let elapsed = t0.elapsed();

    assert_eq!(code, Some(0), "SIGINT must exit 0; logs:\n{}", proc.logs());
    assert!(
        elapsed < PROMPT_EXIT,
        "SIGINT must exit promptly (< {PROMPT_EXIT:?}); took {elapsed:?}"
    );
}

/// Real-process regression: telemetry must acknowledge withdrawal, and a later
/// re-add must bootstrap registration rather than retaining old probe indices.
#[cfg(target_os = "linux")]
#[test]
fn required_mapping_can_withdraw_every_link_and_readd_after_degraded_reads() {
    use std::os::unix::fs::PermissionsExt;

    use srtla_send::bind_map::IpsFile;

    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips");
    let map = dir.path().join("map");
    let stats = dir.path().join("stats");
    let publish = |content: &str, generation: u64, link_id: &str, bad_sha: bool| {
        let sha = IpsFile::from_bytes(content.as_bytes())
            .unwrap()
            .sha256()
            .to_owned();
        let rows = if content.is_empty() {
            serde_json::json!([])
        } else {
            serde_json::json!([{"link_id":link_id,"ip":"127.0.0.1","iface":"lo"}])
        };
        let doc = serde_json::json!({
            "schema_version":1,"generation":generation,
            "ips_file_sha256":if bad_sha { "0".repeat(64) } else { sha },
            "links":rows
        });
        for (path, data) in [(&ips, content.to_owned()), (&map, doc.to_string())] {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, data).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(tmp, path).unwrap();
        }
    };
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    publish("127.0.0.1\n", 1, "path-a", false);
    let mut proc = SenderProc::spawn(&[
        &free_udp_port().to_string(),
        "127.0.0.1",
        &receiver.local_addr().unwrap().port().to_string(),
        ips.to_str().unwrap(),
        "--bind-map",
        map.to_str().unwrap(),
        "--require-bind-map",
        "--stats-file",
        stats.to_str().unwrap(),
        "--stats-file-interval",
        "100",
    ]);
    let observe = |count: usize, state: &str, reason: Option<&str>, after: u64| {
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            if let Ok(bytes) = std::fs::read(&stats)
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && v["last_updated_ms"].as_u64().unwrap() > after
                && v["connections"].as_array().unwrap().len() == count
                && v["bind_map_status"]["state"] == state
                && v["disposition"]["state"] != "pending_apply"
                && reason.is_none_or(|r| v["bind_map_status"]["reason"] == r)
            {
                assert_eq!(
                    v["disposition"]["state"],
                    if state == "active" {
                        "mapped"
                    } else {
                        "retained_last_valid"
                    }
                );
                return v["last_updated_ms"].as_u64().unwrap();
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("no fresh {count}-link {state} snapshot: {}", proc.logs());
    };
    let reload = || {
        let outcomes = |logs: &str| {
            logs.matches("bind-map active (").count()
                + logs.matches("bind-map degraded:").count()
                + logs.matches("bind-map read failed:").count()
        };
        let before = outcomes(&proc.logs());
        proc.signal("HUP");
        let deadline = Instant::now() + Duration::from_secs(6);
        while outcomes(&proc.logs()) == before {
            assert!(
                Instant::now() < deadline,
                "reload did not finish: {}",
                proc.logs()
            );
            thread::sleep(Duration::from_millis(20));
        }
    };
    let mut stamp = observe(1, "active", None, 0);
    let mut packet = [0u8; 2048];
    receiver
        .recv(&mut packet)
        .expect("initial registration probe");

    // Empty IPs with a missing/malformed sidecar must not withdraw.
    std::fs::write(&ips, "").unwrap();
    std::fs::remove_file(&map).unwrap();
    reload();
    stamp = observe(1, "degraded", Some("missing_file"), stamp);
    std::fs::write(&map, "{").unwrap();
    reload();
    stamp = observe(1, "degraded", Some("malformed"), stamp);
    publish("", 2, "path-a", true);
    reload();
    stamp = observe(1, "degraded", Some("retry_exhausted"), stamp);
    publish("", 0, "path-a", false);
    reload();
    stamp = observe(1, "degraded", Some("malformed"), stamp);
    // Same hash and generation with changed identity is stale (ADR-003 §3).
    publish("127.0.0.1\n", 1, "path-b", false);
    reload();
    stamp = observe(1, "degraded", Some("malformed"), stamp);

    publish("", 2, "path-a", false);
    reload();
    stamp = observe(0, "active", None, stamp);
    proc.signal("0"); // Empty is not process exit.
    // Even an unreadable reload after withdrawal must retain the valid EMPTY pool.
    std::fs::remove_file(&ips).unwrap();
    reload();
    stamp = observe(0, "degraded", Some("unreadable"), stamp);

    // Drain old probes so the next packet proves re-add registration.
    receiver.set_nonblocking(true).unwrap();
    while receiver.recv(&mut packet).is_ok() {}
    receiver.set_nonblocking(false).unwrap();
    publish("127.0.0.1\n", 3, "path-a", false);
    reload();
    observe(1, "active", None, stamp);
    receiver
        .recv(&mut packet)
        .expect("fresh registration probe after re-add");
    proc.signal("TERM");
    assert_eq!(proc.wait_exit(KILL_WINDOW), Some(0));
}

#[cfg(target_os = "linux")]
fn owned_udp_ports(pid: u32) -> Vec<u16> {
    let inodes: std::collections::HashSet<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|p| {
            p.to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .collect();
    ["udp", "udp6"]
        .iter()
        .flat_map(|name| {
            std::fs::read_to_string(format!("/proc/{pid}/net/{name}"))
                .unwrap()
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if !inodes.contains(fields[9]) {
                        return None;
                    }
                    u16::from_str_radix(fields[1].split(':').nth(1).unwrap(), 16).ok()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(target_os = "linux")]
#[test]
fn empty_acknowledgement_follows_socket_closure_on_startup_and_rapid_readd() {
    use std::os::unix::fs::PermissionsExt;

    use srtla_send::bind_map::IpsFile;
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips");
    let map = dir.path().join("map");
    let stats = dir.path().join("stats");
    let publish = |ip: &str, generation: u64| {
        let content = if ip.is_empty() {
            String::new()
        } else {
            format!("{ip}\n")
        };
        let links = if ip.is_empty() {
            serde_json::json!([])
        } else {
            serde_json::json!([{"link_id":"path-a","ip":ip,"iface":"lo"}])
        };
        let doc = serde_json::json!({"schema_version":1,"generation":generation,
            "ips_file_sha256":IpsFile::from_bytes(content.as_bytes()).unwrap().sha256(), "links":links});
        for (path, content) in [(&ips, content), (&map, doc.to_string())] {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, content).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(tmp, path).unwrap();
        }
    };
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let listen_port = free_udp_port();
    publish("127.0.0.1", 1);
    let mut proc = SenderProc::spawn(&[
        &listen_port.to_string(),
        "127.0.0.1",
        &receiver.local_addr().unwrap().port().to_string(),
        ips.to_str().unwrap(),
        "--require-bind-map",
        "--bind-map",
        map.to_str().unwrap(),
        "--stats-file",
        stats.to_str().unwrap(),
        "--stats-file-interval",
        "10",
    ]);
    let mut packet = [0; 2048];
    receiver.recv(&mut packet).unwrap();
    assert!(proc.wait_for_log("sender ready for reload signals", START_TIMEOUT));
    // Wait for the first publication before the initial withdrawal.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !stats.exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    for cycle in 0..5 {
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        publish("", 2 + cycle * 2);
        proc.signal("HUP");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(bytes) = std::fs::read(&stats)
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && v["last_updated_ms"].as_u64().unwrap() > after
                && v["bind_map_applied"]["generation"] == 2 + cycle * 2
                && v["bind_map_applied"]["ips_file_sha256"]
                    == IpsFile::from_bytes(b"").unwrap().sha256()
                && v["connections"].as_array().unwrap().is_empty()
                && v["bind_map_status"]["state"] == "active"
                && v["disposition"]["state"] == "mapped"
            {
                assert_eq!(
                    owned_udp_ports(proc.child.id()),
                    vec![listen_port],
                    "withdrawal acknowledged while uplink sockets remain, cycle {cycle}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no withdrawal acknowledgement: {}",
                proc.logs()
            );
            thread::sleep(Duration::from_millis(1));
        }
        receiver.set_nonblocking(true).unwrap();
        while receiver.recv(&mut packet).is_ok() {}
        receiver.set_nonblocking(false).unwrap();
        publish("127.0.0.1", 3 + cycle * 2);
        proc.signal("HUP");
        receiver
            .recv(&mut packet)
            .expect("re-add must send a new probe");
        // Immediately withdraw: do not wait for a nonempty stats snapshot.
    }
    proc.signal("TERM");
    assert_eq!(proc.wait_exit(KILL_WINDOW), Some(0));
}

#[cfg(target_os = "linux")]
#[test]
fn required_non_unicast_sources_never_emit_probes() {
    use std::os::unix::fs::PermissionsExt;

    use srtla_send::bind_map::IpsFile;
    for source in [
        "255.255.255.255",
        "224.0.0.1",
        "239.1.2.3",
        "ff02::1",
        "::ffff:255.255.255.255",
        "::ffff:224.0.0.1",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let ips = dir.path().join("ips");
        let map = dir.path().join("map");
        let stats = dir.path().join("stats");
        let content = format!("{source}\n");
        std::fs::write(&ips, &content).unwrap();
        std::fs::write(
            &map,
            serde_json::json!({"schema_version":1,"generation":1,
            "ips_file_sha256":IpsFile::from_bytes(content.as_bytes()).unwrap().sha256(),
            "links":[{"link_id":"path-a","ip":source,"iface":"lo"}]})
            .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&map, std::fs::Permissions::from_mode(0o600)).unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let listener = free_udp_port();
        let mut proc = SenderProc::spawn(&[
            &listener.to_string(),
            "127.0.0.1",
            &receiver.local_addr().unwrap().port().to_string(),
            ips.to_str().unwrap(),
            "--require-bind-map",
            "--bind-map",
            map.to_str().unwrap(),
            "--stats-file",
            stats.to_str().unwrap(),
            "--stats-file-interval",
            "10",
        ]);
        assert!(
            proc.wait_for_log("required_binding_refused", START_TIMEOUT),
            "{source}: {}",
            proc.logs()
        );
        // The log and asynchronous stats-file writer are different clocks.
        // Do not mistake the initial default snapshot for the refusal report.
        let deadline = Instant::now() + START_TIMEOUT;
        let v = loop {
            if let Ok(bytes) = std::fs::read(&stats)
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && v["disposition"]["state"] == "required_binding_refused"
            {
                break v;
            }
            assert!(
                Instant::now() < deadline,
                "{source}: refusal not published: {}",
                proc.logs()
            );
            thread::sleep(Duration::from_millis(2));
        };
        assert!(v["connections"].as_array().unwrap().is_empty());
        assert_eq!(owned_udp_ports(proc.child.id()), vec![listener]);
        let mut packet = [0; 2048];
        assert!(
            receiver.recv(&mut packet).is_err(),
            "{source} emitted a probe"
        );
        proc.signal("TERM");
        assert_eq!(proc.wait_exit(KILL_WINDOW), Some(0));
    }
}

#[cfg(target_os = "linux")]
fn controlled_read_ordering(noop: bool) {
    use std::os::unix::fs::PermissionsExt;

    use srtla_send::bind_map::IpsFile;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let ips = root.join("ips");
    let map = root.join("map");
    let stats = root.join("stats");
    let library = root.join("gate.so");
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-O2"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/bind_map_read_gate.c"
            ))
            .args(["-ldl", "-o"])
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    let publish = |content: &str, generation: u64| {
        let rows = if content.is_empty() {
            serde_json::json!([])
        } else {
            serde_json::json!([{"link_id":"path-a","ip":content,"iface":"lo"}])
        };
        for (path,data) in [(&ips,content.to_owned()),(&map,serde_json::json!({"schema_version":1,"generation":generation,
            "ips_file_sha256":IpsFile::from_bytes(content.as_bytes()).unwrap().sha256(),"links":rows}).to_string())] {
            let tmp=path.with_extension("tmp");std::fs::write(&tmp,data).unwrap();
            std::fs::set_permissions(&tmp,std::fs::Permissions::from_mode(0o600)).unwrap();std::fs::rename(tmp,path).unwrap();
        }
    };
    let wait_file = |name: &str| {
        let end = Instant::now() + Duration::from_secs(5);
        while !root.join(name).exists() {
            assert!(Instant::now() < end, "missing {name}");
            thread::sleep(Duration::from_millis(2));
        }
    };
    publish("127.0.0.1", 1);
    let listener = free_udp_port();
    let mut proc = SenderProc::spawn_with_env(
        &[
            &listener.to_string(),
            "127.0.0.1",
            &free_udp_port().to_string(),
            ips.to_str().unwrap(),
            "--require-bind-map",
            "--bind-map",
            map.to_str().unwrap(),
            "--stats-file",
            stats.to_str().unwrap(),
            "--stats-file-interval",
            "10",
        ],
        &[
            ("LD_PRELOAD", library.to_str().unwrap()),
            ("SRTLA_TEST_GATE", root.to_str().unwrap()),
            ("SRTLA_TEST_GENERATIONS", if noop { ",1,2," } else { ",2," }),
        ],
    );
    assert!(proc.wait_for_log("sender ready for reload signals", START_TIMEOUT));
    let observe = |generation: u64, state: &str| {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(bytes) = std::fs::read(&stats)
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && v["bind_map_applied"]["generation"] == generation
                && v["disposition"]["state"] == state
            {
                return v;
            }
            assert!(
                Instant::now() < end,
                "missing {generation}/{state}: {}",
                proc.logs()
            );
            thread::sleep(Duration::from_millis(2));
        }
    };
    observe(1, "mapped");
    std::fs::write(root.join("arm"), "").unwrap();
    publish("127.0.0.1", if noop { 1 } else { 2 });
    proc.signal("HUP");
    wait_file(if noop { "captured-1" } else { "captured-2" });
    let final_generation = if noop { 2 } else { 3 };
    publish("", final_generation);
    proc.signal("HUP");
    if noop {
        wait_file("captured-2");
        std::fs::write(root.join("release-1"), "").unwrap();
        assert!(proc.wait_for_log("discarding superseded bind-map read", LOG_TIMEOUT));
        let pending = observe(1, "pending_apply");
        assert!(
            pending.get("bind_map_pending").is_none(),
            "new read has no known identity yet"
        );
        assert_eq!(
            owned_udp_ports(proc.child.id()).len(),
            2,
            "older no-op cannot withdraw or publish"
        );
        std::fs::write(root.join("release-2"), "").unwrap();
    }
    let final_report = observe(final_generation, "mapped");
    assert_eq!(
        final_report["bind_map_applied"]["ips_file_sha256"],
        IpsFile::from_bytes(b"").unwrap().sha256()
    );
    assert!(final_report["connections"].as_array().unwrap().is_empty());
    assert_eq!(owned_udp_ports(proc.child.id()), vec![listener]);
    if !noop {
        std::fs::write(root.join("release-2"), "").unwrap();
        assert!(proc.wait_for_log("discarding superseded bind-map read", LOG_TIMEOUT));
        observe(final_generation, "mapped");
        assert_eq!(
            owned_udp_ports(proc.child.id()),
            vec![listener],
            "old read recreated a socket after acknowledgement"
        );
    }
    proc.signal("TERM");
    assert_eq!(proc.wait_exit(KILL_WINDOW), Some(0));
}

#[cfg(target_os = "linux")]
#[test]
fn obsolete_read_cannot_recreate_sockets_after_newer_empty_ack() {
    controlled_read_ordering(false);
}

#[cfg(target_os = "linux")]
#[test]
fn same_generation_noop_finishing_during_newer_read_keeps_pending() {
    controlled_read_ordering(true);
}

#[cfg(target_os = "linux")]
#[test]
fn empty_startup_publishes_exact_applied_identity_without_uplink_sockets() {
    use std::os::unix::fs::PermissionsExt;

    use srtla_send::bind_map::IpsFile;
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips");
    let map = dir.path().join("map");
    let stats = dir.path().join("stats");
    std::fs::write(&ips, "").unwrap();
    let sha = IpsFile::from_bytes(b"").unwrap().sha256().to_owned();
    std::fs::write(
        &map,
        serde_json::json!({
            "schema_version": 1, "generation": 7,
            "ips_file_sha256": sha, "links": []
        })
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&map, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = free_udp_port();
    let mut proc = SenderProc::spawn(&[
        &listener.to_string(),
        "127.0.0.1",
        &free_udp_port().to_string(),
        ips.to_str().unwrap(),
        "--require-bind-map",
        "--bind-map",
        map.to_str().unwrap(),
        "--stats-file",
        stats.to_str().unwrap(),
        "--stats-file-interval",
        "10",
    ]);
    assert!(proc.wait_for_log("sender ready for reload signals", START_TIMEOUT));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(bytes) = std::fs::read(&stats)
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && v["bind_map_applied"]["generation"] == 7
        {
            assert_eq!(v["bind_map_applied"]["ips_file_sha256"], sha);
            assert_eq!(v["disposition"]["state"], "mapped");
            assert_eq!(v["connections"], serde_json::json!([]));
            assert!(v.get("bind_map_pending").is_none());
            assert_eq!(owned_udp_ports(proc.child.id()), vec![listener]);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "startup identity missing: {}",
            proc.logs()
        );
        thread::sleep(Duration::from_millis(2));
    }
    proc.signal("TERM");
    assert_eq!(proc.wait_exit(KILL_WINDOW), Some(0));
}
