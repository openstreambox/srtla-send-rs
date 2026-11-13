//! Signal shutdown integration tests (Unix).
//!
//! These spawn the real `srtla_send` binary and pin that SIGTERM and SIGINT
//! produce a prompt, clean exit (code 0) rather than death by the default
//! signal action, which a supervisor reports as a failure.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll well past `PROMPT_EXIT` so a slow exit is reported as too slow rather
/// than as "never exited".
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const PROMPT_EXIT: Duration = Duration::from_secs(2);

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

    fn wait_for_log_count(&self, needle: &str, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.logs().matches(needle).count() >= count {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
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

    /// Block until the sender has installed its handler for `signum`.
    ///
    /// The handlers are registered after the "listening for SRT" line is
    /// logged, so signalling straight off that line can still hit the default
    /// action and kill the process. `SigCgt` in `/proc/<pid>/status` is the
    /// kernel's own record of caught signals, so it closes that window
    /// without a guessed sleep.
    #[cfg(target_os = "linux")]
    fn wait_for_handler(&self, signum: u32, timeout: Duration) -> bool {
        let path = format!("/proc/{}/status", self.child.id());
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let caught = std::fs::read_to_string(&path).ok().and_then(|status| {
                let mask = status.lines().find_map(|l| l.strip_prefix("SigCgt:"))?;
                u64::from_str_radix(mask.trim(), 16).ok()
            });
            if caught.is_some_and(|mask| mask & (1 << (signum - 1)) != 0) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// No portable way to observe the handler off Linux; give startup a moment.
    #[cfg(not(target_os = "linux"))]
    fn wait_for_handler(&self, _signum: u32, _timeout: Duration) -> bool {
        thread::sleep(Duration::from_millis(500));
        true
    }

    fn signal(&self, sig: &str) {
        let status = Command::new("kill")
            .args([format!("-{sig}"), self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{sig} failed");
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                // A signal death has no exit code; report it as -1 so it can
                // never be mistaken for the clean 0 these tests require.
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

fn assert_signal_exits_cleanly(sig: &str, signum: u32) {
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips.txt");
    std::fs::write(&ips, "127.0.0.1\n").expect("write ips file");
    let port = free_udp_port().to_string();
    let mut proc = SenderProc::spawn(&[port.as_str(), "127.0.0.1", "9999", ips.to_str().unwrap()]);

    assert!(
        proc.wait_for_log("listening for SRT", START_TIMEOUT),
        "sender never started; logs:\n{}",
        proc.logs()
    );
    assert!(
        proc.wait_for_handler(signum, START_TIMEOUT),
        "sender never installed a SIG{sig} handler; logs:\n{}",
        proc.logs()
    );

    let t0 = Instant::now();
    proc.signal(sig);
    let code = proc.wait_exit(EXIT_TIMEOUT);
    let elapsed = t0.elapsed();

    assert_eq!(
        code,
        Some(0),
        "SIG{sig} must exit 0; logs:\n{}",
        proc.logs()
    );
    assert!(
        elapsed < PROMPT_EXIT,
        "SIG{sig} must exit promptly (< {PROMPT_EXIT:?}); took {elapsed:?}"
    );
}

#[test]
fn sigterm_exits_cleanly_and_promptly() {
    assert_signal_exits_cleanly("TERM", 15);
}

#[test]
fn sigint_exits_cleanly_and_promptly() {
    assert_signal_exits_cleanly("INT", 2);
}

/// A supervisor may signal a reload the moment it has spawned the sender, before
/// the runtime has registered any handler. That SIGHUP must not kill it, and
/// once start-up is done a SIGHUP is still served.
///
/// The window is held open deterministically: `--config` names a FIFO, and
/// reading it blocks before any handler is registered until the test writes.
#[test]
fn a_sighup_before_the_handlers_exist_does_not_kill_the_sender() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips.txt");
    std::fs::write(&ips, "127.0.0.1\n").expect("write ips file");
    let config = dir.path().join("config.toml");
    let fifo = std::ffi::CString::new(config.to_str().unwrap()).unwrap();
    // SAFETY: a valid terminated path; mkfifo only creates the node.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0, "mkfifo");
    let port = free_udp_port().to_string();
    let mut proc = SenderProc::spawn(&[
        port.as_str(),
        "127.0.0.1",
        "9999",
        ips.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    // Blocked opening the FIFO: no reader handler exists yet.
    thread::sleep(Duration::from_millis(300));
    proc.signal("HUP");
    thread::sleep(Duration::from_millis(200));
    assert!(
        matches!(proc.child.try_wait(), Ok(None)),
        "a SIGHUP before the handlers were registered killed the sender; logs:\n{}",
        proc.logs()
    );

    // Release start-up with an empty configuration.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&config)
        .and_then(|mut f| f.write_all(b""))
        .expect("write the FIFO");
    assert!(proc.wait_for_log("sender ready for reload signals", START_TIMEOUT));
    assert!(proc.wait_for_log("listening for SRT", START_TIMEOUT));
    // The early signal preceded the start-up read, so it owes no reload.
    assert_eq!(proc.logs().matches("received SIGHUP").count(), 0);
    proc.signal("HUP");
    assert!(
        proc.wait_for_log_count("received SIGHUP", 1, START_TIMEOUT),
        "a SIGHUP after start-up was not served; logs:\n{}",
        proc.logs()
    );
    proc.signal("TERM");
    assert_eq!(proc.wait_exit(EXIT_TIMEOUT), Some(0));
}

/// Start-up can take seconds before the event loop exists: every uplink dial
/// waits on the resolver, and a strict pair read retries a mismatched hash. A
/// stop request must cut through both, run the shutdown hooks and exit 0.
#[cfg(target_os = "linux")]
mod during_startup {
    use super::*;

    const SLOW_HOST: &str = "slow-receiver.invalid";
    /// Per-lookup hang. Two uplinks make start-up twice this long, far past
    /// `PROMPT_EXIT`, so a signal that is only noticed afterwards fails.
    const LOOKUP_HANG_MS: &str = "4000";

    /// A sender whose two uplink dials each hang in the receiver lookup.
    fn spawn_with_hanging_lookups(dir: &std::path::Path) -> (SenderProc, std::path::PathBuf) {
        let library = dir.join("slow_resolver.so");
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-O2"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/support/slow_resolver.c"
                ))
                .args(["-ldl", "-o"])
                .arg(&library)
                .status()
                .unwrap()
                .success()
        );
        let ips = dir.join("ips.txt");
        let stats = dir.join("stats.json");
        std::fs::write(&ips, "127.0.0.1\n127.0.0.2\n").expect("write ips file");
        let proc = SenderProc::spawn_with_env(
            &[
                &free_udp_port().to_string(),
                SLOW_HOST,
                "9999",
                ips.to_str().unwrap(),
                "--stats-file",
                stats.to_str().unwrap(),
                "--stats-file-interval",
                "50",
            ],
            &[
                ("LD_PRELOAD", library.to_str().unwrap()),
                ("SRTLA_TEST_SLOW_HOST", SLOW_HOST),
                ("SRTLA_TEST_SLOW_MS", LOOKUP_HANG_MS),
            ],
        );
        (proc, stats)
    }

    fn wait_for_file(path: &std::path::Path) {
        let deadline = Instant::now() + START_TIMEOUT;
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "{} never appeared",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_signal_cuts_through_the_dial(sig: &str, signum: u32) {
        let dir = tempfile::tempdir().unwrap();
        let (mut proc, stats) = spawn_with_hanging_lookups(dir.path());
        assert!(proc.wait_for_log("listening for SRT", START_TIMEOUT));
        assert!(proc.wait_for_handler(signum, START_TIMEOUT));
        wait_for_file(&stats);
        // Now inside the first uplink's lookup.
        thread::sleep(Duration::from_millis(300));
        assert!(
            !proc.logs().contains("uplink"),
            "the dial finished early; logs:\n{}",
            proc.logs()
        );

        let t0 = Instant::now();
        proc.signal(sig);
        let code = proc.wait_exit(EXIT_TIMEOUT);
        let elapsed = t0.elapsed();

        assert_eq!(
            code,
            Some(0),
            "SIG{sig} must exit 0; logs:\n{}",
            proc.logs()
        );
        assert!(
            elapsed < PROMPT_EXIT,
            "SIG{sig} during the start-up dial must exit promptly (< {PROMPT_EXIT:?}); took \
             {elapsed:?}; logs:\n{}",
            proc.logs()
        );
        assert!(
            !stats.exists(),
            "the shutdown hook must unlink the stats file"
        );
    }

    #[test]
    fn sigterm_during_the_startup_dial_exits_cleanly_and_promptly() {
        assert_signal_cuts_through_the_dial("TERM", 15);
    }

    #[test]
    fn sigint_during_the_startup_dial_exits_cleanly_and_promptly() {
        assert_signal_cuts_through_the_dial("INT", 2);
    }

    /// The other start-up await: a strict pair read whose hash does not match
    /// retries for two seconds.
    #[test]
    fn sigterm_during_the_strict_startup_read_exits_cleanly_and_promptly() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ips = dir.path().join("ips");
        let map = dir.path().join("map");
        let stats = dir.path().join("stats.json");
        std::fs::write(&ips, "127.0.0.1").unwrap();
        std::fs::write(
            &map,
            serde_json::json!({
                "schema_version":1,"generation":1,"ips_file_sha256":"0".repeat(64),
                "links":[{"link_id":"path-a","ip":"127.0.0.1","iface":"lo"}]
            })
            .to_string(),
        )
        .unwrap();
        for path in [&ips, &map] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut proc = SenderProc::spawn(&[
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
        assert!(proc.wait_for_log("listening for SRT", START_TIMEOUT));
        assert!(proc.wait_for_handler(15, START_TIMEOUT));
        wait_for_file(&stats);

        let t0 = Instant::now();
        proc.signal("TERM");
        let code = proc.wait_exit(EXIT_TIMEOUT);
        let elapsed = t0.elapsed();

        assert_eq!(code, Some(0), "logs:\n{}", proc.logs());
        // Half the retry budget: an exit that waited the read out is too late.
        assert!(
            elapsed < Duration::from_secs(1),
            "SIGTERM during the strict start-up read took {elapsed:?}; logs:\n{}",
            proc.logs()
        );
        assert!(
            !proc.logs().contains("bind-map degraded"),
            "the read was waited out; logs:\n{}",
            proc.logs()
        );
        assert!(
            !stats.exists(),
            "the shutdown hook must unlink the stats file"
        );
    }

    /// Racing the dial against termination must not cost a reload: a SIGHUP
    /// that lands in the same window stays queued and is served exactly once.
    #[test]
    fn sighup_during_the_startup_dial_queues_exactly_one_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (mut proc, _stats) = spawn_with_hanging_lookups(dir.path());
        assert!(proc.wait_for_log("listening for SRT", START_TIMEOUT));
        assert!(proc.wait_for_handler(1, START_TIMEOUT));
        thread::sleep(Duration::from_millis(300));
        proc.signal("HUP");

        // Both start-up dials hang first; the queued reload comes after them.
        assert!(
            proc.wait_for_log("received SIGHUP", Duration::from_secs(15)),
            "queued SIGHUP lost; logs:\n{}",
            proc.logs()
        );
        thread::sleep(Duration::from_millis(1500));
        assert_eq!(
            proc.logs().matches("received SIGHUP").count(),
            1,
            "logs:\n{}",
            proc.logs()
        );
        assert!(
            matches!(proc.child.try_wait(), Ok(None)),
            "sender died; logs:\n{}",
            proc.logs()
        );
    }
}
