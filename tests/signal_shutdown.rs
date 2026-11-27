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
        let mut child = Command::new(BIN)
            .args(args)
            .env("RUST_LOG", "info")
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

    /// Block until the sender has installed its handler for `signum`.
    ///
    /// The binary registers its handlers before it binds the SRT listener, so
    /// by the "listening for SRT" line this returns at once; the wait stays so
    /// these cases still only test the shutdown path, not the startup order
    /// (which the `startup_*` cases below pin). `SigCgt` in
    /// `/proc/<pid>/status` is the kernel's own record of caught signals.
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

// ---------------------------------------------------------------------------
// Startup order: the handlers are in place before the sender publishes.
//
// A supervisor treats the `--stats-file` snapshot (or the control socket, or
// the SRT listener) as "the sender is up" and may signal it right away. If the
// handlers were registered only after that, a SIGTERM in the gap would kill the
// process by the default action: exit by signal, and the stats file left
// behind. The gap is normally a few milliseconds, too short to hit reliably, so
// these cases widen it on purpose: the IP list is a FIFO with no writer, which
// holds the sender inside its startup read for as long as the test likes while
// the stats file is already being published.
// ---------------------------------------------------------------------------

/// Bound for each startup wait below; generous for a loaded CI runner.
const STARTUP_STEP_TIMEOUT: Duration = Duration::from_secs(10);

fn make_fifo(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(
        rc,
        0,
        "mkfifo {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
}

fn wait_for_path(path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Spawn a sender whose IP list is a FIFO nobody writes yet, and wait until it
/// has published its stats file. Returns the process and the two paths.
fn spawn_held_in_startup(
    dir: &std::path::Path,
) -> (SenderProc, std::path::PathBuf, std::path::PathBuf) {
    let ips = dir.join("ips.fifo");
    make_fifo(&ips);
    let stats = dir.join("stats.json");
    let port = free_udp_port().to_string();
    let proc = SenderProc::spawn(&[
        "--stats-file",
        stats.to_str().unwrap(),
        "--stats-file-interval",
        "50",
        port.as_str(),
        "127.0.0.1",
        "9999",
        ips.to_str().unwrap(),
    ]);
    assert!(
        wait_for_path(&stats, STARTUP_STEP_TIMEOUT),
        "sender never published its stats file; logs:\n{}",
        proc.logs()
    );
    (proc, ips, stats)
}

/// Let a startup held by [`spawn_held_in_startup`] finish: open the FIFO for
/// writing once the sender has it open for reading, write one uplink, close.
/// Gives up quietly if the sender is gone, so a regression is reported by the
/// caller's exit assertion rather than as a hang here.
fn release_startup(proc: &mut SenderProc, ips: &std::path::Path) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let deadline = Instant::now() + STARTUP_STEP_TIMEOUT;
    while Instant::now() < deadline {
        // O_NONBLOCK: fails with ENXIO until a reader has the FIFO open,
        // instead of blocking forever if the sender never opens it.
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(ips)
        {
            Ok(mut fifo) => {
                fifo.write_all(b"127.0.0.1\n").expect("write ips fifo");
                return;
            }
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
                if matches!(proc.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("open ips fifo: {e}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn startup_handlers_are_installed_before_the_stats_file_is_published() {
    let dir = tempfile::tempdir().unwrap();
    let (mut proc, ips, _stats) = spawn_held_in_startup(dir.path());

    // No wait here on purpose: the snapshot is visible, so every signal a
    // supervisor might send must already be caught.
    let status = std::fs::read_to_string(format!("/proc/{}/status", proc.child.id()))
        .expect("read /proc status");
    let caught = status
        .lines()
        .find_map(|l| l.strip_prefix("SigCgt:"))
        .and_then(|m| u64::from_str_radix(m.trim(), 16).ok())
        .expect("SigCgt line");
    for (name, signum) in [("HUP", 1u32), ("INT", 2), ("TERM", 15)] {
        assert!(
            caught & (1 << (signum - 1)) != 0,
            "stats file published before the SIG{name} handler was installed (SigCgt \
             {caught:#x}); logs:\n{}",
            proc.logs()
        );
    }

    release_startup(&mut proc, &ips);
}

#[test]
fn startup_sigterm_is_held_and_handled_once_startup_completes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut proc, ips, stats) = spawn_held_in_startup(dir.path());

    // Signal while the sender is still inside startup, exactly what a
    // supervisor stopping a just-started sender does.
    proc.signal("TERM");
    release_startup(&mut proc, &ips);

    let code = proc.wait_exit(EXIT_TIMEOUT);
    assert_eq!(
        code,
        Some(0),
        "a SIGTERM during startup must end in a clean exit, not the default action; logs:\n{}",
        proc.logs()
    );
    // The log pumps may still be draining the pipes after the exit.
    assert!(
        proc.wait_for_log("received SIGTERM", Duration::from_secs(2)),
        "the SIGTERM must reach the sender's handler; logs:\n{}",
        proc.logs()
    );
    let tmp = stats.with_file_name("stats.json.tmp");
    assert!(
        !stats.exists() && !tmp.exists(),
        "the clean exit must unlink the stats file and its .tmp sibling"
    );
}
