//! Required binding against real interfaces: a mapped source that leaves its
//! device and comes back.
//!
//! The in-process tests drive this through a binder that can be told its source
//! is gone. This one asks the kernel: two veth uplinks in a private namespace, a
//! minimal SRTLA receiver in another, and the address of one uplink removed,
//! moved to the other device, or lost with its whole device. In every case the
//! link must go down under its own identity, own no socket and send nothing
//! while its source is not on its mapped device, and return by itself — no
//! `SIGHUP` — once it is.
//!
//! Privileged supplement: it needs root and `ip` (iproute2), nothing else, and
//! self-skips otherwise, so an ordinary CI run does not prove it. Run it as root,
//! for example in a privileged container.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use srtla_protocol::{
    SRTLA_ID_LEN, SRTLA_TYPE_KEEPALIVE, SRTLA_TYPE_REG1, SRTLA_TYPE_REG2, SRTLA_TYPE_REG3,
};

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");
const RECEIVER: &str = "10.9.5.5";
const RECEIVER_PORT: u16 = 5000;
/// One housekeeping tick, plus the telemetry interval, plus slack.
const NOTICED_WITHIN: Duration = Duration::from_secs(3);
/// The slow reconnect backoff (5 s), one tick, registration, and slack.
const RETURNS_WITHIN: Duration = Duration::from_secs(12);
/// A required link is checked against its device every 200 ms, so it must be
/// retired well inside one 1 s housekeeping tick (telemetry interval and
/// polling included).
const RETIRED_WITHIN: Duration = Duration::from_millis(650);
/// Distinct namespace names within one test process.
static TOPOLOGIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// The scenarios measure timing on shared CPU; run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn ip_checked(args: &[&str]) {
    assert!(ip(args), "ip {} failed", args.join(" "));
}

/// Root, and allowed to create a network namespace.
fn can_build_namespaces() -> bool {
    let n = TOPOLOGIES.fetch_add(1, Ordering::SeqCst);
    let probe = format!("srtla-probe-{}-{n}", std::process::id());
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let ok = root && ip(&["netns", "add", &probe]);
    if ok {
        ip(&["netns", "del", &probe]);
    }
    ok
}

/// Sender namespace with uplinks `v0`/`v1`, receiver namespace with their peers
/// `r0`/`r1`. Uplink `i` holds 10.9.`i`.1; the receiver answers on 10.9.5.5,
/// reachable through either uplink.
struct Topology {
    sender: String,
    receiver: String,
}

impl Topology {
    fn build() -> Self {
        let pid = std::process::id();
        let n = TOPOLOGIES.fetch_add(1, Ordering::SeqCst);
        let topology = Self {
            sender: format!("srtla-tx-{pid}-{n}"),
            receiver: format!("srtla-rx-{pid}-{n}"),
        };
        for ns in [&topology.sender, &topology.receiver] {
            ip_checked(&["netns", "add", ns]);
            ip_checked(&["-n", ns, "link", "set", "lo", "up"]);
            topology.sysctl(ns, "all/rp_filter");
            topology.sysctl(ns, "default/rp_filter");
        }
        ip_checked(&[
            "-n",
            &topology.receiver,
            "addr",
            "add",
            &format!("{RECEIVER}/32"),
            "dev",
            "lo",
        ]);
        topology.plug(0);
        topology.plug(1);
        topology
    }

    fn sysctl(&self, ns: &str, key: &str) {
        let script = format!("echo 0 > /proc/sys/net/ipv4/conf/{key}");
        ip_checked(&["netns", "exec", ns, "sh", "-c", &script]);
    }

    /// Create uplink `i` with its addresses and its route to the receiver.
    fn plug(&self, i: u8) {
        let (tx, rx) = (self.sender.as_str(), self.receiver.as_str());
        let (v, r) = (format!("v{i}"), format!("r{i}"));
        ip_checked(&[
            "link", "add", &v, "netns", tx, "type", "veth", "peer", "name", &r, "netns", rx,
        ]);
        // A second address keeps the device addressed while the mapped one is
        // away, as a modem's own management address would.
        ip_checked(&[
            "-n",
            tx,
            "addr",
            "add",
            &format!("10.8.{i}.9/24"),
            "dev",
            &v,
        ]);
        ip_checked(&[
            "-n",
            rx,
            "addr",
            "add",
            &format!("10.9.{i}.2/24"),
            "dev",
            &r,
        ]);
        ip_checked(&["-n", tx, "link", "set", &v, "up"]);
        ip_checked(&["-n", rx, "link", "set", &r, "up"]);
        self.sysctl(tx, &format!("{v}/rp_filter"));
        self.sysctl(rx, &format!("{r}/rp_filter"));
        self.assign(i, &v);
        let metric = (10 * (u32::from(i) + 1)).to_string();
        ip_checked(&[
            "-n", tx, "route", "add", RECEIVER, "dev", &v, "metric", &metric,
        ]);
    }

    fn unplug(&self, i: u8) {
        ip_checked(&["-n", &self.sender, "link", "del", &format!("v{i}")]);
    }

    fn source(i: u8) -> String {
        format!("10.9.{i}.1")
    }

    /// Put uplink `i`'s mapped source on `dev`.
    fn assign(&self, i: u8, dev: &str) {
        let cidr = format!("{}/24", Self::source(i));
        ip_checked(&["-n", &self.sender, "addr", "add", &cidr, "dev", dev]);
    }

    fn unassign(&self, i: u8, dev: &str) {
        let cidr = format!("{}/24", Self::source(i));
        ip_checked(&["-n", &self.sender, "addr", "del", &cidr, "dev", dev]);
    }

    /// Local addresses of the UDP sockets open in the sender namespace.
    fn sender_udp_sockets(&self) -> String {
        let out = Command::new("ip")
            .args(["netns", "exec", &self.sender, "ss", "-H", "-uan"])
            .output()
            .expect("run ss");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        ip(&["netns", "del", &self.sender]);
        ip(&["netns", "del", &self.receiver]);
    }
}

/// A UDP socket created inside `ns`. The namespace is entered on a thread that
/// ends here; the socket keeps living there.
fn udp_socket_in(ns: &str, port: u16) -> UdpSocket {
    let path = format!("/var/run/netns/{ns}");
    thread::spawn(move || {
        let file = std::fs::File::open(&path).expect("open namespace");
        // SAFETY: `file` is an open namespace fd, and `setns` moves only the
        // calling thread, which returns right after binding.
        let entered = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
        assert_eq!(entered, 0, "enter namespace");
        UdpSocket::bind(("0.0.0.0", port)).expect("bind receiver")
    })
    .join()
    .expect("namespace thread")
}

/// Just enough of an SRTLA receiver for links to register and stay alive, plus
/// a record of every datagram's arrival time, source and type.
struct Receiver {
    seen: Arc<Mutex<Vec<(Instant, IpAddr, u16)>>>,
    stop: Arc<AtomicBool>,
}

impl Receiver {
    fn start(ns: &str) -> Self {
        let socket = udp_socket_in(ns, RECEIVER_PORT);
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, stopped) = (seen.clone(), stop.clone());
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !stopped.load(Ordering::SeqCst) {
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 2 {
                    continue;
                }
                let kind = u16::from_be_bytes([buf[0], buf[1]]);
                log.lock().unwrap().push((Instant::now(), peer.ip(), kind));
                match kind {
                    SRTLA_TYPE_REG1 if n >= 2 + SRTLA_ID_LEN / 2 => {
                        // Sender half echoed, receiver half fixed.
                        let mut reply = vec![0xab; 2 + SRTLA_ID_LEN];
                        reply[..2].copy_from_slice(&SRTLA_TYPE_REG2.to_be_bytes());
                        reply[2..2 + SRTLA_ID_LEN / 2]
                            .copy_from_slice(&buf[2..2 + SRTLA_ID_LEN / 2]);
                        let _ = socket.send_to(&reply, peer);
                    }
                    SRTLA_TYPE_REG2 => {
                        let mut reply = [0u8; 32];
                        reply[..2].copy_from_slice(&SRTLA_TYPE_REG3.to_be_bytes());
                        let _ = socket.send_to(&reply, peer);
                    }
                    SRTLA_TYPE_KEEPALIVE => {
                        let _ = socket.send_to(&buf[..n], peer);
                    }
                    _ => {}
                }
            }
        });
        Self { seen, stop }
    }

    /// Datagrams from `source` that arrived after `since`.
    fn heard_from_since(&self, source: &str, since: Instant) -> usize {
        let source: IpAddr = source.parse().unwrap();
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, ip, _)| *at > since && *ip == source)
            .count()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct Sender {
    child: Child,
    logs: Arc<Mutex<String>>,
    stats: std::path::PathBuf,
}

impl Sender {
    /// A required-mode sender in `ns`, mapping link `a` to (10.9.0.1, v0) and
    /// link `b` to (10.9.1.1, v1).
    fn start(ns: &str, dir: &Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let (ips, map, stats) = (dir.join("ips"), dir.join("map"), dir.join("stats"));
        let content = format!("{}\n{}", Topology::source(0), Topology::source(1));
        let sidecar = serde_json::json!({
            "schema_version": 1,
            "generation": 1,
            "ips_file_sha256": srtla_send::bind_map::IpsFile::from_bytes(content.as_bytes())
                .unwrap()
                .sha256()
                .to_string(),
            "links": [
                {"link_id": "a", "ip": Topology::source(0), "iface": "v0"},
                {"link_id": "b", "ip": Topology::source(1), "iface": "v1"},
            ],
        });
        std::fs::write(&ips, content).unwrap();
        std::fs::write(&map, sidecar.to_string()).unwrap();
        for path in [&ips, &map] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // `ip netns exec` replaces itself with the sender, so the child is it.
        let mut child = Command::new("ip")
            .args(["netns", "exec", ns, BIN, "6000", RECEIVER])
            .arg(RECEIVER_PORT.to_string())
            .arg(&ips)
            .arg("--bind-map")
            .arg(&map)
            .args(["--require-bind-map", "--stats-file"])
            .arg(&stats)
            .args(["--stats-file-interval", "50"])
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn srtla_send");
        let logs = Arc::new(Mutex::new(String::new()));
        let streams: [Box<dyn std::io::Read + Send>; 2] = [
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
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
        Self { child, logs, stats }
    }

    fn logs(&self) -> String {
        self.logs.lock().unwrap().clone()
    }

    /// The published row for `link_id`, if the document has one.
    fn row(&self, link_id: &str) -> Option<serde_json::Value> {
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.stats).ok()?).ok()?;
        doc["connections"]
            .as_array()?
            .iter()
            .find(|row| row["link_id"] == link_id)
            .cloned()
    }

    fn carries_traffic(&self, link_id: &str) -> bool {
        self.row(link_id).is_some_and(|row| {
            row.get("binding_state").is_none() && row["weight_percent"].as_u64() > Some(0)
        })
    }

    fn is_retired(&self, link_id: &str) -> bool {
        self.row(link_id)
            .is_some_and(|row| row["binding_state"] == "retired")
    }

    /// Wait for `done`, returning how long it took.
    fn wait(&self, what: &str, within: Duration, done: impl Fn(&Self) -> bool) -> Duration {
        let start = Instant::now();
        while !done(self) {
            assert!(
                start.elapsed() < within,
                "{what} did not happen within {within:?}; rows a={:?} b={:?}; logs:\n{}",
                self.row("a"),
                self.row("b"),
                self.logs()
            );
            thread::sleep(Duration::from_millis(50));
        }
        start.elapsed()
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Link `a` must be down under its own identity, without a socket, and silent
/// for as long as `away` lasts; link `b` must be untouched.
fn assert_retired_and_silent(
    topology: &Topology,
    receiver: &Receiver,
    sender: &Sender,
    case: &str,
    away: Duration,
) {
    let noticed = sender.wait(
        &format!("{case}: link a retired"),
        NOTICED_WITHIN,
        |sender| sender.is_retired("a"),
    );
    assert!(
        noticed <= RETIRED_WITHIN,
        "{case}: retired after {noticed:?}, not within {RETIRED_WITHIN:?}"
    );
    let retired_at = Instant::now();
    let row = sender.row("a").unwrap();
    assert_eq!(row["iface"], "v0", "{case}: identity lost: {row}");
    assert_eq!(row["weight_percent"], 0, "{case}: {row}");
    thread::sleep(away);
    assert!(sender.is_retired("a"), "{case}: link a came back early");
    assert!(sender.carries_traffic("b"), "{case}: link b was disturbed");
    let sockets = topology.sender_udp_sockets();
    assert!(
        !sockets.contains(&format!("{}:", Topology::source(0))),
        "{case}: a socket still holds the mapped source:\n{sockets}"
    );
    assert_eq!(
        receiver.heard_from_since(&Topology::source(0), retired_at),
        0,
        "{case}: link a transmitted while its source was not on v0"
    );
    eprintln!("{case}: retired {noticed:?} after the change, silent for {away:?}");
}

fn assert_returns(receiver: &Receiver, sender: &Sender, case: &str) {
    let restored_at = Instant::now();
    let took = sender.wait(
        &format!("{case}: link a returned"),
        RETURNS_WITHIN,
        |sender| sender.carries_traffic("a"),
    );
    assert!(
        receiver.heard_from_since(&Topology::source(0), restored_at) > 0,
        "{case}: link a reports traffic the receiver never saw"
    );
    assert!(sender.carries_traffic("b"), "{case}: link b was disturbed");
    eprintln!("{case}: returned {took:?} after its source was restored");
}

#[test]
fn a_required_link_goes_down_with_its_source_and_returns_with_it() {
    let _serial = serial();
    if !can_build_namespaces() {
        eprintln!("Skipping: needs root and iproute2 to build network namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let topology = Topology::build();
    let receiver = Receiver::start(&topology.receiver);
    let mut sender = Sender::start(&topology.sender, dir.path());
    sender.wait("both links registered", Duration::from_secs(20), |sender| {
        sender.carries_traffic("a") && sender.carries_traffic("b")
    });

    // The address disappears for a few seconds and comes back.
    topology.unassign(0, "v0");
    assert_retired_and_silent(
        &topology,
        &receiver,
        &sender,
        "blip",
        Duration::from_secs(3),
    );
    topology.assign(0, "v0");
    assert_returns(&receiver, &sender, "blip");

    // The address stays on the host but on the wrong device. An IP-only bind
    // would succeed here, so every retry in this window has to be refused by
    // the device check itself.
    topology.unassign(0, "v0");
    topology.assign(0, "v1");
    assert_retired_and_silent(
        &topology,
        &receiver,
        &sender,
        "moved",
        Duration::from_secs(4),
    );
    topology.unassign(0, "v1");
    topology.assign(0, "v0");
    assert_returns(&receiver, &sender, "moved");

    // The whole device goes away and is created again under the same name.
    topology.unplug(0);
    assert_retired_and_silent(
        &topology,
        &receiver,
        &sender,
        "replug",
        Duration::from_secs(3),
    );
    topology.plug(0);
    assert_returns(&receiver, &sender, "replug");

    // Short blips, each caught well inside one housekeeping tick.
    for blip in 0..4 {
        let case = format!("short blip {blip}");
        thread::sleep(Duration::from_millis(300 + 170 * blip));
        topology.unassign(0, "v0");
        assert_retired_and_silent(
            &topology,
            &receiver,
            &sender,
            &case,
            Duration::from_millis(400),
        );
        topology.assign(0, "v0");
        assert_returns(&receiver, &sender, &case);
    }

    let logs = sender.logs();
    assert!(
        !logs.contains("received SIGHUP"),
        "no reload was sent:\n{logs}"
    );
    assert!(
        !logs.contains("has no I/O entry"),
        "a retired link must not be reported as a broken one:\n{logs}"
    );
    // A returning link is bound against the device as it is now, so the next
    // egress check has nothing stale to rebind.
    assert!(
        !logs.contains("re-enumerated"),
        "a returned link kept the old interface index:\n{logs}"
    );
    assert!(
        matches!(sender.child.try_wait(), Ok(None)),
        "sender died:\n{logs}"
    );
}
