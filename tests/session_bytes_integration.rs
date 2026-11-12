//! ADR-002 end-to-end: the bond-level `bytes_sent_total` is monotonic across a
//! SIGHUP that removes an uplink.
//!
//! This is the regression a naive `links.map(bytes_sent_total).sum()` ships: the
//! removed link's bytes leave the sum and the operator's "total transferred"
//! runs backwards mid-stream. A unit test on [`SessionBytes`] proves the
//! accumulator's arithmetic; only a live process proves the accumulator is
//! actually the thing feeding the published document, that it is advanced
//! before the reload tears the link down, and that a real reload cannot make it
//! regress.
//!
//! Unprivileged by construction: two loopback source addresses (`127.0.0.1` and
//! `127.0.0.2` — all of `127.0.0.0/8` is local on Linux) stand in for two
//! modems, and the receiver is a ~60-line in-process UDP responder rather than
//! `srtla_rec`, so this needs no namespaces, no `sudo`, and no external
//! binaries. It therefore runs in the ordinary gate, unlike `tests/netns_*`.
#![cfg(all(unix, target_os = "linux"))]

use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use srtla_protocol::{
    SRTLA_ID_LEN, SRTLA_TYPE_ACK, SRTLA_TYPE_KEEPALIVE, SRTLA_TYPE_REG1, SRTLA_TYPE_REG2,
    SRTLA_TYPE_REG3,
};

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");
const STATS_INTERVAL_MS: u64 = 200;
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
/// SRT payload size the injector uses; every forwarded packet is exactly this
/// many wire bytes, which is what makes the byte totals checkable by hand.
const PAYLOAD_LEN: usize = 1316;
/// One injection burst. Re-injected on each poll so the scheduler keeps being
/// asked to pick a link, which is what eventually spreads load onto the second
/// uplink instead of parking on whichever one was selected first.
const INJECT_BATCH: u32 = 200;
const INJECT_SEQ_BASE: u32 = 1_000;

// ---- A minimal SRTLA receiver ----------------------------------------------

/// Answers the REG1/REG2/REG3 handshake, echoes keepalives, and ACKs data.
///
/// The ACKs are the load-bearing part: without them in-flight counts climb
/// unbounded on whichever link the scheduler picked first, and the bond never
/// spreads traffic over both uplinks — which would leave the SIGHUP removal
/// with no bytes to take away and the monotonicity assertion vacuous.
struct MiniReceiver {
    port: u16,
    data_packets: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MiniReceiver {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mini receiver");
        let port = socket.local_addr().expect("receiver addr").port();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("receiver read timeout");

        let data_packets = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let counter = data_packets.clone();
        let halt = stop.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !halt.load(Ordering::Relaxed) {
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 2 {
                    continue;
                }
                serve(&socket, &buf[..n], peer, &counter);
            }
        });

        Self {
            port,
            data_packets,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MiniReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(socket: &UdpSocket, pkt: &[u8], peer: SocketAddr, data_packets: &AtomicU64) {
    // SRT data packets carry a clear high bit; everything else is SRTLA control.
    if pkt[0] & 0x80 == 0 {
        data_packets.fetch_add(1, Ordering::Relaxed);
        if pkt.len() >= 4 {
            let seq = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
            let mut ack = [0u8; 8];
            ack[0..2].copy_from_slice(&SRTLA_TYPE_ACK.to_be_bytes());
            ack[4..8].copy_from_slice(&seq.to_be_bytes());
            let _ = socket.send_to(&ack, peer);
        }
        return;
    }

    match u16::from_be_bytes([pkt[0], pkt[1]]) {
        SRTLA_TYPE_REG1 if pkt.len() >= 2 + SRTLA_ID_LEN => {
            // The receiver owns the second half of the group id; the sender's
            // first half rides back verbatim.
            let mut reply = vec![0u8; 2 + SRTLA_ID_LEN];
            reply[0..2].copy_from_slice(&SRTLA_TYPE_REG2.to_be_bytes());
            reply[2..2 + SRTLA_ID_LEN].copy_from_slice(&pkt[2..2 + SRTLA_ID_LEN]);
            reply[2 + SRTLA_ID_LEN / 2..].fill(0xab);
            let _ = socket.send_to(&reply, peer);
        }
        SRTLA_TYPE_REG2 => {
            let mut reply = [0u8; 2];
            reply.copy_from_slice(&SRTLA_TYPE_REG3.to_be_bytes());
            let _ = socket.send_to(&reply, peer);
        }
        SRTLA_TYPE_KEEPALIVE => {
            let _ = socket.send_to(pkt, peer);
        }
        _ => {}
    }
}

// ---- Driving the sender -----------------------------------------------------

struct Sender {
    child: Child,
}

impl Drop for Sender {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Sender {
    fn sighup(&self) {
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("run kill -HUP");
        assert!(status.success(), "kill -HUP failed");
    }
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral udp")
        .local_addr()
        .unwrap()
        .port()
}

/// Read the published telemetry document, tolerating the atomic-publish window
/// in which the file does not yet exist.
fn read_stats(path: &std::path::Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn bond_total(snapshot: &serde_json::Value) -> u64 {
    snapshot["bytes_sent_total"]
        .as_u64()
        .expect("ADR-002 top-level bytes_sent_total must be present and numeric")
}

fn link_totals(snapshot: &serde_json::Value) -> Vec<u64> {
    snapshot["connections"]
        .as_array()
        .expect("connections array")
        .iter()
        .map(|c| {
            c["bytes_sent_total"]
                .as_u64()
                .expect("ADR-002 per-connection bytes_sent_total must be present")
        })
        .collect()
}

fn live_link_total(snapshot: &serde_json::Value) -> u64 {
    link_totals(snapshot).iter().sum()
}

/// A link is reported inactive as `weight_percent == 0`, so this is the only
/// registration signal the telemetry document exposes. Waiting on it (rather
/// than on the connection COUNT, which is populated the instant the pool is
/// built) is what keeps the bond from being driven while an uplink is still in
/// its `Registering` phase and therefore unschedulable.
fn all_links_active(snapshot: &serde_json::Value) -> bool {
    let conns = match snapshot["connections"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return false,
    };
    conns
        .iter()
        .all(|c| c["weight_percent"].as_u64().unwrap_or(0) > 0)
}

fn wait_for<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(value) = probe() {
            return Some(value);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Push `count` SRT-shaped data packets at the sender's local listener.
fn inject(port: u16, first_seq: u32, count: u32) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind injector");
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut pkt = [0u8; PAYLOAD_LEN];
    for i in 0..count {
        // A clear high bit is what marks this an SRT DATA packet.
        let seq = (first_seq + i) & 0x7fff_ffff;
        pkt[0..4].copy_from_slice(&seq.to_be_bytes());
        let _ = socket.send_to(&pkt, target);
        // Paced so the sender's batch flusher and the receiver's ACKs keep up;
        // a blind blast just overruns the loopback socket buffer.
        thread::sleep(Duration::from_micros(300));
    }
}

#[test]
fn bond_bytes_sent_total_is_monotonic_across_a_sighup_link_removal() {
    let receiver = MiniReceiver::start();
    let dir = tempfile::tempdir().expect("tempdir");
    let ips = dir.path().join("ips.txt");
    let stats = dir.path().join("stats.json");
    std::fs::write(&ips, "127.0.0.1\n127.0.0.2\n").expect("write ips file");

    let srt_port = free_udp_port();
    let child = Command::new(BIN)
        .args([
            &srt_port.to_string(),
            "127.0.0.1",
            &receiver.port.to_string(),
            ips.to_str().unwrap(),
            "--stats-file",
            stats.to_str().unwrap(),
            "--stats-file-interval",
            &STATS_INTERVAL_MS.to_string(),
        ])
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn srtla_send");
    let sender = Sender { child };

    // Given: BOTH uplinks have finished REG1/REG2/REG3 and are schedulable.
    let ready = wait_for(READY_TIMEOUT, || {
        let snap = read_stats(&stats)?;
        (snap["connections"].as_array()?.len() == 2 && all_links_active(&snap)).then_some(snap)
    });
    assert!(
        ready.is_some(),
        "both loopback uplinks must register against the mini receiver; last: {:?}",
        read_stats(&stats)
    );

    // When: traffic flows until BOTH links have actually carried some of it.
    // Without this the SIGHUP below would remove an empty link and the
    // monotonicity assertion would hold vacuously.
    let first = wait_for(SNAPSHOT_TIMEOUT, || {
        inject(srt_port, INJECT_SEQ_BASE, INJECT_BATCH);
        let snap = read_stats(&stats)?;
        let totals = link_totals(&snap);
        (totals.len() == 2 && totals.iter().all(|&b| b > 0)).then_some(snap)
    })
    .expect("both uplinks must carry bytes before the removal is meaningful");
    let first_total = bond_total(&first);
    let departed_bytes = link_totals(&first)[1];

    // And: a SIGHUP removes the second uplink — the one that just carried
    // `departed_bytes` — entirely.
    std::fs::write(&ips, "127.0.0.1\n").expect("rewrite ips file");
    sender.sighup();
    let reloaded = wait_for(SNAPSHOT_TIMEOUT, || {
        let snap = read_stats(&stats)?;
        (snap["connections"].as_array()?.len() == 1).then_some(snap)
    });
    assert!(
        reloaded.is_some(),
        "SIGHUP must drop the removed uplink from the pool"
    );

    // And: the surviving link carries more traffic afterwards. Polled rather
    // than slept on: the snapshot only refreshes on a housekeeping tick, which
    // is coarser than the telemetry publish cadence, so a fixed sleep reads a
    // stale document with a fresh timestamp.
    inject(srt_port, INJECT_SEQ_BASE * 2, INJECT_BATCH);
    let second = wait_for(SNAPSHOT_TIMEOUT, || {
        inject(srt_port, INJECT_SEQ_BASE * 3, INJECT_BATCH);
        let snap = read_stats(&stats)?;
        (bond_total(&snap) > first_total).then_some(snap)
    })
    .expect("post-reload traffic must keep accruing on the bond total");
    let second_total = bond_total(&second);
    let second_links = live_link_total(&second);

    // Then: the operator-facing total never ran backwards across the teardown.
    assert!(
        second_total >= first_total,
        "bond bytes_sent_total regressed across a SIGHUP link removal: {first_total} -> \
         {second_total}\nfirst: {first}\nsecond: {second}"
    );

    // And: the bond figure is an accumulator, not a sum of the live links. The
    // departed uplink's bytes are still counted, so the total must now EXCEED
    // the live sum by at least what that link carried — this is the assertion a
    // `links.map(total).sum()` implementation fails.
    assert!(
        departed_bytes > 0,
        "the removed uplink must have carried bytes, got {first}"
    );
    assert!(
        second_total >= second_links + departed_bytes,
        "the bond total dropped the departed link's {departed_bytes} bytes: total={second_total} \
         live-sum={second_links}\n{second}"
    );
    assert!(
        receiver.data_packets.load(Ordering::Relaxed) > 0,
        "the mini receiver never saw forwarded data; the bond was not actually carrying"
    );
}

#[test]
fn unpublished_tail_bytes_are_preserved_on_required_withdrawal_and_default_replacement() {
    use std::os::unix::fs::PermissionsExt;

    use srtla_send::bind_map::IpsFile;
    for required in [false, true] {
        let receiver = MiniReceiver::start();
        let dir = tempfile::tempdir().unwrap();
        let ips = dir.path().join("ips");
        let map = dir.path().join("map");
        let stats = dir.path().join("stats");
        let publish = |content: &str, generation: u64| {
            let links = if content.is_empty() {
                serde_json::json!([])
            } else {
                serde_json::json!([{"link_id":"path-a","ip":"127.0.0.1","iface":"lo"}])
            };
            for (path, data) in [
                (&ips, content.to_owned()),
                (
                    &map,
                    serde_json::json!({"schema_version":1,"generation":generation,
                    "ips_file_sha256":IpsFile::from_bytes(content.as_bytes()).unwrap().sha256(),
                    "links":links})
                    .to_string(),
                ),
            ] {
                let tmp = path.with_extension("tmp");
                std::fs::write(&tmp, data).unwrap();
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::rename(tmp, path).unwrap();
            }
        };
        publish("127.0.0.1\n", 1);
        let port = free_udp_port();
        let mut cmd = Command::new(BIN);
        cmd.args([
            &port.to_string(),
            "127.0.0.1",
            &receiver.port.to_string(),
            ips.to_str().unwrap(),
            "--stats-file",
            stats.to_str().unwrap(),
            "--stats-file-interval",
            "10",
        ]);
        if required {
            cmd.args(["--require-bind-map", "--bind-map", map.to_str().unwrap()]);
        }
        let sender = Sender {
            child: cmd
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        };
        wait_for(READY_TIMEOUT, || {
            let snap = read_stats(&stats)?;
            all_links_active(&snap).then_some(())
        })
        .expect("initial link registered");
        inject(port, 10_000, 10);
        wait_for(SNAPSHOT_TIMEOUT, || {
            let snap = read_stats(&stats)?;
            (bond_total(&snap) > 0).then_some(())
        })
        .expect("initial byte snapshot");
        // Real traffic reaches the receiver after the last published accounting
        // tick, then the entire old pool leaves before the next one.
        let before = receiver.data_packets.load(Ordering::Relaxed);
        inject(port, 20_000, 10);
        let deadline = Instant::now() + Duration::from_secs(2);
        while receiver.data_packets.load(Ordering::Relaxed) < before + 10 {
            assert!(Instant::now() < deadline, "tail packets were not forwarded");
            thread::sleep(Duration::from_millis(1));
        }
        let floor = receiver.data_packets.load(Ordering::Relaxed) * PAYLOAD_LEN as u64;
        assert!(
            bond_total(&read_stats(&stats).unwrap()) < floor,
            "precondition: tail traffic must be newer than the published accounting snapshot"
        );
        if required {
            publish("", 2);
        } else {
            std::fs::write(&ips, "127.0.0.2\n").unwrap();
        }
        sender.sighup();
        let final_snapshot = wait_for(SNAPSHOT_TIMEOUT, || {
            let snap = read_stats(&stats)?;
            let links = snap["connections"].as_array()?;
            let applied = if required {
                links.is_empty() && snap["disposition"]["state"] == "mapped"
            } else {
                links.len() == 1 && link_totals(&snap)[0] == 0
            };
            applied.then_some(snap)
        })
        .expect("old pool removed/replaced");
        assert!(
            bond_total(&final_snapshot) >= floor,
            "late bytes lost: required={required}, wire floor={floor}, snapshot={final_snapshot}"
        );
    }
}
