//! ADR-002 end-to-end: the bond-level `bytes_sent_total` is monotonic across a
//! SIGHUP that removes an uplink. The same receiver also checks when a
//! replacement joins an established group.
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

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use srtla_protocol::{
    SRTLA_ID_LEN, SRTLA_TYPE_ACK, SRTLA_TYPE_KEEPALIVE, SRTLA_TYPE_REG_NGP, SRTLA_TYPE_REG1,
    SRTLA_TYPE_REG2, SRTLA_TYPE_REG3,
};

const BIN: &str = env!("CARGO_BIN_EXE_srtla_send");
const STATS_INTERVAL_MS: u64 = 200;
const REPLACEMENT_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
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
    registrations: mpsc::Receiver<(SocketAddr, [u8; SRTLA_ID_LEN])>,
    all_reg2: mpsc::Receiver<SocketAddr>,
    replacement_keepalives: mpsc::Receiver<SocketAddr>,
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MiniReceiver {
    fn start(delay_replacement: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mini receiver");
        let port = socket.local_addr().expect("receiver addr").port();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("receiver read timeout");

        let data_packets = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let (registration_tx, registrations) = mpsc::channel();
        let (reg2_tx, all_reg2) = mpsc::channel();
        let (keepalive_tx, replacement_keepalives) = mpsc::channel();
        let reply_socket = socket.try_clone().expect("clone receiver socket");
        let counter = data_packets.clone();
        let halt = stop.clone();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut group = None;
            while !halt.load(Ordering::Relaxed) {
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if n < 2 {
                    continue;
                }
                if buf[..2] == SRTLA_TYPE_REG2.to_be_bytes() {
                    let _ = reg2_tx.send(peer);
                }
                let is_replacement = peer.ip() == REPLACEMENT_IP;
                if is_replacement && buf[..2] == SRTLA_TYPE_KEEPALIVE.to_be_bytes() {
                    let _ = keepalive_tx.send(peer);
                }
                if let Some(id) = serve(
                    &socket,
                    &buf[..n],
                    peer,
                    &counter,
                    &mut group,
                    delay_replacement && is_replacement,
                ) {
                    let _ = registration_tx.send((peer, id));
                }
            }
        });

        Self {
            port,
            data_packets,
            registrations,
            all_reg2,
            replacement_keepalives,
            socket: reply_socket,
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

fn serve(
    socket: &UdpSocket,
    pkt: &[u8],
    peer: SocketAddr,
    data_packets: &AtomicU64,
    group: &mut Option<[u8; SRTLA_ID_LEN]>,
    delay_reg3: bool,
) -> Option<[u8; SRTLA_ID_LEN]> {
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
        return None;
    }

    match u16::from_be_bytes([pkt[0], pkt[1]]) {
        SRTLA_TYPE_REG1 if pkt.len() >= 2 + SRTLA_ID_LEN => {
            // The receiver owns the second half of the group id; the sender's
            // first half rides back verbatim.
            let mut reply = vec![0u8; 2 + SRTLA_ID_LEN];
            reply[0..2].copy_from_slice(&SRTLA_TYPE_REG2.to_be_bytes());
            reply[2..2 + SRTLA_ID_LEN].copy_from_slice(&pkt[2..2 + SRTLA_ID_LEN]);
            reply[2 + SRTLA_ID_LEN / 2..].fill(0xab);
            *group = Some(reply[2..].try_into().unwrap());
            let _ = socket.send_to(&reply, peer);
        }
        SRTLA_TYPE_REG2 if pkt.len() == 2 + SRTLA_ID_LEN => {
            let id = pkt[2..].try_into().unwrap();
            if *group == Some(id) {
                if !delay_reg3 {
                    let _ = socket.send_to(&SRTLA_TYPE_REG3.to_be_bytes(), peer);
                }
                return Some(id);
            }
            let _ = socket.send_to(&SRTLA_TYPE_REG_NGP.to_be_bytes(), peer);
        }
        SRTLA_TYPE_KEEPALIVE => {
            let _ = socket.send_to(pkt, peer);
        }
        _ => {}
    }
    None
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

fn spawn_sender(
    ips: &std::path::Path,
    stats: &std::path::Path,
    srt_port: u16,
    receiver_port: u16,
) -> Sender {
    spawn_sender_with_options(ips, stats, srt_port, receiver_port, &[])
}

fn spawn_sender_with_options(
    ips: &std::path::Path,
    stats: &std::path::Path,
    srt_port: u16,
    receiver_port: u16,
    options: &[&str],
) -> Sender {
    let child = Command::new(BIN)
        .args([
            &srt_port.to_string(),
            "127.0.0.1",
            &receiver_port.to_string(),
            ips.to_str().unwrap(),
            "--stats-file",
            stats.to_str().unwrap(),
            "--stats-file-interval",
            &STATS_INTERVAL_MS.to_string(),
        ])
        .args(options)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn srtla_send");
    Sender { child }
}

#[test]
fn bond_bytes_sent_total_is_monotonic_across_a_sighup_link_removal() {
    let receiver = MiniReceiver::start(false);
    let dir = tempfile::tempdir().expect("tempdir");
    let ips = dir.path().join("ips.txt");
    let stats = dir.path().join("stats.json");
    std::fs::write(&ips, "127.0.0.1\n127.0.0.2\n").expect("write ips file");

    let srt_port = free_udp_port();
    let sender = spawn_sender(&ips, &stats, srt_port, receiver.port);

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
fn reloaded_link_joins_promptly_after_reordering_during_registration() {
    let receiver = MiniReceiver::start(true);
    let dir = tempfile::tempdir().expect("tempdir");
    let ips = dir.path().join("ips.txt");
    let stats = dir.path().join("stats.json");
    std::fs::write(&ips, "127.0.0.1\n127.0.0.2\n").expect("write ips file");
    let sender = spawn_sender(&ips, &stats, free_udp_port(), receiver.port);

    let first = receiver
        .registrations
        .recv_timeout(READY_TIMEOUT)
        .expect("first link REG2");
    let second = receiver
        .registrations
        .recv_timeout(READY_TIMEOUT)
        .expect("second link REG2");
    assert_ne!(first.0.ip(), second.0.ip(), "both sources must register");
    assert_eq!(first.1, second.1, "both sources must join one group");
    wait_for(READY_TIMEOUT, || {
        let snapshot = read_stats(&stats)?;
        (snapshot["connections"].as_array()?.len() == 2 && all_links_active(&snapshot))
            .then_some(())
    })
    .expect("sender must have accepted both REG3 replies");

    assert!(receiver.registrations.try_iter().count() == 0);
    // Discard the startup RTT probes and the initial registration.
    receiver.all_reg2.try_iter().for_each(drop);
    std::fs::write(&ips, "127.0.0.1\n127.0.0.3\n").expect("replace second source");
    sender.sighup();
    // A reload can land on the next one-second housekeeping tick. Three seconds
    // allows scheduling headroom but stays below the five-second startup grace.
    let (replacement, group_id) = receiver
        .registrations
        .recv_timeout(Duration::from_secs(3))
        .expect("replacement must send REG2 before the startup grace expires");
    assert_eq!(
        replacement.ip(),
        REPLACEMENT_IP,
        "only the replacement should register"
    );
    assert_eq!(
        group_id, first.1,
        "replacement must join the existing group"
    );

    std::fs::write(&ips, "127.0.0.3\n127.0.0.1\n").expect("move replacement to first slot");
    sender.sighup();
    wait_for(Duration::from_secs(3), || {
        let snapshot = read_stats(&stats)?;
        let rows = snapshot["connections"].as_array()?;
        // REG3 is still withheld. The inactive row can move to slot 0 only
        // once the reorder has applied and the new order has been published.
        (rows.len() == 2
            && rows[0]["weight_percent"].as_u64()? == 0
            && rows[1]["weight_percent"].as_u64()? > 0)
            .then_some(())
    })
    .expect("reorder must move the unregistered socket to the first slot");
    assert!(receiver.replacement_keepalives.try_recv().is_err());

    receiver
        .socket
        .send_to(&SRTLA_TYPE_REG3.to_be_bytes(), replacement)
        .expect("release delayed REG3");
    assert_eq!(
        receiver
            .replacement_keepalives
            .recv_timeout(Duration::from_secs(2))
            .expect("replacement must send keepalive after accepting delayed REG3"),
        replacement,
        "the same socket must complete its original handshake",
    );
    assert_eq!(
        receiver.all_reg2.try_iter().collect::<Vec<_>>(),
        [replacement],
        "only the replacement may send REG2 after the first reload, including probes",
    );
}

#[test]
fn probation_requires_batched_delivery_after_reload_and_falls_back_to_the_last_link() {
    exercise_probation_after_reload(450, 1000);
}

#[test]
fn probation_retains_the_first_ack_batch_across_a_three_second_delay() {
    exercise_probation_after_reload(3000, 6000);
}

fn exercise_probation_after_reload(ack_delay_ms: u64, timeout_ms: u64) {
    use std::collections::HashMap;

    const INITIAL: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const REMAINDER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    let socket = UdpSocket::bind((INITIAL, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(3)))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ips = dir.path().join("ips");
    let stats = dir.path().join("stats.json");
    let port = free_udp_port();
    std::fs::write(&ips, "127.0.0.1\n").unwrap();
    let sender = spawn_sender_with_options(
        &ips,
        &stats,
        port,
        socket.local_addr().unwrap().port(),
        &[
            "--mode",
            "classic",
            "--conn-timeout-ms",
            &timeout_ms.to_string(),
        ],
    );
    let source = UdpSocket::bind((INITIAL, 0)).unwrap();
    let mut group = None;
    let mut registration = HashMap::<Ipv4Addr, Instant>::new();
    let mut batches = HashMap::<SocketAddr, Vec<u32>>::new();
    let mut unique = HashMap::<Ipv4Addr, usize>::new();
    let mut probes = HashMap::<Ipv4Addr, usize>::new();
    let mut delayed = None;
    let mut replacement_proved_at = None;
    let mut seq = 0u32;
    let mut next_send = Instant::now();
    let ignored_counter = AtomicU64::new(0);
    let mut buffer = [0u8; 2048];
    let mut tick = |stage| {
        let now = Instant::now();
        if now >= next_send {
            seq += 1;
            let mut packet = [0; PAYLOAD_LEN];
            packet[..4].copy_from_slice(&seq.to_be_bytes());
            source.send_to(&packet, (INITIAL, port)).unwrap();
            next_send = now + Duration::from_millis(2);
        }
        if delayed.as_ref().is_some_and(|(when, _, _)| now >= *when) {
            let (_, peer, ack): (_, _, Vec<u32>) = delayed.take().unwrap();
            socket
                .send_to(&srtla_protocol::create_ack_packet(&ack), peer)
                .unwrap();
            replacement_proved_at = Some(now);
        }
        if let Ok((n, peer)) = socket.recv_from(&mut buffer) {
            let SocketAddr::V4(peer_v4) = peer else {
                unreachable!()
            };
            let ip = *peer_v4.ip();
            if stage == 3 && ip == INITIAL {
                return false;
            }
            let packet = &buffer[..n];
            if packet.len() >= 16 && packet[0] & 128 == 0 {
                if !registration.contains_key(&ip) {
                    return false;
                }
                if srtla_protocol::is_srt_data_retransmit(packet) {
                    *probes.entry(ip).or_default() += 1;
                } else {
                    *unique.entry(ip).or_default() += 1;
                }
                if ip == REMAINDER && stage == 2 {
                    assert!(
                        srtla_protocol::is_srt_data_retransmit(packet),
                        "unproved link received unique payload while a proven sibling survived"
                    );
                }
                if ip == REPLACEMENT_IP && replacement_proved_at.is_none() {
                    assert!(
                        srtla_protocol::is_srt_data_retransmit(packet),
                        "replacement received unique payload before its own ACK"
                    );
                    if probes.get(&ip) == Some(&1) {
                        socket
                            .send_to(&srtla_protocol::create_ack_packet(&[0x7fff_0000]), peer)
                            .unwrap();
                    }
                }
                let batch = batches.entry(peer).or_default();
                batch.push(u32::from_be_bytes(packet[..4].try_into().unwrap()));
                if batch.len() == 10 {
                    if ip == REPLACEMENT_IP && replacement_proved_at.is_none() {
                        if delayed.is_none() {
                            delayed = Some((
                                now + Duration::from_millis(ack_delay_ms),
                                peer,
                                batch.clone(),
                            ));
                        }
                    } else if ip == INITIAL || (ip == REPLACEMENT_IP && stage > 1) {
                        if ip == INITIAL {
                            // Let the cumulative ACK prune the send log before the
                            // per-link ACK arrives. Socket ownership must still prove A.
                            let mut cumulative_ack = [0u8; 20];
                            cumulative_ack[..2]
                                .copy_from_slice(&srtla_protocol::SRT_TYPE_ACK.to_be_bytes());
                            cumulative_ack[16..].copy_from_slice(&(batch[9] + 1).to_be_bytes());
                            socket.send_to(&cumulative_ack, peer).unwrap();
                        }
                        socket
                            .send_to(&srtla_protocol::create_ack_packet(batch), peer)
                            .unwrap();
                    }
                    batch.clear();
                }
            } else if packet.len() >= 2
                && !(ip == REPLACEMENT_IP
                    && packet[..2] == SRTLA_TYPE_KEEPALIVE.to_be_bytes()
                    && replacement_proved_at.is_none())
                && serve(&socket, packet, peer, &ignored_counter, &mut group, false).is_some()
            {
                assert!(
                    registration.insert(ip, now).is_none(),
                    "{ip} unexpectedly re-registered"
                );
            }
        }
        match stage {
            0 => unique.get(&INITIAL).is_some_and(|count| *count >= 20),
            1 => {
                if let Some(grant) = registration.get(&REPLACEMENT_IP) {
                    assert!(
                        now.duration_since(*grant) < Duration::from_millis(timeout_ms - 25),
                        "batched proof and admission must complete inside the receive timeout"
                    );
                }
                let admitted = unique.get(&REPLACEMENT_IP).is_some_and(|count| *count >= 3);
                if admitted {
                    let elapsed = now.duration_since(registration[&REPLACEMENT_IP]);
                    println!("replacement normal share after {} ms", elapsed.as_millis());
                }
                admitted
            }
            2 => probes.get(&REMAINDER).is_some_and(|count| *count >= 3),
            _ => unique.contains_key(&REMAINDER),
        }
    };

    let mut drive = |stage, timeout| {
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            if tick(stage) {
                return;
            }
        }
        panic!("probation regression timed out in stage {stage}");
    };
    drive(0, READY_TIMEOUT);
    std::fs::write(&ips, "127.0.0.1\n127.0.0.3\n").unwrap();
    sender.sighup();
    drive(1, Duration::from_millis(timeout_ms + 2000));
    std::fs::write(&ips, "127.0.0.1\n127.0.0.2\n").unwrap();
    sender.sighup();
    drive(2, Duration::from_secs(3));
    // Drop all traffic on the already proven leg and stop acknowledging the
    // other leg's probes. The latter must become a unique carrier anyway.
    drive(3, Duration::from_millis(timeout_ms + 2000));
    assert!(replacement_proved_at.is_some());
}
