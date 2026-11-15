//! Source-address follow through a real stack, with one link renumbered
//! mid-stream and no SIGHUP.
//!
//! ```text
//! UDP → srt-live-transmit (caller) → srtla_send ═╦═ link a (10.10.1.1) ═╗
//!                                                ╚═ link b (10.10.2.1) ═╩→ srtla_rec → srt-live-transmit (listener) → UDP sink
//! ```
//!
//! Both links are mapped (`--bind-map`), so each is pinned to its veth. While a
//! live SRT session streams, link b's address is deleted and `10.10.2.3` is
//! added on the same interface, the way a carrier session reset hands a modem
//! a new address. The IP list and bind-map on disk are left stale and the
//! sender is never signalled.
//!
//! What each scenario measures, from the receiver side (veth byte counters and
//! the UDP sink after the SRT listener, never the sender's own claims):
//!
//! * when link b carries stream data again after the renumbering;
//! * whether link a ever stopped carrying data;
//! * whether the SRT session and the SRTLA group survived (sink keeps
//!   receiving; the receiver registered exactly one group and admitted the new
//!   address into it).
//!
//! The control runs the same binary with `--no-follow-address`: link b must
//! then stay dead, which is what makes the follow result falsifiable. A fourth
//! scenario renumbers the only link of a single-link bond, where nothing else
//! carries the stream meanwhile.
//!
//! Privileged and self-skipping like the other `netns_*` targets; run it via
//! `scripts/netns_test_gate.sh --only netns_address_follow`.
#![cfg(target_os = "linux")]

mod common;

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use network_sim::{
    NamespaceProcess, SRT_CALLER_INGEST_PORT, SRT_PAYLOAD_BYTES, SrtlaTestTopology, check_binary,
    spawn_udp_stream, wait_for_registered_uplinks, wait_for_udp_listener,
};
use sha2::{Digest, Sha256};

const SERVICE_IP: &str = "10.99.0.1";
const SRT_LISTEN_PORT: u16 = 4001;
const SRTLA_PORT: u16 = 5000;
const SENDER_SRT_PORT: u16 = 5555;
const SINK_PORT: u16 = 9999;
/// 250 datagrams/s of 1316 bytes, about 2.6 Mbit/s of SRT payload.
const PACKETS_PER_SEC: u32 = 250;
const SAMPLE_MS: u64 = 250;
const STEADY_BEFORE: Duration = Duration::from_secs(6);
const OBSERVE_AFTER: Duration = Duration::from_secs(20);
/// Bytes per sample that count as "carrying stream data" on one link. Control
/// traffic (keepalives, registration) stays far below it.
const DATA_BYTES_PER_SAMPLE: u64 = 4_000;
/// The bound the follow result is held to: the settle time (1.5 s) plus the
/// re-join, with room for a loaded machine. On a single-link bond this is also
/// how long the receiver hears nothing from the bond, so it must stay well
/// inside the strictest receiver's 4 s connection and group timeout.
const RECOVERY_LIMIT: Duration = Duration::from_millis(2_500);
/// After a link rejoins with a fresh window, the scheduler has been seen to
/// send everything over it for up to 1.5 s, on the unchanged sender too
/// (after any reconnect, not only a followed one). The other link keeps its
/// socket and registration throughout; only this quiet window is allowed.
const OTHER_LINK_MAX_QUIET_MS: u64 = 2_000;

/// The harness names veth pairs by process id, and the measurements are timing
/// based, so the scenarios in this file must never overlap.
static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy)]
struct Scenario {
    name: &'static str,
    /// 2: links a and b, b is renumbered. 1: a single-link bond whose only
    /// link (called b here) is renumbered.
    links: usize,
    follow: bool,
    /// Time the interface spends with no address at all between the delete
    /// and the add. Zero is a straight replacement.
    gap: Duration,
}

#[derive(Debug, Default)]
struct Report {
    /// Seconds from the new address appearing until link b carried data.
    b_recovered_after_s: Option<f64>,
    /// Link b's share of data before the renumbering, as a sanity check that
    /// both links were really in use.
    b_share_before: f64,
    /// Samples after warm-up in which link a carried less than a data sample.
    /// The scheduler may briefly favour a link that just rejoined, so one
    /// quiet window is a scheduling choice, not an outage.
    a_quiet_samples: usize,
    /// Longest run of such samples, in ms.
    a_longest_quiet_ms: u64,
    a_samples: usize,
    /// Sender events on link a's own socket: time-outs, reconnects, re-binds.
    /// Any of them would mean the renumbering of link b disturbed link a.
    a_events: usize,
    /// Longest run of empty sink windows after the stream started, in ms.
    sink_longest_gap_ms: u64,
    sink_bytes: u64,
    /// Bytes the far end received in the last 5 s of the observation, i.e.
    /// well after the renumbering.
    sink_bytes_last_5s: u64,
    /// `group ... registered` lines in the receiver log.
    groups_registered: usize,
    /// Whether the receiver admitted the new address into the first group.
    new_address_joined_same_group: Option<bool>,
    /// Sender reconnect attempts on link b while it had no address.
    b_reconnects_during_gap: usize,
    /// Sender reconnect/rebind attempts on link b after the renumbering, over
    /// the whole observation window. The control's retry loop shows up here.
    b_retries_after: usize,
    follow_lines: usize,
    caller_disconnects: usize,
    /// `(seconds since the renumbering, link a bytes, link b bytes)` per sample.
    series: Vec<(f64, u64, u64)>,
}

fn tool(name: &str) -> String {
    check_binary(name)
        .unwrap_or_else(|| panic!("{name} not found"))
        .to_string_lossy()
        .into_owned()
}

/// Write the IP list and a coherent ADR-003 sidecar naming each link's
/// interface, returning both paths.
fn publish_bind_map(dir: &Path, topo: &SrtlaTestTopology) -> (PathBuf, PathBuf) {
    let ips_path = dir.join("srtla_ips.txt");
    let sidecar_path = dir.join("srtla_bind_map.json");
    let ips = topo.sender_ips.join("\n") + "\n";
    let digest: String = Sha256::digest(ips.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let links: Vec<String> = topo
        .sender_ips
        .iter()
        .zip(&topo.sender_ifaces)
        .enumerate()
        .map(|(i, (ip, iface))| {
            format!(
                r#"{{"link_id":"link-{}","ip":"{ip}","iface":"{iface}"}}"#,
                (b'a' + i as u8) as char
            )
        })
        .collect();
    let sidecar = format!(
        r#"{{"schema_version":1,"generation":1,"ips_file_sha256":"{digest}","links":[{}]}}"#,
        links.join(",")
    );
    for (path, body) in [(&ips_path, ips), (&sidecar_path, sidecar)] {
        let mut file = std::fs::File::create(path).expect("write publication");
        file.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (ips_path, sidecar_path)
}

/// UDP sink after the SRT listener: one line per window, `<bytes>`.
fn sink_script() -> String {
    format!(
        "import socket,select,time,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.\
         bind(('127.0.0.1',{SINK_PORT}))\nn=0\nnext=time.monotonic()+{w}\nwhile True:\n\x20   \
         r,_,_=select.select([s],[],[],max(0,next-time.monotonic()))\n\x20   if r:\n\x20       \
         n+=len(s.recv(65536))\n\x20   if time.monotonic()>=next:\n\x20       \
         print(n,flush=True); n=0; next+={w}\n",
        w = SAMPLE_MS as f64 / 1000.0
    )
}

/// Receiver-side byte counters, one per link, in link order.
fn rx_bytes(topo: &SrtlaTestTopology) -> Vec<u64> {
    let paths: Vec<String> = topo
        .receiver_ifaces
        .iter()
        .map(|i| format!("/sys/class/net/{i}/statistics/rx_bytes"))
        .collect();
    let args: Vec<&str> = paths.iter().map(String::as_str).collect();
    let out = topo
        .receiver_ns
        .exec_checked("cat", &args)
        .expect("read rx counters");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().parse::<u64>().unwrap_or(0))
        .collect()
}

/// Delete link `idx`'s address (`10.10.{idx+1}.1`), optionally wait, then add
/// `10.10.{idx+1}.3` and move the test topology's per-source routing onto it on
/// both ends. Returns when the new address appeared, and the address.
fn renumber_link(topo: &SrtlaTestTopology, idx: usize, gap: Duration) -> (Instant, String) {
    let subnet = idx + 1;
    let new_ip = format!("10.10.{subnet}.3");
    let new_ip = new_ip.as_str();
    let gateway = format!("10.10.{subnet}.2");
    let table = subnet.to_string();
    let old = topo.sender_ips[idx].as_str();
    let s_if = topo.sender_ifaces[idx].as_str();
    let r_if = topo.receiver_ifaces[idx].as_str();
    let s = &topo.sender_ns;
    let r = &topo.receiver_ns;
    s.exec_checked("ip", &["addr", "del", &format!("{old}/24"), "dev", s_if])
        .unwrap();
    let _ = s.exec("ip", &["rule", "del", "from", old, "lookup", &table]);
    let _ = r.exec("ip", &["route", "del", &format!("{old}/32"), "dev", r_if]);
    if !gap.is_zero() {
        thread::sleep(gap);
    }
    s.exec_checked("ip", &["addr", "add", &format!("{new_ip}/24"), "dev", s_if])
        .unwrap();
    let appeared = Instant::now();
    s.exec_checked("ip", &["rule", "add", "from", new_ip, "lookup", &table])
        .unwrap();
    s.exec_checked(
        "ip",
        &[
            "route",
            "replace",
            &format!("{SERVICE_IP}/32"),
            "via",
            &gateway,
            "dev",
            s_if,
            "table",
            &table,
        ],
    )
    .unwrap();
    r.exec_checked(
        "ip",
        &[
            "route",
            "add",
            &format!("{new_ip}/32"),
            "dev",
            r_if,
            "src",
            SERVICE_IP,
        ],
    )
    .unwrap();
    (appeared, new_ip.to_string())
}

fn group_of(line: &str) -> Option<&str> {
    let start = line.find("group ")? + "group ".len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_hexdigit() || c == 'x'))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn run(scenario: Scenario) -> Report {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let topo = SrtlaTestTopology::new(scenario.name, scenario.links).expect("topology");
    // The renumbered link, and the one that must be left alone (if any).
    let b = scenario.links - 1;
    let a = (scenario.links > 1).then_some(0usize);
    let dir = tempfile::tempdir().expect("publication dir");
    let (ips, sidecar) = publish_bind_map(dir.path(), &topo);

    let sink_src = sink_script();
    let mut sink = NamespaceProcess::spawn(&topo.receiver_ns, "python3", &["-u", "-c", &sink_src])
        .expect("sink");
    let srt = tool("srt-live-transmit");
    let mut listener = NamespaceProcess::spawn(
        &topo.receiver_ns,
        &srt,
        &[
            &format!("srt://:{SRT_LISTEN_PORT}?mode=listener&latency=2000"),
            &format!("udp://127.0.0.1:{SINK_PORT}"),
        ],
    )
    .expect("srt listener");
    wait_for_udp_listener(&topo.receiver_ns, SRT_LISTEN_PORT, Duration::from_secs(5)).unwrap();
    let mut receiver = NamespaceProcess::spawn(
        &topo.receiver_ns,
        &tool("srtla_rec"),
        &[
            "--srtla_port",
            &SRTLA_PORT.to_string(),
            "--srt_hostname",
            "127.0.0.1",
            "--srt_port",
            &SRT_LISTEN_PORT.to_string(),
        ],
    )
    .expect("srtla_rec");
    wait_for_udp_listener(&topo.receiver_ns, SRTLA_PORT, Duration::from_secs(5)).unwrap();

    let ips_s = ips.to_string_lossy().into_owned();
    let sidecar_s = sidecar.to_string_lossy().into_owned();
    let port_s = SENDER_SRT_PORT.to_string();
    let rec_port_s = SRTLA_PORT.to_string();
    let mut args = vec![
        port_s.as_str(),
        SERVICE_IP,
        rec_port_s.as_str(),
        ips_s.as_str(),
        "--bind-map",
        sidecar_s.as_str(),
        "--conn-timeout-ms",
        "15000",
    ];
    if !scenario.follow {
        args.push("--no-follow-address");
    }
    let mut sender = NamespaceProcess::spawn_with_env(
        &topo.sender_ns,
        env!("CARGO_BIN_EXE_srtla_send"),
        &args,
        // Per-NAK window warnings would evict the lifecycle lines this test
        // reads from the bounded log tail.
        &[("RUST_LOG", "info,srtla_core::connection::congestion=error")],
    )
    .expect("srtla_send");
    wait_for_udp_listener(&topo.sender_ns, SENDER_SRT_PORT, Duration::from_secs(10)).unwrap();
    wait_for_registered_uplinks(&sender, scenario.links, Duration::from_secs(20))
        .expect("links up");

    let mut caller = NamespaceProcess::spawn(
        &topo.sender_ns,
        &srt,
        &[
            &format!("udp://:{SRT_CALLER_INGEST_PORT}"),
            &format!("srt://127.0.0.1:{SENDER_SRT_PORT}?mode=caller&latency=2000"),
        ],
    )
    .expect("srt caller");
    wait_for_udp_listener(
        &topo.sender_ns,
        SRT_CALLER_INGEST_PORT,
        Duration::from_secs(5),
    )
    .unwrap();
    let total = STEADY_BEFORE + scenario.gap + OBSERVE_AFTER + Duration::from_secs(4);
    let mut stream = spawn_udp_stream(
        &topo.sender_ns,
        "127.0.0.1",
        SRT_CALLER_INGEST_PORT,
        PACKETS_PER_SEC,
        SRT_PAYLOAD_BYTES,
        total,
    )
    .expect("stream");

    // Warm-up, then a steady window to measure both links' share.
    thread::sleep(Duration::from_secs(2));
    let warm = rx_bytes(&topo);
    let mut a_quiet = 0;
    let mut a_samples = 0;
    let mut a_run = 0u64;
    let mut a_longest = 0u64;
    let mut prev = warm.clone();
    let steady_until = Instant::now() + STEADY_BEFORE - Duration::from_secs(2);
    while Instant::now() < steady_until {
        thread::sleep(Duration::from_millis(SAMPLE_MS));
        let now = rx_bytes(&topo);
        if let Some(a) = a {
            a_samples += 1;
            if now[a] - prev[a] < DATA_BYTES_PER_SAMPLE {
                a_quiet += 1;
                a_run += 1;
                a_longest = a_longest.max(a_run);
            } else {
                a_run = 0;
            }
        }
        prev = now;
    }
    let before: Vec<u64> = prev.iter().zip(&warm).map(|(n, w)| n - w).collect();
    let b_share_before = before[b] as f64 / before.iter().sum::<u64>().max(1) as f64;

    // Renumber link b with no SIGHUP and stale files on disk.
    let sender_log_before = sender.log_snapshot().len();
    let (appeared, new_ip) = renumber_link(&topo, b, scenario.gap);
    let gap_log = sender.log_snapshot();
    prev = rx_bytes(&topo);
    let mut b_recovered_after_s = None;
    let mut series = Vec::new();
    let observe_until = appeared + OBSERVE_AFTER;
    while Instant::now() < observe_until {
        thread::sleep(Duration::from_millis(SAMPLE_MS));
        let now = rx_bytes(&topo);
        if let Some(a) = a {
            a_samples += 1;
            if now[a] - prev[a] < DATA_BYTES_PER_SAMPLE {
                a_quiet += 1;
                a_run += 1;
                a_longest = a_longest.max(a_run);
            } else {
                a_run = 0;
            }
        }
        series.push((
            appeared.elapsed().as_secs_f64(),
            a.map_or(0, |a| now[a] - prev[a]),
            now[b] - prev[b],
        ));
        if b_recovered_after_s.is_none() && now[b] - prev[b] >= DATA_BYTES_PER_SAMPLE {
            b_recovered_after_s = Some(appeared.elapsed().as_secs_f64());
        }
        prev = now;
    }

    stream.kill();
    caller.kill();
    sender.kill();
    receiver.kill();
    listener.kill();
    sink.kill();

    let sender_log = sender.log_snapshot();
    let b_reconnects_during_gap = gap_log[sender_log_before.min(gap_log.len())..]
        .iter()
        .filter(|l| {
            let l = l.to_lowercase();
            l.contains(&topo.sender_ifaces[b]) && (l.contains("reconnect") || l.contains("rebind"))
        })
        .count();
    let b_retries_after = sender_log[sender_log_before.min(sender_log.len())..]
        .iter()
        .filter(|l| {
            let l = l.to_lowercase();
            l.contains(&topo.sender_ifaces[b])
                && (l.contains("reconnect attempt") || l.contains("failed to re"))
        })
        .count();
    let a_events = sender_log
        .iter()
        .filter(|l| {
            let l = l.to_lowercase();
            a.is_some_and(|a| l.contains(&topo.sender_ifaces[a]))
                && (l.contains("timed out")
                    || l.contains("reconnect")
                    || l.contains("rebind")
                    || l.contains("re-bound"))
        })
        .count();
    let follow_lines = sender_log
        .iter()
        .filter(|l| l.contains("re-bound this link without a reload"))
        .count();

    let receiver_log = receiver.log_snapshot();
    let registered: Vec<&String> = receiver_log
        .iter()
        .filter(|l| l.contains("registered") && l.contains("group"))
        .collect();
    let first_group = registered.first().and_then(|l| group_of(l));
    let new_address_joined_same_group = first_group.map(|g| {
        receiver_log.iter().any(|l| {
            l.contains(&new_ip) && l.contains("connection registration") && group_of(l) == Some(g)
        })
    });

    let sink_windows: Vec<u64> = sink
        .log_snapshot()
        .iter()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    let started = sink_windows.iter().position(|b| *b > 0).unwrap_or(0);
    // Ignore the trailing windows after the processes were stopped.
    let live = &sink_windows[started..sink_windows.len().saturating_sub(2).max(started)];
    let mut longest = 0;
    let mut run_len = 0;
    for b in live {
        if *b == 0 {
            run_len += 1;
            longest = longest.max(run_len);
        } else {
            run_len = 0;
        }
    }
    let caller_disconnects = caller
        .log_snapshot()
        .iter()
        .filter(|l| l.to_lowercase().contains("disconnect"))
        .count();

    let report = Report {
        b_recovered_after_s,
        b_share_before,
        a_quiet_samples: a_quiet,
        a_longest_quiet_ms: a_longest * SAMPLE_MS,
        a_samples,
        a_events,
        sink_longest_gap_ms: longest * SAMPLE_MS,
        sink_bytes: live.iter().sum(),
        sink_bytes_last_5s: live.iter().rev().take((5_000 / SAMPLE_MS) as usize).sum(),
        groups_registered: registered.len(),
        new_address_joined_same_group,
        b_reconnects_during_gap,
        b_retries_after,
        follow_lines,
        caller_disconnects,
        series,
    };
    eprintln!(
        "ADDRESS_FOLLOW_RESULT {} b_recovered_after_s={:?} b_share_before={:.2} a_quiet={}/{} \
         a_longest_quiet_ms={} a_events={} sink_longest_gap_ms={} sink_bytes={} \
         sink_bytes_last_5s={} groups={} same_group={:?} b_reconnects_during_gap={} \
         b_retries_after={} follow_lines={} caller_disconnects={}",
        scenario.name,
        report.b_recovered_after_s,
        report.b_share_before,
        report.a_quiet_samples,
        report.a_samples,
        report.a_longest_quiet_ms,
        report.a_events,
        report.sink_longest_gap_ms,
        report.sink_bytes,
        report.sink_bytes_last_5s,
        report.groups_registered,
        report.new_address_joined_same_group,
        report.b_reconnects_during_gap,
        report.b_retries_after,
        report.follow_lines,
        report.caller_disconnects,
    );
    if std::env::var_os("ADDRESS_FOLLOW_DUMP").is_some() {
        for (t, a, b) in &report.series {
            eprintln!("  sample: t={t:.2} a={a} b={b}");
        }
        for line in sender_log
            .iter()
            .filter(|l| !l.contains("NAK reduced window"))
        {
            eprintln!("  sender: {line}");
        }
        for line in &receiver_log {
            eprintln!("  receiver: {line}");
        }
    }
    report
}

/// The SRT session and the SRTLA group outlived the renumbering: the caller
/// never disconnected, the receiver kept one group, and the far end was still
/// receiving at the end.
fn assert_session_survived(r: &Report) {
    assert_eq!(
        r.caller_disconnects, 0,
        "SRT caller saw a disconnect: {r:?}"
    );
    assert_eq!(
        r.groups_registered, 1,
        "receiver registered a second group: {r:?}"
    );
    assert!(
        r.sink_bytes_last_5s > 0,
        "the far end stopped receiving: {r:?}"
    );
}

/// The link that was not renumbered kept its socket and registration and kept
/// carrying data. `max_quiet_ms` bounds the longest window in which it carried
/// none: the scheduler may briefly send everything over a link that has just
/// rejoined with a fresh window.
fn assert_other_link_untouched(r: &Report, max_quiet_ms: u64) {
    assert!(r.a_samples > 40, "too few samples to judge link a: {r:?}");
    assert_eq!(r.a_events, 0, "link a's socket was disturbed: {r:?}");
    assert!(
        r.a_longest_quiet_ms <= max_quiet_ms,
        "link a stopped carrying data: {r:?}"
    );
}

/// With the renumbered link back, the far end saw no stall longer than a
/// second.
fn assert_stream_continuous(r: &Report) {
    assert!(
        r.sink_longest_gap_ms <= 1_000,
        "stream stalled at the far end: {r:?}"
    );
}

#[test]
fn a_renumbered_link_rebinds_live_without_a_hup() {
    if common::skip_without_deps() {
        return;
    }
    let r = run(Scenario {
        name: "afollow",
        links: 2,
        follow: true,
        gap: Duration::ZERO,
    });
    assert!(r.b_share_before > 0.1, "link b was not in use: {r:?}");
    let after = r.b_recovered_after_s.expect("link b never carried again");
    assert!(
        after <= RECOVERY_LIMIT.as_secs_f64(),
        "link b took {after:.2}s: {r:?}"
    );
    assert_eq!(r.follow_lines, 1, "{r:?}");
    assert_eq!(r.b_retries_after, 0, "{r:?}");
    assert_eq!(r.new_address_joined_same_group, Some(true), "{r:?}");
    assert_session_survived(&r);
    assert_other_link_untouched(&r, OTHER_LINK_MAX_QUIET_MS);
    assert_stream_continuous(&r);
}

#[test]
fn a_link_left_without_an_address_waits_quietly_then_follows() {
    if common::skip_without_deps() {
        return;
    }
    let r = run(Scenario {
        name: "agap",
        links: 2,
        follow: true,
        gap: Duration::from_secs(6),
    });
    assert_eq!(
        r.b_reconnects_during_gap, 0,
        "a link with no address must not retry: {r:?}"
    );
    let after = r.b_recovered_after_s.expect("link b never carried again");
    assert!(
        after <= RECOVERY_LIMIT.as_secs_f64(),
        "link b took {after:.2}s: {r:?}"
    );
    assert_eq!(r.new_address_joined_same_group, Some(true), "{r:?}");
    assert_session_survived(&r);
    assert_other_link_untouched(&r, OTHER_LINK_MAX_QUIET_MS);
    assert_stream_continuous(&r);
}

#[test]
fn control_without_follow_leaves_the_renumbered_link_dead() {
    if common::skip_without_deps() {
        return;
    }
    let r = run(Scenario {
        name: "actrl",
        links: 2,
        follow: false,
        gap: Duration::ZERO,
    });
    assert!(r.b_share_before > 0.1, "link b was not in use: {r:?}");
    assert_eq!(r.b_recovered_after_s, None, "{r:?}");
    assert_eq!(r.follow_lines, 0, "{r:?}");
    // The old behaviour this feature replaces: retrying a bind on an address
    // the host no longer owns.
    assert!(r.b_retries_after > 0, "{r:?}");
    assert_session_survived(&r);
    assert_other_link_untouched(&r, 2 * SAMPLE_MS);
}

#[test]
fn a_single_link_bond_survives_its_only_link_being_renumbered() {
    if common::skip_without_deps() {
        return;
    }
    // The case where a host would otherwise have to restart the session: the
    // renumbered link is the only one, so nothing carries the stream while it
    // is stuck.
    let r = run(Scenario {
        name: "asolo",
        links: 1,
        follow: true,
        gap: Duration::ZERO,
    });
    let after = r.b_recovered_after_s.expect("the link never carried again");
    assert!(
        after <= RECOVERY_LIMIT.as_secs_f64(),
        "the link took {after:.2}s: {r:?}"
    );
    assert_eq!(r.follow_lines, 1, "{r:?}");
    assert_eq!(r.b_retries_after, 0, "{r:?}");
    assert_eq!(r.new_address_joined_same_group, Some(true), "{r:?}");
    assert_session_survived(&r);
    // With no other link to carry the stream, the SRT buffer is all that
    // covers the outage: the far end must not see a stall.
    assert_stream_continuous(&r);
}
