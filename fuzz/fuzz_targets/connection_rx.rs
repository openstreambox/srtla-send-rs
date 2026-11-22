//! The per-link receive path (SRT ACK, NAK, SRTLA ACK, keepalive echo) against
//! arbitrary datagrams interleaved with sends.
//!
//! This follows the dispatch in `src/sender/uplink_recv.rs` without the sockets,
//! so what is exercised is the real parser output feeding the real connection
//! accounting. The properties: no panic or arithmetic overflow, the in-flight
//! counter always equals the packet log, the congestion window stays inside its
//! configured bounds, and RTT state stays finite.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use srtla_core::connection::SrtlaConnection;
use srtla_protocol::*;

#[derive(Debug, Arbitrary)]
enum Op {
    /// The link carried a data packet with this sequence number.
    Send(u32),
    /// A datagram from the receiver. `kind` picks a well-formed header.
    Recv {
        kind: u8,
        tail: Vec<u8>,
        raw: bool,
    },
    KeepaliveSent,
    Advance(u16),
}

fn header(kind: u8) -> u16 {
    match kind % 5 {
        0 => SRT_TYPE_ACK,
        1 => SRT_TYPE_NAK,
        2 => SRTLA_TYPE_ACK,
        3 => SRTLA_TYPE_KEEPALIVE,
        _ => SRT_TYPE_HANDSHAKE,
    }
}

fn new_connection() -> SrtlaConnection {
    thread_local! {
        static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
    }
    RT.with(|rt| rt.block_on(srtla_core::test_helpers::create_test_connection()))
}

fn check(conn: &SrtlaConnection) {
    assert_eq!(conn.in_flight_packets, conn.packet_log.len() as i32);
    assert!(
        conn.window >= WINDOW_MIN * WINDOW_MULT,
        "window {}",
        conn.window
    );
    assert!(
        conn.window <= WINDOW_MAX * WINDOW_MULT,
        "window {}",
        conn.window
    );
    assert!(conn.rtt.kalman_rtt.value().is_finite());
    assert!(conn.rtt.rtt_jitter_ms.is_finite());
}

fuzz_target!(|input: (bool, Vec<Op>)| {
    let (classic, ops) = input;
    let mut conn = new_connection();
    let mut now: u64 = 10_000;

    for op in ops.into_iter().take(256) {
        match op {
            Op::Send(seq) => {
                conn.register_packet((seq & 0x7fff_ffff) as i32, now);
            }
            Op::KeepaliveSent => conn.rtt.record_keepalive_sent(now),
            Op::Advance(ms) => now += ms as u64,
            Op::Recv {
                kind,
                mut tail,
                raw,
            } => {
                let data = if raw {
                    tail
                } else {
                    tail.truncate(300);
                    let mut b = header(kind).to_be_bytes().to_vec();
                    b.extend_from_slice(&tail);
                    b
                };
                match get_packet_type(&data) {
                    Some(SRT_TYPE_ACK) => {
                        if let Some(ack) = parse_srt_ack(&data) {
                            conn.handle_srt_ack(ack as i32, now, true);
                        }
                    }
                    Some(SRT_TYPE_NAK) => {
                        for seq in parse_srt_nak(&data) {
                            conn.handle_nak(seq as i32, now);
                        }
                    }
                    Some(SRTLA_TYPE_ACK) => {
                        for seq in parse_srtla_ack(&data) {
                            conn.handle_srtla_ack_specific(seq as i32, classic, now);
                        }
                        conn.handle_srtla_ack_global();
                    }
                    Some(SRTLA_TYPE_KEEPALIVE) => conn.handle_keepalive_echo(&data, now),
                    _ => {}
                }
            }
        }
        check(&conn);
    }
});
