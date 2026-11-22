//! The registration state machine against arbitrary receive sequences.
//!
//! Uplink sockets are unconnected and registration frames are unauthenticated,
//! so any datagram can arrive at any point in the handshake. The properties:
//! no panic, REG3 and REG_ERR only take effect while that uplink has the
//! matching handshake phase in flight, and a REG2 that is not for the pending
//! uplink never changes the SRTLA id.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use srtla_core::registration::{RegistrationEvent, SrtlaRegistrationManager};
use srtla_protocol::*;

const UPLINKS: usize = 4;

#[derive(Debug, Arbitrary)]
enum Op {
    /// A datagram from an uplink. `kind` selects a well-formed header so the
    /// fuzzer reaches each handler without having to guess the type words.
    Packet {
        conn: u8,
        kind: u8,
        tail: Vec<u8>,
        raw: bool,
    },
    BuildReg1(u8),
    BuildReg2(u8),
    Driver,
    ImmediateReg1(u8),
    ClearTimedOut,
    Rehome,
    Advance(u16),
}

fn header(kind: u8) -> u16 {
    match kind % 8 {
        0 => SRTLA_TYPE_REG1,
        1 => SRTLA_TYPE_REG2,
        2 => SRTLA_TYPE_REG3,
        3 => SRTLA_TYPE_REG_ERR,
        4 => SRTLA_TYPE_REG_NGP,
        5 => SRTLA_TYPE_REG_NAK,
        6 => SRTLA_TYPE_KEEPALIVE,
        _ => SRT_TYPE_HANDSHAKE,
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut reg = SrtlaRegistrationManager::new();
    let mut now: u64 = 1_000;

    for op in ops.into_iter().take(256) {
        match op {
            Op::Packet {
                conn,
                kind,
                mut tail,
                raw,
            } => {
                let conn = conn as usize % UPLINKS;
                let buf = if raw {
                    tail
                } else {
                    tail.truncate(SRTLA_TYPE_REG2_LEN + 8);
                    let mut b = header(kind).to_be_bytes().to_vec();
                    b.extend_from_slice(&tail);
                    b
                };
                let pt = get_packet_type(&buf);
                let pending = reg.pending_reg2_idx();
                let awaiting3 = reg.is_awaiting_reg3(conn);
                let id_before = *reg.srtla_id();

                let event = reg.process_registration_packet(conn, &buf, now);

                match pt {
                    Some(SRTLA_TYPE_REG3) => {
                        assert_eq!(
                            matches!(event, Some(RegistrationEvent::Reg3)),
                            awaiting3,
                            "REG3 accepted without a grant, or refused with one"
                        );
                        assert!(!matches!(event, Some(RegistrationEvent::RegErr)));
                        assert!(!reg.is_awaiting_reg3(conn), "REG3 grant is one-shot");
                    }
                    Some(SRTLA_TYPE_REG_ERR) => {
                        let in_flight = pending == Some(conn) || awaiting3;
                        assert_eq!(
                            matches!(event, Some(RegistrationEvent::RegErr)),
                            in_flight,
                            "REG_ERR must take effect only for an in-flight handshake"
                        );
                        if !in_flight {
                            assert_eq!(reg.pending_reg2_idx(), pending);
                        }
                    }
                    Some(SRTLA_TYPE_REG2) => {
                        let accepted = pending == Some(conn) && buf.len() >= 2 + SRTLA_ID_LEN;
                        if accepted {
                            assert_eq!(reg.srtla_id()[..], buf[2..2 + SRTLA_ID_LEN]);
                            assert_eq!(reg.pending_reg2_idx(), None);
                        } else {
                            assert_eq!(*reg.srtla_id(), id_before);
                            assert_eq!(reg.pending_reg2_idx(), pending);
                        }
                    }
                    _ => {}
                }
                if !matches!(
                    pt,
                    Some(
                        SRTLA_TYPE_REG3 | SRTLA_TYPE_REG_ERR | SRTLA_TYPE_REG2 | SRTLA_TYPE_REG_NGP
                    )
                ) {
                    assert!(event.is_none(), "non-registration frame produced an event");
                }
            }
            Op::BuildReg1(c) => {
                let pkt = reg.build_reg1_for(c as usize % UPLINKS, now);
                assert!(is_srtla_reg1(&pkt));
            }
            Op::BuildReg2(c) => {
                let conn = c as usize % UPLINKS;
                let pkt = reg.build_reg2(conn);
                assert!(is_srtla_reg2(&pkt));
                assert!(reg.is_awaiting_reg3(conn));
            }
            Op::Driver => {
                let sends = reg.reg_driver_pending_sends(UPLINKS, now);
                if let Some((_, pkt)) = sends.reg1 {
                    assert!(is_srtla_reg1(&pkt));
                }
                if let Some(pkt) = sends.broadcast_reg2 {
                    assert!(is_srtla_reg2(&pkt));
                }
            }
            Op::ImmediateReg1(c) => {
                if let Some(pkt) = reg.reg1_if_ngp_immediate(c as usize % UPLINKS, now) {
                    assert!(is_srtla_reg1(&pkt));
                    assert!(reg.pending_reg2_idx().is_some());
                }
            }
            Op::ClearTimedOut => {
                let _ = reg.clear_pending_if_timed_out(now);
            }
            Op::Rehome => reg.reset_for_rehome(),
            Op::Advance(ms) => now += ms as u64,
        }
    }
});
