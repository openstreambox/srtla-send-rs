//! Every stateless wire parser against arbitrary bytes.
//!
//! Beyond "does not panic", this checks the contracts the sender relies on:
//! bounded output, 31-bit sequence numbers only, and parse/build agreement for
//! whatever the parsers accept.
#![no_main]

use libfuzzer_sys::fuzz_target;
use srtla_protocol::*;

fuzz_target!(|data: &[u8]| {
    let _ = get_packet_type(data);
    let _ = is_srt_ack(data);
    let _ = is_srtla_keepalive(data);
    let _ = is_srtla_reg1(data);
    let _ = is_srtla_reg2(data);
    let _ = is_srtla_reg3(data);
    let _ = parse_srt_ack(data);
    // A latency can only come from a complete HSv5 conclusion carrying an
    // HSREQ/HSRSP block: control header, handshake body, spec word, 3 words.
    if parse_srt_handshake_latency(data).is_some() {
        assert!(
            data.len()
                >= SRT_CONTROL_HEADER_LEN + SRT_HANDSHAKE_CIF_LEN + 4 + SRT_HS_EXT_HSREQ_WORDS * 4
        );
    }

    // A sequence number is 31 bits: anything with the MSB set is not one.
    if let Some(sn) = get_srt_sequence_number(data) {
        assert_eq!(sn & 0x8000_0000, 0);
    }

    // NAK: every id the parser hands back becomes a retransmission, so each must
    // be a valid 31-bit sequence number and the expansion must stay bounded.
    let nak = parse_srt_nak(data);
    assert!(
        nak.len() <= data.len() / 4 + 1000,
        "NAK expansion unbounded"
    );
    assert!(
        nak.iter().all(|id| id & 0x8000_0000 == 0),
        "NAK produced a sequence number with the MSB set"
    );

    // SRTLA ACK: at most one entry per word after the 4-byte header, and it
    // round-trips through the builder.
    let acks = parse_srtla_ack(data);
    assert!(acks.len() <= data.len().saturating_sub(4) / 4);
    if !acks.is_empty() {
        let rebuilt = create_ack_packet(&acks);
        assert_eq!(parse_srtla_ack(&rebuilt), acks);
    }

    // Keepalive: the extended form is a strict superset of the plain one, and
    // re-encoding what was decoded reproduces the accepted bytes.
    if let Some(info) = extract_keepalive_conn_info(data) {
        let ts = extract_keepalive_timestamp(data).expect("ext keepalive has a timestamp");
        let rebuilt = create_keepalive_packet_ext(info, ts);
        assert_eq!(&data[..SRTLA_KEEPALIVE_EXT_LEN], &rebuilt[..]);
    }
    if let Some(ts) = extract_keepalive_timestamp(data) {
        assert_eq!(&data[..10], &create_keepalive_packet(ts)[..]);
    }

    // Retransmit flag: setting it only ever touches the R bit in byte 4, is
    // idempotent, and is reflected by the reader.
    let mut copy = data.to_vec();
    set_srt_data_retransmit(&mut copy);
    let mut twice = copy.clone();
    set_srt_data_retransmit(&mut twice);
    assert_eq!(copy, twice);
    if copy.len() >= 8 && copy[0] & 0x80 == 0 {
        assert!(is_srt_data_retransmit(&copy));
        assert_eq!(copy[4] & !0x04, data[4] & !0x04);
    } else {
        assert_eq!(copy, data);
    }
});
