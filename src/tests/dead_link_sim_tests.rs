//! Two-link simulations of a path that dies while its link stays registered.
//!
//! The unit tests in `stall_deselect_tests` set a link's backlog and proof
//! stamps by hand. These drive the real selection and connection code with a
//! small model of the rest of the system instead, because the failure they
//! guard against only shows up in the interplay: NAKs and cumulative SRT ACKs
//! that reach the sender over the healthy link keep draining the dead link's
//! packet log, so its in-flight count never builds the backlog the stall guard
//! used to require, and the scheduler kept feeding the dead path for as long as
//! the link stayed registered.
//!
//! The model follows `srtla_rec` and a live-mode SRT receiver:
//! - every data packet a link delivers counts toward that link's SRTLA ACK,
//!   sent back on the same link after every tenth one;
//! - keepalives are echoed on the link they arrived on;
//! - SRT ACKs (cumulative, every 10 ms) are broadcast on every link the
//!   receiver still has registered, including one whose inbound path is dead;
//! - NAKs go out on the link that delivered most recently, once on gap
//!   detection and again every 50 ms while the packet is still missing;
//! - a packet still missing when its 2000 ms latency budget runs out is
//!   dropped by the receiver. Those drops are what freezes the picture.
//!
//! Return paths can carry random extra delay, separately for keepalive echoes
//! and for the receiver's ACKs. With unequal round trips that reproduces the
//! race real links run: the broadcast SRT ACK over the faster path prunes the
//! slower link's packets before that link's own SRTLA ACK arrives.
//!
//! Loss and jitter use a fixed-seed generator so every run is identical.

#[cfg(test)]
mod tests {
    use std::cmp::Reverse;
    use std::collections::{BTreeMap, BinaryHeap, HashMap};

    use srtla_core::connection::SrtlaConnection;
    use srtla_core::mode::SchedulingMode;
    use srtla_core::selection::select_connection_idx;
    use srtla_core::utils::now_ms;

    use crate::config::ConfigSnapshot;
    use crate::test_helpers::create_test_connections;

    /// SRT receive latency, as CeraUI configures it.
    const LATENCY_MS: u64 = 2000;
    /// CeraUI's `--conn-timeout-ms`.
    const CONN_TIMEOUT_MS: u64 = 15_000;
    /// `srtla_rec` forgets a link after 10 s of silence, checked every 3 s.
    const RECEIVER_CONN_TIMEOUT_MS: u64 = 11_000;
    const SRT_ACK_PERIOD_MS: u64 = 10;
    const NAK_REPORT_PERIOD_MS: u64 = 50;
    const RECV_ACK_INT: usize = 10;
    /// `HOUSEKEEPING_INTERVAL_MS` in the sender loop.
    const HOUSEKEEPING_MS: u64 = 1000;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum PathState {
        /// Delivers both ways, each direction losing `loss_permille` packets.
        Alive { loss_permille: u32 },
        /// Nothing from the sender reaches the receiver, but the receiver's
        /// own packets (SRT ACK broadcasts) still reach the sender until the
        /// receiver times the link out. This is a cut on the receiver's input,
        /// or an uplink that only fails outbound.
        DeadInbound,
        /// Nothing gets through in either direction: an AP that vanished
        /// without a deauth, or an upstream that went dark.
        Blackhole,
    }

    #[derive(Clone, Copy)]
    struct Step {
        at_ms: u64,
        link: usize,
        state: PathState,
    }

    #[derive(Debug)]
    enum Ev {
        Arrive { link: usize, seq: u32 },
        SrtlaAck { link: usize, seqs: Vec<u32> },
        KeepaliveEcho { link: usize, pkt: Vec<u8> },
        SrtAck { link: usize, last_acked: i32 },
        Nak { link: usize, seq: u32 },
    }

    struct Rng(u64);
    impl Rng {
        fn permille(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % 1000) as u32
        }
    }

    #[derive(Default, Debug)]
    struct Outcome {
        /// Simulated ms from the first cut until the dead link was gated.
        gated_after_ms: Option<u64>,
        /// Payload packets (not probes) put on the cut link while it was cut.
        payload_into_dead_path: u64,
        /// Packets the receiver had to drop because they missed the latency.
        receiver_drops: u64,
        /// Simulated ms from the path's recovery until it was readmitted.
        readmitted_after_ms: Option<u64>,
        stall_gate_events: u64,
        /// Share of payload the watched link carried in the final 10 s.
        final_share: f64,
    }

    struct Sim {
        conns: smallvec::SmallVec<SrtlaConnection, 4>,
        rtt_ms: [u64; 2],
        state: [PathState; 2],
        last_arrival: [u64; 2],
        rng: Rng,
        events: BinaryHeap<Reverse<(u64, u64)>>,
        payloads: HashMap<u64, Ev>,
        next_ev: u64,
        // Sender side.
        owner: HashMap<u32, usize>,
        next_seq: u32,
        last_idx: Option<usize>,
        // Receiver side.
        first_sent: BTreeMap<u32, u64>,
        missing: BTreeMap<u32, u64>,
        received_upto: u32,
        max_seen: Option<u32>,
        recv_batch: [Vec<u32>; 2],
        last_active_link: usize,
        receiver_drops: u64,
        /// Extra random delay (0..=n ms) on keepalive echoes and on the
        /// receiver's ACKs, per packet.
        echo_jitter_ms: u64,
        ack_jitter_ms: u64,
        /// Per-link payload packets sent, ms spent held out, and worst
        /// rejoin backoff seen.
        payload_sent: [u64; 2],
        held_out_ms: [u64; 2],
        max_backoff: [u32; 2],
        /// Longest a link went without delivery proof after the first 5 s.
        max_proof_age_ms: [u64; 2],
    }

    impl Sim {
        fn new(rtt_ms: [u64; 2], seed: u64) -> Self {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let conns = rt.block_on(create_test_connections(2));
            Self {
                conns,
                rtt_ms,
                state: [PathState::Alive { loss_permille: 0 }; 2],
                last_arrival: [0; 2],
                rng: Rng(seed),
                events: BinaryHeap::new(),
                payloads: HashMap::new(),
                next_ev: 0,
                owner: HashMap::new(),
                next_seq: 0,
                last_idx: None,
                first_sent: BTreeMap::new(),
                missing: BTreeMap::new(),
                received_upto: 0,
                max_seen: None,
                recv_batch: [Vec::new(), Vec::new()],
                last_active_link: 0,
                receiver_drops: 0,
                echo_jitter_ms: 0,
                ack_jitter_ms: 0,
                payload_sent: [0; 2],
                held_out_ms: [0; 2],
                max_backoff: [0; 2],
                max_proof_age_ms: [0; 2],
            }
        }

        fn schedule(&mut self, at: u64, ev: Ev) {
            self.next_ev += 1;
            self.payloads.insert(self.next_ev, ev);
            self.events.push(Reverse((at, self.next_ev)));
        }

        fn jitter(&mut self, max_ms: u64) -> u64 {
            if max_ms == 0 {
                0
            } else {
                self.rng.permille() as u64 % (max_ms + 1)
            }
        }

        /// One-way delay back to the sender on `link` for a receiver ACK.
        fn ack_delay(&mut self, link: usize) -> u64 {
            self.rtt_ms[link] / 2 + self.jitter(self.ack_jitter_ms)
        }

        /// Whether one packet makes it from sender to receiver on `link`.
        fn forward_ok(&mut self, link: usize) -> bool {
            match self.state[link] {
                PathState::Alive { loss_permille } => self.rng.permille() >= loss_permille,
                _ => false,
            }
        }

        /// Whether one packet makes it from receiver to sender on `link`.
        fn return_ok(&mut self, link: usize, now: u64) -> bool {
            match self.state[link] {
                PathState::Alive { loss_permille } => self.rng.permille() >= loss_permille,
                PathState::DeadInbound => {
                    now.saturating_sub(self.last_arrival[link]) < RECEIVER_CONN_TIMEOUT_MS
                }
                PathState::Blackhole => false,
            }
        }

        fn transmit(&mut self, link: usize, now: u64, seq: u32) {
            if self.forward_ok(link) {
                let at = now + self.rtt_ms[link] / 2;
                self.schedule(at, Ev::Arrive { link, seq });
            }
        }

        fn data_packet(seq: u32, retransmit: bool) -> [u8; 16] {
            let mut pkt = [0u8; 16];
            pkt[..4].copy_from_slice(&seq.to_be_bytes());
            if retransmit {
                srtla_protocol::set_srt_data_retransmit(&mut pkt);
            }
            pkt
        }

        /// Route one payload packet the way the shell does: select, then a
        /// duplicate probe on each gated link when its cadence is due.
        fn send_payload(&mut self, now: u64, cfg: &ConfigSnapshot, seq: u32, rtx: bool) -> usize {
            let idx = select_connection_idx(&mut self.conns, self.last_idx, now, cfg)
                .expect("a link is always selectable");
            self.last_idx = Some(idx);
            let pkt = Self::data_packet(seq, rtx);
            self.conns[idx].queue_data_packet(&pkt, Some(seq), now);
            let _ = self.conns[idx].take_batch(now);
            self.owner.insert(seq, idx);
            self.payload_sent[idx] += 1;
            self.transmit(idx, now, seq);
            for i in 0..self.conns.len() {
                if i == idx || !self.conns[i].is_stall_gated() || !self.conns[i].stall_probe_due() {
                    continue;
                }
                let probe = Self::data_packet(seq, true);
                self.conns[i].queue_probe_packet(&probe, seq, now);
                let _ = self.conns[i].take_batch(now);
                self.transmit(i, now, seq);
            }
            idx
        }

        fn receiver_tick(&mut self, now: u64, ms: u64) {
            // Latency deadline: a packet still missing is dropped for good.
            let late: Vec<u32> = self
                .missing
                .keys()
                .copied()
                .filter(|s| self.first_sent[s] + LATENCY_MS <= now)
                .collect();
            for s in late {
                self.missing.remove(&s);
                self.receiver_drops += 1;
            }
            self.advance_cumulative();
            if ms.is_multiple_of(SRT_ACK_PERIOD_MS) && self.max_seen.is_some() {
                let last_acked = self.received_upto as i32 - 1;
                for link in 0..2 {
                    if self.return_ok(link, now) {
                        let at = now + self.ack_delay(link);
                        self.schedule(at, Ev::SrtAck { link, last_acked });
                    }
                }
            }
            if ms.is_multiple_of(NAK_REPORT_PERIOD_MS) {
                let link = self.last_active_link;
                let due: Vec<u32> = self
                    .missing
                    .iter()
                    .filter(|(_, last)| now.saturating_sub(**last) >= NAK_REPORT_PERIOD_MS)
                    .map(|(s, _)| *s)
                    .collect();
                for s in due {
                    self.missing.insert(s, now);
                    if self.return_ok(link, now) {
                        let at = now + self.ack_delay(link);
                        self.schedule(at, Ev::Nak { link, seq: s });
                    }
                }
            }
        }

        fn advance_cumulative(&mut self) {
            let Some(max) = self.max_seen else { return };
            while self.received_upto <= max && !self.missing.contains_key(&self.received_upto) {
                self.received_upto += 1;
            }
        }

        fn on_arrive(&mut self, now: u64, link: usize, seq: u32) {
            self.last_arrival[link] = now;
            self.last_active_link = link;
            self.recv_batch[link].push(seq);
            if self.recv_batch[link].len() == RECV_ACK_INT {
                let seqs = std::mem::take(&mut self.recv_batch[link]);
                if self.return_ok(link, now) {
                    let at = now + self.ack_delay(link);
                    self.schedule(at, Ev::SrtlaAck { link, seqs });
                }
            }
            match self.max_seen {
                Some(max) if seq <= max => {
                    self.missing.remove(&seq);
                }
                prev => {
                    let from = prev.map_or(0, |m| m + 1);
                    for gap in from..seq {
                        if seq.saturating_sub(gap) < 4096 && !self.missing.contains_key(&gap) {
                            self.missing.insert(gap, now);
                            if self.return_ok(link, now) {
                                let at = now + self.ack_delay(link);
                                self.schedule(at, Ev::Nak { link, seq: gap });
                            }
                        }
                    }
                    self.max_seen = Some(seq);
                }
            }
        }

        fn deliver(&mut self, now: u64, cfg: &ConfigSnapshot, ev: Ev) {
            match ev {
                Ev::Arrive { link, seq } => self.on_arrive(now, link, seq),
                Ev::SrtlaAck { link, seqs } => {
                    self.conns[link].last_received = Some(now);
                    // The shell credits the arrival link first, counts an ACK
                    // for a pruned sequence the arrival link carried as its
                    // proof, and falls back to a scan for accounting (see
                    // `process_connection_events`; `owner` plays the sequence
                    // tracker, which never records probes).
                    for s in seqs {
                        if !self.conns[link].handle_srtla_ack_specific(s as i32, false, now) {
                            if self.owner.get(&s) == Some(&link) {
                                self.conns[link].note_srtla_ack_proof(now);
                            }
                            for i in 0..self.conns.len() {
                                if i != link
                                    && self.conns[i]
                                        .handle_srtla_ack_from_other_link(s as i32, false, now)
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
                Ev::KeepaliveEcho { link, pkt } => {
                    self.conns[link].last_received = Some(now);
                    self.conns[link].handle_keepalive_echo(&pkt, now);
                }
                Ev::SrtAck { link, last_acked } => {
                    self.conns[link].last_received = Some(now);
                    let owner = self.owner.get(&(last_acked as u32)).copied();
                    for (i, c) in self.conns.iter_mut().enumerate() {
                        c.handle_srt_ack(last_acked, now, owner == Some(i));
                    }
                }
                Ev::Nak { link, seq } => {
                    self.conns[link].last_received = Some(now);
                    if let Some(&o) = self.owner.get(&seq) {
                        self.conns[o].handle_nak(seq as i32, now);
                    }
                    // SRT retransmits each NAKed sequence once per report.
                    if self.missing.contains_key(&seq) {
                        self.send_payload(now, cfg, seq, true);
                    }
                }
            }
        }

        /// The sender's 1 s housekeeping tick, as far as it touches the links:
        /// keepalives (and the extra one an RTT measurement asks for), window
        /// recovery and phase transitions.
        fn housekeeping(&mut self, now: u64) {
            for link in 0..self.conns.len() {
                let mut kas = Vec::new();
                if self.conns[link].needs_keepalive(now) {
                    kas.push(self.conns[link].keepalive_packet(now).to_vec());
                }
                if self.conns[link].needs_rtt_measurement(now) {
                    kas.push(self.conns[link].keepalive_packet(now).to_vec());
                }
                for pkt in kas {
                    if self.forward_ok(link) {
                        self.last_arrival[link] = now;
                        if self.return_ok(link, now) {
                            let at = now + self.rtt_ms[link] + self.jitter(self.echo_jitter_ms);
                            self.schedule(at, Ev::KeepaliveEcho { link, pkt });
                        }
                    }
                }
                self.conns[link].perform_window_recovery(now);
                self.conns[link].calculate_bitrate(now);
                self.conns[link].update_phase(now);
            }
        }

        /// Run `duration_ms` at `rate_pps` payload packets per second.
        /// `watch` is the link whose cut/recovery the outcome describes.
        fn run(
            &mut self,
            rate_pps: u64,
            duration_ms: u64,
            steps: &[Step],
            watch: usize,
        ) -> Outcome {
            let cfg = ConfigSnapshot {
                mode: SchedulingMode::Enhanced,
                quality_enabled: true,
                conn_timeout_ms: CONN_TIMEOUT_MS,
                negotiated_latency_ms: LATENCY_MS as u32,
                ..ConfigSnapshot::default()
            };
            let t0 = now_ms() + 1_000;
            for c in self.conns.iter_mut() {
                c.last_received = Some(t0);
            }
            let cut_at = steps
                .iter()
                .find(|s| s.link == watch && !matches!(s.state, PathState::Alive { .. }))
                .map(|s| s.at_ms);
            let heal_at = steps
                .iter()
                .find(|s| {
                    s.link == watch
                        && cut_at.is_some_and(|c| s.at_ms > c)
                        && matches!(s.state, PathState::Alive { .. })
                })
                .map(|s| s.at_ms);
            let mut out = Outcome::default();
            let mut sent_acc: u64 = 0;
            let mut final_window = [0u64; 2];
            for ms in 0..duration_ms {
                let now = t0 + ms;
                for s in steps.iter().filter(|s| s.at_ms == ms) {
                    self.state[s.link] = s.state;
                }
                while let Some(Reverse((at, id))) = self.events.peek().copied() {
                    if at > now {
                        break;
                    }
                    self.events.pop();
                    let ev = self.payloads.remove(&id).unwrap();
                    self.deliver(now, &cfg, ev);
                }
                if ms % HOUSEKEEPING_MS == HOUSEKEEPING_MS / 2 {
                    self.housekeeping(now);
                }
                sent_acc += rate_pps;
                while sent_acc >= 1000 {
                    sent_acc -= 1000;
                    let seq = self.next_seq;
                    self.next_seq += 1;
                    self.first_sent.insert(seq, now);
                    let idx = self.send_payload(now, &cfg, seq, false);
                    let cut = cut_at.is_some_and(|c| ms >= c) && heal_at.is_none_or(|h| ms < h);
                    if cut && idx == watch {
                        out.payload_into_dead_path += 1;
                    }
                    if ms + 10_000 >= duration_ms {
                        final_window[idx] += 1;
                    }
                }
                self.receiver_tick(now, ms);
                for l in 0..2 {
                    if self.conns[l].is_stall_gated() {
                        self.held_out_ms[l] += 1;
                    }
                    self.max_backoff[l] =
                        self.max_backoff[l].max(self.conns[l].stall_rejoin_backoff());
                    let proof = self.conns[l].last_ack_or_rtt_sample_ms;
                    if ms > 5_000 && proof != 0 {
                        self.max_proof_age_ms[l] = self.max_proof_age_ms[l].max(now - proof);
                    }
                }
                let gated = self.conns[watch].is_stall_gated();
                if let Some(c) = cut_at
                    && ms >= c
                    && out.gated_after_ms.is_none()
                    && gated
                {
                    out.gated_after_ms = Some(ms - c);
                }
                if let Some(h) = heal_at
                    && ms >= h
                    && out.readmitted_after_ms.is_none()
                    && !gated
                {
                    out.readmitted_after_ms = Some(ms - h);
                }
            }
            out.receiver_drops = self.receiver_drops;
            out.stall_gate_events = self.conns[watch].stall_gate_events();
            let total = final_window[0] + final_window[1];
            out.final_share = if total == 0 {
                0.0
            } else {
                final_window[watch] as f64 / total as f64
            };
            out
        }
    }

    /// A 30 s outage of link 0, as in the field runs.
    fn cut_and_heal(state: PathState) -> Vec<Step> {
        vec![
            Step {
                at_ms: 20_000,
                link: 0,
                state,
            },
            Step {
                at_ms: 50_000,
                link: 0,
                state: PathState::Alive { loss_permille: 0 },
            },
        ]
    }

    /// Per-link rates from the field runs: 0.3 to 1.0 Mbit/s of 1316-byte
    /// packets is about 30 to 95 packets/s in total, and higher bitrates only
    /// make the backlog signal faster.
    const RATES_PPS: [u64; 3] = [30, 100, 400];

    #[test]
    fn a_path_that_dies_inbound_is_held_out_within_1600_ms() {
        for rate in RATES_PPS {
            let mut sim = Sim::new([7, 7], 0x5eed_0001 ^ rate);
            let out = sim.run(rate, 70_000, &cut_and_heal(PathState::DeadInbound), 0);
            let gated = out.gated_after_ms.expect("the dead link must be gated");
            assert!(
                gated <= 1_600,
                "{rate} pkt/s: gated {gated} ms after the cut, {out:?}"
            );
            assert_eq!(
                out.receiver_drops, 0,
                "{rate} pkt/s: SRT must recover every lost packet in its latency, {out:?}"
            );
        }
    }

    #[test]
    fn a_blackholed_path_is_held_out_within_1600_ms() {
        for rate in RATES_PPS {
            let mut sim = Sim::new([7, 7], 0x5eed_0002 ^ rate);
            let out = sim.run(rate, 70_000, &cut_and_heal(PathState::Blackhole), 0);
            let gated = out.gated_after_ms.expect("the dead link must be gated");
            assert!(
                gated <= 1_600,
                "{rate} pkt/s: gated {gated} ms after the cut, {out:?}"
            );
            assert_eq!(
                out.receiver_drops, 0,
                "{rate} pkt/s: SRT must recover every lost packet in its latency, {out:?}"
            );
        }
    }

    #[test]
    fn a_dead_path_gets_no_payload_once_gated() {
        // Before the gate engages the scheduler cannot know; after it, only
        // the 1-in-100 duplicate probes may go there.
        for rate in RATES_PPS {
            let mut sim = Sim::new([7, 7], 0x5eed_0003 ^ rate);
            let out = sim.run(rate, 70_000, &cut_and_heal(PathState::DeadInbound), 0);
            let gated_s = out.gated_after_ms.unwrap() as f64 / 1000.0;
            // Half the load at most, for as long as it took to gate, plus
            // retransmits that went the same way.
            let budget = (rate as f64 * gated_s).ceil() as u64 + 10;
            assert!(
                out.payload_into_dead_path <= budget,
                "{rate} pkt/s: {} payload packets into the dead path, budget {budget}, {out:?}",
                out.payload_into_dead_path
            );
        }
    }

    #[test]
    fn a_recovered_path_is_readmitted_once_after_the_dwell() {
        // An 8 s outage: shorter than both the receiver's and the sender's
        // link timeouts, so the stall gate alone decides when the link
        // comes back (a longer one goes through re-registration instead).
        let steps = |state| {
            vec![
                Step {
                    at_ms: 20_000,
                    link: 0,
                    state,
                },
                Step {
                    at_ms: 28_000,
                    link: 0,
                    state: PathState::Alive { loss_permille: 0 },
                },
            ]
        };
        for state in [PathState::DeadInbound, PathState::Blackhole] {
            for rate in RATES_PPS {
                let mut sim = Sim::new([7, 7], 0x5eed_0004 ^ rate);
                let out = sim.run(rate, 60_000, &steps(state), 0);
                let back = out
                    .readmitted_after_ms
                    .expect("the healed link must be readmitted");
                // First echo within a keepalive period, then the 2 s dwell.
                assert!(
                    (2_000..=4_000).contains(&back),
                    "{state:?} {rate} pkt/s: readmitted {back} ms after healing, {out:?}"
                );
                assert_eq!(
                    out.stall_gate_events, 1,
                    "{state:?} {rate} pkt/s: one outage must gate exactly once, {out:?}"
                );
                assert_eq!(out.receiver_drops, 0, "{state:?} {rate} pkt/s, {out:?}");
                // Only at the rate where the scheduler splits load between two
                // equal links at all; below it one link carries everything.
                if rate == 400 {
                    assert!(
                        out.final_share > 0.05,
                        "{state:?} {rate} pkt/s: the healed link must carry load again, {out:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_lossy_but_alive_path_is_never_gated() {
        // 5, 10 and 20 % loss in each direction, for two simulated minutes.
        // The link stays slower and NAK-heavy, but it delivers, so it must
        // keep its place in the rotation.
        for loss_permille in [50, 100, 200] {
            for rate in RATES_PPS {
                let mut sim = Sim::new([7, 7], 0x5eed_0005 ^ rate ^ loss_permille as u64);
                let steps = [Step {
                    at_ms: 5_000,
                    link: 0,
                    state: PathState::Alive { loss_permille },
                }];
                let out = sim.run(rate, 125_000, &steps, 0);
                assert_eq!(
                    out.stall_gate_events, 0,
                    "{loss_permille}‰ loss at {rate} pkt/s gated a live link, {out:?}"
                );
            }
        }
    }

    #[test]
    fn a_slower_healthy_sibling_does_not_gate_the_fast_link() {
        // Unequal round trips (7 ms Wi-Fi next to 60 ms cellular) reorder
        // packets across the links and draw NAKs for packets that do arrive.
        for rate in RATES_PPS {
            let mut sim = Sim::new([7, 60], 0x5eed_0006 ^ rate);
            let out = sim.run(rate, 60_000, &[], 0);
            assert_eq!(out.stall_gate_events, 0, "{rate} pkt/s, {out:?}");
            assert_eq!(sim.conns[1].stall_gate_events(), 0, "{rate} pkt/s, {out:?}");
        }
    }

    // --- Jittered, unequal return paths ---
    //
    // `srtla_rec` broadcasts each SRT ACK on every link, so on a link whose
    // return path is slower than its sibling's, the SRT ACK over the faster
    // path prunes the link's packets before its own SRTLA ACK arrives. Those
    // SRTLA ACKs still have to count as the slower link's proof, or a healthy
    // link is left with only the keepalive echo and gets held out on jitter.

    /// Keepalive echoes up to 20 ms late, receiver ACKs up to 10 ms late.
    fn jittered(rtts: [u64; 2], seed: u64) -> Sim {
        let mut sim = Sim::new(rtts, seed);
        sim.echo_jitter_ms = 20;
        sim.ack_jitter_ms = 10;
        sim
    }

    #[test]
    fn a_healthy_link_with_the_slower_return_path_is_never_held_out() {
        // Wi-Fi next to cellular, or two carriers: lossless, but 18 to 40 ms
        // apart. Non-round packet rates keep selection off a fixed phase.
        for (rtts, rate, min_share) in [
            ([20, 40], 97, 0.2),
            ([7, 25], 97, 0.2),
            ([7, 25], 103, 0.2),
            ([30, 30], 67, 0.4),
            ([40, 80], 151, 0.0),
        ] {
            for seed in 0..4u64 {
                let mut sim = jittered(rtts, 0xabc0_0000 ^ rate ^ (seed << 20));
                let _ = sim.run(rate, 120_000, &[], 0);
                let gates = [
                    sim.conns[0].stall_gate_events(),
                    sim.conns[1].stall_gate_events(),
                ];
                assert_eq!(
                    gates,
                    [0, 0],
                    "{rtts:?} ms at {rate} pkt/s, seed {seed}: healthy links held out {gates:?} \
                     times, {:?} ms",
                    sim.held_out_ms
                );
                let share =
                    sim.payload_sent[1] as f64 / (sim.payload_sent[0] + sim.payload_sent[1]) as f64;
                assert!(
                    share >= min_share,
                    "{rtts:?} ms at {rate} pkt/s: the slower link must carry a real share, got \
                     {share:.2}"
                );
                // Carrying real load, it must keep earning SRTLA-ACK proof
                // between keepalive echoes rather than living on the echoes.
                if min_share > 0.0 {
                    assert!(
                        sim.max_proof_age_ms[1] < 800,
                        "{rtts:?} ms at {rate} pkt/s, seed {seed}: the slower link went {} ms \
                         without proof",
                        sim.max_proof_age_ms[1]
                    );
                }
            }
        }
    }

    #[test]
    fn a_dead_link_is_caught_on_jittered_unequal_paths() {
        // Either link of a 7/25 ms pair dies, inbound only or both ways.
        for (watch, rate) in [(0, 31), (0, 103), (1, 103), (0, 401)] {
            for state in [PathState::DeadInbound, PathState::Blackhole] {
                for seed in 0..4u64 {
                    let mut sim = jittered([7, 25], 0xd00d ^ rate ^ (seed << 20));
                    let steps = [Step {
                        at_ms: 20_000 + seed * 131,
                        link: watch,
                        state,
                    }];
                    let out = sim.run(rate, 40_000, &steps, watch);
                    let gated = out.gated_after_ms.expect("the dead link must be held out");
                    assert!(
                        gated <= 1_600,
                        "link {watch} {state:?} at {rate} pkt/s, seed {seed}: held out after \
                         {gated} ms, {out:?}"
                    );
                    assert_eq!(out.stall_gate_events, 1, "{out:?}");
                }
            }
        }
    }

    #[test]
    fn a_lossy_link_on_jittered_unequal_paths_is_never_held_out() {
        for rtts in [[7, 25], [25, 7]] {
            for loss_permille in [50, 100] {
                for rate in [67, 103, 401] {
                    for seed in 0..3u64 {
                        let mut sim =
                            jittered(rtts, 0x7055 ^ rate ^ (seed << 20) ^ loss_permille as u64);
                        let steps = [Step {
                            at_ms: 5_000,
                            link: 0,
                            state: PathState::Alive { loss_permille },
                        }];
                        let out = sim.run(rate, 125_000, &steps, 0);
                        assert_eq!(
                            [out.stall_gate_events, sim.conns[1].stall_gate_events()],
                            [0, 0],
                            "{rtts:?} ms, {loss_permille}‰ loss on link 0 at {rate} pkt/s, seed \
                             {seed}"
                        );
                    }
                }
            }
        }
    }
}
