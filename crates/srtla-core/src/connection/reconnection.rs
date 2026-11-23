use tracing::{debug, info};

use super::STARTUP_GRACE_MS;

/// Attempts an established link makes at the housekeeping cadence before it
/// slows down. The common IRL fault is a sub-second blip (a bumped USB cable, a
/// modem re-attaching), and SRT drops the session after 5 s of silence. Retrying
/// every second, as C srtla_send does, lets the link re-register inside that
/// window; a first retry 5 s after the timeout arrives too late.
const FAST_RETRY_ATTEMPTS: u32 = 4;
const FAST_RETRY_DELAY_MS: u64 = 1000;
/// Cadence once the fast attempts are spent. Every retry rebuilds the socket,
/// which drops any REG2 answer still in flight, so a link that is still down
/// after the fast attempts gets 5 s per try. A recovering modem with a
/// multi-second RTT can then answer in time.
const SLOW_RETRY_DELAY_MS: u64 = 5000;

/// Housekeeping checks for a retry once per 1 s tick (`HOUSEKEEPING_INTERVAL_MS`
/// in the sender), but each attempt is stamped with the time its tick was
/// serviced. When one tick is serviced a few ms later than the next, a strict
/// `elapsed >= 1000` check fails by a hair and the retry slips a whole tick.
/// Half a tick of slack keeps retries on the tick they are due. The keepalive
/// cadence has the same shape and shares it.
pub(super) const TICK_SLACK_MS: u64 = 500;

/// Delivery and retry state for an individual uplink across UDP sockets.
#[derive(Debug, Clone, Default)]
pub struct DeliveryProbation {
    pub(crate) held: bool,
    pub(crate) delivered: bool,
    attempted: bool,
    next_probe_ms: u64,
    no_data_stops: u32,
    retry_at_ms: Option<u64>,
}

impl DeliveryProbation {
    pub(crate) fn reset_socket(&mut self) {
        *self = Self {
            no_data_stops: self.no_data_stops,
            ..Self::default()
        };
    }

    pub(crate) fn note_attempt(&mut self) {
        self.attempted = true;
    }

    pub(crate) fn note_delivery(&mut self) {
        if !self.attempted {
            return;
        }
        self.delivered = true;
        self.no_data_stops = 0;
        self.retry_at_ms = None;
    }

    pub(crate) fn probe_due(&mut self, now_ms: u64) -> bool {
        if self.delivered || now_ms < self.next_probe_ms {
            return false;
        }
        self.next_probe_ms =
            now_ms.saturating_add(crate::config_snapshot::PROBATION_PROBE_INTERVAL_MS);
        true
    }

    pub(crate) fn defer_timeout(
        &mut self,
        now_ms: u64,
        registered: bool,
        has_alternative: bool,
    ) -> bool {
        if registered && self.retry_at_ms.is_none() && self.attempted && !self.delivered {
            self.no_data_stops = (self.no_data_stops + 1).min(5);
            let delay = match self.no_data_stops {
                2 => 10_000,
                3 => 20_000,
                4 => 40_000,
                5 => 60_000,
                _ => 0,
            };
            self.retry_at_ms = Some(now_ms.saturating_add(delay));
        }
        has_alternative && self.retry_at_ms.is_some_and(|deadline| now_ms < deadline)
    }
}

/// Reconnection state and retry pacing
#[derive(Debug, Clone, Default)]
pub struct ReconnectionState {
    pub last_reconnect_attempt_ms: u64,
    /// Attempts since the link last completed registration (REG3). A successful
    /// socket rebuild does not reset it: the link is only back once the
    /// receiver answers.
    pub reconnect_failure_count: u32,
    pub connection_established_ms: u64,
    pub startup_grace_deadline_ms: u64,
}

fn elapsed_reaches(now: u64, since: u64, delay_ms: u64) -> bool {
    now.saturating_sub(since) + TICK_SLACK_MS >= delay_ms
}

impl ReconnectionState {
    fn retry_delay(&self) -> u64 {
        if self.reconnect_failure_count < FAST_RETRY_ATTEMPTS {
            FAST_RETRY_DELAY_MS
        } else {
            SLOW_RETRY_DELAY_MS
        }
    }

    pub fn should_attempt_reconnect(&self, now: u64) -> bool {
        if self.connection_established_ms == 0 {
            if now <= self.startup_grace_deadline_ms {
                return false;
            }
            // Match the C implementation during initial registration by retrying
            // once per housekeeping pass.
            if self.last_reconnect_attempt_ms == 0 {
                return true;
            }
            return elapsed_reaches(now, self.last_reconnect_attempt_ms, FAST_RETRY_DELAY_MS);
        }

        if self.last_reconnect_attempt_ms == 0 {
            return true;
        }

        elapsed_reaches(now, self.last_reconnect_attempt_ms, self.retry_delay())
    }

    pub fn record_attempt(&mut self, label: &str, now: u64) {
        self.last_reconnect_attempt_ms = now;

        // For initial registration we keep retry cadence fast and skip backoff
        if self.connection_established_ms == 0 {
            debug!(
                "{}: Initial registration retry scheduled (next attempt in ~1s)",
                label
            );
            return;
        }

        self.reconnect_failure_count = self.reconnect_failure_count.saturating_add(1);

        info!(
            "{}: Reconnect attempt #{}, next attempt in {}s",
            label,
            self.reconnect_failure_count,
            self.retry_delay() / 1000
        );
    }

    pub fn mark_success(&mut self, label: &str) {
        if self.reconnect_failure_count > 0 {
            info!("{}: Reconnection successful, resetting retry pacing", label);
            self.reconnect_failure_count = 0;
        }
    }

    pub fn reset_startup_grace(&mut self, now: u64) {
        self.startup_grace_deadline_ms = now + STARTUP_GRACE_MS;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICK_MS: u64 = 1000;

    /// A link that was established (REG3 seen) and has just timed out.
    fn established() -> ReconnectionState {
        ReconnectionState {
            connection_established_ms: 1_000,
            ..Default::default()
        }
    }

    /// Drive housekeeping ticks with the link down the whole time and return
    /// the gap, in ticks, between each pair of consecutive attempts.
    fn ticks_between_attempts(mut state: ReconnectionState, attempts: usize) -> Vec<u64> {
        let mut now = 50_000;
        let mut last_attempt_tick = None;
        let mut gaps = Vec::new();
        for tick in 0u64.. {
            if state.should_attempt_reconnect(now) {
                state.record_attempt("test", now);
                if let Some(last) = last_attempt_tick {
                    gaps.push(tick - last);
                }
                last_attempt_tick = Some(tick);
                if gaps.len() == attempts - 1 {
                    return gaps;
                }
            }
            now += TICK_MS;
        }
        unreachable!()
    }

    #[test]
    fn fast_attempts_then_flat_five_seconds() {
        assert_eq!(
            ticks_between_attempts(established(), 8),
            vec![1, 1, 1, 5, 5, 5, 5]
        );
    }

    #[test]
    fn retry_lands_on_the_next_tick_despite_service_jitter() {
        let mut state = established();
        state.record_attempt("test", 50_003);
        // The next tick was serviced on schedule, 997 ms after the late one.
        assert!(state.should_attempt_reconnect(51_000));
    }

    #[test]
    fn slow_retry_does_not_come_a_tick_early() {
        let mut state = ReconnectionState {
            reconnect_failure_count: FAST_RETRY_ATTEMPTS - 1,
            ..established()
        };
        state.record_attempt("test", 50_000);
        assert!(!state.should_attempt_reconnect(54_000));
        assert!(state.should_attempt_reconnect(55_000));
    }

    #[test]
    fn registration_restores_the_fast_attempts() {
        let mut state = established();
        for i in 0..10 {
            state.record_attempt("test", 50_000 + i * SLOW_RETRY_DELAY_MS);
        }
        state.mark_success("test");
        assert_eq!(ticks_between_attempts(state, 5), vec![1, 1, 1, 5]);
    }

    #[test]
    fn initial_registration_retries_every_tick_without_counting() {
        let mut state = ReconnectionState {
            startup_grace_deadline_ms: 10_000,
            ..Default::default()
        };
        assert!(!state.should_attempt_reconnect(10_000));
        assert!(state.should_attempt_reconnect(10_001));
        state.record_attempt("test", 10_001);
        assert_eq!(state.reconnect_failure_count, 0);
        assert!(state.should_attempt_reconnect(11_000));
    }
}

#[cfg(test)]
mod probation_tests {
    use super::*;

    #[test]
    fn repeated_registered_no_data_timeouts_back_off_until_delivery() {
        let mut probation = DeliveryProbation::default();
        let mut now = 1;
        for delay in [0, 10_000, 20_000, 40_000, 60_000, 60_000] {
            probation.reset_socket();
            assert!(!probation.defer_timeout(now, false, true));
            assert!(!probation.defer_timeout(now, true, true));
            probation.note_attempt();
            assert_eq!(probation.defer_timeout(now, true, true), delay > 0);
            if delay > 0 {
                assert!(probation.defer_timeout(now + delay - 1, true, true));
                assert!(!probation.defer_timeout(now + 1, true, false));
            }
            assert!(!probation.defer_timeout(now + delay, true, true));
            now += delay + 1;
        }
        probation.note_delivery();
        probation.reset_socket();
        probation.note_attempt();
        assert!(!probation.defer_timeout(now, true, true));
    }
}
