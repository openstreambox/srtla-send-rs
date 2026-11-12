//! Shared statistics for external telemetry consumers.
//!
//! Exports per-link metrics via the Unix socket `stats` command for external
//! consumers like gst-app's bitrate controller.
//!
//! ## Design Principles
//!
//! 1. **Raw metrics only**: Export values directly from `SrtlaConnection` without
//!    transformation or speculation. Let consumers decide how to interpret them.
//!
//! 2. **Match established formats**: Per-link metrics align with `ConnectionInfo`
//!    (the extended keepalive format sent to srtla_rec).
//!
//! 3. **Include quality_multiplier**: This is the exact value used by enhanced/
//!    rtt-threshold selection algorithms, useful for understanding sender behavior.
//!
//! 4. **Simple aggregates**: Only sums and counts, no derived calculations like
//!    "capacity estimation" that would require assumptions about packet sizes.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use serde::Serialize;
use srtla_core::connection::SrtlaConnection;
use srtla_core::selection::calculate_quality_multiplier;
use srtla_core::selection::classifier::{ClassificationResult, WeakReason};
use srtla_core::selection::enhanced::in_flight_cap_packets;
use srtla_core::selection::link_cc::{CcState, LinkCcSnapshot};
use srtla_core::utils::now_ms;

use crate::config::ConfigSnapshot;

/// Per-link statistics.
///
/// Fields match `ConnectionInfo` (extended keepalive format) where applicable,
/// plus additional context useful for external monitoring.
#[derive(Clone, Debug, Serialize)]
pub struct LinkStats {
    /// This link's position in IP-list order — the same `conn_id` the ADR-001
    /// telemetry document publishes, and therefore **transient**: a SIGHUP that
    /// reorders the file hands the same modem a different one. Correlates a
    /// record across the two surfaces within one snapshot; anything that must
    /// survive a reload keys on `link_id` instead.
    pub conn_id: usize,
    /// Local IP address used for this link
    pub ip: IpAddr,
    /// Egress interface this link's socket is bound to (ADR-003). Absent — not
    /// empty — for an unmapped link, so "no bind-map row" stays distinguishable
    /// from "an interface named the empty string".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// The bind-map sidecar's writer-assigned identity, echoed verbatim
    /// (ADR-003). The sender never invents one, so an unmapped link has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_id: Option<String>,
    /// Human-readable label (e.g., "host:port via ip")
    pub label: String,
    /// True if SRTLA registration completed (REG3 received)
    pub connected: bool,
    /// True if no packets received within timeout period
    pub timed_out: bool,

    // --- Core metrics (same as ConnectionInfo in extended keepalives) ---
    /// Congestion window size (packet count). Higher = more capacity.
    /// This is the primary capacity signal used by all selection modes.
    pub window: i32,
    /// Packets sent but not yet ACKed. Higher = more load on this link.
    pub in_flight: i32,
    /// Smoothed RTT in milliseconds. From Kalman filter.
    pub rtt_ms: u32,
    /// Total NAK count since connection established. Indicates packet loss.
    pub nak_count: i32,
    /// Measured send rate in **bytes** per second (not estimated).
    ///
    /// Named for its unit on purpose. This was `bitrate_bps` while
    /// carrying bytes/sec, sitting next to genuinely bit-denominated
    /// fields like `cc_target_bps`, and feeding a Prometheus gauge whose
    /// name also claimed bits. Anything that compared the two, or
    /// graphed the gauge, was silently out by a factor of 8.
    pub bitrate_bytes_per_sec: u32,
    /// Wire bytes this link has sent for the whole process lifetime (ADR-002).
    /// Survives a socket replacement; restarts only when the process does.
    pub bytes_sent_total: u64,

    // --- RTT baseline tracking ---
    /// Dual-window minimum RTT baseline in milliseconds.
    pub rtt_min_ms: f64,
    /// Kalman RTT velocity in ms/sample (positive = rising, negative = falling).
    pub rtt_velocity: f64,

    // --- Selection algorithm context ---
    /// Base score: window / (in_flight + 1). Used by classic mode.
    /// Higher score = more available capacity on this link.
    pub base_score: i32,
    /// Quality multiplier (0.35 to 1.1) used by enhanced mode.
    /// - 1.1 = perfect (no NAKs ever)
    /// - 1.0 = normal
    /// - <1.0 = degraded due to recent NAKs
    /// - ~0.35 = heavily penalized (NAK burst)
    ///
    /// This is the EXACT multiplier used in `select_connection_idx()`.
    /// In classic mode, this is always 1.0 (quality scoring disabled).
    pub quality_multiplier: f64,

    // --- Weak-link classifier ---
    //
    // Output of `WeakLinkFilter::classify`. Currently informational only —
    // not consumed by selection. Once we soak the classifier behaviour
    // against real-world IRL traffic, the `weak` flag becomes an admission
    // gate in Enhanced selection.
    /// Whether the classifier flagged this link as weak this tick.
    pub weak: bool,
    /// Why the link was (or was not) flagged. One of: `healthy`, `high_rtt`,
    /// `no_traffic`, `low_share`, `bypassed`.
    pub weak_reason: String,
    /// This link's share of total throughput in permille (0..=1000).
    pub weak_share_permille: u32,
    /// Threshold the share was checked against (permille). Reflects
    /// entering vs leaving for hysteresis.
    pub weak_threshold_permille: u32,

    // --- Per-link CC soft cap ---
    //
    // Output of `LinkCcController::tick_all`. `cc_state`/`cc_backing_off`
    // are reported for telemetry and drive the CC controller's own
    // bitrate backoff; the routing-admission gate uses the sustained
    // `loss_degraded` latch, not the raw per-window backoff. `cc_target_bps`
    // scales the score multiplicatively via `enhanced::cc_soft_cap_multiplier`
    // so the scheduler steers traffic away from a link before it hits its
    // CC-predicted ceiling.
    /// Current state: `bootstrap` / `climbing` / `holding` /
    /// `backing_off` / `drain`.
    pub cc_state: String,
    /// Active climb sub-mode when `cc_state == climbing`. One of
    /// `normal` / `hai` / `fast_recovery`. `normal` for any other
    /// state (informational only).
    pub cc_climb_mode: String,
    /// Target sendable rate this link's CC believes is sustainable (bps).
    pub cc_target_bps: u64,
    /// Age-bucketed RTT EWMA (ms) — input to the CC state machine.
    pub cc_rtt_ewma_ms: f64,
    /// 1:3 weighted moving deviation around `cc_rtt_ewma_ms` (ms).
    pub cc_rtt_var_ms: f64,
    /// Lowest RTT ever observed on this link (ms).
    pub cc_rtt_min_ms: f64,
    /// Loss permille over the 1s rolling window.
    pub cc_loss_permille: u32,
    /// Time-decayed loss fraction (0..1) driving continuous phase
    /// demotion. Latches `cc_loss_degraded` once sustained high.
    pub cc_loss_ewma: f64,
    /// Whether the sustained-loss verdict has latched. A degraded link
    /// is demoted in score but kept schedulable, never removed.
    pub cc_loss_degraded: bool,

    // --- Adaptive batch-send regime ---
    /// Current per-connection batch-send regime. One of
    /// `low_activity` / `normal` / `high_load`. Driven from observed
    /// bitrate in housekeeping; dashboards can use it to explain why
    /// one link is batching more aggressively than another.
    pub batch_regime: String,

    // --- Stalled-link deselect (`stall_deselect`, default on) ---
    //
    // Mirrors librist's `rtt_muted` / `rtt_mute_events`: the live flag says
    // whether this link is pulled out of rotation right now, the counter says
    // how often it has happened over the link's life — the pair is what lets a
    // field run distinguish one clean failover from a flapping link.
    /// Whether this link's stall LATCH is engaged (out of the payload
    /// rotation until its rejoin dwell completes; carries keepalives plus a
    /// 1-in-N duplicate-packet probe trickle). Deliberately sourced from the
    /// sticky latch, not the routing flag: the sub-second transient silence
    /// pull is invisible here, so a capacity-tracking consumer (belacoder)
    /// is not whipsawed by routine HARQ pauses sampled at the 1 s stats
    /// cadence.
    pub stall_gated: bool,
    /// Cumulative stall-latch engagements since the link was created.
    pub stall_gate_events: u64,
    /// Cumulative fast silence-pull engagements (a loaded link heard nothing
    /// for ~2 RTTs and was transiently skipped). Ticks on routine cellular
    /// HARQ stalls — rate telemetry, not an alarm; compare against
    /// `stall_gate_events` to tell micro-stalls from real black holes.
    pub silence_pulls: u64,
    /// Whether this link is the elected sole carrier: every schedulable link
    /// is quality-gated, and this is the one still carrying the payload.
    pub sole_carrier: bool,
    /// Whether a sibling holds that role and this link is being held out of
    /// the rotation because of it.
    pub sole_carrier_excluded: bool,
    /// Cumulative sole-carrier handovers *from another link* to this one.
    /// Taking a vacant role is not counted, so this is a pure churn signal —
    /// climbing every second or two is the ping-pong this election exists to
    /// prevent, and says the margin or the minimum hold is wrong for these
    /// links. Use the `sole_carrier` flag to see whether it engaged at all.
    pub sole_carrier_elections: u64,

    // --- In-flight cap soft admission gate ---
    //
    // Derived from `cc_target_bps`: cap = (pps / 40) packets ≈ 25 ms of
    // sustainable in-flight. When `in_flight > in_flight_cap_packets`
    // the link is excluded from Enhanced selection while at least one
    // un-gated alternative is schedulable, bounding per-link queueing
    // delay before the CC controller has to back off on loss.
    /// In-flight cap in packets. `0` means "no signal" — the per-link
    /// CC hasn't published a `cc_target_bps` yet, so the cap is
    /// inactive.
    pub in_flight_cap_packets: u32,
    /// Whether the cap was active this tick (i.e. `in_flight` exceeded
    /// `in_flight_cap_packets`). When true and at least one other link
    /// is un-gated, this link is being skipped by Enhanced selection.
    pub in_flight_cap_active: bool,
}

impl Default for LinkStats {
    /// A neutral, fully-inactive link.
    ///
    /// Exists so a caller that cares about three of these ~35 fields can say so
    /// with `..Default::default()` instead of restating the rest; the telemetry
    /// projection tests are the current consumers. `IpAddr` has no `Default`, so
    /// the whole impl has to be written out rather than derived.
    fn default() -> Self {
        Self {
            conn_id: 0,
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            iface: None,
            link_id: None,
            label: String::new(),
            connected: false,
            timed_out: false,
            window: 0,
            in_flight: 0,
            rtt_ms: 0,
            nak_count: 0,
            bitrate_bytes_per_sec: 0,
            bytes_sent_total: 0,
            rtt_min_ms: 0.0,
            rtt_velocity: 0.0,
            base_score: 0,
            quality_multiplier: 1.0,
            weak: false,
            weak_reason: weak_reason_str(WeakReason::Healthy).to_string(),
            weak_share_permille: 0,
            weak_threshold_permille: 0,
            cc_state: "unknown".to_string(),
            cc_climb_mode: "normal".to_string(),
            cc_target_bps: 0,
            cc_rtt_ewma_ms: 0.0,
            cc_rtt_var_ms: 0.0,
            cc_rtt_min_ms: 0.0,
            cc_loss_permille: 0,
            cc_loss_ewma: 0.0,
            cc_loss_degraded: false,
            batch_regime: "normal".to_string(),
            stall_gated: false,
            stall_gate_events: 0,
            silence_pulls: 0,
            sole_carrier: false,
            sole_carrier_excluded: false,
            sole_carrier_elections: 0,
            in_flight_cap_packets: 0,
            in_flight_cap_active: false,
        }
    }
}

/// Aggregate statistics snapshot.
#[derive(Clone, Debug, Serialize)]
pub struct StatsSnapshot {
    /// Current scheduling mode: "classic" or "enhanced"
    pub mode: String,
    /// Whether quality scoring is enabled (always false for classic mode)
    pub quality_enabled: bool,

    /// Number of links that are connected AND not timed out
    pub active_links: usize,
    /// Total configured links
    pub total_links: usize,

    /// Sum of window across active links
    pub total_window: i32,
    /// Sum of in_flight across active links
    pub total_in_flight: i32,

    /// Wire bytes the whole bond has sent this session (ADR-002), in **bytes**
    /// — not bits, and not a rate. Monotonic for the process lifetime: it does
    /// not regress when a link reconnects or is dropped by a SIGHUP reload.
    ///
    /// Deliberately NOT `links.map(bytes_sent_total).sum()`: a link torn down by
    /// a reload would take its bytes out of that sum and the operator's "total
    /// transferred" would go backwards.
    pub session_bytes_sent: u64,

    // --- Weak-link classifier output ---
    /// Estimated max delay budget the classifier derived this tick (ms).
    /// Zero when classification was bypassed (e.g. under the throughput floor).
    pub weak_link_estimated_max_delay_ms: u32,
    /// Delay tier the cascade chose this tick (ms).
    pub weak_link_selected_delay_ms: u32,

    /// One-way delivery budget in ms read off the SRT peer's handshake — the
    /// TSBPD delay it will hold packets for. Zero until the handshake crosses,
    /// or if the peer runs without TSBPD; the classifier estimates a budget
    /// from its own RTT samples in that case.
    pub negotiated_latency_ms: u32,

    /// Per-link details
    pub links: Vec<LinkStats>,

    /// The ADR-003 operating-mode pair: is the bind-map in force
    /// (`bind_map_status`), and what is the sender actually running
    /// (`disposition`). Flattened so both appear at the top level of `get_stats`
    /// and of the telemetry document under their own names.
    ///
    /// Applied identity and connections share one snapshot lock; request
    /// ingress fences final applied publication through a separate gate.
    #[serde(flatten)]
    pub bind_map: crate::bind_map::BindMapReport,
}

impl Default for StatsSnapshot {
    fn default() -> Self {
        Self {
            mode: "enhanced".to_string(),
            quality_enabled: true,
            active_links: 0,
            total_links: 0,
            total_window: 0,
            total_in_flight: 0,
            session_bytes_sent: 0,
            weak_link_estimated_max_delay_ms: 0,
            weak_link_selected_delay_ms: 0,
            negotiated_latency_ms: 0,
            links: Vec::new(),
            bind_map: crate::bind_map::BindMapReport::default(),
        }
    }
}

/// The ADR-003 identity echo for one uplink.
///
/// Both halves are `None` for an unmapped link, which is what makes a legacy
/// run's telemetry document byte-identical to the pre-ADR-003 producer's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkIdentity {
    pub iface: Option<String>,
    pub link_id: Option<String>,
}

/// Monotonic bond-level byte accumulator behind [`StatsSnapshot::session_bytes_sent`].
///
/// Each link's own counter is monotonic but *local* — it disappears when the
/// link is torn down by a SIGHUP reload, and a re-added IP comes back as a fresh
/// connection starting at 0. Summing the live links would therefore make the
/// bond total jump backwards on every reload. Instead this banks each link's
/// **delta** since the last observation, keyed by the connection's stable
/// `conn_id`, so bytes are only ever added.
#[derive(Default)]
struct SessionBytes {
    total: u64,
    last_seen: HashMap<u64, u64>,
}

impl SessionBytes {
    fn observe(&mut self, connections: &[SrtlaConnection]) -> u64 {
        self.observe_totals(
            connections
                .iter()
                .map(|c| (c.conn_id, c.session_bytes_sent())),
        )
    }

    /// Bank each live connection's delta since the last observation, then drop
    /// bookkeeping for connections that are gone — their bytes are already in
    /// `total`, so forgetting them is what keeps the accumulator monotonic
    /// instead of subtracting a departed link back out.
    fn observe_totals(&mut self, totals: impl IntoIterator<Item = (u64, u64)>) -> u64 {
        let mut live = HashSet::with_capacity(self.last_seen.len());
        for (conn_id, link_total) in totals {
            let previous = self.last_seen.insert(conn_id, link_total);
            self.total = self
                .total
                .saturating_add(link_total.saturating_sub(previous.unwrap_or(0)));
            live.insert(conn_id);
        }
        self.last_seen.retain(|conn_id, _| live.contains(conn_id));
        self.total
    }
}

/// Thread-safe container for stats export.
///
/// Updated by sender during housekeeping (~1s interval).
/// Read by config handler when `stats` command is received.
#[derive(Clone, Default)]
pub struct SharedStats {
    inner: Arc<RwLock<StatsSnapshot>>,
    session_bytes: Arc<Mutex<SessionBytes>>,
    reload_request: Arc<Mutex<u64>>,
}

impl SharedStats {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StatsSnapshot::default())),
            session_bytes: Arc::new(Mutex::new(SessionBytes::default())),
            reload_request: Arc::new(Mutex::new(0)),
        }
    }

    /// Linearize request ingress with final applied publication.
    pub fn begin_reload_request(&self) -> u64 {
        let mut request = self
            .reload_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *request = request
            .checked_add(1)
            .expect("reload request space exhausted");
        if let Ok(mut snapshot) = self.inner.write() {
            snapshot.bind_map.disposition.state =
                crate::bind_map::BindMapDisposition::PendingApply.as_str();
            snapshot.bind_map.bind_map_pending = None;
        }
        *request
    }

    pub fn current_reload_request(&self) -> u64 {
        *self
            .reload_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Accept a read only while its request still owns the ingress fence.
    pub fn with_reload_request<T>(&self, request: u64, accept: impl FnOnce() -> T) -> Option<T> {
        let current = self
            .reload_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *current != request {
            return None;
        }
        Some(accept())
    }

    pub fn set_bind_map_if_current(
        &self,
        report: crate::bind_map::BindMapReport,
        request: u64,
    ) -> bool {
        let current = self
            .reload_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *current != request {
            return false;
        }
        self.set_bind_map(report);
        true
    }

    /// Record the sender's current ADR-003 operating mode.
    ///
    /// Use only when the connection set is unchanged (a refused reload).
    /// Applied changes use `update_with_bind_map` after socket teardown.
    pub fn set_bind_map(&self, report: crate::bind_map::BindMapReport) {
        if let Ok(mut guard) = self.inner.write() {
            guard.bind_map = report;
        }
    }

    /// Bank the old pool's final deltas before teardown, without publishing.
    pub fn observe_connection_bytes(&self, connections: &[SrtlaConnection]) {
        self.session_bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(connections);
    }

    /// Update stats from current connection state.
    ///
    /// `classification` carries the weak-link classifier's per-tick output.
    /// Pass `None` when the classifier is disabled or unavailable; the weak
    /// fields are populated with neutral defaults in that case.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &self,
        connections: &[SrtlaConnection],
        config: &ConfigSnapshot,
        classification: Option<&ClassificationResult>,
        link_cc: Option<&HashMap<u64, LinkCcSnapshot>>,
        identities: Option<&HashMap<u64, LinkIdentity>>,
    ) {
        self.update_with_bind_map(
            connections,
            config,
            classification,
            link_cc,
            identities,
            None,
        );
    }

    /// Publish connection state and an applied bind-map report under one lock.
    #[allow(clippy::too_many_arguments)]
    pub fn update_with_bind_map(
        &self,
        connections: &[SrtlaConnection],
        config: &ConfigSnapshot,
        classification: Option<&ClassificationResult>,
        link_cc: Option<&HashMap<u64, LinkCcSnapshot>>,
        identities: Option<&HashMap<u64, LinkIdentity>>,
        report: Option<&crate::bind_map::BindMapReport>,
    ) {
        self.update_for_reload(
            connections,
            config,
            classification,
            link_cc,
            identities,
            report,
            None,
        );
    }

    /// Only the newest ingress request may publish a joined applied receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn update_for_reload(
        &self,
        connections: &[SrtlaConnection],
        config: &ConfigSnapshot,
        classification: Option<&ClassificationResult>,
        link_cc: Option<&HashMap<u64, LinkCcSnapshot>>,
        identities: Option<&HashMap<u64, LinkIdentity>>,
        report: Option<&crate::bind_map::BindMapReport>,
        request: Option<u64>,
    ) -> bool {
        let current = self
            .reload_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if request.is_some_and(|request| request != *current) {
            return false;
        }
        let current_time_ms = now_ms();
        let quality_enabled = config.quality_enabled && !config.mode.is_classic();

        let session_bytes_sent = self
            .session_bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(connections);

        let mut snapshot = StatsSnapshot {
            mode: format!("{}", config.mode),
            quality_enabled,
            total_links: connections.len(),
            session_bytes_sent,
            weak_link_estimated_max_delay_ms: classification
                .map(|c| c.estimated_max_delay_ms)
                .unwrap_or(0),
            weak_link_selected_delay_ms: classification.map(|c| c.selected_delay_ms).unwrap_or(0),
            negotiated_latency_ms: config.negotiated_latency_ms,
            ..Default::default()
        };

        for (idx, conn) in connections.iter().enumerate() {
            let timed_out = conn.is_timed_out(current_time_ms);
            let is_active = conn.connected && !timed_out;

            // Quality multiplier: use actual selection algorithm calculation,
            // or 1.0 if quality scoring is disabled (classic mode)
            let quality_multiplier = if quality_enabled {
                calculate_quality_multiplier(conn, current_time_ms)
            } else {
                1.0
            };

            let weak_entry =
                classification.and_then(|c| c.per_link.iter().find(|e| e.conn_id == conn.conn_id));
            let (weak, weak_reason, weak_share, weak_threshold) = match weak_entry {
                Some(e) => (
                    e.weak,
                    weak_reason_str(e.reason).to_string(),
                    e.share_permille,
                    e.threshold_permille,
                ),
                None => (false, "unknown".to_string(), 0, 0),
            };

            let cc_entry = link_cc.and_then(|m| m.get(&conn.conn_id).copied());
            let (
                cc_state,
                cc_climb_mode,
                cc_target_bps,
                cc_rtt_ewma,
                cc_rtt_var,
                cc_rtt_min,
                cc_loss_pm,
                cc_loss_ewma,
                cc_loss_degraded,
            ) = match cc_entry {
                Some(s) => (
                    cc_state_str(s.state).to_string(),
                    s.climb_mode.as_str().to_string(),
                    s.target_bps,
                    s.rtt_ewma_ms,
                    s.rtt_var_ms,
                    s.rtt_min_ms,
                    s.loss_permille,
                    s.loss_ewma,
                    s.loss_degraded,
                ),
                None => (
                    "unknown".to_string(),
                    "normal".to_string(),
                    0,
                    0.0,
                    0.0,
                    0.0,
                    0,
                    0.0,
                    false,
                ),
            };

            let cap = in_flight_cap_packets(cc_target_bps, conn.get_rtt_min_ms());
            let in_flight_cap_pkts = cap.unwrap_or(0).max(0) as u32;
            let in_flight_cap_active = cap.map(|c| conn.in_flight_packets > c).unwrap_or(false);

            let identity = identities.and_then(|m| m.get(&conn.conn_id));
            let link = LinkStats {
                conn_id: idx,
                ip: conn.local_ip,
                iface: identity.and_then(|i| i.iface.clone()),
                link_id: identity.and_then(|i| i.link_id.clone()),
                label: conn.label.clone(),
                connected: conn.connected,
                timed_out,
                window: conn.window,
                in_flight: conn.in_flight_packets,
                rtt_ms: conn.get_smooth_rtt_ms() as u32,
                nak_count: conn.total_nak_count(),
                bitrate_bytes_per_sec: (conn.current_bitrate_mbps() * 1_000_000.0 / 8.0) as u32,
                bytes_sent_total: conn.session_bytes_sent(),
                rtt_min_ms: conn.get_rtt_min_ms(),
                rtt_velocity: conn.get_rtt_velocity(),
                base_score: conn.get_score(),
                quality_multiplier,
                weak,
                weak_reason,
                weak_share_permille: weak_share,
                weak_threshold_permille: weak_threshold,
                cc_state,
                cc_climb_mode,
                cc_target_bps,
                cc_rtt_ewma_ms: cc_rtt_ewma,
                cc_rtt_var_ms: cc_rtt_var,
                cc_rtt_min_ms: cc_rtt_min,
                cc_loss_permille: cc_loss_pm,
                cc_loss_ewma,
                cc_loss_degraded,
                batch_regime: conn.batch_sender.regime().as_str().to_string(),
                stall_gated: conn.stall_latched(),
                stall_gate_events: conn.stall_gate_events(),
                silence_pulls: conn.silence_pulls(),
                sole_carrier: conn.is_sole_carrier(),
                sole_carrier_excluded: conn.is_sole_carrier_excluded(),
                sole_carrier_elections: conn.sole_carrier_elections(),
                in_flight_cap_packets: in_flight_cap_pkts,
                in_flight_cap_active,
            };

            if is_active {
                snapshot.active_links += 1;
                snapshot.total_window += conn.window;
                snapshot.total_in_flight += conn.in_flight_packets;
            }

            snapshot.links.push(link);
        }

        if let Ok(mut guard) = self.inner.write() {
            snapshot.bind_map = report.cloned().unwrap_or_else(|| guard.bind_map.clone());
            *guard = snapshot;
            true
        } else {
            false
        }
    }

    /// Read one coherent connection/report snapshot.
    pub fn get(&self) -> StatsSnapshot {
        self.inner
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.get()).unwrap_or_else(|_| "{}".to_string())
    }
}

fn weak_reason_str(reason: WeakReason) -> &'static str {
    match reason {
        WeakReason::Healthy => "healthy",
        WeakReason::HighRtt => "high_rtt",
        WeakReason::QueueBuilding => "queue_building",
        WeakReason::NoTraffic => "no_traffic",
        WeakReason::LowShare => "low_share",
        WeakReason::Bypassed => "bypassed",
    }
}

fn cc_state_str(state: CcState) -> &'static str {
    state.as_str()
}

#[cfg(test)]
mod tests {
    use srtla_core::mode::SchedulingMode;

    use super::*;

    #[test]
    fn test_shared_stats_new() {
        let stats = SharedStats::new();
        let snapshot = stats.get();
        assert_eq!(snapshot.active_links, 0);
        assert_eq!(snapshot.total_links, 0);
    }

    #[test]
    fn test_shared_stats_empty_update() {
        let stats = SharedStats::new();
        let config = ConfigSnapshot {
            mode: SchedulingMode::Enhanced,
            quality_enabled: true,
            ..ConfigSnapshot::default()
        };
        stats.update(&[], &config, None, None, None);
        let snapshot = stats.get();
        assert_eq!(snapshot.mode, "enhanced");
        assert!(snapshot.quality_enabled);
    }

    #[test]
    fn test_to_json_contains_expected_fields() {
        let stats = SharedStats::new();
        let json = stats.to_json();
        assert!(json.contains("\"mode\""));
        assert!(json.contains("\"active_links\""));
        assert!(json.contains("\"total_window\""));
        assert!(json.contains("\"links\""));
        assert!(json.contains("\"session_bytes_sent\""));
    }

    // ---- ADR-002 session-bytes accumulator --------------------------------

    #[test]
    fn session_bytes_sums_live_links() {
        let mut acc = SessionBytes::default();
        assert_eq!(acc.observe_totals([(7, 1_000), (9, 500)]), 1_500);
    }

    #[test]
    fn session_bytes_banks_only_the_delta_between_observations() {
        let mut acc = SessionBytes::default();
        acc.observe_totals([(7, 1_000)]);
        assert_eq!(
            acc.observe_totals([(7, 1_600)]),
            1_600,
            "a link's own counter is cumulative, so re-observing it must add 600, not 1600"
        );
    }

    #[test]
    fn session_bytes_survives_a_link_teardown() {
        // A SIGHUP reload that drops an uplink must not take its bytes with it —
        // this is the regression a naive `links.map(total).sum()` would ship.
        let mut acc = SessionBytes::default();
        acc.observe_totals([(7, 1_000), (9, 500)]);

        assert_eq!(acc.observe_totals([(7, 1_000)]), 1_500);
    }

    #[test]
    fn session_bytes_counts_a_readded_link_from_zero() {
        // A re-added IP comes back as a NEW connection (fresh conn_id, counter at
        // 0). Its bytes must accrue on top of the banked total, never replace it.
        let mut acc = SessionBytes::default();
        acc.observe_totals([(7, 1_000)]);
        acc.observe_totals([]);

        assert_eq!(acc.observe_totals([(11, 300)]), 1_300);
    }

    #[test]
    fn session_bytes_never_regresses_on_a_backwards_link_counter() {
        // Per-link counters are monotonic by construction; if one ever went
        // backwards the bond total must still refuse to shrink.
        let mut acc = SessionBytes::default();
        acc.observe_totals([(7, 1_000)]);

        assert_eq!(acc.observe_totals([(7, 400)]), 1_000);
    }

    #[test]
    fn session_bytes_forgets_departed_links() {
        // Bookkeeping for a link that is gone must not accumulate across a long
        // session of SIGHUP churn.
        let mut acc = SessionBytes::default();
        acc.observe_totals([(1, 10), (2, 10), (3, 10)]);
        acc.observe_totals([(3, 10)]);

        assert_eq!(acc.last_seen.len(), 1);
        assert_eq!(acc.total, 30);
    }

    #[test]
    fn empty_update_reports_zero_session_bytes() {
        let stats = SharedStats::new();
        let config = ConfigSnapshot {
            mode: SchedulingMode::Enhanced,
            quality_enabled: true,
            ..ConfigSnapshot::default()
        };
        stats.update(&[], &config, None, None, None);
        assert_eq!(stats.get().session_bytes_sent, 0);
    }
}

#[cfg(test)]
mod departing_bytes_tests {
    use super::*;
    #[test]
    fn final_queued_bytes_survive_removal_and_replacement_without_early_publication() {
        for replace in [false, true] {
            let stats = SharedStats::new();
            let config = ConfigSnapshot::default();
            let mut old =
                SrtlaConnection::new_registering(1, "old".into(), "127.0.0.1".parse().unwrap(), 0);
            old.queue_data_packet(&[0; 100], Some(1), 0);
            stats.update(std::slice::from_ref(&old), &config, None, None, None);
            assert_eq!(stats.get().session_bytes_sent, 100);
            old.queue_data_packet(&[0; 37], Some(2), 1);
            stats.observe_connection_bytes(std::slice::from_ref(&old));
            assert_eq!(
                stats.get().session_bytes_sent,
                100,
                "banking must not publish an intermediate snapshot"
            );
            let mut next = Vec::new();
            if replace {
                let mut new = SrtlaConnection::new_registering(
                    2,
                    "new".into(),
                    "127.0.0.1".parse().unwrap(),
                    1,
                );
                new.queue_data_packet(&[0; 11], Some(3), 1);
                next.push(new);
            }
            stats.update(&next, &config, None, None, None);
            assert_eq!(
                stats.get().session_bytes_sent,
                if replace { 148 } else { 137 }
            );
            stats.update(&next, &config, None, None, None);
            assert_eq!(
                stats.get().session_bytes_sent,
                if replace { 148 } else { 137 },
                "do not double count"
            );
        }
    }
}
