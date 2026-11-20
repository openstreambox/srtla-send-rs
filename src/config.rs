//! Runtime configuration for SRTLA sender.
//!
//! `DynamicConfig` holds atomic state that can be flipped at runtime. The
//! actual wire protocol lives in [`crate::control`] — this module exposes
//! plain getters/setters that the control dispatcher calls into.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

// The hot-path snapshot type + its default constants are core; they live in
// `config_snapshot` (free of this module's control/stats coupling). Re-exported
// here so the existing `crate::config::{ConfigSnapshot, STALL_*}` paths keep
// resolving across the codebase.
pub use srtla_core::config_snapshot::{
    CONN_TIMEOUT_MS, CONN_TIMEOUT_MS_MAX, CONN_TIMEOUT_MS_MIN, ConfigSnapshot, STALL_ACK_STALE_MS,
    STALL_MIN_IN_FLIGHT_PACKETS,
};
use srtla_core::mode::SchedulingMode;
use srtla_core::priority::CriticalWindow;

use crate::control::dispatch;
use crate::stats::SharedStats;

/// Dynamic configuration that can be modified at runtime.
/// Uses atomic types for lock-free concurrent access.
#[derive(Clone)]
pub struct DynamicConfig {
    mode: Arc<AtomicU8>,
    quality_enabled: Arc<AtomicBool>,
    stall_deselect: Arc<AtomicBool>,
    stall_min_in_flight: Arc<AtomicI32>,
    stall_ack_stale_ms: Arc<AtomicU64>,
    conn_timeout_ms: Arc<AtomicU64>,
    /// Whole-bond re-home on a dead bond whose receiver hostname has moved.
    ///
    /// Deliberately absent from [`ConfigSnapshot`]: that snapshot is taken on
    /// the per-packet hot path and is a published telemetry/config shape, while
    /// this is read once, at sender startup, to build the re-home gate. See
    /// `sender::rehome`.
    rehome_on_failure: Arc<AtomicBool>,
    /// Learned from the wire rather than configured: see
    /// [`DynamicConfig::set_negotiated_latency_ms`].
    negotiated_latency_ms: Arc<AtomicU32>,
    /// Host-requested standby per link source IP: the monotonic time it ends.
    /// Deliberately absent from [`ConfigSnapshot`]; the event loop copies it
    /// onto the connections whenever `standby_generation` moves.
    standby: Arc<Mutex<HashMap<IpAddr, u64>>>,
    standby_generation: Arc<AtomicU64>,
}

/// Longest standby one `set_link_standby` call may request. A host renews it
/// while it needs the link held; one that dies releases the link within this.
pub const LINK_STANDBY_TTL_MS_MAX: u64 = 30_000;
/// Shortest standby, so a renewal loop has room for a scheduling hiccup.
pub const LINK_STANDBY_TTL_MS_MIN: u64 = 1_000;
/// Standby length when the request names none.
pub const LINK_STANDBY_TTL_MS_DEFAULT: u64 = 10_000;

impl Default for DynamicConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicConfig {
    pub fn new() -> Self {
        Self {
            mode: Arc::new(AtomicU8::new(SchedulingMode::Enhanced.as_u8())),
            quality_enabled: Arc::new(AtomicBool::new(true)),
            stall_deselect: Arc::new(AtomicBool::new(true)),
            stall_min_in_flight: Arc::new(AtomicI32::new(STALL_MIN_IN_FLIGHT_PACKETS)),
            stall_ack_stale_ms: Arc::new(AtomicU64::new(STALL_ACK_STALE_MS)),
            conn_timeout_ms: Arc::new(AtomicU64::new(CONN_TIMEOUT_MS)),
            rehome_on_failure: Arc::new(AtomicBool::new(true)),
            negotiated_latency_ms: Arc::new(AtomicU32::new(0)),
            standby: Arc::new(Mutex::new(HashMap::new())),
            standby_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create config from CLI arguments.
    pub fn from_cli(
        mode: SchedulingMode,
        no_quality: bool,
        no_stall_deselect: bool,
        stall_min_in_flight: i32,
        stall_ack_stale_ms: u64,
        conn_timeout_ms: u64,
        no_rehome: bool,
    ) -> Self {
        Self {
            mode: Arc::new(AtomicU8::new(mode.as_u8())),
            quality_enabled: Arc::new(AtomicBool::new(!no_quality)),
            stall_deselect: Arc::new(AtomicBool::new(!no_stall_deselect)),
            stall_min_in_flight: Arc::new(AtomicI32::new(stall_min_in_flight)),
            stall_ack_stale_ms: Arc::new(AtomicU64::new(stall_ack_stale_ms)),
            conn_timeout_ms: Arc::new(AtomicU64::new(
                conn_timeout_ms.clamp(CONN_TIMEOUT_MS_MIN, CONN_TIMEOUT_MS_MAX),
            )),
            rehome_on_failure: Arc::new(AtomicBool::new(!no_rehome)),
            negotiated_latency_ms: Arc::new(AtomicU32::new(0)),
            standby: Arc::new(Mutex::new(HashMap::new())),
            standby_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Put the link with source address `ip` into standby until `now_ms +
    /// ttl_ms` (clamped), or release it. Returns the applied TTL, `0` on release.
    pub fn set_link_standby(&self, ip: IpAddr, standby: bool, ttl_ms: u64, now_ms: u64) -> u64 {
        let mut table = self.standby.lock().unwrap_or_else(PoisonError::into_inner);
        let applied = if standby {
            let ttl = ttl_ms.clamp(LINK_STANDBY_TTL_MS_MIN, LINK_STANDBY_TTL_MS_MAX);
            table.insert(ip, now_ms.saturating_add(ttl));
            ttl
        } else {
            table.remove(&ip);
            0
        };
        self.standby_generation.fetch_add(1, Ordering::Release);
        applied
    }

    /// Changes whenever a standby is set or released.
    #[inline(always)]
    pub fn standby_generation(&self) -> u64 {
        self.standby_generation.load(Ordering::Acquire)
    }

    /// Copy the standby table onto the connections. Expired entries are
    /// dropped; a connection whose IP is not in the table has no standby.
    pub fn apply_link_standby(
        &self,
        connections: &mut [srtla_core::connection::SrtlaConnection],
        now_ms: u64,
    ) {
        let mut table = self.standby.lock().unwrap_or_else(PoisonError::into_inner);
        table.retain(|_, until| *until > now_ms);
        for c in connections.iter_mut() {
            c.standby_until_ms = table.get(&c.local_ip).copied().unwrap_or(0);
        }
    }

    /// Whether a bond that has been entirely dead past the all-failed window may
    /// migrate to a newly-resolved receiver address. On by default: it can only
    /// fire when the bond is already dead, where the alternative is to stay dead
    /// until DNS luck changes or the process is restarted.
    pub fn rehome_on_failure(&self) -> bool {
        self.rehome_on_failure.load(Ordering::Relaxed)
    }

    /// Create a snapshot of current configuration.
    /// Call this once at the start of each select iteration to avoid
    /// multiple atomic loads per packet in the hot path.
    #[inline]
    pub fn snapshot(&self) -> ConfigSnapshot {
        ConfigSnapshot {
            mode: SchedulingMode::from_u8(self.mode.load(Ordering::Relaxed)),
            quality_enabled: self.quality_enabled.load(Ordering::Relaxed),
            stall_deselect: self.stall_deselect.load(Ordering::Relaxed),
            stall_min_in_flight: self.stall_min_in_flight.load(Ordering::Relaxed),
            stall_ack_stale_ms: self.stall_ack_stale_ms.load(Ordering::Relaxed),
            conn_timeout_ms: self.conn_timeout_ms.load(Ordering::Relaxed),
            negotiated_latency_ms: self.negotiated_latency_ms.load(Ordering::Relaxed),
        }
    }

    /// Record the TSBPD receive delay the far-end SRT listener declared in its
    /// handshake response. Returns true if this changed the stored value.
    ///
    /// Unlike everything else here this is not operator configuration — it is
    /// read off the wire by [`crate::sender::uplink_recv`] as the handshake
    /// crosses. It arrives once per SRT session, shortly after the first link
    /// registers, and changes only if the session is re-established on
    /// different terms; until then consumers see 0 and estimate a budget from
    /// their own RTT samples instead.
    pub fn set_negotiated_latency_ms(&self, latency_ms: u32) -> bool {
        self.negotiated_latency_ms
            .swap(latency_ms, Ordering::Relaxed)
            != latency_ms
    }

    /// Get the current scheduling mode.
    #[inline]
    pub fn mode(&self) -> SchedulingMode {
        SchedulingMode::from_u8(self.mode.load(Ordering::Relaxed))
    }

    /// Set the scheduling mode.
    pub fn set_mode(&self, mode: SchedulingMode) {
        self.mode.store(mode.as_u8(), Ordering::Relaxed);
    }

    /// Set whether quality scoring is enabled.
    pub fn set_quality_enabled(&self, enabled: bool) {
        self.quality_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Toggle the stalled-link deselect guard at runtime.
    pub fn set_stall_deselect(&self, enabled: bool) {
        self.stall_deselect.store(enabled, Ordering::Relaxed);
    }

    /// Set the per-link liveness timeout at runtime, clamped to
    /// [`CONN_TIMEOUT_MS_MIN`], [`CONN_TIMEOUT_MS_MAX`]. Returns the applied
    /// value. Intended for a latency-aware client (belacoder) to scale the
    /// window to `max(default, 2 x SRT latency)` so a link outage the
    /// receiver buffer can absorb resumes warm instead of re-handshaking.
    pub fn set_conn_timeout_ms(&self, ms: u64) -> u64 {
        let applied = ms.clamp(CONN_TIMEOUT_MS_MIN, CONN_TIMEOUT_MS_MAX);
        self.conn_timeout_ms.store(applied, Ordering::Relaxed);
        applied
    }
}

/// Spawn the stdin command reader in a std::thread. Stdin on Linux
/// doesn't have a clean async story — easier to stay blocking here.
/// The Unix control socket, which actually needs subscriptions, lives
/// in an async tokio task launched by main instead.
pub fn spawn_stdin_listener(
    config: DynamicConfig,
    stats: SharedStats,
    critical_window: CriticalWindow,
) {
    std::thread::spawn(move || {
        let reader = BufReader::new(std::io::stdin());
        for line in reader.lines().map_while(Result::ok) {
            if let Some(resp) = dispatch(&config, Some(&stats), Some(&critical_window), line.trim())
            {
                // Responses on stdin just go to stdout so scripts can pipe.
                println!("{}", resp.to_json());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = DynamicConfig::new();
        let snap = config.snapshot();
        assert_eq!(snap.mode, SchedulingMode::Enhanced);
        assert!(snap.quality_enabled);
    }

    #[test]
    fn test_config_from_cli() {
        let config = DynamicConfig::from_cli(
            SchedulingMode::Classic,
            true,
            false,
            STALL_MIN_IN_FLIGHT_PACKETS,
            STALL_ACK_STALE_MS,
            CONN_TIMEOUT_MS,
            false,
        );
        let snap = config.snapshot();
        assert_eq!(snap.mode, SchedulingMode::Classic);
        assert!(!snap.quality_enabled); // no_quality=true means disabled
        assert!(snap.stall_deselect); // on by default (no_stall_deselect=false)
    }

    #[test]
    fn test_effective_quality() {
        // Classic mode - quality scoring never effective
        let snap = ConfigSnapshot {
            mode: SchedulingMode::Classic,
            quality_enabled: true,
            ..ConfigSnapshot::default()
        };
        assert!(!snap.effective_quality_enabled());

        // Enhanced mode - effective
        let snap = ConfigSnapshot {
            mode: SchedulingMode::Enhanced,
            quality_enabled: true,
            ..ConfigSnapshot::default()
        };
        assert!(snap.effective_quality_enabled());
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let config = DynamicConfig::new();
        let config_clone = config.clone();

        let writer = thread::spawn(move || {
            for _ in 0..100 {
                config_clone.set_mode(SchedulingMode::Classic);
                config_clone.set_mode(SchedulingMode::Enhanced);
            }
        });

        let config_clone2 = config.clone();
        let reader = thread::spawn(move || {
            for _ in 0..100 {
                let _ = config_clone2.snapshot();
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
    }
}
