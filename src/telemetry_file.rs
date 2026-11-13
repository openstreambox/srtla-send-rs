//! ADR-001 sender telemetry stats-file emitter (opt-in via `--stats-file`).
//!
//! A per-uplink JSON snapshot written atomically (temp sibling -> fsync ->
//! `rename(2)`) so a concurrent reader never observes a torn document. The file
//! is published on a fixed cadence and removed on clean shutdown.
//!
//! The module is **fully opt-in**: with no `--stats-file` flag a
//! [`TelemetryWriter`] is never constructed and zero filesystem writes happen.
//!
//! This module owns the publish MECHANICS only. The document's schema, units,
//! and serializer live in [`crate::telemetry_doc`] and are re-exported here so
//! `telemetry_file::` import paths reach both halves.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::warn;

pub use crate::telemetry_doc::{
    TELEMETRY_SCHEMA_VERSION, TelemetryConn, TelemetryInputs, build_current_telemetry_json,
    build_telemetry_json, build_telemetry_json_from_stats, conns_from_stats,
};

/// Default publish cadence for `--stats-file-interval`, in milliseconds.
pub const DEFAULT_STATS_FILE_INTERVAL_MS: u64 = 1000;

/// Sibling temp path used by the atomic publish (`<path>.tmp`).
fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Write `json` to the temp sibling and fsync it before the rename so the bytes
/// are durable. The `File` is closed at the end of this scope, before the caller
/// renames it into place.
fn write_tmp(tmp: &Path, json: &str) -> io::Result<()> {
    let mut file = File::create(tmp)?;
    file.write_all(json.as_bytes())?;
    file.sync_all()
}

/// Atomically publish `json` to `path`: write a `.tmp` sibling, fsync, then
/// `rename(2)` over the live path. On the same filesystem rename is atomic, so a
/// concurrent reader only ever sees a complete previous-or-next document. On any
/// I/O error the temp sibling is removed and the previous snapshot is left in
/// place (to go stale) rather than vanishing.
pub fn write_atomic(path: &Path, json: &str) -> io::Result<()> {
    let tmp = tmp_path(path);
    match write_tmp(&tmp, json).and_then(|()| fs::rename(&tmp, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Best-effort removal of the live file and any leftover temp sibling.
pub fn remove(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(tmp_path(path));
}

/// The shared "latest snapshot" slot between the packet-forwarding event loop
/// and the dedicated writer thread: a mutex-guarded single value plus a condvar
/// the loop signals on each publish. `None` means "nothing pending".
type Slot = Arc<(Mutex<Option<String>>, Condvar)>;

/// The function the writer thread runs to actually persist a drained snapshot.
/// Production uses [`write_atomic`]; tests inject a fault-injecting variant to
/// prove the publish call never blocks the event loop on I/O.
type WriteFn = dyn Fn(&Path, &str) -> io::Result<()> + Send + 'static;

/// Body of the dedicated OS writer thread.
///
/// It owns the only filesystem access on the telemetry path: it blocks on the
/// condvar until a snapshot is published (or shutdown is signalled), takes the
/// latest value, and runs `write_fn` (temp -> fsync -> `rename(2)`) off the
/// event-loop task. On shutdown it drains a final snapshot for durability, then
/// unlinks the live file + `.tmp` sibling and exits — the unlink-on-exit cleanup
/// lives here, not in `Drop`, so an abrupt last write is never orphaned.
fn writer_loop(
    path: &Path,
    slot: &(Mutex<Option<String>>, Condvar),
    shutdown: &AtomicBool,
    write_fn: &WriteFn,
) {
    let (lock, cvar) = slot;
    loop {
        let taken = {
            let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
            let mut guard = cvar
                .wait_while(guard, |pending| {
                    pending.is_none() && !shutdown.load(Ordering::SeqCst)
                })
                .unwrap_or_else(PoisonError::into_inner);
            guard.take()
        };
        if let Some(json) = taken
            && let Err(e) = write_fn(path, &json)
        {
            warn!("telemetry stats-file write failed: {}: {e}", path.display());
        }
        if shutdown.load(Ordering::SeqCst) {
            let final_slot = {
                let mut guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
                guard.take()
            };
            if let Some(json) = final_slot {
                let _ = write_fn(path, &json);
            }
            remove(path);
            return;
        }
    }
}

/// Opt-in telemetry sink bound to a single stats-file path.
///
/// Constructed only when `--stats-file` is supplied. The expensive part of a
/// publish — the temp-write + `fsync` + `rename(2)` — runs on a dedicated OS
/// thread, never on the packet-forwarding event-loop task. [`publish_prebuilt`]
/// only overwrites a shared latest-snapshot slot and signals a condvar (all
/// O(microseconds)), so an eMMC stall can never stall the stream.
///
/// Publishing is best-effort: an I/O failure is logged on the writer thread and
/// dropped, never fatal to the stream. On drop the writer signals shutdown and
/// joins the thread; the thread drains any final snapshot, then unlinks the live
/// file + `.tmp` sibling, so any graceful exit cleans up.
///
/// [`publish_prebuilt`]: TelemetryWriter::publish_prebuilt
pub struct TelemetryWriter {
    slot: Slot,
    shutdown: Arc<AtomicBool>,
    /// Taken by whichever [`close`](TelemetryWriter::close) runs first.
    handle: Mutex<Option<JoinHandle<()>>>,
    period: Duration,
    path: PathBuf,
}

impl TelemetryWriter {
    /// Returns an error if the dedicated writer thread cannot be spawned.
    pub fn new(path: impl Into<PathBuf>, interval_ms: u64) -> Result<Self> {
        Self::with_write_fn(path, interval_ms, write_atomic)
    }

    /// Construct a writer whose persistence step is `write_fn`, spawning the
    /// dedicated writer thread. Production passes [`write_atomic`]; tests inject
    /// a fault-injecting closure to assert the publish path is non-blocking.
    fn with_write_fn(
        path: impl Into<PathBuf>,
        interval_ms: u64,
        write_fn: impl Fn(&Path, &str) -> io::Result<()> + Send + 'static,
    ) -> Result<Self> {
        let path = path.into();
        let slot: Slot = Arc::new((Mutex::new(None), Condvar::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let slot = slot.clone();
            let shutdown = shutdown.clone();
            let thread_path = path.clone();
            let write_fn: Box<WriteFn> = Box::new(write_fn);
            std::thread::Builder::new()
                .name("telemetry-writer".to_string())
                .spawn(move || writer_loop(&thread_path, &slot, &shutdown, write_fn.as_ref()))
                .context("spawn telemetry writer thread")?
        };
        Ok(Self {
            slot,
            shutdown,
            handle: Mutex::new(Some(handle)),
            period: Duration::from_millis(interval_ms.max(1)),
            path,
        })
    }

    /// The publish cadence (`--stats-file-interval`, floored at 1 ms).
    pub fn period(&self) -> Duration {
        self.period
    }

    /// The live stats-file path this writer publishes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hand an already-serialized ADR-001 snapshot document to the writer thread.
    ///
    /// Non-blocking by construction: it overwrites the shared latest-snapshot
    /// slot (drop-OLDER coalesce — an undrained prior snapshot is replaced, so
    /// the consumer only ever sees the freshest state) and signals the writer
    /// thread. It never touches the filesystem, so the packet-forwarding loop is
    /// never stalled by telemetry I/O. The actual temp -> fsync -> rename
    /// happens on the writer thread.
    pub fn publish_prebuilt(&self, json: &str) {
        let (lock, cvar) = &*self.slot;
        {
            let mut guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
            *guard = Some(json.to_string());
        }
        cvar.notify_one();
    }

    /// Stop the writer thread and wait for it: it drains a final snapshot and
    /// unlinks the live file and its `.tmp` sibling before this returns.
    ///
    /// Callable from any owner, any number of times. The process calls it on
    /// its way out rather than relying on the last `Arc` to drop, because that
    /// last owner can be the publisher task, and a runtime that is shutting
    /// down need not run that task to completion. Later publishes write nothing.
    pub fn close(&self) {
        // Signal shutdown under the mutex so the writer thread can never miss the
        // wakeup (it re-checks the flag inside the same critical section it waits
        // in), then join.
        let (lock, cvar) = &*self.slot;
        {
            let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
            self.shutdown.store(true, Ordering::SeqCst);
        }
        cvar.notify_one();
        let handle = self
            .handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for TelemetryWriter {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    use super::*;

    /// The ADR-001 canonical link, kept local so the writer tests do not depend
    /// on the document module's test fixtures.
    fn sample_conn() -> TelemetryConn {
        TelemetryConn {
            conn_id: 0,
            rtt_ms: 42,
            nak_count: 3,
            weight_percent: 85,
            window: 8192,
            in_flight: 100,
            bitrate_bytes_per_sec: 312_500,
            ..TelemetryConn::default()
        }
    }

    fn doc(last_updated_ms: u64, conns: &[TelemetryConn]) -> String {
        build_telemetry_json(
            last_updated_ms,
            &TelemetryInputs {
                conns,
                ..TelemetryInputs::default()
            },
        )
    }

    // ---- Atomicity: reader never sees a partial document ------------------

    #[test]
    fn write_atomic_roundtrips_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let json = doc(111, &[sample_conn()]);

        write_atomic(&path, &json).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), json);
        assert!(!tmp_path(&path).exists(), "temp sibling left behind");
    }

    #[test]
    fn write_atomic_replaces_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");

        write_atomic(&path, &doc(111, &[])).unwrap();
        write_atomic(&path, &doc(222, &[])).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"last_updated_ms\":222"));
        assert!(
            !content.contains("\"last_updated_ms\":111"),
            "a publish must replace the previous snapshot, not append"
        );
    }

    #[test]
    fn write_atomic_into_a_non_writable_directory_reports_the_error() {
        // Given: a stats-file path whose parent directory does not exist, the
        // shape of an operator typo or an unwritable location.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-dir").join("stats.json");

        // When/Then: the failure is reported rather than swallowed, and no
        // stray temp sibling is left behind for the next reader to find.
        let err = write_atomic(&path, "{}").expect_err("unwritable path must fail");
        assert!(!path.exists());
        assert!(!tmp_path(&path).exists(), "temp sibling left behind: {err}");
    }

    #[test]
    fn concurrent_reader_never_sees_torn_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        // Seed one complete snapshot so the reader always finds a live file.
        write_atomic(&path, &doc(1, &[])).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicU64::new(0));

        // Alternate small/large snapshots to maximize the byte-length delta, so a
        // non-atomic publish would be caught as an unparseable document.
        let small = vec![sample_conn()];
        let big: Vec<TelemetryConn> = (0..64u32)
            .map(|i| TelemetryConn {
                conn_id: i,
                rtt_ms: i,
                nak_count: i,
                weight_percent: 100,
                window: i as i32 * 100,
                in_flight: i as i32,
                bitrate_bytes_per_sec: i * 1000,
                ..TelemetryConn::default()
            })
            .collect();

        let writer = {
            let path = path.clone();
            let stop = stop.clone();
            let writes = writes.clone();
            thread::spawn(move || {
                let mut t = 2u64;
                while !stop.load(Ordering::Relaxed) {
                    let v = if t & 1 == 1 { &small } else { &big };
                    let _ = write_atomic(&path, &doc(t, v));
                    writes.fetch_add(1, Ordering::Relaxed);
                    t += 1;
                }
            })
        };

        let mut parse_errors = 0;
        for _ in 0..1000 {
            if let Ok(content) = fs::read_to_string(&path)
                && serde_json::from_str::<serde_json::Value>(&content).is_err()
            {
                parse_errors += 1;
            }
        }

        // Ensure the writer thread has actually run before stopping it.
        // Bounded spin-wait to prevent writer starvation under parallel load.
        for _ in 0..100 {
            if writes.load(Ordering::Relaxed) > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();

        assert_eq!(parse_errors, 0, "reader observed a torn/partial document");
        assert!(writes.load(Ordering::Relaxed) > 0, "writer never ran");
    }

    // ---- Opt-in + unlink-on-exit semantics -------------------------------

    /// The publisher task briefly holds its own reference while it builds a
    /// snapshot. If the process's reference goes first, cleanup must not wait
    /// for that task, which a shutting-down runtime may never run again:
    /// `close` finishes it from any owner, and later publishes write nothing.
    #[test]
    fn close_unlinks_the_file_while_another_owner_still_holds_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let writer = Arc::new(TelemetryWriter::new(&path, 1).unwrap());
        writer.publish_prebuilt(&doc(1, &[sample_conn()]));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !path.exists() {
            assert!(Instant::now() < deadline, "first snapshot never written");
            thread::sleep(Duration::from_millis(1));
        }
        let publisher = writer.clone();

        writer.close();

        assert!(!path.exists(), "close must unlink the live file");
        assert!(!tmp_path(&path).exists());
        publisher.publish_prebuilt(&doc(2, &[sample_conn()]));
        thread::sleep(Duration::from_millis(20));
        assert!(!path.exists(), "a publish after close recreated the file");
        writer.close();
        drop(writer);
        drop(publisher);
        assert!(!path.exists());
    }

    #[test]
    fn constructing_writer_creates_no_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let writer = TelemetryWriter::new(&path, 1000)?;
        // No publish call -> nothing on disk (opt-in: construction is inert).
        assert!(
            !path.exists(),
            "constructing a writer must not create the file"
        );
        assert_eq!(writer.path(), path);
        Ok(())
    }

    #[test]
    fn the_period_defaults_to_one_second_and_never_reaches_zero() {
        assert_eq!(DEFAULT_STATS_FILE_INTERVAL_MS, 1000);
        let writer = TelemetryWriter::new("unused", DEFAULT_STATS_FILE_INTERVAL_MS).unwrap();
        assert_eq!(writer.period(), Duration::from_millis(1000));
        // A zero interval would spin a tokio interval at zero delay; floor it.
        assert_eq!(
            TelemetryWriter::new("unused", 0).unwrap().period(),
            Duration::from_millis(1)
        );
    }

    /// Spin (bounded) until `cond` holds; the writer thread persists snapshots
    /// asynchronously, so disk assertions must await the thread, not the publish.
    fn wait_until(mut cond: impl FnMut() -> bool, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(2));
        }
        cond()
    }

    #[test]
    fn drop_unlinks_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        {
            let writer = TelemetryWriter::new(&path, 1000).unwrap();
            writer.publish_prebuilt(&doc(0, &[]));
            assert!(
                wait_until(|| path.exists(), Duration::from_secs(2)),
                "publish should create the live file (on the writer thread)"
            );
        }
        assert!(!path.exists(), "the live file must be unlinked on drop");
    }

    // ---- Writer-thread design (off-loop publish, coalesce, shutdown) ------

    #[test]
    fn telemetry_writer_thread_does_not_block_loop() {
        // Fault-inject a writer whose FIRST persist blocks 200 ms (a stalled
        // eMMC). A publish issued while the thread is mid-stall must still return
        // in well under 20 ms — it only touches the mutex + condvar, never the
        // (blocked) filesystem — so the packet-forwarding loop is never stalled.
        let calls = Arc::new(AtomicUsize::new(0));
        let writer = {
            let calls = calls.clone();
            TelemetryWriter::with_write_fn("unused", 1000, move |_path, _json| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    thread::sleep(Duration::from_millis(200));
                }
                Ok(())
            })
            .unwrap()
        };

        writer.publish_prebuilt("first");
        // Wait until the writer thread has actually entered the blocking persist.
        assert!(
            wait_until(|| calls.load(Ordering::SeqCst) >= 1, Duration::from_secs(2)),
            "writer never started the stalled write"
        );

        let started = Instant::now();
        writer.publish_prebuilt("during-stall");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(20),
            "publish blocked on writer I/O ({elapsed:?}); it must be off the loop"
        );
    }

    #[test]
    fn telemetry_slot_keeps_latest() {
        // While the writer is busy persisting snapshot A, three more publishes
        // (B, C, D) land in the single slot, each overwriting the last. When the
        // writer drains, it must take only the FRESHEST (D) — B and C are dropped
        // (drop-OLDER coalesce), never written.
        let writes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let entered_first: Slot = Arc::new((Mutex::new(None), Condvar::new()));
        let release_first: Slot = Arc::new((Mutex::new(None), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));

        let writer = {
            let writes = writes.clone();
            let entered_first = entered_first.clone();
            let release_first = release_first.clone();
            let calls = calls.clone();
            TelemetryWriter::with_write_fn("unused", 1000, move |_path, json| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                writes.lock().unwrap().push(json.to_string());
                if n == 0 {
                    signal(&entered_first);
                    wait_signalled(&release_first);
                }
                Ok(())
            })
            .unwrap()
        };

        writer.publish_prebuilt("A");
        wait_signalled(&entered_first);
        // The writer is now blocked inside A's persist; coalesce B, C, D.
        writer.publish_prebuilt("B");
        writer.publish_prebuilt("C");
        writer.publish_prebuilt("D");
        signal(&release_first);

        drop(writer);

        let w = writes.lock().unwrap();
        assert_eq!(w.first().map(String::as_str), Some("A"));
        assert_eq!(w.last().map(String::as_str), Some("D"));
        assert!(
            !w.iter().any(|s| s == "B" || s == "C"),
            "older undrained snapshots must be dropped, got {w:?}"
        );
    }

    #[test]
    fn telemetry_unlinked_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let tmp = tmp_path(&path);

        let writer = TelemetryWriter::new(&path, 1000).unwrap();
        writer.publish_prebuilt(&doc(1, &[sample_conn()]));
        assert!(
            wait_until(|| path.exists(), Duration::from_secs(2)),
            "writer thread should have published the live file"
        );

        // A final snapshot is pending when shutdown is signalled: the writer must
        // drain it (durability) then unlink both the live file and the temp sibling.
        writer.publish_prebuilt(&doc(2, &[sample_conn()]));
        drop(writer);

        assert!(!path.exists(), "live file must be unlinked on shutdown");
        assert!(!tmp.exists(), "temp sibling must be unlinked on shutdown");
    }

    #[test]
    fn a_failing_write_never_propagates_out_of_the_writer_thread() {
        // Given: a persistence step that always fails, the shape of a full or
        // read-only filesystem.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let calls = Arc::new(AtomicUsize::new(0));
        let writer = {
            let calls = calls.clone();
            TelemetryWriter::with_write_fn(&path, 1000, move |_p, _j| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("disk full"))
            })
            .unwrap()
        };

        // When: snapshots are published anyway.
        writer.publish_prebuilt(&doc(1, &[]));
        assert!(
            wait_until(|| calls.load(Ordering::SeqCst) >= 1, Duration::from_secs(2)),
            "writer never attempted the failing write"
        );
        writer.publish_prebuilt(&doc(2, &[]));

        // Then: the publish side is unaffected and shutdown still completes —
        // telemetry is best-effort and must never take the stream down.
        drop(writer);
        assert!(!path.exists());
    }

    /// Mark a [`Slot`] as signalled and wake any waiter (test rendezvous).
    fn signal(slot: &Slot) {
        let (lock, cvar) = &**slot;
        *lock.lock().unwrap() = Some(String::new());
        cvar.notify_all();
    }

    /// Block until [`signal`] has marked `slot` (test rendezvous).
    fn wait_signalled(slot: &Slot) {
        let (lock, cvar) = &**slot;
        let mut guard = lock.lock().unwrap();
        while guard.is_none() {
            guard = cvar.wait(guard).unwrap();
        }
    }

    #[test]
    fn explicit_remove_clears_live_and_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        write_atomic(&path, &doc(1, &[])).unwrap();
        // A stray temp sibling (e.g. from a crashed write) is also cleared.
        fs::write(tmp_path(&path), b"partial").unwrap();

        remove(&path);

        assert!(!path.exists(), "live file must be gone");
        assert!(!tmp_path(&path).exists(), "temp sibling must be gone");
    }

    #[test]
    fn telemetry_atomic_publish() {
        // The publish path is temp-sibling -> rename: the full document lands at
        // `<path>.tmp` first, then a single rename(2) moves it onto the live
        // path so a concurrent reader only ever sees a complete file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let tmp = tmp_path(&path);
        let json = doc(1_749_556_546_000, &[sample_conn()]);

        assert_eq!(tmp.file_name().unwrap(), "stats.json.tmp");

        write_tmp(&tmp, &json).unwrap();
        assert!(tmp.exists(), "temp sibling must exist before the rename");
        assert_eq!(fs::read_to_string(&tmp).unwrap(), json);
        assert!(!path.exists(), "live path must not exist until the rename");

        fs::rename(&tmp, &path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), json);
        assert!(
            !tmp.exists(),
            "the `.tmp` sibling is consumed by the rename"
        );

        write_atomic(&path, &json).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), json);
        assert!(!tmp.exists(), "write_atomic must not leave a temp sibling");
    }
}
