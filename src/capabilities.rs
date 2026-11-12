//! The `--capabilities-json` pre-spawn probe.
//!
//! A supervisor must decide **before spawning a stream** whether the installed
//! binary understands the flags it wants to pass (`--bind-map`,
//! `--stats-file`, …). Passing an unknown flag to an old binary makes it exit
//! non-zero with a usage error, which at spawn time is a failed stream rather
//! than a graceful downgrade.
//!
//! The load-bearing half of this contract lives in the **caller**: a non-zero
//! exit, unparseable output, or a timeout means NO SUPPORT — fall back to the
//! legacy spawn. A binary predating this flag answers it with
//! `error: unexpected argument` and exit `2`, which is exactly that signal, so
//! callers must treat *any* non-zero exit the same way rather than matching on
//! the code or the message.
//!
//! The same document is served at runtime by the JSON-RPC `get_capabilities`
//! method (`crate::control`), which adds only an additive `methods` array. A
//! supervisor that probed the binary and a consumer that asks the live socket
//! can never be told two different things — pinned by
//! `get_capabilities_matches_the_pre_spawn_probe_document`.
//!
//! The capability key set is **frozen**: entries are added deliberately (a
//! consumer ignores unknown keys, so growth is safe), never speculatively.

use serde::Serialize;

/// Version of the **capability document** itself, independent of the telemetry
/// schema's version or of any sidecar's.
pub const CAPABILITIES_SCHEMA_VERSION: u32 = 1;

/// Required-binding behavioral contract, ADR-003 §9.4; independent of schemas.
pub const BIND_MAP_CONTRACT_VERSION: u32 = 2;

/// Scheduling modes this build accepts for `--mode` and for the JSON-RPC
/// `set_mode` method. Mirrors `srtla_core::mode::SchedulingMode`.
const MODES: [&str; 2] = ["classic", "enhanced"];

/// What this build can do.
///
/// Some entries are platform-derived rather than constant, because a build that
/// cannot honor a feature must not claim it can:
///
/// - `bind_map`, required-binding flags and contract revision — device pinning is Linux-only.
/// - `control_socket_jsonrpc` — the control socket is a Unix domain socket.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether `--bind-map` can actually steer egress on this platform.
    pub bind_map: bool,
    /// Whether --require-bind-map refuses source-only startup fallback.
    pub bind_map_required: bool,
    /// Whether required mode supports validated empty-map withdrawal.
    pub bind_map_required_empty_reload: bool,
    /// Required-binding contract revision; zero means unsupported/unverified.
    pub bind_map_contract: u32,
    /// Whether `--stats-file` publishes the telemetry snapshot document.
    pub stats_file: bool,
    /// Whether `--dry-run` validates the configuration without binding.
    pub dry_run: bool,
    /// Whether `--control-socket` speaks the JSON-RPC 2.0 control dialect.
    pub control_socket_jsonrpc: bool,
    /// Whether the liveness timeout is settable (`--conn-timeout-ms` and the
    /// `set_conn_timeout` method).
    pub conn_timeout_ms: bool,
    /// Accepted `--mode` / `set_mode` values.
    pub modes: [&'static str; 2],
}

/// The full document written to stdout by `--capabilities-json`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityDocument {
    pub schema_version: u32,
    pub binary: &'static str,
    pub version: &'static str,
    pub capabilities: Capabilities,
}

/// Build the capability document for this binary.
#[must_use]
pub fn capability_document() -> CapabilityDocument {
    CapabilityDocument {
        schema_version: CAPABILITIES_SCHEMA_VERSION,
        binary: "srtla_send",
        version: env!("CARGO_PKG_VERSION"),
        capabilities: Capabilities {
            bind_map: cfg!(target_os = "linux"),
            bind_map_required: cfg!(target_os = "linux"),
            bind_map_required_empty_reload: cfg!(target_os = "linux"),
            bind_map_contract: if cfg!(target_os = "linux") {
                BIND_MAP_CONTRACT_VERSION
            } else {
                0
            },
            stats_file: true,
            dry_run: true,
            control_socket_jsonrpc: cfg!(unix),
            conn_timeout_ms: true,
            modes: MODES,
        },
    }
}

/// The document as the single line of JSON the probe prints.
///
/// Serializing a fixed struct of primitives cannot fail, so this returns a
/// plain `String` rather than making every caller handle an impossible error.
#[must_use]
pub fn capability_json() -> String {
    serde_json::to_string(&capability_document())
        .unwrap_or_else(|e| unreachable!("capability document is always serializable: {e}"))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn document_carries_the_frozen_top_level_shape() {
        let v: Value = serde_json::from_str(&capability_json()).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["binary"], "srtla_send");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));

        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["binary", "capabilities", "schema_version", "version"],
            "top-level key set is frozen"
        );
    }

    #[test]
    fn capability_key_set_is_frozen() {
        let v: Value = serde_json::from_str(&capability_json()).unwrap();
        let mut keys: Vec<&str> = v["capabilities"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "bind_map",
                "bind_map_contract",
                "bind_map_required",
                "bind_map_required_empty_reload",
                "conn_timeout_ms",
                "control_socket_jsonrpc",
                "dry_run",
                "modes",
                "stats_file",
            ],
            "capability key set is frozen; add nothing speculative"
        );
        assert_eq!(v["capabilities"]["modes"], serde_json::json!(MODES));
    }

    /// The emitted field order is the struct's declaration order. A consumer
    /// diffing raw probe output across builds sees that order, so it is pinned
    /// here rather than left to whatever a future field insertion produces.
    #[test]
    fn emitted_field_order_is_stable() {
        let line = capability_json();
        let expected_prefix = format!(
            r#"{{"schema_version":1,"binary":"srtla_send","version":"{}","capabilities":{{"bind_map":"#,
            env!("CARGO_PKG_VERSION")
        );
        assert!(
            line.starts_with(&expected_prefix),
            "unexpected field order: {line}"
        );
        assert!(line.ends_with(r#","modes":["classic","enhanced"]}}"#));
    }

    #[test]
    fn the_document_is_a_single_line() {
        let line = capability_json();
        assert!(!line.contains('\n'), "probe output must be one line");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_claims_bind_map_and_the_control_socket() {
        let doc = capability_document();
        assert!(doc.capabilities.bind_map);
        assert!(doc.capabilities.control_socket_jsonrpc);
    }
}

#[cfg(test)]
mod bind_map_contract_tests {
    #[test]
    fn revision_two_means_identified_ordered_apply_on_linux_only() {
        let document = super::capability_document();
        assert_eq!(super::BIND_MAP_CONTRACT_VERSION, 2);
        assert_eq!(
            document.capabilities.bind_map_contract,
            if cfg!(target_os = "linux") { 2 } else { 0 }
        );
        let json: serde_json::Value = serde_json::from_str(&super::capability_json()).unwrap();
        assert_eq!(
            json["capabilities"]["bind_map_contract"].as_u64(),
            Some(if cfg!(target_os = "linux") { 2 } else { 0 })
        );
    }
}
