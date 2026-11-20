//! Machine-friendly control protocol for `srtla_send`.
//!
//! Speaks JSON-RPC 2.0 over stdin or a Unix socket, one request per line.
//! Requests that omit `id` are notifications and get no response; this is
//! the hot path for `mark_critical` where an upstream encoder fires a
//! hint-per-keyframe and never wants to block waiting for an ACK.
//!
//! Methods:
//! - `set_mode { mode: "classic"|"enhanced" }`
//! - `set_quality { enabled: bool }`
//! - `set_stall_deselect { enabled: bool }`
//! - `set_conn_timeout { ms: u64 }` (clamped; response echoes the applied value)
//! - `get_status` → current `ConfigSnapshot`
//! - `get_stats` → per-link telemetry
//! - `get_capabilities` → the `--capabilities-json` document plus `methods`
//!
//! Keyframe / critical-packet hints travel on a dedicated UDP sidecar
//! (`srtla_core::priority`) rather than over this control socket. The sidecar
//! shares the network stack with the SRT data path so priority events
//! are ordered tightly against the packets they describe.
//!
//! JSON-RPC error codes follow the spec:
//! `-32700` parse error, `-32600` invalid request, `-32601` method not found,
//! `-32602` invalid params, `-32603` internal error. Anything above `-32000`
//! is reserved for future app-specific errors.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use srtla_core::mode::SchedulingMode;
use srtla_core::priority::CriticalWindow;
#[cfg(unix)]
use tokio::sync::mpsc;

use crate::capabilities;
use crate::config::DynamicConfig;
use crate::stats::SharedStats;
#[cfg(unix)]
use crate::subscriptions::SubscriptionHub;

const JSONRPC_VERSION: &str = "2.0";

/// Every method name this control plane dispatches, `get_capabilities`
/// included. Published by `get_capabilities` so a client feature-detects from
/// one round trip instead of probing each name for `-32601`.
const METHODS: [&str; 11] = [
    "get_capabilities",
    "get_stats",
    "get_status",
    "get_subscription_count",
    "set_conn_timeout",
    "set_link_standby",
    "set_mode",
    "set_quality",
    "set_stall_deselect",
    "subscribe",
    "unsubscribe",
];

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;

#[derive(Debug, Deserialize)]
struct Request {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct Response {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorObject>,
    id: Value,
}

#[derive(Debug, Serialize)]
struct ErrorObject {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl ErrorObject {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(id: Value, err: ErrorObject) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            result: None,
            error: Some(err),
            id,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // Serializing our own Response type cannot realistically fail,
            // but we never want to panic in the control plane.
            r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"response serialization failed"},"id":null}"#.to_string()
        })
    }
}

/// Per-connection context needed for `subscribe` / `unsubscribe`.
///
/// Unix-only, along with the rest of the async dispatch surface: its only
/// consumer is the Unix-domain control socket, which does not exist on Windows.
/// The sync [`dispatch`] path (stdin/readline, used on every platform) has no
/// push channel and answers subscribe-style methods with method-not-found.
#[cfg(unix)]
pub struct SubscriptionContext<'a> {
    pub hub: &'a SubscriptionHub,
    /// Push channel for *this* connection. Used by the hub to fan out
    /// published events onto the socket.
    pub push_tx: mpsc::Sender<String>,
    /// Subscription ids owned by this connection, for cleanup on drop.
    pub owned_ids: &'a mut Vec<String>,
}

/// Sync dispatch — used by the stdin/readline loops. Subscriptions are
/// unsupported here (there's no push channel to write to) and requests
/// for `subscribe` / `unsubscribe` will come back with method not found.
pub fn dispatch(
    config: &DynamicConfig,
    stats: Option<&SharedStats>,
    critical_window: Option<&CriticalWindow>,
    line: &str,
) -> Option<Response> {
    dispatch_inner(config, stats, critical_window, line)
}

/// Async dispatch — used by the Unix socket handler, which has a push
/// channel and can support subscriptions. Any `subscribe`/`unsubscribe`
/// request routes through the given hub.
#[cfg(unix)]
pub async fn dispatch_async(
    config: &DynamicConfig,
    stats: Option<&SharedStats>,
    critical_window: Option<&CriticalWindow>,
    subscription_ctx: Option<&mut SubscriptionContext<'_>>,
    line: &str,
) -> Option<Response> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Some(Response::err(
                Value::Null,
                ErrorObject {
                    code: PARSE_ERROR,
                    message: "parse error".into(),
                    data: Some(Value::String(e.to_string())),
                },
            ));
        }
    };
    if req.jsonrpc != JSONRPC_VERSION {
        return req.id.map(|id| {
            Response::err(
                id,
                ErrorObject::new(INVALID_REQUEST, "jsonrpc version must be \"2.0\""),
            )
        });
    }

    let is_notification = req.id.is_none();
    let id_for_response = req.id.clone().unwrap_or(Value::Null);

    let result = match (req.method.as_str(), subscription_ctx) {
        ("subscribe", Some(ctx)) => handle_subscribe(ctx, &req.params).await,
        ("unsubscribe", Some(ctx)) => handle_unsubscribe(ctx, &req.params).await,
        ("get_subscription_count", Some(ctx)) => {
            Ok(serde_json::json!({ "count": ctx.hub.len().await }))
        }
        (_, _) => handle_method(config, stats, critical_window, &req.method, &req.params),
    };

    if is_notification {
        return None;
    }
    Some(match result {
        Ok(value) => Response::ok(id_for_response, value),
        Err(err) => Response::err(id_for_response, err),
    })
}

#[cfg(unix)]
async fn handle_subscribe(
    ctx: &mut SubscriptionContext<'_>,
    params: &Value,
) -> Result<Value, ErrorObject> {
    let topic = params
        .get("topic")
        .and_then(Value::as_str)
        .ok_or_else(|| ErrorObject::new(INVALID_PARAMS, "expected params.topic: string"))?;
    if !is_known_topic(topic) {
        return Err(ErrorObject::new(
            INVALID_PARAMS,
            format!("unknown topic: {topic}"),
        ));
    }
    let id = ctx.hub.subscribe(topic, ctx.push_tx.clone()).await;
    ctx.owned_ids.push(id.clone());
    Ok(serde_json::json!({ "subscription_id": id }))
}

#[cfg(unix)]
async fn handle_unsubscribe(
    ctx: &mut SubscriptionContext<'_>,
    params: &Value,
) -> Result<Value, ErrorObject> {
    let id = params
        .get("subscription_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ErrorObject::new(INVALID_PARAMS, "expected params.subscription_id: string")
        })?;
    let removed = ctx.hub.unsubscribe(id).await;
    ctx.owned_ids.retain(|x| x != id);
    Ok(serde_json::json!({ "removed": removed }))
}

#[cfg(unix)]
fn is_known_topic(topic: &str) -> bool {
    matches!(topic, "stats" | "priority.window")
}

fn dispatch_inner(
    config: &DynamicConfig,
    stats: Option<&SharedStats>,
    critical_window: Option<&CriticalWindow>,
    line: &str,
) -> Option<Response> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            // No id available — reply with null per spec.
            return Some(Response::err(
                Value::Null,
                ErrorObject {
                    code: PARSE_ERROR,
                    message: "parse error".into(),
                    data: Some(Value::String(e.to_string())),
                },
            ));
        }
    };

    if req.jsonrpc != JSONRPC_VERSION {
        return req.id.map(|id| {
            Response::err(
                id,
                ErrorObject::new(INVALID_REQUEST, "jsonrpc version must be \"2.0\""),
            )
        });
    }

    let is_notification = req.id.is_none();
    let id_for_response = req.id.clone().unwrap_or(Value::Null);
    let result = handle_method(config, stats, critical_window, &req.method, &req.params);

    if is_notification {
        return None;
    }

    Some(match result {
        Ok(value) => Response::ok(id_for_response, value),
        Err(err) => Response::err(id_for_response, err),
    })
}

fn handle_method(
    config: &DynamicConfig,
    stats: Option<&SharedStats>,
    critical_window: Option<&CriticalWindow>,
    method: &str,
    params: &Value,
) -> Result<Value, ErrorObject> {
    match method {
        "set_mode" => {
            let mode_str = params
                .get("mode")
                .and_then(Value::as_str)
                .ok_or_else(|| ErrorObject::new(INVALID_PARAMS, "expected params.mode: string"))?;
            let mode = parse_mode(mode_str)?;
            config.set_mode(mode);
            Ok(json!({ "mode": mode.to_string() }))
        }

        "set_quality" => {
            let enabled = params
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or_else(|| ErrorObject::new(INVALID_PARAMS, "expected params.enabled: bool"))?;
            config.set_quality_enabled(enabled);
            Ok(json!({ "enabled": enabled }))
        }

        "set_stall_deselect" => {
            let enabled = params
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or_else(|| ErrorObject::new(INVALID_PARAMS, "expected params.enabled: bool"))?;
            config.set_stall_deselect(enabled);
            Ok(json!({ "enabled": enabled }))
        }

        "set_link_standby" => {
            use crate::config::StandbyKey;
            let key = match (params.get("link_id"), params.get("ip")) {
                (Some(_), Some(_)) => {
                    return Err(ErrorObject::new(
                        INVALID_PARAMS,
                        "name the link by params.link_id or params.ip, not both",
                    ));
                }
                (Some(id), None) => StandbyKey::LinkId(
                    id.as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| {
                            ErrorObject::new(INVALID_PARAMS, "expected params.link_id: string")
                        })?
                        .to_string(),
                ),
                (None, Some(ip)) => {
                    StandbyKey::Ip(ip.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                        ErrorObject::new(INVALID_PARAMS, "expected params.ip: IP address string")
                    })?)
                }
                (None, None) => {
                    return Err(ErrorObject::new(
                        INVALID_PARAMS,
                        "expected params.link_id (preferred) or params.ip",
                    ));
                }
            };
            let standby = params
                .get("standby")
                .and_then(Value::as_bool)
                .ok_or_else(|| ErrorObject::new(INVALID_PARAMS, "expected params.standby: bool"))?;
            let ttl_ms = match params.get("ttl_ms") {
                None => crate::config::LINK_STANDBY_TTL_MS_DEFAULT,
                Some(v) => match v.as_u64() {
                    Some(0) | None if standby => {
                        return Err(ErrorObject::new(
                            INVALID_PARAMS,
                            "expected params.ttl_ms: u64 greater than 0",
                        ));
                    }
                    other => other.unwrap_or(0),
                },
            };
            // Resolve against the live links in the latest snapshot (at most
            // one housekeeping tick old). A hold must name exactly one link: an
            // IP that two bind-map twins share would hold both, and a hold on
            // nothing would look applied while doing nothing.
            let stats = stats
                .ok_or_else(|| ErrorObject::new(INTERNAL_ERROR, "stats provider not registered"))?;
            let snap = stats.get();
            let matched = snap
                .links
                .iter()
                .filter(|l| key.matches(l.ip, l.link_id.as_deref()))
                .count();
            if standby && matched != 1 {
                return Err(ErrorObject {
                    code: INVALID_PARAMS,
                    message: if matched == 0 {
                        "no live link matches".into()
                    } else {
                        "more than one live link matches; name it by params.link_id".into()
                    },
                    data: Some(json!({ "matched": matched })),
                });
            }
            // Echo the applied TTL: it is clamped, so a renewal loop must pace
            // itself on the response, not on its input. Release ignores ttl_ms.
            let applied =
                config.set_link_standby(key.clone(), standby, ttl_ms, srtla_core::utils::now_ms());
            let mut result = json!({ "standby": standby, "ttl_ms": applied, "matched": matched });
            match key {
                StandbyKey::LinkId(id) => result["link_id"] = json!(id),
                StandbyKey::Ip(ip) => result["ip"] = json!(ip.to_string()),
            }
            Ok(result)
        }

        "set_conn_timeout" => {
            let ms = params
                .get("ms")
                .and_then(Value::as_u64)
                .ok_or_else(|| ErrorObject::new(INVALID_PARAMS, "expected params.ms: u64"))?;
            // The applied value is echoed back because it is clamped: a
            // latency-aware client should trust the response, not its input.
            let applied = config.set_conn_timeout_ms(ms);
            Ok(json!({ "ms": applied }))
        }

        "get_status" => {
            let snap = config.snapshot();
            let (windows_received, malformed) = critical_window
                .map(|w| (w.windows_received(), w.malformed_datagrams()))
                .unwrap_or((0, 0));
            Ok(json!({
                "mode": snap.mode.to_string(),
                "quality_enabled": snap.quality_enabled,
                "stall_deselect": snap.stall_deselect,
                "stall_min_in_flight": snap.stall_min_in_flight,
                "stall_ack_stale_ms": snap.stall_ack_stale_ms,
                "conn_timeout_ms": snap.conn_timeout_ms,
                "critical_windows_received": windows_received,
                "critical_malformed_datagrams": malformed,
            }))
        }

        "get_stats" => {
            let stats = stats
                .ok_or_else(|| ErrorObject::new(INTERNAL_ERROR, "stats provider not registered"))?;
            let json_str = stats.to_json();
            serde_json::from_str(&json_str).map_err(|e| ErrorObject {
                code: INTERNAL_ERROR,
                message: "failed to re-parse stats JSON".into(),
                data: Some(Value::String(e.to_string())),
            })
        }

        // Must stay byte-equal to the `--capabilities-json` document apart from
        // `methods`, so a supervisor that probed before spawning and a consumer
        // asking the live socket cannot be told two different things.
        "get_capabilities" => {
            let mut doc =
                serde_json::to_value(capabilities::capability_document()).map_err(|e| {
                    ErrorObject {
                        code: INTERNAL_ERROR,
                        message: "failed to serialize capability document".into(),
                        data: Some(Value::String(e.to_string())),
                    }
                })?;
            doc.as_object_mut()
                .ok_or_else(|| {
                    ErrorObject::new(INTERNAL_ERROR, "capability document is not an object")
                })?
                .insert("methods".into(), json!(METHODS));
            Ok(doc)
        }

        // Reserved for the future streaming API. A subscription-capable
        // control plane will replace these returning METHOD_NOT_FOUND with
        // a persistent-connection impl. Reserving the names now so clients
        // written against the current protocol don't collide with built-in
        // methods when the streaming upgrade lands.
        "subscribe" | "unsubscribe" => Err(ErrorObject::new(
            METHOD_NOT_FOUND,
            format!("{method} is reserved for a future streaming protocol, not yet implemented"),
        )),

        other => Err(ErrorObject::new(
            METHOD_NOT_FOUND,
            format!("unknown method: {other}"),
        )),
    }
}

fn parse_mode(s: &str) -> Result<SchedulingMode, ErrorObject> {
    match s {
        "classic" => Ok(SchedulingMode::Classic),
        "enhanced" => Ok(SchedulingMode::Enhanced),
        other => Err(ErrorObject::new(
            INVALID_PARAMS,
            format!("unknown mode '{other}': use classic or enhanced"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_returns_jsonrpc_error() {
        let config = DynamicConfig::new();
        let resp = dispatch(&config, None, None, "not valid json").unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        assert_eq!(v["error"]["code"], PARSE_ERROR);
        assert_eq!(v["id"], Value::Null);
    }

    #[test]
    fn notification_returns_none() {
        let config = DynamicConfig::new();
        // set_mode happens to work as a notification; no id means no response.
        let req = r#"{"jsonrpc":"2.0","method":"set_mode","params":{"mode":"classic"}}"#;
        assert!(dispatch(&config, None, None, req).is_none());
        assert_eq!(config.mode(), SchedulingMode::Classic);
    }

    #[test]
    fn set_mode_happy_path() {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"set_mode","params":{"mode":"classic"}}"#;
        let resp = dispatch(&config, None, None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        assert_eq!(v["result"]["mode"], "classic");
        assert_eq!(v["id"], 1);
        assert_eq!(config.mode(), SchedulingMode::Classic);
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"2.0","id":"abc","method":"noop"}"#;
        let resp = dispatch(&config, None, None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(v["id"], "abc");
    }

    #[test]
    fn invalid_params_returns_invalid_params() {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"set_quality","params":{}}"#;
        let resp = dispatch(&config, None, None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        assert_eq!(v["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn wrong_jsonrpc_version_rejects() {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"1.0","id":1,"method":"get_status"}"#;
        let resp = dispatch(&config, None, None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        assert_eq!(v["error"]["code"], INVALID_REQUEST);
    }

    fn get_capabilities_result() -> Value {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"get_capabilities"}"#;
        let resp = dispatch(&config, None, None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        v["result"].clone()
    }

    #[test]
    fn get_capabilities_matches_the_pre_spawn_probe_document() {
        let mut result = get_capabilities_result();
        let methods = result
            .as_object_mut()
            .unwrap()
            .remove("methods")
            .expect("methods is the one additive key");
        assert_eq!(methods, json!(METHODS));

        let probe: Value = serde_json::from_str(&capabilities::capability_json()).unwrap();
        assert_eq!(
            result, probe,
            "the runtime document must equal the pre-spawn probe document modulo `methods`"
        );
    }

    /// The subscription trio is dispatched only on the async path, which is the
    /// only one holding a push channel; the sync path answers it
    /// method-not-found by design.
    const SUBSCRIPTION_METHODS: [&str; 3] = ["subscribe", "unsubscribe", "get_subscription_count"];

    #[test]
    fn every_advertised_non_subscription_method_is_dispatched() {
        let result = get_capabilities_result();
        let listed: Vec<&str> = result["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(listed.contains(&"get_capabilities"));

        let config = DynamicConfig::new();
        for method in listed.iter().filter(|m| !SUBSCRIPTION_METHODS.contains(m)) {
            let req = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
            let resp = dispatch(&config, None, None, &req).unwrap();
            let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
            assert_ne!(
                v["error"]["code"].as_i64(),
                Some(i64::from(METHOD_NOT_FOUND)),
                "{method} is advertised but answers unknown-method"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_advertised_subscription_method_is_dispatched_on_the_async_path() {
        let config = DynamicConfig::new();
        let hub = SubscriptionHub::new();
        let (push_tx, _rx) = mpsc::channel(1);
        let mut owned_ids = Vec::new();
        let mut ctx = SubscriptionContext {
            hub: &hub,
            push_tx,
            owned_ids: &mut owned_ids,
        };

        for method in SUBSCRIPTION_METHODS {
            let req = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
            let resp = dispatch_async(&config, None, None, Some(&mut ctx), &req)
                .await
                .unwrap();
            let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
            assert_ne!(
                v["error"]["code"].as_i64(),
                Some(i64::from(METHOD_NOT_FOUND)),
                "{method} is advertised but answers unknown-method on the async path"
            );
        }
    }

    #[test]
    fn get_status_returns_all_fields() {
        let config = DynamicConfig::new();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"get_status"}"#;
        let resp = dispatch(&config, None, None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        let result = &v["result"];
        assert!(result["mode"].is_string());
        assert!(result["quality_enabled"].is_boolean());
    }

    /// ADR-003 rides on `get_stats` ADDITIVELY: the operating-mode pair at the
    /// top level and the identity echo per link. A consumer that predates the
    /// bind-map keeps reading every field it already knew.
    #[test]
    fn get_stats_carries_the_bind_map_mode_and_the_per_link_identity() {
        let config = DynamicConfig::new();
        let stats = SharedStats::new();
        stats.set_bind_map(crate::bind_map::BindMapReport::new(
            crate::bind_map::BindMapStatus::Active,
            crate::bind_map::BindMapDisposition::Mapped,
            &[],
        ));

        let req = r#"{"jsonrpc":"2.0","id":1,"method":"get_stats"}"#;
        let resp = dispatch(&config, Some(&stats), None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();
        let result = &v["result"];

        assert_eq!(result["bind_map_status"]["state"], "active");
        assert_eq!(result["disposition"]["state"], "mapped");
        assert!(
            result["links"].is_array(),
            "the per-link array stays where it was: {result}"
        );
        // Pre-existing keys must still be there — additive means additive.
        assert!(result["mode"].is_string());
        assert!(result["total_links"].is_number());
    }

    /// A run with no `--bind-map` still STATES its mode rather than omitting it,
    /// so a UI reads "legacy" as a fact instead of inferring it from silence.
    #[test]
    fn get_stats_reports_the_absent_mode_when_no_bind_map_was_supplied() {
        let config = DynamicConfig::new();
        let stats = SharedStats::new();

        let req = r#"{"jsonrpc":"2.0","id":1,"method":"get_stats"}"#;
        let resp = dispatch(&config, Some(&stats), None, req).unwrap();
        let v: Value = serde_json::from_str(&resp.to_json()).unwrap();

        assert_eq!(v["result"]["bind_map_status"]["state"], "absent");
        assert_eq!(v["result"]["disposition"]["state"], "legacy_unique_only");
        assert!(
            v["result"]["bind_map_status"].get("reason").is_none(),
            "a non-degraded status must not carry a reason"
        );
    }
}
