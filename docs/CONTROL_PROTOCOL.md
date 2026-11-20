# srtla_send control protocol

srtla_send exposes runtime control over a Unix socket (preferred) or stdin. The wire format is JSON-RPC 2.0, one message per line. The socket path is set with `--control-socket <path>`.

## Request/response

One request per line, UTF-8 JSON. Responses end with a newline.

Request:

```json
{"jsonrpc": "2.0", "id": 1, "method": "set_mode", "params": {"mode": "enhanced"}}
```

Success:

```json
{"jsonrpc": "2.0", "result": {"mode": "enhanced"}, "id": 1}
```

Error (standard JSON-RPC codes):

```json
{"jsonrpc": "2.0", "error": {"code": -32602, "message": "expected params.mode: string"}, "id": 1}
```

## Notifications

Requests without `id` are notifications. srtla_send processes them and sends no response. Useful for one-way config pokes when round-tripping a reply would be wasteful.

```json
{"jsonrpc": "2.0", "method": "set_mode", "params": {"mode": "classic"}}
```

## Methods

### `set_mode`

Switch the link scheduler.

| param | type | values |
| --- | --- | --- |
| `mode` | string | `"classic"`, `"enhanced"` |

Result: `{ "mode": "<current>" }`.

### `set_quality`

Toggle quality scoring (enhanced mode).

Params: `{ "enabled": bool }`. Result: `{ "enabled": bool }`.

### `set_link_standby`

Hold one link back from unique payload while it stays registered, for a host that wants a path ready but idle (a backup kept warm, or an old path kept while a new one proves itself).

| param | type | values |
| --- | --- | --- |
| `link_id` | string | the link's bind-map `link_id` (preferred: the stable identity) |
| `ip` | string | the link's source address; only when exactly one live link has it |
| `standby` | bool | `true` to hold, `false` to release |
| `ttl_ms` | u64, optional | how long the hold lasts; default 10000, clamped to 1000..30000; `0` is an error; ignored on release |

Name the link by exactly one of `link_id` or `ip`. A hold is checked against the live links in the latest stats snapshot (at most one housekeeping tick old) and must match exactly one: none, or an `ip` that two bind-map twins share, is `-32602` with `data.matched`. A release that matches nothing is a no-op and says `matched: 0`.

Result: `{ "link_id" | "ip": <as given>, "standby": bool, "ttl_ms": <applied, 0 on release>, "matched": <live links named> }`.

- The link keeps its registration and keepalives, so its RTT and liveness stay current. Like a stall-gated link it gets an occasional duplicate probe (1 in 100 routed packets), so a fresh SRTLA ACK on it is rare: with batches of 10 at the receiver, about one per thousand stream packets. Its `last_srtla_ack_age_ms` grows while held and is not a liveness signal.
- Fail-open predicate: a held link is gated only while some other link is usable (not timed out, registered) and neither stalled nor held. A weak, late or in-flight-capped link counts, so a held link stays held while such a link carries alone. With no such link, the held link carries.
- The hold ends after `ttl_ms` unless renewed (pace renewals on the returned `ttl_ms`), on release, or when its link leaves the pool or stops being uniquely named; it never moves to another link. It lives in process memory only.
- A change applies with the next packet from the SRT client; a link created by a reload picks up an existing hold the same way. Batches already queued on the link still drain.
- Without a hold, selection is unchanged. The hold does not detect a path that answers keepalives but drops data; that needs the stall gate or the host's own proof.
- `get_stats` reports `standby` (a hold is in force) and `standby_gated` (the last selection pass actually held the link back). `stall_gated` keeps meaning a stall. Prometheus exports `srtla_send_link_standby_gated`.

### `get_status`

Return the full runtime configuration plus priority-sidecar telemetry.

Result:

```json
{
  "mode": "enhanced",
  "quality_enabled": true,
  "critical_windows_received": 142,
  "critical_malformed_datagrams": 0
}
```

### `get_stats`

Return per-link telemetry (the JSON previously returned by `stats`).

Per-link delivery counters, both process-monotonic (a reconnect or reload keeps them):

| field | meaning |
| --- | --- |
| `packets_sent_total` | Data datagrams queued on the link: payload, SRT retransmits and duplicate probes. Counted where `bytes_sent_total` is counted. |
| `srtla_acked_packets_total` | Sequence numbers listed in SRTLA ACKs that arrived on the link. `srtla_rec` acknowledges a packet only on the link it arrived on, so this is delivery over that path as the receiver saw it, independent of the sender's packet logs. |
| `last_srtla_ack_age_ms` | Milliseconds since an SRTLA ACK last arrived on the link. Absent before the first one. Keepalive replies do not reset it. |

A consumer that needs a path's delivered rate takes deltas of `srtla_acked_packets_total` over time and scales them by `bytes_sent_total / packets_sent_total` for that link. The receiver holds up to a few packets per link before it sends an ACK, so the count trails the wire by that batch.

## Subscriptions

The Unix control socket supports server-push subscriptions. Polling `get_stats` at 1 Hz misses sub-second link-state changes (NAK bursts, quality drops, reconnects); subscriptions let clients receive push events on the same socket they already use for requests.

### `subscribe`

Params: `{ "topic": "stats" | "priority.window" }`. Result: `{ "subscription_id": string }`.

### `unsubscribe`

Params: `{ "subscription_id": string }`. Result: `{ "removed": bool }`.

### Push events

Server-originated notifications are sent on the same connection:

```json
{
  "jsonrpc": "2.0",
  "method": "stats.update",
  "params": {
    "subscription_id": "sub-0",
    "data": { /* StatsSnapshot */ }
  }
}
```

Topics currently implemented:

| Topic | Data | Cadence |
| --- | --- | --- |
| `stats` | Full `StatsSnapshot` (same shape as `get_stats`) | Once per second, aligned with housekeeping |
| `priority.window` | `{ at_ms, window_ms, deadline_ms }` | Once per keyframe window from the priority sidecar |

Subscriptions live for the life of the connection. Dropping the socket cancels every subscription it owns.

Stdin is request-only — subscriptions only work on the Unix socket.

## Error codes

| code | meaning |
| --- | --- |
| `-32700` | parse error (invalid JSON) |
| `-32600` | invalid request (missing / wrong `jsonrpc` field) |
| `-32601` | method not found |
| `-32602` | invalid params |
| `-32603` | internal error |

## Examples

Using `socat` on the Unix socket:

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"get_status"}' \
    | socat - UNIX-CONNECT:/tmp/srtla.sock
{"jsonrpc":"2.0","result":{"mode":"enhanced",...},"id":1}
```

Switching mode at runtime:

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"set_mode","params":{"mode":"classic"}}' \
    | socat - UNIX-CONNECT:/tmp/srtla.sock
```
