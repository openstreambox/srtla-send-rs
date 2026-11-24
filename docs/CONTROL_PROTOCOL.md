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

#### Payload routing report

A sender that sets top-level `payload_report` (currently `1`) also reports what
the scheduler routed, per link:

| Field | Meaning |
| --- | --- |
| `payload_packets_total` | SRT data packets routed to this link as their unique copy, SRT retransmissions included. Duplicate probes, keepalives, registration and SRT control packets are not counted. Monotonic over the link's life. |
| `payload_bytes_total` | Bytes of those packets. |
| `payload_age_ms` | Time from the last payload packet routed to this link to the moment the snapshot was built. Absent until the first one. |
| `payload_held_out` | The last scheduling pass held this link out of unique payload (stall gate or quality gate), so it gets at most duplicate probes. Recomputed per packet. |

and at the top level `snapshot_age_ms`, the time from building the snapshot to
reading it. A link carried payload within the last `W` ms of the read when
`payload_age_ms + snapshot_age_ms <= W`.

Use these, not `stall_gated`, to decide whether a link carries the stream.
`stall_gated` reports the stall latch. The latch gates routing only while a
healthy sibling can carry the traffic, so a latched link with no healthy sibling
carries the whole stream while `stall_gated` stays `true`. `bytes_sent_total`
also counts duplicate probes, so it moves on a held-out link too.

Without `payload_report` every one of these fields is unknown, never zero. The
`--stats-file` document carries the same fields under the same names.

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
