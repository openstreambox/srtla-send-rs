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

A sender that sets top-level `payload_report` (`1` or more; currently `2`) also reports what
the scheduler routed, per link:

| Field | Meaning |
| --- | --- |
| `payload_packets_total` | SRT data packets routed to this link as their unique copy, SRT retransmissions included. Duplicate probes, keepalives, registration and SRT control packets are not counted. Monotonic per sender connection: recovery and socket replacement keep it, while a reload that changes the link's address or interface starts a new connection at zero. |
| `payload_bytes_total` | Bytes of those packets. |
| `payload_age_ms` | Time from the last payload packet routed to this link to the moment the snapshot was built. Absent until the first one. |
| `payload_held_out` | The last packet's scheduling pass held this link out of unique payload (stall gate or quality gate), so it gets at most duplicate probes. Also false for links skipped for other reasons (timed out, registering, disconnected). Informational only. |

and at the top level `snapshot_age_ms`, the time from building the snapshot to
the `get` that read it.

Freshness differs between the two transports:

- `get_stats` and the `stats` topic: `snapshot_age_ms` is the age at the read.
  A link carried payload within the last `W` ms of the read when
  `payload_age_ms + snapshot_age_ms <= W`.
- `--stats-file`: `snapshot_age_ms` is the age when the document was serialised,
  before the writer thread wrote and renamed it. Add the time since
  `last_updated_ms` (wall clock, same host):
  `payload_age_ms + snapshot_age_ms + (now - last_updated_ms) <= W`. Without that
  term a stalled writer, or a file left behind by a crashed sender, would read
  fresh forever.

`payload_report` is present from startup, so a document can carry it before the
first snapshot exists, with no links and no `snapshot_age_ms`. Decide whether a
link carries the stream on `payload_age_ms` only; `payload_held_out` is a
last-packet value that explains why a link gets no payload.

Use these, not `stall_gated`, to decide whether a link carries the stream.
`stall_gated` reports the stall latch. The latch gates routing only while a
healthy sibling can carry the traffic, so a latched link with no healthy sibling
carries the whole stream while `stall_gated` stays `true`. `bytes_sent_total`
also counts duplicate probes, so it moves on a held-out link too.

Without `payload_report` every one of these fields is unknown, never zero. The
`--stats-file` document carries the same fields under the same names.

#### Per-link delivery evidence (`payload_report` >= 2)

What the receiver confirmed on each link. `srtla_rec` sends one SRTLA ACK per
10 data packets that arrive on a link (`RECV_ACK_INT`), back on that link,
listing their sequence numbers. The sender counts each SRTLA ACK on the link it
arrived on, before any packet-log matching, so a log pruned by a cumulative SRT
ACK over a sibling does not hide delivery.

| Field | Meaning |
| --- | --- |
| `packets_sent_total` | Data datagrams queued on the link: payload, SRT retransmissions and duplicate probes. Counted where `bytes_sent_total` is counted. |
| `srtla_acked_packets_total` | Sequence numbers listed in SRTLA ACKs that arrived on the link: delivery over that path as the receiver saw it. |
| `packets_since_srtla_ack` | Data datagrams (payload and probes) queued on the link since its last SRTLA ACK arrived, or since the link was last (re)established when none has arrived since. A delivering link cycles through about 10 divided by its delivery ratio; a black-holed one only grows. |
| `last_srtla_ack_age_ms` | Time from the last SRTLA ACK on the link to the moment the snapshot was built. Absent before the first, and again after recovery or a socket replacement until the next one. Keepalive replies do not reset it. |

`packets_sent_total` and `srtla_acked_packets_total` are monotonic per sender
connection, like `payload_packets_total`. `packets_since_srtla_ack` and
`last_srtla_ack_age_ms` describe the link as currently established: recovery
follows a silent path, and a replaced socket starts a fresh ACK batch at the
receiver, which keys batches by source address, so both clear until the next
ACK.

Use `packets_since_srtla_ack` with `last_srtla_ack_age_ms` to judge from one
sample whether a link delivers: count packets, not seconds, because a link that
gets only probes (1 in 100 packets) sees an ACK every 1,000 stream packets. For
a delivered rate, take deltas of `srtla_acked_packets_total` over time and scale
by `bytes_sent_total / packets_sent_total` for that link. The receiver holds up
to 9 packets per link before it sends an ACK, so the count trails the wire by
that batch.

The freshness rules above apply unchanged. The `--stats-file` document carries
the same four fields under the same names; a reader that knows only
`payload_report` 1 ignores them.

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
