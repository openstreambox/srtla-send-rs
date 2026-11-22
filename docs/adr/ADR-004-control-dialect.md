# ADR-004: Control dialect — upstream JSON-RPC adopted verbatim, extended additively

## Status

Accepted. **Supersedes the transport section of ADR-001** (`ADR-001: JSON-RPC Control
Protocol for srtla_send`). ADR-001 is retained for schema history: its telemetry
*document* contract (the `--stats-file` snapshot shape and its units) is still in force
and is unaffected by this decision. What ADR-001 specified about the **control-socket
transport** — the `hello` handshake, the `subscribe-events` method, and the kebab-case
method naming — is withdrawn and replaced by what is written here.

## Context

CERALIVE's sender is a hard fork rebased onto upstream `irlserver/srtla_send`. Upstream
already ships a control plane on `--control-socket`: JSON-RPC 2.0, one request per line,
`id`-less requests treated as notifications, snake_case method names
(`set_mode`, `set_quality`, `set_stall_deselect`, `set_conn_timeout`, `get_status`,
`get_stats`, `subscribe`, `unsubscribe`, `get_subscription_count`), and spec error codes
(`-32700` … `-32603`).

The pre-rebase CERALIVE sender had specified its own dialect in ADR-001: a `hello`
handshake carrying a `capabilities` string array, a `subscribe-events` method, and
kebab-case names throughout. Both dialects answer the same questions. Keeping both would
mean two parsers on the sender, two clients on the consumer, and a permanent
naming-convention seam down the middle of one socket.

A second, narrower requirement sits next to this: a supervisor must be able to decide
**before spawning a stream** which optional flags the installed binary understands. That
question cannot be asked over the control socket, because the socket only exists once the
process is running with the very flags in question.

## Decision

**The control dialect is upstream's, adopted verbatim.** No second dialect is introduced,
and nothing in ADR-001's transport section is re-ported:

- **No `hello`.** Upstream has no handshake; a client sends a request and reads a
  response.
- **No `subscribe-events`.** Upstream's `subscribe` / `unsubscribe` with a `topic`
  parameter is the subscription surface.
- **No kebab-case method names.** Every method is snake_case, matching upstream's
  existing `set_mode` / `get_stats`. A method named `get-capabilities` is not added.

**CERALIVE extends the dialect only additively**, in two shapes:

1. **New methods**, snake_case, that upstream does not define. The first is
   `get_capabilities`.
2. **New optional fields** inside upstream's *existing* payloads — `get_stats` and the
   subscription pushes gain the ADR-003 identity/mode fields (`iface`, `link_id`,
   `bind_map_status`, `disposition`) and the ADR-002 cumulative `bytes_sent_total`. An
   absent optional field means "not applicable", never `null` and never `""`, so an older
   consumer parsing a newer document and a newer consumer parsing an older one both
   succeed.

Neither shape removes, renames, or retypes anything upstream defines. A client written
against upstream's dialect keeps working against a CERALIVE build.

### `get_capabilities` and `--capabilities-json` are one document

The pre-spawn question is answered by a CLI flag, `--capabilities-json`, which prints one
line of JSON and exits `0` before logging is initialized and without binding a socket or
writing a file. The same document is served at runtime by the `get_capabilities` JSON-RPC
method, which adds exactly one key — `methods`, an array of every method name the control
plane dispatches, including `get_capabilities` itself. The probe cannot carry that array
honestly (it has no socket to enumerate), and a live consumer needs it to feature-detect
in one round trip.

```json
{"schema_version":1,"binary":"srtla_send","version":"4.2.0","capabilities":{"bind_map":true,"allow_empty_bond":true,"stats_file":true,"dry_run":true,"control_socket_jsonrpc":true,"conn_timeout_ms":true,"modes":["classic","enhanced"]}}
```

Apart from `methods`, the runtime result and the probe output are the **same document**.
A supervisor that probed the binary before spawning and a consumer that asks the live
socket can never be told two different things. This is pinned by
`get_capabilities_matches_the_pre_spawn_probe_document` (`src/control.rs`), which removes
`methods` from the RPC result and asserts equality with `capabilities::capability_json()`.

The capability key set is **frozen**: `bind_map`, `allow_empty_bond`, `stats_file`, `dry_run`,
`control_socket_jsonrpc`, `conn_timeout_ms`, `modes`. Nothing speculative is added. The
set may grow later — a consumer ignores keys it does not know — but growth is a deliberate
decision, and `capability_key_set_is_frozen` fails on an accidental one.

Three entries are platform-derived rather than constant, because a build that cannot honor
a feature must not claim it can: `bind_map` is `SO_BINDTODEVICE`, which is Linux-only,
`allow_empty_bond` requires Linux bind-map support, and
`control_socket_jsonrpc` needs a Unix domain socket. On the device target (Linux) all three are
`true`.

### The failure contract belongs to the caller

`--capabilities-json` is only useful if its *absence* is also an answer. A binary
predating the flag rejects it with `error: unexpected argument` and exit `2`. That is the
"no support" signal, and it is the caller's job to read it as one:

> **Any non-zero exit, unparseable output, or timeout means NO SUPPORT.** Fall back to the
> legacy spawn and do not pass the optional flags.

Callers must not match on the exit code or the message text — a future clap version, a
different locale, or a wrapper could change either. Only "exited 0 and produced one
parseable document" counts as support. `an_unknown_flag_alongside_the_probe_is_a_usage_error`
(`tests/capabilities_probe.rs`) pins the sender's half of this; the load-bearing half is
in the supervisor.

## Consequences

- One parser on the sender, one client dialect for every consumer. The TypeScript control
  binding and the CeraUI backend are written against upstream's dialect, not ADR-001's.
- ADR-001's transport section is dead text and carries a supersession banner. Its
  telemetry document contract is untouched and still normative.
- An upstream merge that adds a control method lands with no naming conflict, because
  CERALIVE's additions follow upstream's own convention. The one collision risk —
  upstream later defining `get_capabilities` itself — resolves by adopting upstream's
  shape and re-pinning the equality test, not by introducing a parallel name.
- `methods` must be kept in step with the dispatch table by hand.
  `every_advertised_non_subscription_method_is_dispatched` and
  `every_advertised_subscription_method_is_dispatched_on_the_async_path` fail when an
  advertised name answers `-32601`, so a stale entry cannot ship; an *unlisted* new method
  is not caught mechanically and is a review concern.
