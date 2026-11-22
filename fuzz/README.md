# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the
receive side of the sender. They need the pinned nightly from
`rust-toolchain.toml` and `cargo install cargo-fuzz`. The package is outside the
root workspace and has its own lockfile.

| Target | What it drives |
|---|---|
| `protocol_parsers` | Every stateless parser in `srtla-protocol` on arbitrary bytes: SRT ACK/NAK, SRTLA ACK, keepalive (plain and extended), SRT handshake latency, retransmit flag. Checks bounded output, 31-bit sequence numbers and parse/build agreement. |
| `registration_rx` | `SrtlaRegistrationManager` with arbitrary datagram and driver sequences. Checks that REG3 and REG_ERR only take effect for a handshake in flight and that a stray REG2 never replaces the SRTLA id. |
| `connection_rx` | The per-link receive path (SRT ACK, NAK, SRTLA ACK, keepalive echo) mirroring `src/sender/uplink_recv.rs` without sockets. Checks the in-flight counter against the packet log, the window bounds and RTT finiteness. |

```sh
cargo install cargo-fuzz
mkdir -p fuzz/corpus/protocol_parsers && cp fuzz/seeds/protocol_parsers/* fuzz/corpus/protocol_parsers/
cargo fuzz run protocol_parsers -- -max_total_time=300 -max_len=2048
cargo fuzz run registration_rx -- -max_total_time=300 -max_len=2048
cargo fuzz run connection_rx -- -max_total_time=300 -max_len=2048
```

`fuzz/seeds/` holds a few hand-built packets for `protocol_parsers`; copy them
into the corpus directory first, because libFuzzer writes new inputs into the
corpus it is given. Generated corpora, artifacts and build output are not
committed. A crash is reproduced
with `cargo fuzz run <target> <artifact>` and should become a regression test
next to the code it covers.
