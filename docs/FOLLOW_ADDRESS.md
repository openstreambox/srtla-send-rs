# Following a modem's new address

Mobile networks hand out addresses that do not last. A carrier may end the data
session every day or so, or renew a lease, and the modem comes back on the same
interface with a new address. Before this, the link kept sending from the old
address, which the box no longer owned, so that link stopped carrying video
until someone reloaded the IP list. On a bond with only one link, the stream
ended.

Now `srtla_send` notices on its own and moves just that link to the new address.
The receiver keeps treating it as the same stream, and the other links are not
touched. Nothing has to be reloaded or restarted. It is on by default.

## Which links it applies to

- Only links that have a row in the bind-map (`--bind-map`), which pins each
  link to a named interface such as `wwan0`. A link that comes only from the
  plain IP list is never moved, because for such a link the address *is* the
  link.
- Only to a new address on the **same interface**. A modem that comes back as a
  different interface still needs a reload, as before.
- The new address must be of the same kind as the old one: IPv4 for IPv4, IPv6
  for IPv6, and an IPv6 privacy address for a privacy address. An address
  another link already uses is never taken.

## What happens

1. The bound address disappears from the interface. The sender waits 1.5 s,
   so an address that blinks out and straight back does not disturb anything.
2. If the interface now has a suitable new address, the sender moves the link
   onto it and the link re-joins the stream it was part of. In tests, the link
   carried video again about 1.6 to 1.7 s after the address changed.
3. If the interface has no address at all, the link is taken out of service and
   waits quietly instead of retrying every second. As soon as an address
   appears, the link comes back.

If an address keeps changing, the link waits longer between moves: 2 s at first,
doubling up to 30 s. After a minute without a move, the wait is back to 2 s.

## What you see in the log

Each line starts with the link's name.

- `source address moved 10.64.0.10 -> 10.64.0.11 on wwan0; re-bound this link without a reload`
- `source address 10.64.0.10 left wwan0 and nothing replaced it; link is down until an address returns or a reload names one`
- `source address 10.64.0.10 is back on wwan0; link re-bound`

## Limits

- **IPv6 renumbering.** The link moves when the old address is removed. Some
  networks first only mark the old prefix as deprecated and keep it valid for a
  while; the link stays on it until the address is removed.
- **All links down.** Taking a link out of service only helps while another
  link carries the stream. If every link has been down for more than 10 s, the
  sender gives up and exits, as it always has.
- **The receiver's timeouts.** The receiver drops a connection, and a whole
  group, that stays silent too long. Some receivers use 4 s, others 10 s or
  more. Moving a link took about 1.6 to 1.7 s in tests, inside all of them. A
  link that is left without any address for longer than the receiver allows
  comes back as a new connection, and on a single-link bond as a new session.
- **Linux only.** On other systems nothing changes.

## Turning it off

Pass `--no-follow-address`. A renumbered link then waits for a reload (`SIGHUP`
with a fresh IP list), as it did before.

Builds older than this feature do not know the flag and refuse to start with it.
The capability probe does not report it, so a supervisor that passes the flag
should check the version first.
