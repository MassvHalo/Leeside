# Passive fingerprint tap (7a): design note and what landed

As of 2026-10-31. Source: `../../docs/actor-identity.md` section 7, which
shipped the columns `ja4`, `ja4t`, `h2_fp` as contract only, and the review
notes of 2026-10-31 (the go-ahead with answers; the race and privacy
additions; the curated-list rule for the mismatch flag). The code is
`src/tap/`, the subcommand `leesided tap`, the unit
`leeside-sample/deploy/systemd/leesided-tap.service`.

## What it is

A sniffer on the host watches the web ports arrive, computes JA4 (TLS
ClientHello) and JA4T (TCP SYN) per connection, and hands them to leesided
over a third datagram socket, `fp.sock`. leesided joins them to turns by
connection and time and fills the two columns at ingest, or a little later
when the event beat the tap's datagram. Nothing sits on the request path:
no patched nginx, no proxy of our own, no header a client could forge. The
package's `X-Leeside-*` path from section 7 stays as the contract for an
edge that can inject headers; the two coexist, and a trusted-proxy value on
the event is never overwritten.

Why these two values matter: a client forges any HTTP header for free, but
its TLS and TCP stacks are what they are. A `ua_class = chromium` turn whose
ClientHello is Python's is the mismatch the brief's `ua_vs_ja4_mismatch`
flag names.

## What it sees and what it cannot

- **JA4**: the ClientHello is cleartext, before any key exchange, so the
  tap reads it whole: version, ciphers, extensions, ALPN, SNI presence.
  Rules per FoxIO's `technical_details/JA4.md`; the spec's worked example
  is a unit test, and two captured hellos (curl, Python urllib) are pinned
  against an independent reading of the same bytes.
- **JA4T**: window size, option kinds in order, MSS and window scale from
  the SYN, as `64240_2-1-3-1-1-4_1460_8`. FoxIO publishes values for JA4T
  but no text spec; the shape here follows the published values, with `00`
  for a part the SYN did not carry. Captured on port 80 too, so a
  plain-HTTP or redirect hit has a JA4T and no JA4.
- **H2 (`h2_fp`)**: the HTTP/2 SETTINGS frame is inside TLS. A passive tap
  cannot see it; `h2_fp` stays null until nginx produces it.
- **Behind a CDN** the tap would fingerprint the CDN's stack, not the
  client's. The DNS record is grey-clouded today, so nginx sees real
  clients; if that ever changes the tap must be turned off and the edge's
  header used instead.

## The join

The event carries `remote_port`, added in step 2 for exactly this kind of
join. A connection is `(client ip, client port)`; the ClientHello arrives
before the HTTP request, the request before the response, the event after
the response, so in the usual order the fingerprint is already in the map
when the event arrives.

- Key: `HMAC(conn, ip:port)` with the resolver's hasher, so the map holds
  no address.
- Entry: `syn_ts`, `close_ts`, `last`, `tls` (is a ClientHello expected on
  this port), `ja4`, `ja4t`. Keep-alive means many turns per connection,
  all with the same values; that is correct, the stack did not change.
- Time: a turn joins the connection whose `[syn_ts − 1 s, close_ts + 30 s]`
  holds its `ts_ms`, newest SYN first. That is what makes port reuse behind
  a NAT harmless: the same `(ip, port)` a minute later is a new entry with
  its own interval.
- Lifetime: SYN until FIN or RST plus 30 s grace, 5 min idle cap, 65 536
  entries with oldest-first eviction. Swept with the 60 s sweep.
- **The race.** Both the event and the tap's datagram ride datagrams, and
  the event can win. A turn whose join finds nothing (or finds a connection
  that has no ClientHello yet) is deferred: leesided keeps `turn_id`,
  `ts_ms`, the UA class and which columns are missing, for 60 s. When the
  datagram arrives the stored row is updated in place (`coalesce` on the
  two columns, `json_insert` for the flag). After 60 s the columns stay
  null and `missed` counts it. A connection the tap marked `tls: false`
  (port 80) ends the wait for `ja4` at once.
- An event with a `remote_port` the map does not know counts as `unknown`.
  On the `direct` path that should stay near zero; on a `forwarded` path it
  will be 100 %, since the port is the proxy's.

## Privacy

The tap sees raw addresses. It sends `(ip, port)` over `fp.sock` exactly
as the package sends `ip` on `events.sock` today, under the same "ip over
the socket only" exception in the brief, and leesided hashes on receipt:
the connection key is a keyed hash, the entry holds fingerprints and
timestamps, and nothing raw is written anywhere. `ja4` and `ja4t` are stack
fingerprints shared by every copy of a browser or library version and are
stored in clear, as the brief specifies, like `ua_class`.

## Process and privilege

Capturing needs `CAP_NET_RAW`. leesided itself should not hold it, so the
tap is a separate process: the `leesided tap` subcommand of the same binary
(one build, one crate), started by `leesided-tap.service` as www-data with
`AmbientCapabilities=CAP_NET_RAW`, after `leesided.service`. The name
`leeside-tap` belonged to the package's stand-in for leesided and is gone;
this one is `leesided-tap`, daemon side.

Capture is an `AF_PACKET` socket in cooked mode (`SOCK_DGRAM`), so loopback
and Ethernet frames look the same and no libpcap is needed on the box; the
process reads only inbound packets and filters to the configured ports in
user space. A kernel-side BPF filter is the first optimisation if a busy
host ever shows the tap in `top`. SYNs give JA4T; the first bytes on a TLS
port are buffered per half-open connection (10 000 at most, oldest dropped,
16 KB each) until a ClientHello parses or the bytes turn out not to be one;
FIN or RST closes. Interface: `LEESIDED_TAP_IFACE`, default the interface
of the IPv4 default route from `/proc/net/route`; `lo` for the e2e. Ports:
`LEESIDED_TAP_PORTS` (80,443) and `LEESIDED_TAP_TLS_PORTS` (443).
`leesided tap --probe` says whether the process may capture, which the e2e
uses to run or skip its tap act.

One datagram per finding, up to three per connection:

```json
{"v":1,"ts_ms":1761900000123,"ip":"203.0.113.7","port":51234,"ja4t":"65535_2-4-8-1-3_1460_7","tls":true}
{"v":1,"ts_ms":1761900000131,"ip":"203.0.113.7","port":51234,"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"}
{"v":1,"ts_ms":1761900004000,"ip":"203.0.113.7","port":51234,"close":true}
```

## leesided side

- `fp.sock` next to the other two, same mode and group. `Engine::fingerprint`
  hashes the key, updates the connection map, and emits the late fills.
- `ingest` looks the connection up before resolution, so the tap's JA4 also
  feeds the weak `ja4+asn` binding from `docs/actors.md` (still weak, never
  merges). A deferred fill updates the row only; the binding is not
  back-filled.
- `ua_vs_ja4_mismatch`: no heuristic. `data/ja4-classes.json` maps JA4 to
  `browser`, `library` or `unknown`; the flag fires only for a known library
  JA4 under a browser `ua_class`, at ingest or on the late fill. The file is
  seeded from FoxIO's sample mapping (`ja4plus-mapping.csv`, six entries);
  `bin/ja4-classes.py` converts that CSV shape, or a ja4db export with the
  same columns, into the file. ja4db.com itself redirects to a
  script-rendered page and answered 404 on the API path tried; when an
  export is in hand, run the script and point `LEESIDED_JA4_CLASSES` at the
  result. Unknown is the default and never flags.
- `/health` gains `tap: {messages, bad_message, matched, deferred,
  filled_late, missed, unknown, connections, pending}` and `ja4_classes`.
- Features v3, when there is data to look at: `cluster_actors_ja4_asn`,
  `ja4_asn_agreement`, `ja4_class_mismatch_rate`. Not before: the vector
  only changes with a version bump and a reason.

## Licence

JA4 is BSD-3. JA4T is under the FoxIO License 1.1, which permits internal
business use that does not monetise the fingerprinting itself and excludes
offering it as a hosted service; read it before this ships in anything
sold.

## Tests

- Unit (`src/tap/`): the spec's worked example and ALPN table; GREASE; two
  captured hellos, whole and split across segments; plain HTTP is `NotTls`;
  JA4T for Linux- and Windows-shaped SYNs and absent parts; the capture
  state machine over hand-built IPv4 and IPv6 packets (SYN, hello in two
  segments, FIN, plain port, SYN-ACK ignored); the connection map (join by
  time across port reuse, deferred fill, `tls: false` ending a wait, sweep).
- Integration: SYN and hello datagrams then the event fill both columns and
  the unknown port stays null and is `missed` after 60 s; the event first
  and the datagrams after fill the stored row and add the flag through
  `json_insert`; a trusted-proxy `ja4` on the event is kept while `ja4t`
  comes from the tap; a Python JA4 under a Chromium UA flags at ingest; a
  bad datagram counts; no raw address reaches the store.
- End to end (`bin/e2e.sh`): a private nginx with a self-signed certificate
  and php-fpm on 18443 (so `REMOTE_PORT` is the client's), the tap on `lo`,
  one curl and one Python request, both turns carrying distinct `ja4`
  values and a `ja4t`. Runs when the binary may capture, else prints the
  `setcap` line and skips.
