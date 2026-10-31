# Actor resolution: design note

As of 2026-10-31. Source: `../../docs/actor-identity.md` section 8 and the
review notes of 2026-10-31. This is the design for leesided's `actors`
module; code follows the go-ahead on this note. The Windside brief depends
on `actor_id` existing per turn, so it waits for this.

## What it does

Input: v2 turns, each carrying identifiers the package recorded and never
resolved: `principal`, `session_key`, `credential_hash` with its status,
`tag_id` with its status, `peer_key`, `ip_hash`, `net_hash`, `ua_hash`,
`shape_hash`, later `ja4` and `asn`.

Output: one `actor_id` per turn, written on the turn row at ingest; per-actor
windows the rules and Windside read through a new `actor` scope; a bindings
table that says which identifier values currently belong to which actor; a
merges table that says which actor ids have folded into which.

Nothing here touches the request path's budget: resolution runs at ingest,
after the event arrives. The check path only does lookups in the in-memory
bindings map.

## Identifiers, strong and weak

| Kind | Value | Strength | Level | TTL | Counts when |
| --- | --- | --- | --- | --- | --- |
| `principal` | the hashed auth id | strong | 1 (highest) | 365 d | present (not `anon`) |
| `credential` | `credential_hash` | strong | 1 | 90 d | `credential_status = verified` only |
| `session` | `session_key` | strong | 2 | 7 d | present and distinct from `peer_key` (the fallback is not a session) |
| `tag` | `tag_id` | strong | 3 | 365 d | `tag_status` is `valid` or `issued` |
| `net` | `net_hash` | weak | 4 | 6 h | present |
| `ja4+asn` | `ja4` with `asn` | weak | 4 | 6 h | both present; `ja4` alone when `asn` is null |
| `shape+net` | `shape_hash` with `net_hash` | weak | 4 | 6 h | both present |
| `ua+net` | `ua_hash` with `net_hash` | weak | 4 | 6 h | both present |

`principal` and `credential` share a level because they never co-occur on
one surface: a principal is the web identity, a verified credential the
machine identity. An unverified or rejected credential binds nothing; it is
a fact on the turn and a feature, not an identity. `peer_key` is not an
identifier at all here: it is already the rules' peer scope, and as an
identity it would be the mistake the brief warns about.

## The partition rule

Precedence is a partition rule, not a ranking. **A higher-level identifier
never merges through a lower one.** Concretely, for a turn carrying
identifiers at several levels:

1. Take the highest level present that has a live binding. That binding's
   actor is the turn's actor. If no present identifier has a live binding,
   the turn opens a new actor.
2. Every present identifier at a lower level is re-pointed to that actor
   from this turn on, whatever it was bound to before. Nothing is merged by
   this step: the previous actor keeps its history.
3. Two actors merge only when a turn links them through an identifier and
   **neither actor has a live binding at a higher level that the other
   contradicts**. Anonymous actor B (a tag, a session, no principal) linked
   to anonymous actor A merges into A; the browser's anonymous history
   joins. Actor B with principal Q linked by a shared tag to actor A with
   principal P does not merge: the tag re-points to the current actor and
   both histories stand (shared browser, logout then login).
4. The same applies on the machine surfaces: two verified credentials under
   one `net` or `shape` cluster are two actors; weak kinds never merge
   anything (below).

Worked cases the tests encode:

- Anonymous browsing opens actor A from tag T and session S1. S1 expires;
  S2 arrives with T: T is live, S2 binds to A. The user logs in: P has no
  binding, T and S2 point at A, A has no principal: P binds to A. A is now
  P's actor with its anonymous prefix.
- P logs in on a second device: P is live (level 1), S3 is new: S3 binds to
  A. One actor, two sessions.
- On the first device Q logs in: Q has no binding; the regenerated session
  S4 has none; T is bound to A, and A holds P at level 1, which contradicts
  Q. Rule 3 forbids the merge, rule 1 opens actor C for Q, rule 2 re-points
  T to C from this turn on. A keeps everything up to the logout.
- Two anonymous actors A (tag T, from a cookie-less burst that then got a
  tag) and B (session S5): a turn carries T and S5; neither holds a level-1
  binding; they merge, the older id canonical.

## Ids and merges keep history

Actor ids are deterministic: `actor_id = HMAC(actor, first turn's peer_key
|| ts_us)` under the install key, 16 hex. The same first turn always opens
the same actor, which is what the restart determinism test needs.

When A and B merge, the **older actor id stays canonical** and
`actor_merges(merged_id, into_id, at_ts_us, via_kind)` records B → A.
Turns keep the `actor_id` they were ingested with; **history is never
rewritten**. Everything downstream resolves through the canonical id:
`canonical(actor_id)` follows `merged_into` to the root (path-compressed in
memory), and features, labels, scores and the UI key on the canonical id.
A query for an actor's turns is `actor_id IN (id, every id merged into it)`.

## Bindings expire

`actor_bindings(kind, value, actor_id, first_seen, last_seen, expires_at)`
with `expires_at = last_seen + ttl(kind)`, refreshed on every turn that
carries the identifier. **An expired binding does not link**: the lookup in
step 1 ignores it, and the value binds afresh to whichever actor the turn
resolves to. Expired rows are swept with the 60 s sweep and kept in the
table for 30 days for the UI, then deleted.

## Weak edges are features, never merges

`net`, `ja4+asn`, `shape+net`, `ua+net` never take part in rules 1 to 3.
They are bound like any identifier (so the UI can show "other actors on
this network") and they feed two things only:

- Cluster features on the actor window, for Windside: `cluster_actors_net`
  (distinct actors sharing the actor's current `net_hash` within the TTL),
  `cluster_actors_ja4_asn`, `ja4_asn_agreement` (does this actor's TLS stack
  match the others on its network), `shape_cluster_size`.
- The cross-request signals from the brief that need a cluster:
  `tag_dropped` (an actor got `issued` and a later turn from the same weak
  cluster arrives `absent`), `credential_moved` (one credential seen from a
  new `ja4` or `asn`, or two ASNs inside an hour).

A weak cluster is a query over bindings, not an entity.

## What the rules and the check path see

- `Windows` gains an `actors` map; `scope: actor` joins the rule grammar and
  the sticky decisions. A `block` on an actor holds for every identifier
  bound to it.
- The probe has no `tag_id`, so at probe time the actor is looked up from
  `session_key`, then `principal`, then a verified `credential_hash`, in the
  in-memory bindings map. A probe whose identifiers have no live binding has
  no actor window (empty, like an anonymous principal scope). The event that
  follows resolves fully and may open the actor.
- `features.rs` moves to v2: the v1 vector plus the cluster features above,
  computed on the actor window; `surface` enters as four indicators.

## Rebuild on start

The bindings and merges tables are loaded first. Then the last 24 h of
`turns` replay through the resolver in `ts_us` order **without writing**:
they already carry `actor_id`, so the replay only refills the windows and
confirms bindings. The determinism test: ingest a fixed sequence of turns
into an empty store, record every `actor_id`; restart; ingest the same
sequence again into another empty store; the assignments are identical,
and a store that was restarted mid-sequence ends with the same assignments
as one that was not.

## Enrichment contract

`asn` and `country` are columns on `turns` (`asn` exists since 0002,
`country` arrives with this migration), filled by a separate enrichment
step at ingest from `GeoLite2-ASN.mmdb` and `GeoLite2-Country.mmdb` via the
`maxminddb` crate (paths from `LEESIDED_GEOIP_ASN`, `LEESIDED_GEOIP_COUNTRY`;
files refreshed weekly by `geoipupdate` from the unit's licence key). With
a file missing the daemon logs once at start and leaves the column null.
**No resolution path requires them**: `ja4+asn` degrades to `ja4` alone,
`country` is a feature for the Accept-Language check and nothing else. The
first cut lands with both null and clusters on `net_hash`.

## Schema (migration 0005)

```sql
CREATE TABLE actors (
  id          TEXT PRIMARY KEY,      -- 16 hex, deterministic from the first turn
  opened_us   INTEGER NOT NULL,
  last_us     INTEGER NOT NULL,
  merged_into TEXT,                  -- null when canonical
  turns       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE actor_bindings (
  kind        TEXT NOT NULL,         -- principal | credential | session | tag | net | ja4_asn | shape_net | ua_net
  value       TEXT NOT NULL,         -- the 16-hex hash, or "a:b" for pairs
  actor_id    TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (kind, value)
);
CREATE INDEX actor_bindings_actor ON actor_bindings (actor_id);
CREATE INDEX actor_bindings_expires ON actor_bindings (expires_at);
CREATE TABLE actor_merges (
  merged_id   TEXT PRIMARY KEY,
  into_id     TEXT NOT NULL,
  at_us       INTEGER NOT NULL,
  via_kind    TEXT NOT NULL
);
ALTER TABLE turns ADD COLUMN actor_id TEXT;
ALTER TABLE turns ADD COLUMN country TEXT;
CREATE INDEX turns_actor ON turns (actor_id, ts_us);
```

In memory: `DashMap<(Kind, u64), Binding>` for the strong kinds (the probe
path reads it), the same for weak kinds (ingest only), `DashMap<u64, Actor>`
with `merged_into` for canonicalisation, and the `actors` windows map.

## API

`GET /actors/{id}`: canonical id, merged ids, live bindings by kind (hashes
only), recent turns, open decisions. `GET /turns` gains `actor_id`.
`POST /actors/{id}/split` is deliberately absent in v1: a wrong merge is
corrected by expiry and the partition rule, not by hand.

## Tests

- Partition rule: each worked case above, table-driven over a sequence of
  turns, asserting the `actor_id` of every turn and the bindings after.
- Merge keeps ids stable: the older id is canonical, `actor_merges` has the
  row, early turns keep their original id, `canonical()` resolves chains.
- Expiry: a session binding past its TTL does not link; the same value binds
  afresh; a tag within its year does.
- Weak kinds never merge: two actors on one `net_hash` with the same shape
  stay two; the cluster features count two.
- Machine surfaces: two verified credentials on one `net` are two actors;
  an unverified credential binds nothing; a verified one binds at level 1.
- Determinism across restart, as above.
- Enrichment: with the mmdb files absent, ingest succeeds, `asn` and
  `country` are null, one warning at start; with files present (a fixture
  mmdb in `tests/`), the columns are filled and `ja4+asn` forms.
- Check path: a probe for a bound session reads the actor window; a block
  on the actor answers a probe for a different session bound to it.

## Open choices for you

1. TTLs as tabled (principal and tag a year, credential 90 days, session 7
   days, weak kinds 6 hours). Say if any should differ.
2. The probe lacks `tag_id`. Adding it is a package change (the tag is read
   before the gate, so it is available); without it, a returning anonymous
   browser is actor-less at probe time until its first event lands. I'd
   leave it out of v1 and add it if the gap shows in data.
3. Deterministic ids from the first turn mean an actor opened by a replayed
   event gets the same id; a collision needs two turns with the same
   `peer_key` and `ts_us`, which the join already assumes cannot happen.

Order of work once approved: migration and in-memory structures; the
resolver with the partition tests; wiring into ingest and the check path
(actor scope, sticky); the enrichment step behind feature-flagged file
paths; `features` v2; API; the restart determinism test. The passive tap
(7a) is a separate short note after this lands.
