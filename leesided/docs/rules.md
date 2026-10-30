# leesided rules

As of 2026-10-29. Part 1 is the rule design: the rule document, three example
rules and the SQLite tables. Part 2 is the implementation plan. Both sessions
(A: the rules module, B: wiring) read this one file. A change to the rule
document format is written here before any code changes.

## Part 1: the rule design

### The rule document

One JSON object per rule. This is what `rules/install/*.json` holds, what
`POST /rules` accepts, what Spark proposes, and what `GET /rules/export`
dumps. Unknown fields are rejected at every level.

```json
{
  "id": "portal-otp-burst",
  "note": "Five OTP failures within two minutes from one session",
  "mode": "enforce",
  "action": "rate_limit",
  "retry_after_s": 30,
  "match": { "route": ["portal.login"], "verb": ["POST"], "principal": "any" },
  "when": {
    "scope": "session",
    "window_s": 120,
    "count": { "auth_event": ["login_failed"] },
    "gte": 5
  },
  "expires_at": null,
  "origin": { "kind": "install" }
}
```

| Field | Type | Rule |
| --- | --- | --- |
| `id` | string | `^[a-z0-9][a-z0-9-]{2,63}$`; the primary key, never changes across versions |
| `note` | string | 1..=200 chars; what the rule is for, shown in the UI and in the verdict trace |
| `mode` | `monitor` \| `shadow` \| `enforce` | the rule's own ceiling; the effective mode is `min(global, rule)` |
| `action` | `log` \| `watch` \| `rate_limit` \| `challenge` \| `block` | what the verdict carries; `allow` is never written in a rule, it is the absence of a hit |
| `retry_after_s` | int | 1..=86400; required with `rate_limit`, rejected with any other action; also the stickiness of that decision |
| `block_min` | int, optional | 1..=1440; minutes a `block` sticks to the session; rejected with any other action; absent = 1440 (the 24 h conversation cap) |
| `match` | object | which probes the rule is evaluated for (below) |
| `when` | condition or `{ "all": [c1, c2, c3] }`, optional | what the window must show; absent means the rule fires on every matching probe (a per-route `log` or `watch`) |
| `expires_at` | unix seconds, optional | after this the rule evaluates as shadow until the sweep writes that downgrade; must be in the future at write time |
| `origin` | `{ "kind", "incident"?, "model"? }` | `kind` is `install` \| `operator` \| `spark`; `incident` is the incident id for a Spark proposal; `model` the model name that wrote it |

`match`:

| Field | Type | Rule |
| --- | --- | --- |
| `route` | list of route templates | 1..=16 entries, exact match on the probe's `route`; `"*"` means any route and is allowed only alone |
| `verb` | list of `GET` `POST` `PUT` `PATCH` `DELETE` `HEAD` `OPTIONS` | 1..=8 entries |
| `principal` | `any` \| `anon` \| `authenticated` | the probe's `principal` is `anon` or a 16-hex hash |

A condition. Exactly one of `count`, `distinct`, `sequence`:

| Field | Type | Rule |
| --- | --- | --- |
| `scope` | `session` (default) \| `peer` \| `principal` | which window to look at; `principal` on an `anon` probe never matches |
| `window_s` | int, optional | 1..=86400; turns older than `probe.ts - window_s` are ignored; absent means the whole held window (64 turns) |
| `count` | turn filter | number of earlier turns in the window matching the filter |
| `gte`, `lte` | int | only with `count`, at least one of them; `lte: 0` means "no such turn" |
| `distinct` | `{ "field": "bound_id" \| "route", "model"? }` | number of distinct values across the window; `model` narrows `bound_id` to one model basename; takes `gte` only, 1..=64 (the window size); without `model`, two models sharing an id hash count as two values |
| `sequence` | list of 2..=8 route templates | the probe's route is the last entry and the newest k-1 turns in the session match the rest, in order; rejects `scope` and `window_s` |

A turn filter. Every field optional, OR inside a list, AND across fields:

| Field | Type |
| --- | --- |
| `route` | list of route templates |
| `verb` | list of verbs |
| `status` | list of ints 0..=599 or the strings `"4xx"`, `"5xx"` |
| `validation_failed` | `true` (failed on any field) or a list of field names (failed on any of them) |
| `exception` | list of exception basenames |
| `auth_event` | list of auth event names |
| `req_shape` | list of exact shape strings |
| `bound_model` | list of model basenames |

### What a rule can see

The check for turn N runs before turn N is handled. The window holds turns
1..N-1; the current turn is known only from the probe (`verb`, `route`,
`principal`, `ts`, the three keys). So `count` and `distinct` describe the
past, `match` describes the present, and `sequence` joins them.

### Three example rules

The install set. Each uses one condition kind; the tests round-trip all three
through the schema and `POST /rules/validate`.

```json
{
  "id": "portal-otp-burst",
  "note": "Five OTP failures within two minutes from one session",
  "mode": "enforce",
  "action": "rate_limit",
  "retry_after_s": 30,
  "match": { "route": ["portal.login"], "verb": ["POST"], "principal": "any" },
  "when": { "scope": "session", "window_s": 120,
            "count": { "auth_event": ["login_failed"] }, "gte": 5 },
  "origin": { "kind": "install" }
}
```

```json
{
  "id": "venue-enumeration",
  "note": "One peer walking venue ids: five distinct ids within ten minutes",
  "mode": "shadow",
  "action": "block",
  "block_min": 10,
  "match": { "route": ["venues.show", "api.venues.visit"], "verb": ["GET", "POST"], "principal": "any" },
  "when": { "all": [
    { "scope": "peer", "window_s": 600,
      "distinct": { "field": "bound_id", "model": "Venue" }, "gte": 5 },
    { "scope": "peer", "window_s": 600,
      "count": { "exception": ["ModelNotFoundException"] }, "gte": 8 }
  ] },
  "origin": { "kind": "install" }
}
```

```json
{
  "id": "visit-straight-to-login",
  "note": "A visit posted right after a login with nothing viewed in between",
  "mode": "monitor",
  "action": "challenge",
  "match": { "route": ["api.venues.visit"], "verb": ["POST"], "principal": "any" },
  "when": { "sequence": ["portal.login", "api.venues.visit"] },
  "origin": { "kind": "install" }
}
```

### The verdict

What the check socket answers, as the brief defines it, plus two tracing
fields the Laravel side ignores:

```json
{"action":"rate_limit","mode":"enforce","rule":"portal-otp-burst","retry_after":30,
 "generation":7,"hash":"3f1c…"}
```

`rule` is the id of the winning rule, absent on `allow`. `retry_after` is
present only for `rate_limit`.

### The tables

```sql
-- one row per rule id; body is the rule document as written, version bumps on every write
CREATE TABLE rules (
  id          TEXT PRIMARY KEY,
  version     INTEGER NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('proposed', 'active', 'retired')),
  mode        TEXT NOT NULL,            -- denormalised from body for listing
  action      TEXT NOT NULL,            -- denormalised from body for listing
  origin_kind TEXT NOT NULL,            -- install | operator | spark
  body        TEXT NOT NULL,            -- JSON rule document
  expires_at  INTEGER,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- append-only history; every write to rules inserts here first
CREATE TABLE rule_versions (
  id          TEXT NOT NULL,
  version     INTEGER NOT NULL,
  state       TEXT NOT NULL,
  body        TEXT NOT NULL,
  changed_by  TEXT NOT NULL,            -- operator | spark | system | install
  reason      TEXT,
  changed_at  INTEGER NOT NULL,
  PRIMARY KEY (id, version)
);

-- sticky verdicts: a block on a session, a rate_limit on the condition's scope key
CREATE TABLE decisions (
  scope        TEXT NOT NULL CHECK (scope IN ('session', 'peer', 'principal')),
  key          TEXT NOT NULL,           -- the 16-hex hash
  action       TEXT NOT NULL,           -- rate_limit | block
  mode         TEXT NOT NULL,           -- effective mode when decided
  rule         TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (scope, key)
);
CREATE INDEX decisions_expires ON decisions (expires_at);

-- hourly counters per rule version and effective mode
CREATE TABLE rule_stats (
  rule         TEXT NOT NULL,
  version      INTEGER NOT NULL,
  hour         INTEGER NOT NULL,        -- unix seconds / 3600
  mode         TEXT NOT NULL,           -- effective mode at the time
  matched      INTEGER NOT NULL DEFAULT 0,   -- conditions held
  would_act    INTEGER NOT NULL DEFAULT 0,   -- matched and action >= rate_limit
  acted        INTEGER NOT NULL DEFAULT 0,   -- would_act and mode == enforce and not proposed
  PRIMARY KEY (rule, version, hour, mode)
);
```

The event tables the rules join to:

```sql
-- one row per ingested event, schema v1 fields as columns, shapes and hashes only
CREATE TABLE turns (
  session_key       TEXT NOT NULL,
  ts_us             INTEGER NOT NULL,  -- round(ts * 1e6); the join key with the check record
  ts                REAL NOT NULL,
  peer_key          TEXT NOT NULL,
  principal         TEXT NOT NULL,
  verb              TEXT NOT NULL,
  route             TEXT NOT NULL,
  status            INTEGER NOT NULL,
  latency_ms        REAL NOT NULL,
  bytes_in          INTEGER NOT NULL,
  bytes_out         INTEGER NOT NULL,
  req_shape         TEXT NOT NULL,
  resp_shape        TEXT NOT NULL,
  bound             TEXT NOT NULL,      -- JSON as received
  validation_failed TEXT,               -- JSON list or NULL
  exception         TEXT,
  auth_event        TEXT,
  gate              TEXT,               -- JSON as received, NULL = no verdict reached the app
  ua_hash           TEXT NOT NULL,
  dropped_since_last INTEGER NOT NULL,
  rules_matched     TEXT,               -- JSON list of {rule, version, action, mode, proposed|sticky}, from the check record
  verdict           TEXT,               -- the action answered, from the check record
  ruleset_hash      BLOB,               -- the set that judged it
  PRIMARY KEY (session_key, ts_us)
);
CREATE INDEX turns_peer ON turns (peer_key, ts_us);
CREATE INDEX turns_principal ON turns (principal, ts_us);
CREATE INDEX turns_ts ON turns (ts_us);

-- one feature vector per ingested turn: the Windside training corpus.
-- vector is a JSON array of f32 in the order features::NAMES gives for that version
CREATE TABLE features (
  session_key TEXT NOT NULL,
  ts_us       INTEGER NOT NULL,
  version     INTEGER NOT NULL,
  vector      TEXT NOT NULL,            -- "values" is reserved in SQLite
  PRIMARY KEY (session_key, ts_us)
);

-- one row per closed session window
CREATE TABLE conversations (
  session_key TEXT PRIMARY KEY,
  peer_key    TEXT NOT NULL,
  principal   TEXT NOT NULL,            -- last non-anon seen, else anon
  opened_ts   REAL NOT NULL,
  closed_ts   REAL NOT NULL,
  turns       INTEGER NOT NULL,
  errors_4xx  INTEGER NOT NULL,
  errors_5xx  INTEGER NOT NULL,
  routes      INTEGER NOT NULL,         -- distinct
  flags       INTEGER NOT NULL          -- bit 0 watch
);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- 'mode'
CREATE TABLE schema_version (version INTEGER NOT NULL);
```

Check records are not a table of their own: a `CheckRecord` is an `UPDATE
turns SET rules_matched, verdict, ruleset_hash WHERE peer_key = ? AND ts_us
= ?`, held in a small pending map if the turn has not landed yet (the event
arrives after the check) and applied when it does. Pending records older
than 60 s are dropped and counted as `check.unjoined`.

**The join key is `(peer_key, ts_us)`, not `(session_key, ts)`.** Two
reasons, both found in the first end-to-end run. Laravel regenerates the
session id on login (and logout), so the probe of a login turn carries the
old session key and its event the new one; the peer key is the same on both
because it is computed per request from ip and user agent. And `ts_us`
(microseconds, integer) makes the equality exact where a float compare would
depend on serialisation. `turns` still keys on `(session_key, ts_us)`; the
join uses the `turns_peer` index. A consequence worth knowing: the turns
before a login sit in the old session's window and the turns after in the
new one, so a session-scope `count` does not see across a successful login.
Peer scope does.

**Turns with no check at all.** A 404 from route-model binding is thrown
before `GateTurn` runs (the gate sits after `SubstituteBindings`), so those
turns have `gate = null` and no check record. They are not fail-opens; the
fail-open count is `gate = null` where a check record *exists*.

## Part 2: implementation

### Where it lives

The rule engine is one module with no IO of its own; the check server, ingest
and store call into it. That split is what makes it testable and
benchmarkable without sockets or SQLite.

```text
leesided/src/
  rules/
    model.rs      Rule, Match, When, Condition, TurnFilter: serde types, deny_unknown_fields, validate()
    schema.rs     JSON Schema export (schemars) for Spark's prompt and the UI
    symbols.rs    string interner: route templates, exceptions, auth events, shapes, model names -> Sym(u32)
    compile.rs    Rule -> Compiled; Vec<Rule> -> RuleSet (route index + wildcard list)
    eval.rs       RuleSet x Probe x Windows -> hits; severity pick; no allocation on the hot path
    windows.rs    per-session, per-peer, per-principal ring buffers of TurnSummary
    decisions.rs  sticky outcomes: in-memory mirror + write-behind to SQLite
    stats.rs      hourly counters, flushed by the writer
    service.rs    RulesService: load/reload (ArcSwap<RuleSet>), accept/edit/retire, global mode
  check/          UDS stream server; one JSON line in, one out; calls rules::eval
  ingest/         UDS datagram server; validates events, feeds windows, writes turns
  store/          SQLite: migrations, single writer thread, read connection, StoreOp enum
  api/            axum on 127.0.0.1: /rules, /mode, /health, ...
```

Crates: tokio, axum, rusqlite (bundled, WAL), serde, serde_json, schemars,
arc-swap, dashmap, smallvec, parking_lot, tracing, thiserror; criterion and
proptest as dev-dependencies. Nothing else without a reason stated in the
session summary.

### Types and validation

The serde structs mirror the rule document one to one, with
`#[serde(deny_unknown_fields)]` on every struct so a Spark-emitted rule with
an invented field is rejected rather than half-read. `schemars::JsonSchema`
is derived on the same structs, so `GET /rules/schema` and `leesided rules
schema` print the exact grammar the engine accepts. That output goes into
Spark's prompt; nobody hand-writes a second copy.

```rust
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,                                     // ^[a-z0-9][a-z0-9-]{2,63}$
    pub note: String,                                   // 1..=200 chars
    pub mode: Mode,                                     // monitor | shadow | enforce
    pub action: Action,                                 // log | watch | rate_limit | challenge | block
    #[serde(default)] pub retry_after_s: Option<u32>,   // 1..=86400; only with rate_limit
    #[serde(default)] pub block_min: Option<u32>,       // 1..=1440; only with block
    #[serde(rename = "match")] pub matcher: Match,
    #[serde(default)] pub when: Option<When>,
    #[serde(default)] pub expires_at: Option<i64>,      // unix seconds
    pub origin: Origin,                                 // { kind, incident?, model? }
}
pub struct Match { pub route: Vec<String>, pub verb: Vec<Verb>, pub principal: PrincipalKind }
#[serde(untagged)]
pub enum When { One(Condition), All { all: Vec<Condition> } }   // all: 1..=3
pub struct Condition {
    #[serde(default)] pub scope: Scope,                 // session (default) | peer | principal
    #[serde(default)] pub window_s: Option<u32>,        // 1..=86400; None = whole conversation
    #[serde(default)] pub count: Option<TurnFilter>,
    #[serde(default)] pub gte: Option<u32>,
    #[serde(default)] pub lte: Option<u32>,
    #[serde(default)] pub distinct: Option<Distinct>,   // { field: bound_id | route, model? }
    #[serde(default)] pub sequence: Option<Vec<String>>, // 2..=8 route templates, ends at the current turn
}
pub struct TurnFilter {   // every field optional; OR inside a list, AND across fields
    route, verb, status /* 0..=599 or "4xx" | "5xx" */, validation_failed /* true | [field] */,
    exception, auth_event, req_shape, bound_model
}
```

`Rule::validate()` runs after deserialisation and again on every load. It
checks: exactly one of `count`, `distinct`, `sequence` per condition; `gte`
or `lte` only with `count`, at least one of them, `gte <= lte`; `distinct`
takes `gte` only, 1..=64; `sequence` rejects `scope`, `window_s`, `gte` and
`lte`, and must end with a route in `match.route` unless that is `"*"`
(otherwise the rule could never fire); route lists 1..=16 with `"*"` allowed
only alone; verb lists 1..=8 without duplicates; filter lists 1..=16; status
codes 0..=599; `validation_failed: false` rejected; `retry_after_s` required
with `rate_limit` and rejected otherwise; `expires_at` in the future at
write time. Errors come back as `Vec<ValidationError { path, message }>` so
the UI can point at the field. `Condition.scope` is `Option<Scope>` in the
struct so "given" and "defaulted" can be told apart for the `sequence`
check; `scope()` resolves the default.

Untagged `When` has one cost: an unknown field inside a condition is still
rejected, but the message is serde's "did not match any variant" rather than
the field name. The install set and operator rules go through
`POST /rules/validate` first, so the precise message matters less than the
rejection.

`Action` derives `Ord` as log < watch < rate_limit < challenge < block and
`Mode` as monitor < shadow < enforce. Eval relies on both orderings, so they
live on the types and have their own tests.

### Symbols and compiled rules

Strings on the hot path are interned once to `Sym(u32)`: route templates,
exception basenames, auth event names, `req_shape` strings, model names.
`Symbols` is append-only (`DashMap<Box<str>, Sym>` plus
`RwLock<Vec<Arc<str>>>`). Interning happens on ingest and on compile, never
on the check path: the check path calls `get()`, and an unknown route simply
matches only wildcard rules. The table is capped at 1 M entries; beyond that
new strings map to a `Sym::OVERFLOW` sentinel and a counter is bumped (shapes
are the only field that could grow without bound).

Compile turns a `Rule` into fixed-size pieces, allocated once:

```rust
struct Compiled {
    ix: u32,                        // index into RuleSet.rules and .meta
    verbs: u8,                      // bitmask over Verb
    principal: PrincipalKind,
    conds: SmallVec<[CCond; 3]>,
    action: Action, mode: Mode, retry_after_s: u32,
    block_ttl_s: u32,               // block_min * 60, default 86400
    expires_at: Option<i64>,
    proposed: bool,                 // evaluated for stats only, never the verdict
}
struct CCond { scope: Scope, window_ms: Option<u64>, test: CTest }
enum CTest {
    Count { f: CFilter, gte: Option<u32>, lte: Option<u32> },
    Distinct { field: DistinctField, model: Option<Sym>, gte: u32 },
    Sequence(SmallVec<[Sym; 8]>),
}
struct CFilter { routes: Option<SymSet>, verbs: Option<u8>, status: Option<StatusSet>,
                 validation: Option<ValSel>, exceptions: Option<SymSet>, auth: Option<SymSet>,
                 shapes: Option<SymSet>, bound_models: Option<SymSet> }
pub struct RuleSet {
    rules: Vec<Compiled>,
    meta: Vec<RuleMeta>,            // id, version, note, origin, for reporting
    by_route: HashMap<Sym, SmallVec<[u32; 4]>>,
    wildcard: SmallVec<[u32; 8]>,
    generation: u64,                // bumped on every reload within a process
    hash: [u8; 32],                 // sha256 over sorted "id:version" of loaded rules; stable across restarts
}
```

`SymSet` is a sorted `SmallVec<[Sym; 8]>` with binary search; `StatusSet` is
a 600-bit bitset (`[u64; 10]`). The whole `RuleSet` lives in an
`arc_swap::ArcSwap<RuleSet>`: the check path does one `load()` per probe, a
reload builds a new set and swaps the pointer, in-flight evaluations finish
on the old one. No lock on the hot path and no half-loaded set, ever.

**Reload is a function call, not a file watch.** leesided is the only writer
of its rules. A Spark proposal, an operator accept, an edit or a retire all
go through the writer thread, which acks, and the caller then runs
`RulesService::reload()`. Both `generation` and `hash` go on every check
record and into the UI header, so any verdict can be traced to the exact rule
set that produced it. `POST /rules/reload` exists for the rare manual case
and is idempotent.

**Proposed rules are compiled too**, with `proposed = true`: eval bumps their
stats (matched, would_act) but never lets them win the verdict. When an
operator opens a proposal it already shows what it would have done over the
hours since Spark wrote it, which is the evidence acceptance should rest on.

**Files only for the install set.** Hand-written rules live in the repo as
`rules/install/*.json`, imported at first start as active, shadow, origin
`install`, so they are git-tracked. SQLite remains the runtime truth;
`leesided rules export` dumps the active set as JSON for moving between
hosts.

### Conversation windows

Ingest keeps in memory exactly what a rule can ask about, nothing more:

```rust
struct TurnSummary {
    ts_ms: u64, route: Sym, verb: Verb, status: u16,
    validation_fields: SmallVec<[Sym; 4]>,   // empty = did not fail validation
    exception: Option<Sym>, auth_event: Option<Sym>, req_shape: Sym,
    bound: SmallVec<[(Sym, u32); 2]>,        // (model, id_hash parsed from the 8 hex)
}
struct Window { turns: VecDeque<TurnSummary> /* capped at 64, grows lazily */,
                opened_ms: u64, last_ms: u64, flags: u8 /* watch */,
                peer_key: u64, principal: Option<u64>,   // for the close summary
                total: u32, errors_4xx: u32, errors_5xx: u32 }
pub struct Windows {
    sessions:   DashMap<u64, Window>,        // session_key 16 hex -> u64
    peers:      DashMap<u64, Window>,
    principals: DashMap<u64, Window>,        // "anon" is never indexed here
}
```

Keys are the event's hashes parsed as integers, so a lookup hashes a u64, not
a string. 64 turns is the window; a `count` over a longer history is answered
from the 64 we hold and documented as such (anything needing more is a
Windside feature, not a rule). The ring is a `VecDeque` that grows as turns
arrive rather than a fixed 64-slot array, so the typical short session costs
a few hundred bytes; the running totals cover turns the ring has dropped. A
sweep every 60 s evicts sessions idle for 30 min or older than 24 h and emits
the conversation-close summary; peer and principal windows evict after 60 min
idle. Hard cap 200 k per map: a new key at the cap first evicts everything
idle more than 5 min, and if the map is still full the turn is not indexed
and a counter the UI can show is bumped (a true LRU over a `DashMap` would
cost more on ingest than the cap is worth). A restart loses the windows, and
that is accepted: counts rebuild within one window, and blocks survive
because decisions are persisted.

**The N-1 timing.** The check for turn N runs before turn N is handled; its
event arrives afterwards. So the window a check sees holds turns 1..N-1, and
the current turn is known only from the probe (verb, route, principal).
`sequence` therefore compares the probe's route plus the newest k-1 routes in
the window. The probe's `ts` equals the event's `ts` (both come from the
middleware's `TurnContext`), so `(session_key, ts)` is the join key between a
check record and its turn row.

### The check path

One connection, one probe, no allocation beyond the response line, and no
`await` between parse and write. Budget: eval p99 under 50 µs with 500 rules
loaded; round trip under 1 ms including the socket.

1. Read one line (cap 4 KB); `serde_json::from_slice::<Probe>`. A parse
   failure answers `allow` and bumps `check.bad_probe`.
2. Take `now_ms` and the global mode from an `AtomicU8`.
3. Sticky first: `decisions.get(session_key)`, then `peer_key`, then
   `principal` unless anon. A live `block` or `rate_limit` is the verdict
   immediately, mode downgraded to `min(global, decision.mode)`,
   `retry_after` recomputed from `expires_at`.
4. `let rs = ruleset.load();` `route_sym = symbols.get(&probe.route)`;
   candidates are `rs.by_route[route_sym]` (if present) followed by
   `rs.wildcard`.
5. Per candidate: an `expires_at` already passed means evaluate as shadow;
   verb bit; principal kind; then the conditions in order, fetching each
   scope's `Window` lazily at most once per probe and holding the `DashMap`
   read ref for the rest of the eval (a few microseconds; ingest writes to
   that shard wait that long). A scope whose key is absent (principal on an
   anon probe, or a key never seen) reads as an empty window, so `lte` holds
   and `gte`, `distinct` and `sequence` do not. `Count` scans newest to
   oldest, stops at the window edge, exits early once `gte` is met when there
   is no `lte`. `Distinct` fills a `SmallVec<[u64; 64]>` with dedupe and
   exits at `gte`. `Sequence` compares the probe's route, then the newest k-1
   turns.
6. Collect `Hit { ix, action, effective_mode, proposed, sticky }`. The
   verdict is the non-proposed hit with the highest `action`; ties go to the
   lowest `ix` (rules load sorted by `id`, so this is deterministic). No
   hits: `allow` with mode = global.
7. Stickiness: `block` inserts a decision on the session for `block_min`
   minutes (default the 24 h conversation cap); `rate_limit` inserts one on the first
   condition's `scope` key (`Hit.sticky`, session for a rule with no `when`;
   `None` when that key is absent, in which case nothing sticks) for
   `retry_after_s`. Insert into the mirror, then `StoreOp::DecisionUpsert`
   to the writer. `challenge`, `watch` and `log` are re-evaluated every turn.
8. `stats.bump(ix, hour, effective_mode, acted)` for every hit, proposed ones
   included, where `acted = effective_mode == enforce && action >=
   rate_limit`. Then `StoreOp::CheckRecord { session_key, ts, hits, verdict,
   generation, hash }`, so the turn row carries `rules_matched` and `verdict`
   once the event lands.
9. Serialise the `Verdict` into a reused buffer, write, close.

In monitor and shadow the verdict is still sent, with that mode; the Laravel
side records it on the event's `gate` field and changes nothing. leesided
later joins its `CheckRecord` to the event: a `gate == null` where a record
exists is a fail-open (a timeout or error on the PHP side) and is counted per
hour, because the claim that the middleware degrades to monitor by
construction rests on that number being visible in the UI.

### Store

SQLite in WAL mode with `synchronous = NORMAL`. One connection is owned by a
writer thread (a `std::thread`, not a tokio task, since
`rusqlite::Connection` is not `Sync`); a second read-only connection serves
the API and reloads. Everything that writes sends a `StoreOp` over a bounded
channel (capacity 10 k); when the channel is full the op is dropped and
counted rather than blocking the check path.

```rust
enum StoreOp {
    Turn(TurnRow), ConversationClose(Summary),
    CheckRecord { .. }, DecisionUpsert(Decision), DecisionDelete(Key),
    StatsFlush(Vec<StatRow>),
    RuleWrite { rule: Rule, state: State, changed_by: String, reason: Option<String>,
                ack: oneshot::Sender<Result<u32>> },
    ModeSet(Mode),
}
```

The writer drains whatever is in the channel into one transaction every
50 ms or every 256 ops. `RuleWrite` is the only op with an ack: it validates
again, bumps `version`, inserts into `rule_versions`, upserts `rules`,
commits, and acks. The caller then runs `RulesService::reload()`, which reads
`state IN ('active', 'proposed')` through the read connection, validates and
compiles every body, computes `hash`, bumps `generation` and swaps the
`ArcSwap`. A body that fails validation at load is skipped, logged at error
with its id, and listed by `GET /rules?invalid=true`; it is never
auto-retired and never silently dropped.

Tables are the ones in Part 1. Migrations are numbered SQL files embedded
with `include_str!` and applied in order against a `schema_version` table.
On start: migrate, import `rules/install/*.json` if the `rules` table is
empty, load decisions with `expires_at > now` into the mirror, load the
global mode, reload rules.

### API, mode, sweeps

axum on `127.0.0.1:<port>`. The UI is served off-host, at
`https://leeside.halowifi.com`, by nginx, which proxies `/api/` to this
port; so with `LEESIDED_API_TOKEN` set, every route but `/health` needs
`Authorization: Bearer <token>` and answers 401 otherwise (compared in
constant time). Unset, the API is open, for local runs and tests. The
token lives in `/etc/leeside/leesided.env` on the host.

| Route | Does |
| --- | --- |
| `GET /rules?state=` | list; default active; `invalid=true` adds bodies that failed load |
| `GET /rules/{id}` | body, versions, stats for the last 24 h |
| `POST /rules/validate` | dry run: `{ ok, errors[] }`, never writes |
| `POST /rules` | operator-authored; state active; mode as given, default shadow |
| `POST /rules/{id}/accept` | proposed to active; `{ mode? }` default shadow, whatever the proposal said |
| `PUT /rules/{id}` | new version; the only way to raise a mode to enforce |
| `POST /rules/{id}/retire` | state retired; drops out of the compiled set on reload |
| `POST /rules/reload` | manual reload; idempotent |
| `GET /rules/schema` | the JSON Schema from schemars |
| `GET /rules/export` | the active set as JSON, for seeding another host |
| `GET /mode`, `PUT /mode` | global mode; `PUT {"mode":"monitor"}` is the kill switch |
| `GET /decisions` | live sticky decisions, soonest to expire first, with the server's `now` |
| `DELETE /decisions/{scope}/{key}` | lift one decision now; 404 if none; the rule can trip again |
| `GET /turns?peer=&session=&route=&verdict=&limit=` | newest turns first; `verdict=none` for turns with no check record; `limit` 1..=500, default 100 |
| `GET /health` | `{ ok, generation, hash, mode, windows, dropped }`; never needs the token |

Spark's proposals arrive through the incident pipeline as `RuleWrite {
state: proposed, changed_by: "spark" }` inside the process, never through
this API from outside.

Global mode is an `AtomicU8` plus the `settings` row; `enforce = false` in
config pins it to monitor and makes a `PUT /mode` asking for enforce return
409. Every verdict carries the effective mode, so the UI header can show it
and the Laravel side never needs to know about the ladder.

Sweeps run on one tokio interval every 60 s: expired decisions (mirror and
table), rules past `expires_at` (a `RuleWrite` to shadow with `changed_by:
"system"`, so the drop is in the version history), idle windows (close
summaries). The stats flush runs every 10 s on its own interval.

### Configuration

Environment variables, read once at start; no config file in v1.

| Variable | Default | Meaning |
| --- | --- | --- |
| `LEESIDED_SOCKET_DIR` | `/run/leeside` | holds `events.sock` (datagram) and `check.sock` (stream), mode 0660 |
| `LEESIDED_DB` | `/var/lib/leeside/leesided.sqlite` | the store |
| `LEESIDED_API` | `127.0.0.1:7390` | the local HTTP API |
| `LEESIDED_ENFORCE` | `true` | `false` pins the global mode to monitor |
| `LEESIDED_RULES_DIR` | `rules/install` next to the binary, else the repo path | the install set |
| `LEESIDED_SOCKET_MODE` | `660` (octal) | permission bits on both sockets |
| `LEESIDED_SOCKET_GID` | unset | numeric group to chown the sockets to (www-data's gid on the sample host); numeric so the daemon never reads `/etc/group` |

Socket paths count against the 108-byte `sun_path` limit; keep
`LEESIDED_SOCKET_DIR` short.

Subcommands: `leesided serve` (default), `leesided rules schema`, `leesided
rules export`, `leesided rules validate <file>`. `serve` stops on SIGINT
after flushing stats and draining the writer (`StoreOp::Shutdown`).

The install set is imported as `active` in **shadow** regardless of the mode
its file says, so a git-tracked `enforce` never goes live on first start;
an operator promotes it with `PUT /rules/{id}`.

### Windside groundwork

`features.rs` is the v1 extractor: 30 named `f32`s per turn over the
session window (volume, pacing, error ratios, auth, breadth, payload,
navigation, user-agent changes) plus two over the peer window and
`is_anon`. Ingest writes one `features` row per event, so the training
corpus accumulates from the first deploy. `features::NAMES` and
`features::VERSION` are what a model file must match. Windside scoring on
the check path is not wired yet; the extractor cost is paid on ingest only.

### Tests and bench

- Model: an unknown field is rejected at every level; exactly one test per
  condition; every limit above; `retry_after_s` without `rate_limit`
  rejected; `"*"` beside another route rejected; the schema export
  round-trips the three example rules from Part 1.
- Eval, table-driven: each condition kind; `lte: 0` over the whole
  conversation; peer scope across three sessions; `sequence` with the probe's
  route last; an expired rule evaluates as shadow; a proposed rule bumps
  stats and never wins; severity and tie-break; the mode downgrade matrix
  (3 global x 3 rule).
- Property test: a naive evaluator over `Vec<Rule>` and `Vec<TurnSummary>`
  agrees with the compiled one on 1 000 random rule sets and windows.
- Stickiness: a block holds across later turns until close; a rate limit
  expires on time and `retry_after` counts down.
- Persistence: decisions written, process dropped, reopened, still enforced;
  the rule set reloads with the same `hash` after a restart.
- Reload under load: swap the set 100 times while 10 k evals run on four
  threads; no panic, `generation` monotonic in the check records.
- Contract: the brief's example probe answers a configured verdict; the
  brief's example event lands in the right window with the right summary; a
  `CheckRecord` joins its turn on `(session_key, ts)`.
- Bench (criterion): 500 rules, 64-turn windows, 10 k probes, p99 eval under
  50 µs. Integration: UDS round trip p99 under 1 ms driven by the sample
  app's `bin/traffic.sh`.

### Sessions

**Session A: the rules module, no IO.** `model.rs`, `schema.rs`,
`symbols.rs`, `compile.rs`, `eval.rs`, `windows.rs`, with the table-driven
eval tests, the naive-versus-compiled property test and the criterion bench.
No SQLite, socket or axum code.

**Session B: wiring.** Migrations, the writer thread and `StoreOp` channel,
the decisions mirror, `RulesService` with reload, the check server, ingest,
stats and sweeps, the install-set import, the API. Then the integration
tests and the UDS round trip against `../leeside-sample/bin/traffic.sh`.

**Done when**: both suites green; the bench and round-trip numbers in the
session summary; `GET /rules/schema` output copied into the Spark prompt file
rather than retyped; the three example rules accepted by `POST
/rules/validate`; a proposal written through `RuleWrite` shows up in `GET
/rules?state=proposed` with non-zero stats after the traffic script runs, and
wins no verdict until accepted.
