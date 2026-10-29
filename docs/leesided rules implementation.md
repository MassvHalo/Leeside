# leesided rules implementation

Oct 29, 2026 · @Kumar Mrinal

## Where it lives

The rule engine is one module with no IO of its own; the check server, ingest and store call into it. That split is what makes it testable and benchmarkable without sockets or SQLite.

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

Crates: tokio, axum, rusqlite (bundled, WAL), serde, serde\_json, schemars, arc-swap, dashmap, smallvec, parking\_lot, tracing, thiserror; criterion and proptest as dev-dependencies. Nothing else without a reason stated in the session summary.

## Types and validation

The serde structs mirror the rule document one to one, with `#[serde(deny_unknown_fields)]` on every struct so a Spark-emitted rule with an invented field is rejected rather than half-read. `schemars::JsonSchema` is derived on the same structs, so `GET /rules/schema` and `leesided rules schema` print the exact grammar the engine accepts. That output goes into Spark's prompt; nobody hand-writes a second copy.

```rust
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,                                     // ^[a-z0-9][a-z0-9-]{2,63}$
    pub note: String,                                   // 1..=200 chars
    pub mode: Mode,                                     // monitor | shadow | enforce
    pub action: Action,                                 // log | watch | rate_limit | challenge | block
    #[serde(default)] pub retry_after_s: Option<u32>,   // 1..=86400; only with rate_limit
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

`Rule::validate()` runs after deserialisation and again on every load. It checks: exactly one of `count`, `distinct`, `sequence` per condition; `gte` or `lte` only with `count`, at least one of them; `distinct` takes `gte` only; `sequence` rejects `scope` and `window_s`; route lists 1..=16 with `"*"` allowed only alone; verb lists 1..=8; `retry_after_s` only with `rate_limit`; `expires_at` in the future at write time. Errors come back as `Vec<ValidationError { path, message }>` so the UI can point at the field.

`Action` derives `Ord` as log < watch < rate\_limit < challenge < block and `Mode` as monitor < shadow < enforce. Eval relies on both orderings, so they live on the types and have their own tests.

## Symbols and compiled rules

Strings on the hot path are interned once to `Sym(u32)`: route templates, exception basenames, auth event names, `req_shape` strings, model names. `Symbols` is append-only (`DashMap<Box<str>, Sym>` plus `RwLock<Vec<Arc<str>>>`). Interning happens on ingest and on compile, never on the check path: the check path calls `get()`, and an unknown route simply matches only wildcard rules. The table is capped at 1 M entries; beyond that new strings map to a `Sym::OVERFLOW` sentinel and a counter is bumped (shapes are the only field that could grow without bound).

Compile turns a `Rule` into fixed-size pieces, allocated once:

```rust
struct Compiled {
    ix: u32,                        // index into RuleSet.rules and .meta
    verbs: u8,                      // bitmask over Verb
    principal: PrincipalKind,
    conds: SmallVec<[CCond; 3]>,
    action: Action, mode: Mode, retry_after_s: u32,
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

`SymSet` is a sorted `SmallVec<[Sym; 8]>` with binary search; `StatusSet` is a 600-bit bitset (`[u64; 10]`). The whole `RuleSet` lives in an `arc_swap::ArcSwap<RuleSet>`: the check path does one `load()` per probe, a reload builds a new set and swaps the pointer, in-flight evaluations finish on the old one. No lock on the hot path and no half-loaded set, ever.

**Reload is a function call, not a file watch.** leesided is the only writer of its rules. A Spark proposal, an operator accept, an edit or a retire all go through the writer thread, which acks, and the caller then runs `RulesService::reload()`. Both `generation` and `hash` go on every check record and into the UI header, so any verdict can be traced to the exact rule set that produced it. `POST /rules/reload` exists for the rare manual case and is idempotent.

**Proposed rules are compiled too**, with `proposed = true`: eval bumps their stats (matched, would\_act) but never lets them win the verdict. When an operator opens a proposal it already shows what it would have done over the hours since Spark wrote it, which is the evidence acceptance should rest on.

**Files only for the install set.** Hand-written rules live in the repo as `rules/install/*.json`, imported at first start as active, shadow, origin `install`, so they are git-tracked. SQLite remains the runtime truth; `leesided rules export` dumps the active set as JSON for moving between hosts.

## Conversation windows

Ingest keeps in memory exactly what a rule can ask about, nothing more:

```rust
struct TurnSummary {
    ts_ms: u64, route: Sym, verb: Verb, status: u16,
    validation_fields: SmallVec<[Sym; 4]>,   // empty = did not fail validation
    exception: Option<Sym>, auth_event: Option<Sym>, req_shape: Sym,
    bound: SmallVec<[(Sym, u32); 2]>,        // (model, id_hash parsed from the 8 hex)
}
struct Window { turns: ArrayDeque<TurnSummary, 64>, opened_ms: u64, last_ms: u64, flags: u8 /* watch */ }
pub struct Windows {
    sessions:   DashMap<u64, Window>,        // session_key 16 hex -> u64
    peers:      DashMap<u64, Window>,
    principals: DashMap<u64, Window>,        // "anon" is never indexed here
}
```

Keys are the event's hashes parsed as integers, so a lookup hashes a u64, not a string. 64 turns is the window; a `count` over a longer history is answered from the 64 we hold and documented as such (anything needing more is a Windside feature, not a rule). A sweep every 60 s evicts sessions idle for 30 min or older than 24 h and emits the conversation-close summary; peer and principal windows evict after 60 min idle. Hard cap 200 k sessions, LRU beyond that, with a counter the UI can show. A restart loses the windows, and that is accepted: counts rebuild within one window, and blocks survive because decisions are persisted.

**The N-1 timing.** The check for turn N runs before turn N is handled; its event arrives afterwards. So the window a check sees holds turns 1..N-1, and the current turn is known only from the probe (verb, route, principal). `sequence` therefore compares the probe's route plus the newest k-1 routes in the window. The probe's `ts` equals the event's `ts` (both come from the middleware's `TurnContext`), so `(session_key, ts)` is the join key between a check record and its turn row.

## The check path

One connection, one probe, no allocation beyond the response line, and no `await` between parse and write. Budget: eval p99 under 50 µs with 500 rules loaded; round trip under 1 ms including the socket.

1. Read one line (cap 4 KB); `serde_json::from_slice::<Probe>`. A parse failure answers `allow` and bumps `check.bad_probe`.
2. Take `now_ms` and the global mode from an `AtomicU8`.
3. Sticky first: `decisions.get(session_key)`, then `peer_key`, then `principal` unless anon. A live `block` or `rate_limit` is the verdict immediately, mode downgraded to `min(global, decision.mode)`, `retry_after` recomputed from `expires_at`.
4. `let rs = ruleset.load();` `route_sym = symbols.get(&probe.route)`; candidates are `rs.by_route[route_sym]` (if present) followed by `rs.wildcard`.
5. Per candidate: an `expires_at` already passed means evaluate as shadow; verb bit; principal kind; then the conditions in order, fetching each scope's `Window` lazily at most once per probe and holding the `DashMap` ref only for the scan. `Count` scans newest to oldest, stops at the window edge, exits early once `gte` is met when there is no `lte`. `Distinct` fills a `SmallVec<[u32; 32]>` with dedupe and exits at `gte`. `Sequence` compares the probe's route, then the newest k-1 turns.
6. Collect `Hit { ix, action, effective_mode, proposed }`. The verdict is the non-proposed hit with the highest `action`; ties go to the lowest `ix` (rules load sorted by `id`, so this is deterministic). No hits: `allow` with mode = global.
7. Stickiness: `block` inserts a decision on the session, expiring at conversation close (24 h cap); `rate_limit` inserts one on the matching condition's `scope` key for `retry_after_s`. Insert into the mirror, then `StoreOp::DecisionUpsert` to the writer. `challenge`, `watch` and `log` are re-evaluated every turn.
8. `stats.bump(ix, hour, effective_mode, acted)` for every hit, proposed ones included, where `acted = effective_mode == enforce && action >= rate_limit`. Then `StoreOp::CheckRecord { session_key, ts, hits, verdict, generation, hash }`, so the turn row carries `rules_matched` and `verdict` once the event lands.
9. Serialise the `Verdict` into a reused buffer, write, close.

In monitor and shadow the verdict is still sent, with that mode; the Laravel side records it on the event's `gate` field and changes nothing. leesided later joins its `CheckRecord` to the event: a `gate == null` where a record exists is a fail-open (a timeout or error on the PHP side) and is counted per hour, because the claim that the middleware degrades to monitor by construction rests on that number being visible in the UI.

## Store

SQLite in WAL mode with `synchronous = NORMAL`. One connection is owned by a writer thread (a `std::thread`, not a tokio task, since `rusqlite::Connection` is not `Sync`); a second read-only connection serves the API and reloads. Everything that writes sends a `StoreOp` over a bounded channel (capacity 10 k); when the channel is full the op is dropped and counted rather than blocking the check path.

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

The writer drains whatever is in the channel into one transaction every 50 ms or every 256 ops. `RuleWrite` is the only op with an ack: it validates again, bumps `version`, inserts into `rule_versions`, upserts `rules`, commits, and acks. The caller then runs `RulesService::reload()`, which reads `state IN ('active', 'proposed')` through the read connection, validates and compiles every body, computes `hash`, bumps `generation` and swaps the `ArcSwap`. A body that fails validation at load is skipped, logged at error with its id, and listed by `GET /rules?invalid=true`; it is never auto-retired and never silently dropped.

Tables are the four from the rules design (`rules`, `rule_versions`, `decisions`, `rule_stats`) plus two columns on `turns`: `rules_matched TEXT` (JSON list of `{rule, version, action, mode}`) and `verdict TEXT`, and `ruleset_hash BLOB` so a turn names the set that judged it. Migrations are numbered SQL files embedded with `include_str!` and applied in order against a `schema_version` table. On start: migrate, import `rules/install/*.json` if the `rules` table is empty, load decisions with `expires_at > now` into the mirror, load the global mode, reload rules.

## API, mode, sweeps

axum on `127.0.0.1:<port>`, no auth in v1 (same host as the UI; the day the UI moves off-host this gets a token, written into the brief first).

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

Spark's proposals arrive through the incident pipeline as `RuleWrite { state: proposed, changed_by: "spark" }` inside the process, never through this API from outside.

Global mode is an `AtomicU8` plus the `settings` row; `enforce = false` in config pins it to monitor and makes a `PUT /mode` asking for enforce return 409. Every verdict carries the effective mode, so the UI header can show it and the Laravel side never needs to know about the ladder.

Sweeps run on one tokio interval every 60 s: expired decisions (mirror and table), rules past `expires_at` (a `RuleWrite` to shadow with `changed_by: "system"`, so the drop is in the version history), idle windows (close summaries). The stats flush runs every 10 s on its own interval.

## Tests and bench

- Model: an unknown field is rejected at every level; exactly one test per condition; every limit above; `retry_after_s` without `rate_limit` rejected; `"*"` beside another route rejected; the schema export round-trips the three example rules from the design.
- Eval, table-driven: each condition kind; `lte: 0` over the whole conversation; peer scope across three sessions; `sequence` with the probe's route last; an expired rule evaluates as shadow; a proposed rule bumps stats and never wins; severity and tie-break; the mode downgrade matrix (3 global x 3 rule).
- Property test: a naive evaluator over `Vec<Rule>` and `Vec<TurnSummary>` agrees with the compiled one on 1 000 random rule sets and windows.
- Stickiness: a block holds across later turns until close; a rate limit expires on time and `retry_after` counts down.
- Persistence: decisions written, process dropped, reopened, still enforced; the rule set reloads with the same `hash` after a restart.
- Reload under load: swap the set 100 times while 10 k evals run on four threads; no panic, `generation` monotonic in the check records.
- Contract: the brief's example probe answers a configured verdict; the brief's example event lands in the right window with the right summary; a `CheckRecord` joins its turn on `(session_key, ts)`.
- Bench (criterion): 500 rules, 64-turn windows, 10 k probes, p99 eval under 50 µs. Integration: UDS round trip p99 under 1 ms driven by the sample app's `bin/traffic.sh`.

## Muse Code sessions

Two sittings in `leesided/`, after the scaffold session has produced the binary skeleton. Save this document as `leesided/docs/rules.md` first, with the rule-document format and the four tables from the rules design pasted in at the top, so both sessions read one file.

**Session A: the rules module, no IO**

```text
Read AGENTS.md, ../docs/brief.md and docs/rules.md. Implement src/rules/model.rs,
schema.rs, symbols.rs, compile.rs, eval.rs and windows.rs exactly as
docs/rules.md describes, with no SQLite, socket or axum code in this session.
deny_unknown_fields on every serde struct, schemars derived on the same
structs, a validate() that returns a list of {path, message}. Write the
table-driven eval tests, the naive-versus-compiled property test and the
criterion bench; the bench must show p99 under 50 microseconds with 500 rules
and 64-turn windows. Before writing code, show me the type definitions and
the eval loop in pseudocode, and wait for my go-ahead.
```

**Session B: wiring**

```text
Read AGENTS.md, ../docs/brief.md and docs/rules.md. Wire the rules module in:
the four tables and the three turns columns as migrations, the single writer
thread with the StoreOp channel and batching, the decisions mirror with
write-behind, RulesService with ArcSwap reload plus generation and hash,
proposed rules compiled for stats only, the check server calling rules::eval
on the hot path with no await between parse and write, stats buckets and
flush, the sweeps, the install-set import, and the /rules, /rules/schema,
/rules/export, /rules/reload and /mode endpoints. Then run the integration
tests: the brief's example probe and event, decisions surviving a restart,
reload under load, and the UDS round trip against
../leeside-sample/bin/traffic.sh with p99 under 1 ms. Report the numbers. Do
not weaken a test to make it pass; tell me instead.
```

**Done when**: both suites green; the bench and round-trip numbers in the session summary; `GET /rules/schema` output copied into the Spark prompt file rather than retyped; the three example rules from the design accepted by `POST /rules/validate`; a proposal written through `RuleWrite` shows up in `GET /rules?state=proposed` with non-zero stats after the traffic script runs, and wins no verdict until accepted.
