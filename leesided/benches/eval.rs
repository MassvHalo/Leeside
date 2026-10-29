//! 500 rules, 64-turn windows, 10 k probes. Prints the p50/p99/max of a
//! single eval before handing over to criterion; the budget is p99 under
//! 50 µs.

use criterion::{black_box, Criterion};
use leesided::rules::compile::{RuleMeta, RuleSet, State};
use leesided::rules::eval::{eval, Probe};
use leesided::rules::model::{Mode, Rule, Verb};
use leesided::rules::symbols::Symbols;
use leesided::rules::windows::{EventKeys, TurnSummary, Windows};
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::{Duration, Instant};

const NOW_S: i64 = 1_761_600_000;
const BASE_MS: u64 = 1_761_600_000_000;
const RULES: usize = 500;
const ROUTES: usize = 50;
const SESSIONS: u64 = 1000;
const PEERS: u64 = 200;
const PROBES: usize = 10_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

const VERBS: [&str; 3] = ["GET", "POST", "PUT"];
const EXCEPTIONS: [&str; 3] = [
    "ValidationException",
    "ModelNotFoundException",
    "RuntimeException",
];
const AUTH: [&str; 2] = ["login_failed", "login"];
const MODELS: [&str; 3] = ["Venue", "User", "Order"];
const FIELDS: [&str; 3] = ["otp", "phone", "guests"];

fn route(i: u64) -> String {
    format!("r{i}.show")
}

fn rule_json(rng: &mut Rng, i: usize) -> serde_json::Value {
    let wildcard = rng.below(25) == 0;
    let routes: Vec<String> = if wildcard {
        vec!["*".into()]
    } else {
        (0..1 + rng.below(3))
            .map(|_| route(rng.below(ROUTES as u64)))
            .collect()
    };
    let action = *rng.pick(&["log", "watch", "rate_limit", "challenge", "block"]);
    let scope = *rng.pick(&["session", "session", "peer", "principal"]);
    let cond = match rng.below(6) {
        0 => serde_json::json!({ "scope": scope, "window_s": 120,
            "count": { "auth_event": [AUTH[rng.below(2) as usize]] }, "gte": 3 + rng.below(5) }),
        1 => serde_json::json!({ "scope": scope, "window_s": 600,
            "count": { "status": ["4xx"], "exception": [EXCEPTIONS[rng.below(3) as usize]] }, "gte": 2 + rng.below(6) }),
        2 => {
            serde_json::json!({ "scope": scope, "count": { "route": [route(rng.below(ROUTES as u64))] }, "lte": 0 })
        }
        3 => serde_json::json!({ "scope": scope, "window_s": 300,
            "distinct": { "field": "bound_id", "model": MODELS[rng.below(3) as usize] }, "gte": 5 + rng.below(20) }),
        4 => {
            serde_json::json!({ "scope": scope, "distinct": { "field": "route" }, "gte": 4 + rng.below(10) })
        }
        _ => {
            serde_json::json!({ "count": { "validation_failed": [FIELDS[rng.below(3) as usize]], "verb": ["POST"] }, "gte": 2 })
        }
    };
    let when = if rng.below(3) == 0 {
        let mut all = vec![cond];
        all.push(serde_json::json!({ "scope": "peer", "window_s": 60, "count": {}, "gte": 1 + rng.below(10) }));
        serde_json::json!({ "all": all })
    } else {
        cond
    };
    let mut v = serde_json::json!({
        "id": format!("bench-{i:03}"), "note": "bench", "mode": *rng.pick(&["shadow", "enforce"]), "action": action,
        "match": { "route": routes, "verb": [VERBS[rng.below(3) as usize], "GET"], "principal": "any" },
        "when": when,
        "origin": { "kind": "operator" }
    });
    if action == "rate_limit" {
        v["retry_after_s"] = 30.into();
    }
    if v["match"]["verb"][0] == "GET" {
        v["match"]["verb"] = serde_json::json!(["GET", "POST"]);
    }
    v
}

fn turn(rng: &mut Rng, syms: &Symbols, ts_ms: u64) -> TurnSummary {
    let status = *rng.pick(&[200u16, 200, 200, 302, 401, 404, 422, 500]);
    let mut bound: SmallVec<[(_, u32); 2]> = SmallVec::new();
    if rng.below(2) == 0 {
        bound.push((syms.intern(rng.pick(&MODELS)), rng.below(40) as u32));
    }
    TurnSummary {
        ts_ms,
        route: syms.intern(&route(rng.below(ROUTES as u64))),
        verb: if rng.below(3) == 0 {
            Verb::Post
        } else {
            Verb::Get
        },
        status,
        validation_fields: if status == 422 {
            [syms.intern(rng.pick(&FIELDS))].into_iter().collect()
        } else {
            SmallVec::new()
        },
        exception: (status >= 400).then(|| syms.intern(rng.pick(&EXCEPTIONS))),
        auth_event: (rng.below(4) == 0).then(|| syms.intern(rng.pick(&AUTH))),
        req_shape: syms.intern(if status == 422 {
            "{otp:str:6,phone:str:10}"
        } else {
            "[]"
        }),
        bound,
    }
}

struct Fixture {
    syms: Symbols,
    windows: Windows,
    rs: RuleSet,
    probes: Vec<(Verb, String, u64, u64, Option<u64>, u64)>,
}

fn fixture() -> Fixture {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let syms = Symbols::default();
    let mut entries = Vec::with_capacity(RULES);
    for i in 0..RULES {
        let json = rule_json(&mut rng, i);
        let rule =
            Rule::parse(&json.to_string(), NOW_S).unwrap_or_else(|e| panic!("{json}: {e:?}"));
        let meta = RuleMeta {
            id: Arc::from(rule.id.as_str()),
            version: 1,
            note: String::new(),
            origin: rule.origin.clone(),
            state: if i % 10 == 0 {
                State::Proposed
            } else {
                State::Active
            },
        };
        entries.push((rule, meta));
    }
    let rs = RuleSet::compile(entries, &syms, 1);

    let windows = Windows::default();
    let mut ts = BASE_MS;
    for session in 0..SESSIONS {
        let keys = EventKeys {
            session,
            peer: session % PEERS,
            principal: session.is_multiple_of(3).then_some(session),
        };
        for _ in 0..64 {
            ts += 100;
            let t = turn(&mut rng, &syms, ts);
            windows.record(&keys, t);
        }
    }
    let probes = (0..PROBES)
        .map(|_| {
            let session = rng.below(SESSIONS);
            (
                if rng.below(3) == 0 {
                    Verb::Post
                } else {
                    Verb::Get
                },
                route(rng.below(ROUTES as u64)),
                session,
                session % PEERS,
                session.is_multiple_of(3).then_some(session),
                ts + 1000,
            )
        })
        .collect();
    Fixture {
        syms,
        windows,
        rs,
        probes,
    }
}

fn run_one(f: &Fixture, p: &(Verb, String, u64, u64, Option<u64>, u64)) -> usize {
    let probe = Probe {
        verb: p.0,
        route: &p.1,
        session_key: p.2,
        peer_key: p.3,
        principal: p.4,
        ts_ms: p.5,
    };
    eval(&f.rs, &f.syms, &f.windows, &probe, Mode::Enforce, NOW_S)
        .hits
        .len()
}

fn percentiles(f: &Fixture) {
    // Warm up, then time each probe on its own.
    for p in &f.probes {
        black_box(run_one(f, p));
    }
    let mut samples: Vec<Duration> = Vec::with_capacity(f.probes.len());
    let mut hits = 0usize;
    for p in &f.probes {
        let t0 = Instant::now();
        hits += black_box(run_one(f, p));
        samples.push(t0.elapsed());
    }
    samples.sort();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    println!(
        "eval over {} rules ({} by-route lists, {} wildcard), {} probes, {} hits total",
        f.rs.len(),
        f.rs.by_route.len(),
        f.rs.wildcard.len(),
        f.probes.len(),
        hits
    );
    println!(
        "p50 {:?}  p90 {:?}  p99 {:?}  p999 {:?}  max {:?}",
        at(0.50),
        at(0.90),
        at(0.99),
        at(0.999),
        samples[samples.len() - 1]
    );
    let budget = Duration::from_micros(50);
    println!(
        "p99 budget 50µs: {}",
        if at(0.99) <= budget {
            "within"
        } else {
            "EXCEEDED"
        }
    );
}

fn main() {
    let f = fixture();
    percentiles(&f);
    let mut c = Criterion::default().configure_from_args();
    let mut i = 0usize;
    c.bench_function("eval/500-rules/64-turn-windows", |b| {
        b.iter(|| {
            let p = &f.probes[i % f.probes.len()];
            i += 1;
            black_box(run_one(&f, p))
        })
    });
    c.final_summary();
}
