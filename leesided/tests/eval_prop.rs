//! A naive evaluator over the rule document and plain string turns must
//! agree with the compiled engine on random rule sets, windows and probes.

use leesided::rules::compile::{RuleMeta, RuleSet, State};
use leesided::rules::eval::{eval, Probe, VerdictAction};
use leesided::rules::model::*;
use leesided::rules::symbols::Symbols;
use leesided::rules::windows::{id8, EventKeys, TurnSummary, Windows, WINDOW_TURNS};
use proptest::prelude::*;
use smallvec::SmallVec;
use std::sync::Arc;

const NOW_S: i64 = 1_761_600_000;
const BASE_MS: u64 = 1_761_600_000_000;
const ROUTES: [&str; 6] = [
    "home",
    "portal.login",
    "venues.show",
    "api.venues.index",
    "api.venues.visit",
    "_unrouted",
];
const EXCEPTIONS: [&str; 3] = [
    "ValidationException",
    "ModelNotFoundException",
    "RuntimeException",
];
const AUTH: [&str; 2] = ["login_failed", "login"];
const SHAPES: [&str; 3] = ["[]", "{otp:str:6,phone:str:10}", "{guests:int}"];
const MODELS: [&str; 2] = ["Venue", "User"];
const FIELDS: [&str; 3] = ["otp", "phone", "guests"];
const SESSIONS: [u64; 2] = [11, 12];
const PEERS: [u64; 2] = [21, 22];
const PRINCIPALS: [Option<u64>; 3] = [None, Some(31), Some(32)];

/// A turn before interning: what ingest will see, as strings.
#[derive(Debug, Clone)]
struct Event {
    session: u64,
    peer: u64,
    principal: Option<u64>,
    route: &'static str,
    verb: Verb,
    status: u16,
    validation: Vec<&'static str>,
    exception: Option<&'static str>,
    auth: Option<&'static str>,
    shape: &'static str,
    bound: Vec<(&'static str, u32)>,
}

fn pick<T: Copy + std::fmt::Debug + 'static>(items: &'static [T]) -> impl Strategy<Value = T> {
    (0..items.len()).prop_map(move |i| items[i])
}

fn subset<T: Copy + std::fmt::Debug + 'static>(
    items: &'static [T],
    max: usize,
) -> impl Strategy<Value = Vec<T>> {
    proptest::sample::subsequence(items.to_vec(), 1..=max.min(items.len()))
}

fn scope() -> impl Strategy<Value = Option<Scope>> {
    proptest::option::of(pick(&[Scope::Session, Scope::Peer, Scope::Principal]))
}

fn window() -> impl Strategy<Value = Option<u32>> {
    proptest::option::of(1u32..200)
}

fn event() -> impl Strategy<Value = Event> {
    (
        pick(&SESSIONS),
        pick(&PEERS),
        pick(&PRINCIPALS),
        pick(&ROUTES),
        pick(&Verb::ALL),
        prop_oneof![
            Just(200u16),
            Just(302),
            Just(401),
            Just(404),
            Just(422),
            Just(500)
        ],
        proptest::sample::subsequence(FIELDS.to_vec(), 0..=2),
        proptest::option::of(pick(&EXCEPTIONS)),
        proptest::option::of(pick(&AUTH)),
        pick(&SHAPES),
        proptest::collection::vec((pick(&MODELS), 1u32..5), 0..=2),
    )
        .prop_map(
            |(
                session,
                peer,
                principal,
                route,
                verb,
                status,
                validation,
                exception,
                auth,
                shape,
                bound,
            )| Event {
                session,
                peer,
                principal,
                route,
                verb,
                status,
                validation,
                exception,
                auth,
                shape,
                bound,
            },
        )
}

fn filter() -> impl Strategy<Value = TurnFilter> {
    (
        proptest::option::of(subset(&ROUTES, 3)),
        proptest::option::of(subset(&Verb::ALL, 3)),
        proptest::option::of(proptest::collection::vec(
            prop_oneof![
                (0u16..600).prop_map(StatusSel::Code),
                Just(StatusSel::Class(StatusClass::C4xx)),
                Just(StatusSel::Class(StatusClass::C5xx)),
            ],
            1..=3,
        )),
        proptest::option::of(prop_oneof![
            Just(ValidationSel::Any(true)),
            subset(&FIELDS, 2)
                .prop_map(|f| ValidationSel::Fields(f.into_iter().map(String::from).collect())),
        ]),
        proptest::option::of(subset(&EXCEPTIONS, 2)),
        proptest::option::of(subset(&AUTH, 2)),
        proptest::option::of(subset(&SHAPES, 2)),
        proptest::option::of(subset(&MODELS, 2)),
    )
        .prop_map(
            |(
                route,
                verb,
                status,
                validation_failed,
                exception,
                auth_event,
                req_shape,
                bound_model,
            )| {
                let strs =
                    |v: Option<Vec<&str>>| v.map(|v| v.into_iter().map(String::from).collect());
                TurnFilter {
                    route: strs(route),
                    verb,
                    status,
                    validation_failed,
                    exception: strs(exception),
                    auth_event: strs(auth_event),
                    req_shape: strs(req_shape),
                    bound_model: strs(bound_model),
                    credential_status: None,
                }
            },
        )
}

fn condition(match_routes: Vec<String>) -> impl Strategy<Value = Condition> {
    let count = (scope(), window(), filter(), 0u32..6, 0u32..6, any::<u8>()).prop_map(
        |(scope, window_s, f, a, b, which)| {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let (gte, lte) = match which % 3 {
                0 => (Some(lo), None),
                1 => (None, Some(hi)),
                _ => (Some(lo), Some(hi)),
            };
            Condition {
                scope,
                window_s,
                count: Some(f),
                gte,
                lte,
                ..Default::default()
            }
        },
    );
    let distinct = (
        scope(),
        window(),
        pick(&[DistinctField::BoundId, DistinctField::Route]),
        proptest::option::of(pick(&MODELS)),
        1u32..6,
    )
        .prop_map(|(scope, window_s, field, model, gte)| Condition {
            scope,
            window_s,
            distinct: Some(Distinct {
                field,
                model: if field == DistinctField::BoundId {
                    model.map(String::from)
                } else {
                    None
                },
                filter: None,
            }),
            gte: Some(gte),
            ..Default::default()
        });
    let last_choices: Vec<String> = if match_routes == ["*"] {
        ROUTES.iter().map(|r| r.to_string()).collect()
    } else {
        match_routes
    };
    let sequence = (
        proptest::collection::vec(pick(&ROUTES), 1..=3),
        proptest::sample::select(last_choices),
    )
        .prop_map(|(mut seq, last)| {
            let mut s: Vec<String> = seq.drain(..).map(String::from).collect();
            s.push(last);
            Condition {
                sequence: Some(s),
                ..Default::default()
            }
        });
    prop_oneof![3 => count, 2 => distinct, 1 => sequence]
}

fn rule(i: usize) -> impl Strategy<Value = (Rule, bool)> {
    let routes = prop_oneof![
        1 => Just(vec!["*".to_string()]),
        4 => subset(&ROUTES, 3).prop_map(|r| r.into_iter().map(String::from).collect::<Vec<_>>()),
    ];
    routes.prop_flat_map(move |routes| {
        let conds = prop_oneof![
            1 => Just(None),
            3 => condition(routes.clone()).prop_map(|c| Some(When::One(c))),
            2 => proptest::collection::vec(condition(routes.clone()), 1..=3).prop_map(|all| Some(When::All { all })),
        ];
        (
            pick(&[Mode::Monitor, Mode::Shadow, Mode::Enforce]),
            pick(&[Action::Log, Action::Watch, Action::RateLimit, Action::Challenge, Action::Block]),
            subset(&Verb::ALL, 4),
            pick(&[PrincipalKind::Any, PrincipalKind::Anon, PrincipalKind::Authenticated]),
            conds,
            proptest::option::of(prop_oneof![Just(NOW_S - 1), Just(NOW_S + 1000)]),
            any::<bool>(),
        )
            .prop_map(move |(mode, action, verb, principal, when, expires_at, proposed)| {
                let rule = Rule {
                    id: format!("rule-{i:02}"),
                    note: "prop".into(),
                    mode,
                    action,
                    retry_after_s: (action == Action::RateLimit).then_some(30),
                    block_min: None,
                    matcher: Match { route: routes.clone(), verb, principal, surface: vec![] },
                    when,
                    expires_at,
                    origin: Origin { kind: OriginKind::Operator, incident: None, model: None },
                };
                // Rules are validated at write time; an expired one is a rule
                // that was valid when written, so validate with a past clock.
                (rule, proposed)
            })
    })
}

fn probe() -> impl Strategy<Value = (Verb, &'static str, u64, u64, Option<u64>, u64)> {
    (
        pick(&Verb::ALL),
        prop_oneof![5 => pick(&ROUTES), 1 => Just("never.seen")],
        pick(&SESSIONS),
        pick(&PEERS),
        pick(&PRINCIPALS),
        0u64..300_000,
    )
}

/// The naive evaluator: strings, vectors, and the rule document as written.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn naive(
    rules: &[(Rule, bool)],
    events: &[Event],
    verb: Verb,
    route: &str,
    session: u64,
    peer: u64,
    principal: Option<u64>,
    ts_ms: u64,
    global: Mode,
) -> (Vec<(String, Action, Mode, bool)>, Option<String>) {
    let window = |scope: Scope| -> Vec<&Event> {
        let all: Vec<&Event> = events
            .iter()
            .filter(|e| match scope {
                Scope::Session => e.session == session,
                Scope::Peer => e.peer == peer,
                Scope::Principal => principal.is_some() && e.principal == principal,
                // The generator never presents a credential, so that window is empty.
                Scope::Credential => false,
                // Nor an actor.
                Scope::Actor => false,
            })
            .collect();
        let start = all.len().saturating_sub(WINDOW_TURNS);
        all[start..].to_vec()
    };
    let ts_of =
        |e: &Event| BASE_MS + events.iter().position(|x| std::ptr::eq(x, e)).unwrap() as u64 * 1000;
    let mut sorted: Vec<&(Rule, bool)> = rules.iter().collect();
    sorted.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    let mut hits = Vec::new();
    for (r, proposed) in sorted {
        if !(r.matcher.is_wildcard() || r.matcher.route.iter().any(|x| x == route)) {
            continue;
        }
        if !r.matcher.verb.contains(&verb) || !r.matcher.principal.accepts(principal) {
            continue;
        }
        let mut mode = global.min(r.mode);
        if r.expires_at.is_some_and(|e| e <= NOW_S) {
            mode = mode.min(Mode::Shadow);
        }
        let held = r.when.as_ref().is_none_or(|w| {
            w.conditions().iter().all(|c| {
                if let Some(seq) = &c.sequence {
                    let k = seq.len();
                    if seq[k - 1] != route {
                        return false;
                    }
                    let w = window(Scope::Session);
                    if w.len() < k - 1 {
                        return false;
                    }
                    w.iter()
                        .rev()
                        .take(k - 1)
                        .zip(seq[..k - 1].iter().rev())
                        .all(|(e, r)| e.route == r)
                } else {
                    let oldest = c
                        .window_s
                        .map_or(0, |s| ts_ms.saturating_sub(s as u64 * 1000));
                    let w = window(c.scope());
                    let in_window: Vec<&Event> = w
                        .iter()
                        .rev()
                        .take_while(|e| ts_of(e) >= oldest)
                        .copied()
                        .collect();
                    if let Some(f) = &c.count {
                        let n = in_window.iter().filter(|e| naive_matches(f, e)).count() as u32;
                        c.gte.is_none_or(|g| n >= g) && c.lte.is_none_or(|l| n <= l)
                    } else {
                        let d = c.distinct.as_ref().unwrap();
                        let mut seen: Vec<String> = Vec::new();
                        for e in in_window {
                            if d.filter.as_ref().is_some_and(|f| !naive_matches(f, e)) {
                                continue;
                            }
                            match d.field {
                                DistinctField::Route => seen.push(e.route.to_string()),
                                DistinctField::Credential => {}
                                DistinctField::BoundId => {
                                    for (m, id) in &e.bound {
                                        if d.model.as_deref().is_none_or(|only| only == *m) {
                                            seen.push(format!("{m}:{id}"));
                                        }
                                    }
                                }
                            }
                        }
                        seen.sort();
                        seen.dedup();
                        seen.len() as u32 >= c.gte.unwrap()
                    }
                }
            })
        });
        if held {
            hits.push((r.id.clone(), r.action, mode, *proposed));
        }
    }
    let winner = hits
        .iter()
        .filter(|h| !h.3)
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|h| h.0.clone());
    (hits, winner)
}

fn naive_matches(f: &TurnFilter, e: &Event) -> bool {
    f.route
        .as_ref()
        .is_none_or(|l| l.iter().any(|r| r == e.route))
        && f.verb.as_ref().is_none_or(|l| l.contains(&e.verb))
        && f.status.as_ref().is_none_or(|l| {
            l.iter().any(|s| match s {
                StatusSel::Code(c) => *c == e.status,
                StatusSel::Class(StatusClass::C4xx) => (400..500).contains(&e.status),
                StatusSel::Class(StatusClass::C5xx) => (500..600).contains(&e.status),
            })
        })
        && f.validation_failed.as_ref().is_none_or(|v| match v {
            ValidationSel::Any(_) => !e.validation.is_empty(),
            ValidationSel::Fields(fields) => {
                e.validation.iter().any(|x| fields.iter().any(|f| f == x))
            }
        })
        && f.exception
            .as_ref()
            .is_none_or(|l| e.exception.is_some_and(|x| l.iter().any(|y| y == x)))
        && f.auth_event
            .as_ref()
            .is_none_or(|l| e.auth.is_some_and(|x| l.iter().any(|y| y == x)))
        && f.req_shape
            .as_ref()
            .is_none_or(|l| l.iter().any(|s| s == e.shape))
        && f.bound_model
            .as_ref()
            .is_none_or(|l| e.bound.iter().any(|(m, _)| l.iter().any(|y| y == m)))
        && f.credential_status.is_none()
}

fn summary(e: &Event, ts_ms: u64, syms: &Symbols) -> TurnSummary {
    TurnSummary {
        ts_ms,
        route: syms.intern(e.route),
        verb: e.verb,
        status: e.status,
        validation_fields: e.validation.iter().map(|f| syms.intern(f)).collect(),
        exception: e.exception.map(|x| syms.intern(x)),
        auth_event: e.auth.map(|x| syms.intern(x)),
        req_shape: syms.intern(e.shape),
        bound: e
            .bound
            .iter()
            .map(|(m, id)| (syms.intern(m), id8(&format!("{id:08x}")).unwrap()))
            .collect::<SmallVec<_>>(),
        bytes_out: 0,
        latency_ms: 0.0,
        ua_hash: 0,
        credential: None,
        credential_status: 0,
        surface: 0,
        tag_status: 0,
        net: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, .. ProptestConfig::default() })]

    #[test]
    fn compiled_agrees_with_naive(
        rules in proptest::collection::vec(rule(0), 1..=12)
            .prop_map(|rs: Vec<(Rule, bool)>| rs.into_iter().enumerate().map(|(i, (mut r, p))| { r.id = format!("rule-{i:02}"); (r, p) }).collect::<Vec<_>>()),
        events in proptest::collection::vec(event(), 0..=80),
        (verb, route, session, peer, principal, offset) in probe(),
        global in pick(&[Mode::Monitor, Mode::Shadow, Mode::Enforce]),
    ) {
        for (r, _) in &rules {
            let errors = r.validate(NOW_S - 2);
            prop_assert!(errors.is_empty(), "generator produced an invalid rule: {} {errors:?}", serde_json::to_string(r).unwrap());
        }
        let syms = Symbols::default();
        let windows = Windows::default();
        for (i, e) in events.iter().enumerate() {
            windows.record(
                &EventKeys { session: e.session, peer: e.peer, principal: e.principal, credential: None, actor: None, cluster: None },
                summary(e, BASE_MS + i as u64 * 1000, &syms),
            );
        }
        let ts_ms = BASE_MS + events.len() as u64 * 1000 + offset;
        let entries = rules.iter().map(|(r, proposed)| {
            (r.clone(), RuleMeta {
                id: Arc::from(r.id.as_str()), version: 1, note: String::new(), origin: r.origin.clone(),
                state: if *proposed { State::Proposed } else { State::Active },
            })
        }).collect();
        let rs = RuleSet::compile(entries, &syms, 1);
        let p = Probe { verb, route, session_key: session, peer_key: peer, principal, ts_ms,
            surface: Surface::Web,
            credential: None,
            credential_verified: false, actor: None };
        let got = eval(&rs, &syms, &windows, &p, global, NOW_S);
        let (want_hits, want_winner) = naive(&rules, &events, verb, route, session, peer, principal, ts_ms, global);

        let mut got_hits: Vec<(String, Action, Mode, bool)> = got.hits.iter()
            .map(|h| (rs.meta[h.ix as usize].id.to_string(), h.action, h.mode, h.proposed)).collect();
        got_hits.sort();
        let mut want_hits = want_hits;
        want_hits.sort();
        prop_assert_eq!(got_hits, want_hits);
        prop_assert_eq!(got.verdict.rule.as_deref().map(String::from), want_winner.clone());
        match want_winner {
            None => prop_assert_eq!((got.verdict.action, got.verdict.mode), (VerdictAction::Allow, global)),
            Some(id) => {
                let (r, _) = rules.iter().find(|(r, _)| r.id == id).unwrap();
                prop_assert_eq!(got.verdict.action, VerdictAction::from(r.action));
                prop_assert_eq!(got.verdict.retry_after, (r.action == Action::RateLimit).then_some(30));
            }
        }
    }
}
