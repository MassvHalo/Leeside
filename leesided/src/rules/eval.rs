//! `RuleSet` x `Probe` x `Windows` -> hits and a verdict. No allocation on
//! this path beyond the `SmallVec`s on the stack; the verdict's `rule` and
//! `hash` are `Arc` clones.

use super::compile::{CCond, CTest, RuleSet};
use super::model::{Action, DistinctField, Mode, Scope, Surface, Verb};
use super::symbols::{Sym, Symbols};
use super::windows::{Window, Windows, WINDOW_TURNS};
use dashmap::mapref::one::Ref;
use serde::Serialize;
use smallvec::SmallVec;
use std::sync::Arc;

/// The probe, decoded once by the check server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe<'a> {
    pub verb: Verb,
    pub route: &'a str,
    pub session_key: u64,
    pub peer_key: u64,
    /// `None` for `anon`.
    pub principal: Option<u64>,
    pub ts_ms: u64,
    /// `web` for a v1 probe.
    pub surface: Surface,
    /// The 16-hex `credential_hash` on a v2 probe, when a credential was presented.
    pub credential: Option<u64>,
    /// Only a verified credential stands in for the peer.
    pub credential_verified: bool,
    /// The canonical actor the probe's identifiers name, when any is bound.
    pub actor: Option<u64>,
}

/// One rule whose conditions held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub ix: u32,
    pub action: Action,
    /// `min(global, rule)`, or shadow when the rule has expired.
    pub mode: Mode,
    pub proposed: bool,
    /// Where a `rate_limit` would stick; `None` when the scope key is absent
    /// (a principal-scope rule on an anonymous probe).
    pub sticky: Option<(Scope, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictAction {
    Allow,
    Log,
    Watch,
    RateLimit,
    Challenge,
    Block,
}

impl VerdictAction {
    pub fn as_str(self) -> &'static str {
        match self {
            VerdictAction::Allow => "allow",
            VerdictAction::Log => "log",
            VerdictAction::Watch => "watch",
            VerdictAction::RateLimit => "rate_limit",
            VerdictAction::Challenge => "challenge",
            VerdictAction::Block => "block",
        }
    }
}

impl From<Action> for VerdictAction {
    fn from(a: Action) -> Self {
        match a {
            Action::Log => VerdictAction::Log,
            Action::Watch => VerdictAction::Watch,
            Action::RateLimit => VerdictAction::RateLimit,
            Action::Challenge => VerdictAction::Challenge,
            Action::Block => VerdictAction::Block,
        }
    }
}

/// What the check socket answers. The Laravel side reads `action`, `mode`,
/// `rule` and `retry_after`; `generation` and `hash` are for tracing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub action: VerdictAction,
    pub mode: Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u32>,
    pub generation: u64,
    pub hash: Arc<str>,
}

impl Verdict {
    pub fn allow(rs: &RuleSet, mode: Mode) -> Verdict {
        Verdict {
            action: VerdictAction::Allow,
            mode,
            rule: None,
            retry_after: None,
            generation: rs.generation,
            hash: rs.hash_hex.clone(),
        }
    }
}

#[derive(Debug)]
pub struct Outcome {
    pub verdict: Verdict,
    /// Every rule that held, proposed ones included, in candidate order.
    pub hits: SmallVec<[Hit; 4]>,
    /// Index into `hits` of the rule that produced the verdict.
    pub winner: Option<usize>,
}

/// Each scope's window, fetched at most once per probe.
struct Fetched<'a> {
    windows: &'a Windows,
    keys: [Option<u64>; 5],
    refs: [Option<Option<Ref<'a, u64, Window>>>; 5],
}

impl<'a> Fetched<'a> {
    fn new(windows: &'a Windows, probe: &Probe) -> Self {
        // A presented credential is the identity: behind it one address is
        // many users, so the peer window reads as empty and no rule can
        // rate-limit a partner's IP. Without a credential (an unauthenticated
        // scanner on api, say) the peer applies exactly as on web.
        let peer =
            (!(probe.credential.is_some() && probe.credential_verified)).then_some(probe.peer_key);
        Fetched {
            windows,
            keys: [
                Some(probe.session_key),
                peer,
                probe.principal,
                probe.credential,
                probe.actor,
            ],
            refs: [None, None, None, None, None],
        }
    }

    #[inline]
    fn key(&self, scope: Scope) -> Option<u64> {
        self.keys[scope as usize]
    }

    #[inline]
    fn get(&mut self, scope: Scope) -> Option<&Window> {
        let i = scope as usize;
        if self.refs[i].is_none() {
            let fetched = match (scope, self.keys[i]) {
                (_, None) => None,
                (Scope::Session, Some(k)) => self.windows.session(k),
                (Scope::Peer, Some(k)) => self.windows.peer(k),
                (Scope::Principal, Some(k)) => self.windows.principal(k),
                (Scope::Credential, Some(k)) => self.windows.credential(k),
                (Scope::Actor, Some(k)) => self.windows.actor(k),
            };
            self.refs[i] = Some(fetched);
        }
        self.refs[i].as_ref().and_then(|r| r.as_deref())
    }
}

pub fn eval(
    rs: &RuleSet,
    syms: &Symbols,
    windows: &Windows,
    probe: &Probe,
    global: Mode,
    now_s: i64,
) -> Outcome {
    let route_sym = syms.get(probe.route);
    let mut fetched = Fetched::new(windows, probe);
    let mut hits: SmallVec<[Hit; 4]> = SmallVec::new();
    let by_route: &[u32] = route_sym
        .and_then(|r| rs.by_route.get(&r))
        .map_or(&[], |v| v.as_slice());

    for &ix in by_route.iter().chain(rs.wildcard.iter()) {
        let c = &rs.rules[ix as usize];
        if c.verbs & probe.verb.bit() == 0
            || c.surfaces & probe.surface.bit() == 0
            || !c.principal.accepts(probe.principal)
        {
            continue;
        }
        let mut mode = global.min(c.mode);
        if c.expires_at.is_some_and(|e| e <= now_s) {
            mode = mode.min(Mode::Shadow);
        }
        if !c
            .conds
            .iter()
            .all(|cond| holds(cond, route_sym, probe, &mut fetched))
        {
            continue;
        }
        hits.push(Hit {
            ix,
            action: c.action,
            mode,
            proposed: c.proposed,
            sticky: fetched.key(c.sticky_scope).map(|k| (c.sticky_scope, k)),
        });
    }

    // Highest action wins; ties go to the lowest ix (rules are sorted by id).
    let mut winner: Option<usize> = None;
    for (i, h) in hits.iter().enumerate() {
        if h.proposed {
            continue;
        }
        let better = match winner {
            None => true,
            Some(w) => {
                h.action > hits[w].action || (h.action == hits[w].action && h.ix < hits[w].ix)
            }
        };
        if better {
            winner = Some(i);
        }
    }

    let verdict = match winner {
        None => Verdict::allow(rs, global),
        Some(i) => {
            let h = &hits[i];
            let c = &rs.rules[h.ix as usize];
            Verdict {
                action: h.action.into(),
                mode: h.mode,
                rule: Some(rs.meta[h.ix as usize].id.clone()),
                retry_after: (h.action == Action::RateLimit).then_some(c.retry_after_s),
                generation: rs.generation,
                hash: rs.hash_hex.clone(),
            }
        }
    };
    Outcome {
        verdict,
        hits,
        winner,
    }
}

#[inline]
fn holds(cond: &CCond, route_sym: Option<Sym>, probe: &Probe, f: &mut Fetched) -> bool {
    let oldest_ok = cond
        .window_ms
        .map_or(0, |ms| probe.ts_ms.saturating_sub(ms));
    let w = f.get(cond.scope);
    match &cond.test {
        CTest::Count {
            f: filter,
            gte,
            lte,
        } => {
            let mut n: u32 = 0;
            if let Some(w) = w {
                for t in w.newest() {
                    if t.ts_ms < oldest_ok {
                        break;
                    }
                    if filter.matches(t) {
                        n += 1;
                        if lte.is_none() && gte.is_some_and(|g| n >= g) {
                            break;
                        }
                    }
                }
            }
            gte.is_none_or(|g| n >= g) && lte.is_none_or(|l| n <= l)
        }
        CTest::Distinct {
            field,
            model,
            gte,
            filter,
        } => {
            let mut seen: SmallVec<[u64; WINDOW_TURNS]> = SmallVec::new();
            if let Some(w) = w {
                'turns: for t in w.newest() {
                    if t.ts_ms < oldest_ok {
                        break;
                    }
                    if filter.as_ref().is_some_and(|f| !f.matches(t)) {
                        continue;
                    }
                    match field {
                        DistinctField::Route => push_if_absent(&mut seen, t.route.0 as u64),
                        DistinctField::Credential => {
                            if let Some(c) = t.credential {
                                push_if_absent(&mut seen, c);
                            }
                        }
                        DistinctField::BoundId => {
                            for (m, id) in &t.bound {
                                if model.is_some_and(|only| only != *m) {
                                    continue;
                                }
                                push_if_absent(&mut seen, ((m.0 as u64) << 32) | *id as u64);
                                if seen.len() as u32 >= *gte {
                                    break 'turns;
                                }
                            }
                        }
                    }
                    if seen.len() as u32 >= *gte {
                        break;
                    }
                }
            }
            seen.len() as u32 >= *gte
        }
        CTest::Sequence(routes) => {
            let k = routes.len();
            if k == 0 || route_sym != Some(routes[k - 1]) {
                return false;
            }
            match w {
                Some(w) if w.len() >= k - 1 => w
                    .newest()
                    .take(k - 1)
                    .zip(routes[..k - 1].iter().rev())
                    .all(|(t, r)| t.route == *r),
                _ => false,
            }
        }
    }
}

#[inline]
fn push_if_absent(seen: &mut SmallVec<[u64; WINDOW_TURNS]>, v: u64) {
    if !seen.contains(&v) {
        seen.push(v);
    }
}

#[cfg(test)]
mod tests {
    use super::super::compile::{meta, State};
    use super::super::model::Rule;
    use super::super::windows::{turn, EventKeys, TurnSummary};
    use super::*;

    const NOW_S: i64 = 1_761_600_000;
    const NOW_MS: u64 = 1_761_600_000_000;
    const SESSION: u64 = 0xa1b2c3d4e5f60718;
    const PEER: u64 = 0x0f1e2d3c4b5a6978;

    struct H {
        syms: Symbols,
        windows: Windows,
    }

    impl H {
        fn new() -> H {
            H {
                syms: Symbols::default(),
                windows: Windows::default(),
            }
        }

        fn set(&self, rules: &[(serde_json::Value, State)]) -> RuleSet {
            let entries = rules
                .iter()
                .map(|(v, state)| {
                    let r =
                        Rule::parse(&v.to_string(), NOW_S).unwrap_or_else(|e| panic!("{v}: {e:?}"));
                    let m = meta(&r.id, 1, *state);
                    (r, m)
                })
                .collect();
            RuleSet::compile(entries, &self.syms, 1)
        }

        fn t(&self, ts_ms: u64, route: &str, status: u16) -> TurnSummary {
            turn(ts_ms, self.syms.intern(route), status)
        }

        fn record(&self, session: u64, t: TurnSummary) {
            self.windows.record(
                &EventKeys {
                    session,
                    peer: PEER,
                    principal: None,
                    credential: None,
                    actor: None,
                    cluster: None,
                },
                t,
            );
        }

        fn probe<'a>(&self, verb: Verb, route: &'a str) -> Probe<'a> {
            Probe {
                verb,
                route,
                session_key: SESSION,
                peer_key: PEER,
                principal: None,
                ts_ms: NOW_MS,
                surface: Surface::Web,
                credential: None,
                credential_verified: false,
                actor: None,
            }
        }

        fn eval(&self, rs: &RuleSet, probe: &Probe, global: Mode) -> Outcome {
            eval(rs, &self.syms, &self.windows, probe, global, NOW_S)
        }
    }

    fn rule(
        id: &str,
        action: &str,
        mode: &str,
        route: &str,
        when: serde_json::Value,
    ) -> serde_json::Value {
        let mut v = serde_json::json!({
            "id": id, "note": "t", "mode": mode, "action": action,
            "match": { "route": [route], "verb": ["GET", "POST"], "principal": "any" },
            "origin": { "kind": "operator" }
        });
        if action == "rate_limit" {
            v["retry_after_s"] = 30.into();
        }
        if !when.is_null() {
            v["when"] = when;
        }
        v
    }

    fn login_failed(h: &H, ts_ms: u64) -> TurnSummary {
        let mut t = h.t(ts_ms, "portal.login", 401);
        t.verb = Verb::Post;
        t.auth_event = Some(h.syms.intern("login_failed"));
        t
    }

    #[test]
    fn count_gte_within_window() {
        let h = H::new();
        let rs = h.set(&[(
            rule("otp-burst", "rate_limit", "enforce", "portal.login",
                serde_json::json!({"window_s": 120, "count": {"auth_event": ["login_failed"]}, "gte": 5})),
            State::Active,
        )]);
        let p = h.probe(Verb::Post, "portal.login");
        for i in 0..4 {
            h.record(SESSION, login_failed(&h, NOW_MS - 1000 * (10 - i)));
        }
        let o = h.eval(&rs, &p, Mode::Enforce);
        assert_eq!(o.verdict.action, VerdictAction::Allow);
        assert!(o.hits.is_empty());

        h.record(SESSION, login_failed(&h, NOW_MS - 1000));
        let o = h.eval(&rs, &p, Mode::Enforce);
        assert_eq!(o.verdict.action, VerdictAction::RateLimit);
        assert_eq!(o.verdict.mode, Mode::Enforce);
        assert_eq!(&*o.verdict.rule.clone().unwrap(), "otp-burst");
        assert_eq!(o.verdict.retry_after, Some(30));
        assert_eq!(o.hits[0].sticky, Some((Scope::Session, SESSION)));
        assert_eq!(serde_json::to_value(&o.verdict).unwrap()["retry_after"], 30);
    }

    #[test]
    fn window_edge_excludes_old_turns() {
        let h = H::new();
        let rs = h.set(&[(
            rule("otp-burst", "block", "enforce", "portal.login",
                serde_json::json!({"window_s": 120, "count": {"auth_event": ["login_failed"]}, "gte": 3})),
            State::Active,
        )]);
        h.record(SESSION, login_failed(&h, NOW_MS - 121_000));
        h.record(SESSION, login_failed(&h, NOW_MS - 119_000));
        h.record(SESSION, login_failed(&h, NOW_MS - 1_000));
        assert_eq!(
            h.eval(&rs, &h.probe(Verb::Post, "portal.login"), Mode::Enforce)
                .verdict
                .action,
            VerdictAction::Allow
        );
        h.record(SESSION, login_failed(&h, NOW_MS - 500));
        assert_eq!(
            h.eval(&rs, &h.probe(Verb::Post, "portal.login"), Mode::Enforce)
                .verdict
                .action,
            VerdictAction::Block
        );
    }

    #[test]
    fn lte_zero_over_the_whole_conversation() {
        let h = H::new();
        let rs = h.set(&[(
            rule(
                "visit-without-home",
                "challenge",
                "enforce",
                "api.venues.visit",
                serde_json::json!({"count": {"route": ["home"]}, "lte": 0}),
            ),
            State::Active,
        )]);
        let p = h.probe(Verb::Post, "api.venues.visit");
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Challenge,
            "no window at all"
        );
        h.record(SESSION, h.t(NOW_MS - 5000, "venues.show", 200));
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Challenge
        );
        h.record(SESSION, h.t(NOW_MS - 4000, "home", 200));
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Allow
        );
    }

    #[test]
    fn distinct_bound_ids_across_peer_sessions() {
        let h = H::new();
        let rs = h.set(&[(
            rule(
                "enum",
                "block",
                "enforce",
                "venues.show",
                serde_json::json!({"scope": "peer", "window_s": 600,
                    "distinct": {"field": "bound_id", "model": "Venue"}, "gte": 4}),
            ),
            State::Active,
        )]);
        let venue = h.syms.intern("Venue");
        let other = h.syms.intern("Other");
        for (session, id) in [(1u64, 1u32), (2, 2), (3, 2), (3, 3)] {
            let mut t = h.t(NOW_MS - 1000, "venues.show", 404);
            t.bound.push((venue, id));
            h.record(session, t);
        }
        let mut t = h.t(NOW_MS - 1000, "venues.show", 200);
        t.bound.push((other, 99));
        h.record(1, t);
        let p = h.probe(Verb::Get, "venues.show");
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Allow,
            "3 distinct Venue ids"
        );
        let mut t = h.t(NOW_MS - 500, "venues.show", 404);
        t.bound.push((venue, 4));
        h.record(2, t);
        let o = h.eval(&rs, &p, Mode::Enforce);
        assert_eq!(o.verdict.action, VerdictAction::Block);
        assert_eq!(o.hits[0].sticky, Some((Scope::Peer, PEER)));
    }

    #[test]
    fn distinct_routes_in_session() {
        let h = H::new();
        let rs = h.set(&[(
            rule(
                "wide",
                "watch",
                "enforce",
                "*",
                serde_json::json!({"distinct": {"field": "route"}, "gte": 3}),
            ),
            State::Active,
        )]);
        h.record(SESSION, h.t(NOW_MS - 3000, "home", 200));
        h.record(SESSION, h.t(NOW_MS - 2000, "home", 200));
        h.record(SESSION, h.t(NOW_MS - 1000, "venues.show", 200));
        assert_eq!(
            h.eval(&rs, &h.probe(Verb::Get, "x"), Mode::Enforce)
                .verdict
                .action,
            VerdictAction::Allow
        );
        h.record(SESSION, h.t(NOW_MS - 500, "api.venues.index", 200));
        assert_eq!(
            h.eval(&rs, &h.probe(Verb::Get, "x"), Mode::Enforce)
                .verdict
                .action,
            VerdictAction::Watch
        );
    }

    #[test]
    fn sequence_ends_with_the_probe_route() {
        let h = H::new();
        let rs = h.set(&[(
            rule(
                "seq",
                "challenge",
                "enforce",
                "api.venues.visit",
                serde_json::json!({"sequence": ["home", "portal.login", "api.venues.visit"]}),
            ),
            State::Active,
        )]);
        let p = h.probe(Verb::Post, "api.venues.visit");
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Allow,
            "empty window"
        );
        h.record(SESSION, h.t(NOW_MS - 3000, "home", 200));
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Allow,
            "too short"
        );
        h.record(SESSION, h.t(NOW_MS - 2000, "portal.login", 200));
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Challenge
        );
        h.record(SESSION, h.t(NOW_MS - 1000, "venues.show", 200));
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Allow,
            "newest must match"
        );
        let wrong = h.probe(Verb::Post, "portal.login");
        assert_eq!(
            h.eval(&rs, &wrong, Mode::Enforce).verdict.action,
            VerdictAction::Allow
        );
    }

    #[test]
    fn expired_rule_evaluates_as_shadow() {
        let h = H::new();
        let mut r = rule("old", "block", "enforce", "home", serde_json::Value::Null);
        r["expires_at"] = (NOW_S + 10).into();
        let rs = h.set(&[(r, State::Active)]);
        let p = h.probe(Verb::Get, "home");
        let o = eval(&rs, &h.syms, &h.windows, &p, Mode::Enforce, NOW_S);
        assert_eq!(
            (o.verdict.action, o.verdict.mode),
            (VerdictAction::Block, Mode::Enforce)
        );
        let o = eval(&rs, &h.syms, &h.windows, &p, Mode::Enforce, NOW_S + 10);
        assert_eq!(
            (o.verdict.action, o.verdict.mode),
            (VerdictAction::Block, Mode::Shadow)
        );
        let o = eval(&rs, &h.syms, &h.windows, &p, Mode::Monitor, NOW_S + 10);
        assert_eq!(o.verdict.mode, Mode::Monitor);
    }

    #[test]
    fn proposed_rule_hits_but_never_wins() {
        let h = H::new();
        let rs = h.set(&[
            (
                rule(
                    "proposed-block",
                    "block",
                    "enforce",
                    "home",
                    serde_json::Value::Null,
                ),
                State::Proposed,
            ),
            (
                rule(
                    "real-log",
                    "log",
                    "enforce",
                    "home",
                    serde_json::Value::Null,
                ),
                State::Active,
            ),
        ]);
        let o = h.eval(&rs, &h.probe(Verb::Get, "home"), Mode::Enforce);
        assert_eq!(o.hits.len(), 2);
        assert!(o
            .hits
            .iter()
            .any(|h| h.proposed && h.action == Action::Block));
        assert_eq!(o.verdict.action, VerdictAction::Log);
        assert_eq!(&*o.verdict.rule.unwrap(), "real-log");

        let only = h.set(&[(
            rule(
                "proposed-block",
                "block",
                "enforce",
                "home",
                serde_json::Value::Null,
            ),
            State::Proposed,
        )]);
        let o = h.eval(&only, &h.probe(Verb::Get, "home"), Mode::Enforce);
        assert_eq!(o.hits.len(), 1);
        assert_eq!(o.winner, None);
        assert_eq!(o.verdict.action, VerdictAction::Allow);
    }

    #[test]
    fn severity_then_lowest_ix_wins() {
        let h = H::new();
        let rs = h.set(&[
            (
                rule(
                    "zz-watch",
                    "watch",
                    "enforce",
                    "home",
                    serde_json::Value::Null,
                ),
                State::Active,
            ),
            (
                rule(
                    "mm-challenge",
                    "challenge",
                    "enforce",
                    "home",
                    serde_json::Value::Null,
                ),
                State::Active,
            ),
            (
                rule(
                    "aa-challenge",
                    "challenge",
                    "enforce",
                    "*",
                    serde_json::Value::Null,
                ),
                State::Active,
            ),
            (
                rule("bb-log", "log", "enforce", "*", serde_json::Value::Null),
                State::Active,
            ),
        ]);
        let o = h.eval(&rs, &h.probe(Verb::Get, "home"), Mode::Enforce);
        assert_eq!(o.hits.len(), 4);
        assert_eq!(&*o.verdict.rule.unwrap(), "aa-challenge");
        let o = h.eval(&rs, &h.probe(Verb::Get, "unknown.route"), Mode::Enforce);
        assert_eq!(o.hits.len(), 2, "only wildcard rules see an unknown route");
        assert_eq!(&*o.verdict.rule.unwrap(), "aa-challenge");
    }

    #[test]
    fn mode_downgrade_matrix() {
        let h = H::new();
        for (global, rule_mode, want) in [
            (Mode::Monitor, Mode::Monitor, Mode::Monitor),
            (Mode::Monitor, Mode::Shadow, Mode::Monitor),
            (Mode::Monitor, Mode::Enforce, Mode::Monitor),
            (Mode::Shadow, Mode::Monitor, Mode::Monitor),
            (Mode::Shadow, Mode::Shadow, Mode::Shadow),
            (Mode::Shadow, Mode::Enforce, Mode::Shadow),
            (Mode::Enforce, Mode::Monitor, Mode::Monitor),
            (Mode::Enforce, Mode::Shadow, Mode::Shadow),
            (Mode::Enforce, Mode::Enforce, Mode::Enforce),
        ] {
            let rs = h.set(&[(
                rule(
                    "mode-r",
                    "block",
                    rule_mode.as_str(),
                    "home",
                    serde_json::Value::Null,
                ),
                State::Active,
            )]);
            let o = h.eval(&rs, &h.probe(Verb::Get, "home"), global);
            assert_eq!(o.verdict.mode, want, "global {global:?} rule {rule_mode:?}");
            let o = h.eval(&rs, &h.probe(Verb::Get, "other"), global);
            assert_eq!(
                (o.verdict.action, o.verdict.mode),
                (VerdictAction::Allow, global),
                "allow carries global"
            );
        }
    }

    #[test]
    fn verb_and_principal_gates() {
        let h = H::new();
        let mut anon_only = rule(
            "anon-only",
            "log",
            "enforce",
            "home",
            serde_json::Value::Null,
        );
        anon_only["match"]["principal"] = "anon".into();
        anon_only["match"]["verb"] = serde_json::json!(["GET"]);
        let mut auth_only = rule(
            "auth-only",
            "watch",
            "enforce",
            "home",
            serde_json::Value::Null,
        );
        auth_only["match"]["principal"] = "authenticated".into();
        let rs = h.set(&[(anon_only, State::Active), (auth_only, State::Active)]);
        let o = h.eval(&rs, &h.probe(Verb::Get, "home"), Mode::Enforce);
        assert_eq!(o.verdict.action, VerdictAction::Log);
        let o = h.eval(&rs, &h.probe(Verb::Post, "home"), Mode::Enforce);
        assert_eq!(o.verdict.action, VerdictAction::Allow);
        let mut p = h.probe(Verb::Get, "home");
        p.principal = Some(42);
        let o = h.eval(&rs, &p, Mode::Enforce);
        assert_eq!(o.verdict.action, VerdictAction::Watch);
    }

    #[test]
    fn principal_scope_on_anon_probe_reads_an_empty_window() {
        let h = H::new();
        let rs = h.set(&[
            (
                rule(
                    "p-gte",
                    "block",
                    "enforce",
                    "home",
                    serde_json::json!({"scope": "principal", "count": {}, "gte": 1}),
                ),
                State::Active,
            ),
            (
                rule(
                    "p-lte",
                    "log",
                    "enforce",
                    "home",
                    serde_json::json!({"scope": "principal", "count": {}, "lte": 0}),
                ),
                State::Active,
            ),
        ]);
        let o = h.eval(&rs, &h.probe(Verb::Get, "home"), Mode::Enforce);
        assert_eq!(o.hits.len(), 1);
        assert_eq!(o.verdict.action, VerdictAction::Log);
        assert_eq!(o.hits[0].sticky, None);
    }

    #[test]
    fn all_conditions_must_hold() {
        let h = H::new();
        let rs = h.set(&[(
            rule(
                "both",
                "block",
                "enforce",
                "venues.show",
                serde_json::json!({"all": [
                    {"count": {"status": ["4xx"]}, "gte": 2},
                    {"scope": "peer", "count": {"exception": ["ModelNotFoundException"]}, "gte": 1}
                ]}),
            ),
            State::Active,
        )]);
        let p = h.probe(Verb::Get, "venues.show");
        h.record(SESSION, h.t(NOW_MS - 2000, "venues.show", 404));
        h.record(SESSION, h.t(NOW_MS - 1500, "venues.show", 403));
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Allow
        );
        let mut t = h.t(NOW_MS - 1000, "venues.show", 404);
        t.exception = Some(h.syms.intern("ModelNotFoundException"));
        h.record(999, t);
        assert_eq!(
            h.eval(&rs, &p, Mode::Enforce).verdict.action,
            VerdictAction::Block
        );
    }

    #[test]
    fn verdict_wire_shape() {
        let h = H::new();
        let rs = h.set(&[]);
        let o = h.eval(&rs, &h.probe(Verb::Get, "home"), Mode::Monitor);
        let v = serde_json::to_value(&o.verdict).unwrap();
        assert_eq!(v["action"], "allow");
        assert_eq!(v["mode"], "monitor");
        assert!(v.get("rule").is_none() && v.get("retry_after").is_none());
        assert_eq!(v["generation"], 1);
        assert_eq!(v["hash"].as_str().unwrap().len(), 64);
    }
}
