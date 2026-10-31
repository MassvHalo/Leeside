//! `Rule` -> `Compiled`, `Vec<Rule>` -> `RuleSet`. Everything the hot path
//! touches is fixed-size and interned here, once, so eval does no string
//! work and no allocation.

use super::model::{
    Action, Condition, DistinctField, Mode, Origin, PrincipalKind, Rule, Scope, StatusClass,
    StatusSel, Surface, TurnFilter, ValidationSel, Verb,
};
use super::symbols::{Sym, Symbols};
use super::windows::TurnSummary;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::Arc;

/// How long a `block` without `block_min` sticks: the conversation's 24 h cap.
pub const BLOCK_TTL_S: u32 = 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Proposed,
    Active,
    Retired,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Proposed => "proposed",
            State::Active => "active",
            State::Retired => "retired",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        match s {
            "proposed" => Some(State::Proposed),
            "active" => Some(State::Active),
            "retired" => Some(State::Retired),
            _ => None,
        }
    }
}

/// What a verdict or a stats row reports about a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: Arc<str>,
    pub version: u32,
    pub note: String,
    pub origin: Origin,
    pub state: State,
}

/// A sorted small set of symbols with binary search.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymSet(SmallVec<[Sym; 8]>);

impl SymSet {
    pub fn from_strs<'a>(strs: impl IntoIterator<Item = &'a str>, syms: &Symbols) -> SymSet {
        let mut v: SmallVec<[Sym; 8]> = strs.into_iter().map(|s| syms.intern(s)).collect();
        v.sort_unstable();
        v.dedup();
        SymSet(v)
    }

    #[inline]
    pub fn contains(&self, s: Sym) -> bool {
        self.0.binary_search(&s).is_ok()
    }
}

/// A 640-bit bitset over status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSet([u64; 10]);

impl StatusSet {
    pub fn from_sels(sels: &[StatusSel]) -> StatusSet {
        let mut set = StatusSet([0; 10]);
        for sel in sels {
            match sel {
                StatusSel::Code(c) => set.set(*c),
                StatusSel::Class(StatusClass::C4xx) => (400..500).for_each(|c| set.set(c)),
                StatusSel::Class(StatusClass::C5xx) => (500..600).for_each(|c| set.set(c)),
            }
        }
        set
    }

    fn set(&mut self, code: u16) {
        let c = code as usize;
        if c < 640 {
            self.0[c / 64] |= 1 << (c % 64);
        }
    }

    #[inline]
    pub fn contains(&self, code: u16) -> bool {
        let c = code as usize;
        c < 640 && self.0[c / 64] & (1 << (c % 64)) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValSel {
    Any,
    Fields(SymSet),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CFilter {
    pub routes: Option<SymSet>,
    pub verbs: Option<u8>,
    pub status: Option<StatusSet>,
    pub validation: Option<ValSel>,
    pub exceptions: Option<SymSet>,
    pub auth: Option<SymSet>,
    pub shapes: Option<SymSet>,
    pub bound_models: Option<SymSet>,
}

impl CFilter {
    pub fn compile(f: &TurnFilter, syms: &Symbols) -> CFilter {
        let set = |l: &Option<Vec<String>>| {
            l.as_ref()
                .map(|l| SymSet::from_strs(l.iter().map(String::as_str), syms))
        };
        CFilter {
            routes: set(&f.route),
            verbs: f
                .verb
                .as_ref()
                .map(|v| v.iter().fold(0u8, |m, v| m | v.bit())),
            status: f.status.as_ref().map(|s| StatusSet::from_sels(s)),
            validation: f.validation_failed.as_ref().map(|v| match v {
                ValidationSel::Any(_) => ValSel::Any,
                ValidationSel::Fields(fields) => {
                    ValSel::Fields(SymSet::from_strs(fields.iter().map(String::as_str), syms))
                }
            }),
            exceptions: set(&f.exception),
            auth: set(&f.auth_event),
            shapes: set(&f.req_shape),
            bound_models: set(&f.bound_model),
        }
    }

    /// AND across fields, OR inside each set.
    #[inline]
    pub fn matches(&self, t: &TurnSummary) -> bool {
        self.routes.as_ref().is_none_or(|s| s.contains(t.route))
            && self.verbs.is_none_or(|m| m & t.verb.bit() != 0)
            && self.status.as_ref().is_none_or(|s| s.contains(t.status))
            && self.validation.as_ref().is_none_or(|v| match v {
                ValSel::Any => !t.validation_fields.is_empty(),
                ValSel::Fields(s) => t.validation_fields.iter().any(|f| s.contains(*f)),
            })
            && self
                .exceptions
                .as_ref()
                .is_none_or(|s| t.exception.is_some_and(|x| s.contains(x)))
            && self
                .auth
                .as_ref()
                .is_none_or(|s| t.auth_event.is_some_and(|a| s.contains(a)))
            && self.shapes.as_ref().is_none_or(|s| s.contains(t.req_shape))
            && self
                .bound_models
                .as_ref()
                .is_none_or(|s| t.bound.iter().any(|(m, _)| s.contains(*m)))
    }
}

// `Count` carries its filter inline: the scan reads it per turn, and a box
// would add a pointer chase to the hot path for a few hundred bytes per rule.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CTest {
    Count {
        f: CFilter,
        gte: Option<u32>,
        lte: Option<u32>,
    },
    Distinct {
        field: DistinctField,
        model: Option<Sym>,
        gte: u32,
    },
    /// Ends with the route the probe must carry.
    Sequence(SmallVec<[Sym; 8]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CCond {
    pub scope: Scope,
    pub window_ms: Option<u64>,
    pub test: CTest,
}

impl CCond {
    fn compile(c: &Condition, syms: &Symbols) -> CCond {
        if let Some(f) = &c.count {
            CCond {
                scope: c.scope(),
                window_ms: c.window_s.map(|w| w as u64 * 1000),
                test: CTest::Count {
                    f: CFilter::compile(f, syms),
                    gte: c.gte,
                    lte: c.lte,
                },
            }
        } else if let Some(d) = &c.distinct {
            CCond {
                scope: c.scope(),
                window_ms: c.window_s.map(|w| w as u64 * 1000),
                test: CTest::Distinct {
                    field: d.field,
                    model: d.model.as_deref().map(|m| syms.intern(m)),
                    gte: c.gte.unwrap_or(1),
                },
            }
        } else {
            let seq = c.sequence.as_deref().unwrap_or(&[]);
            CCond {
                scope: Scope::Session,
                window_ms: None,
                test: CTest::Sequence(seq.iter().map(|r| syms.intern(r)).collect()),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    /// Index into `RuleSet.rules` and `.meta`.
    pub ix: u32,
    pub verbs: u8,
    /// Bitmask over `Surface`; `match.surface` empty compiles to all four.
    pub surfaces: u8,
    pub principal: PrincipalKind,
    pub conds: SmallVec<[CCond; 3]>,
    pub action: Action,
    pub mode: Mode,
    pub retry_after_s: u32,
    /// How long a `block` sticks to the session.
    pub block_ttl_s: u32,
    pub expires_at: Option<i64>,
    /// Evaluated for stats only, never the verdict.
    pub proposed: bool,
    /// Where a `rate_limit` sticks: the first condition's scope.
    pub sticky_scope: Scope,
}

pub struct RuleSet {
    pub rules: Vec<Compiled>,
    pub meta: Vec<RuleMeta>,
    pub by_route: HashMap<Sym, SmallVec<[u32; 4]>>,
    pub wildcard: SmallVec<[u32; 8]>,
    /// Bumped on every reload within a process.
    pub generation: u64,
    /// sha256 over sorted `id:version` lines; stable across restarts.
    pub hash: [u8; 32],
    pub hash_hex: Arc<str>,
}

impl RuleSet {
    pub fn empty(generation: u64) -> RuleSet {
        RuleSet::compile(Vec::new(), &Symbols::default(), generation)
    }

    /// Rules are sorted by id first, so `ix` order (the tie-break) is
    /// deterministic across hosts and restarts.
    pub fn compile(mut entries: Vec<(Rule, RuleMeta)>, syms: &Symbols, generation: u64) -> RuleSet {
        entries.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        let mut hasher = Sha256::new();
        let mut rules = Vec::with_capacity(entries.len());
        let mut meta = Vec::with_capacity(entries.len());
        let mut by_route: HashMap<Sym, SmallVec<[u32; 4]>> = HashMap::new();
        let mut wildcard: SmallVec<[u32; 8]> = SmallVec::new();
        for (ix, (rule, m)) in entries.into_iter().enumerate() {
            let ix = ix as u32;
            hasher.update(rule.id.as_bytes());
            hasher.update(b":");
            hasher.update(m.version.to_string().as_bytes());
            hasher.update(b"\n");
            if rule.matcher.is_wildcard() {
                wildcard.push(ix);
            } else {
                for r in &rule.matcher.route {
                    let list = by_route.entry(syms.intern(r)).or_default();
                    if !list.contains(&ix) {
                        list.push(ix);
                    }
                }
            }
            let conds: SmallVec<[CCond; 3]> = rule
                .when
                .as_ref()
                .map(|w| {
                    w.conditions()
                        .iter()
                        .map(|c| CCond::compile(c, syms))
                        .collect()
                })
                .unwrap_or_default();
            rules.push(Compiled {
                ix,
                verbs: rule.matcher.verb.iter().fold(0u8, |acc, v| acc | v.bit()),
                surfaces: Surface::mask(&rule.matcher.surface),
                principal: rule.matcher.principal,
                sticky_scope: conds.first().map_or(Scope::Session, |c| c.scope),
                conds,
                action: rule.action,
                mode: rule.mode,
                retry_after_s: rule.retry_after_s.unwrap_or(0),
                block_ttl_s: rule.block_min.map_or(BLOCK_TTL_S, |m| m * 60),
                expires_at: rule.expires_at,
                proposed: m.state == State::Proposed,
            });
            meta.push(m);
        }
        let hash: [u8; 32] = hasher.finalize().into();
        RuleSet {
            rules,
            meta,
            by_route,
            wildcard,
            generation,
            hash,
            hash_hex: Arc::from(hex(&hash)),
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every verb a rule could match, for callers that build masks.
    pub fn verb_mask(verbs: &[Verb]) -> u8 {
        verbs.iter().fold(0u8, |acc, v| acc | v.bit())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
pub(crate) fn meta(id: &str, version: u32, state: State) -> RuleMeta {
    RuleMeta {
        id: Arc::from(id),
        version,
        note: String::new(),
        origin: Origin {
            kind: super::model::OriginKind::Operator,
            incident: None,
            model: None,
        },
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_761_600_000;

    fn rule(id: &str, routes: &[&str]) -> Rule {
        Rule::parse(
            &serde_json::json!({
                "id": id, "note": "t", "mode": "shadow", "action": "watch",
                "match": { "route": routes, "verb": ["GET"], "principal": "any" },
                "origin": { "kind": "operator" }
            })
            .to_string(),
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn sorted_by_id_indexed_by_route_and_hashed_stably() {
        let syms = Symbols::default();
        let set = |order: [&str; 3]| {
            RuleSet::compile(
                vec![
                    (rule(order[0], &["*"]), meta(order[0], 1, State::Active)),
                    (
                        rule(order[1], &["home", "venues.show"]),
                        meta(order[1], 2, State::Proposed),
                    ),
                    (rule(order[2], &["home"]), meta(order[2], 1, State::Active)),
                ],
                &syms,
                7,
            )
        };
        let a = set(["zed", "alpha", "mid"]);
        assert_eq!(
            a.meta.iter().map(|m| &*m.id).collect::<Vec<_>>(),
            ["alpha", "mid", "zed"]
        );
        assert_eq!(a.wildcard.as_slice(), &[2]);
        assert_eq!(a.by_route[&syms.get("home").unwrap()].as_slice(), &[0, 1]);
        assert_eq!(
            a.by_route[&syms.get("venues.show").unwrap()].as_slice(),
            &[0]
        );
        assert!(a.rules[0].proposed && !a.rules[1].proposed);
        assert_eq!(a.generation, 7);
        assert_eq!(a.hash_hex.len(), 64);

        let b = RuleSet::compile(
            vec![
                (rule("mid", &["home"]), meta("mid", 1, State::Active)),
                (
                    rule("alpha", &["home", "venues.show"]),
                    meta("alpha", 2, State::Active),
                ),
                (rule("zed", &["*"]), meta("zed", 1, State::Active)),
            ],
            &Symbols::default(),
            1,
        );
        assert_eq!(a.hash, b.hash, "hash depends on ids and versions only");
        let c = RuleSet::compile(
            vec![(rule("mid", &["home"]), meta("mid", 2, State::Active))],
            &syms,
            1,
        );
        assert_ne!(a.hash, c.hash);
    }

    #[test]
    fn status_set_classes_and_codes() {
        let s = StatusSet::from_sels(&[StatusSel::Code(200), StatusSel::Class(StatusClass::C5xx)]);
        assert!(s.contains(200) && s.contains(500) && s.contains(599));
        assert!(!s.contains(201) && !s.contains(499) && !s.contains(600) && !s.contains(u16::MAX));
        let four = StatusSet::from_sels(&[StatusSel::Class(StatusClass::C4xx)]);
        assert!(four.contains(400) && four.contains(499) && !four.contains(500));
    }

    #[test]
    fn filter_fields_are_anded_and_lists_ored() {
        let syms = Symbols::default();
        let f: TurnFilter = serde_json::from_value(serde_json::json!({
            "route": ["a", "b"], "status": ["4xx"], "validation_failed": ["otp"],
            "exception": ["ValidationException"], "bound_model": ["Venue"]
        }))
        .unwrap();
        let cf = CFilter::compile(&f, &syms);
        let mut t = super::super::windows::turn(0, syms.intern("b"), 422);
        assert!(
            !cf.matches(&t),
            "no validation field, no exception, no bound"
        );
        t.validation_fields.push(syms.intern("otp"));
        t.exception = Some(syms.intern("ValidationException"));
        t.bound.push((syms.intern("Venue"), 1));
        assert!(cf.matches(&t));
        t.status = 200;
        assert!(!cf.matches(&t));
        t.status = 404;
        t.route = syms.intern("c");
        assert!(!cf.matches(&t));
        t.route = syms.intern("a");
        t.validation_fields.clear();
        t.validation_fields.push(syms.intern("phone"));
        assert!(!cf.matches(&t));
        assert!(
            CFilter::default().matches(&t),
            "an empty filter matches everything"
        );
    }
}
