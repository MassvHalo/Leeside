//! The rule document, one to one with docs/rules.md Part 1. Every struct
//! rejects unknown fields so a half-understood rule never loads; the same
//! structs derive `JsonSchema`, so the grammar Spark is prompted with is the
//! grammar the engine accepts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The mode ladder. Eval relies on the `Ord`: monitor < shadow < enforce.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Monitor,
    Shadow,
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Monitor => "monitor",
            Mode::Shadow => "shadow",
            Mode::Enforce => "enforce",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "monitor" => Some(Mode::Monitor),
            "shadow" => Some(Mode::Shadow),
            "enforce" => Some(Mode::Enforce),
            _ => None,
        }
    }
}

/// What a verdict carries. `allow` is never written in a rule: it is the
/// absence of a hit. Eval relies on the `Ord`: log < ... < block.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Log,
    Watch,
    RateLimit,
    Challenge,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Log => "log",
            Action::Watch => "watch",
            Action::RateLimit => "rate_limit",
            Action::Challenge => "challenge",
            Action::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verb {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl Verb {
    pub const ALL: [Verb; 7] = [
        Verb::Get,
        Verb::Post,
        Verb::Put,
        Verb::Patch,
        Verb::Delete,
        Verb::Head,
        Verb::Options,
    ];

    /// One bit per verb, for the compiled verb mask.
    #[inline]
    pub fn bit(self) -> u8 {
        1 << (self as u8)
    }

    pub fn parse(s: &str) -> Option<Verb> {
        match s {
            "GET" => Some(Verb::Get),
            "POST" => Some(Verb::Post),
            "PUT" => Some(Verb::Put),
            "PATCH" => Some(Verb::Patch),
            "DELETE" => Some(Verb::Delete),
            "HEAD" => Some(Verb::Head),
            "OPTIONS" => Some(Verb::Options),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Get => "GET",
            Verb::Post => "POST",
            Verb::Put => "PUT",
            Verb::Patch => "PATCH",
            Verb::Delete => "DELETE",
            Verb::Head => "HEAD",
            Verb::Options => "OPTIONS",
        }
    }
}

/// Which window a condition reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Session,
    Peer,
    Principal,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Session => "session",
            Scope::Peer => "peer",
            Scope::Principal => "principal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Any,
    Anon,
    Authenticated,
}

impl PrincipalKind {
    /// `principal` is `None` for an anonymous probe, `Some(hash)` otherwise.
    #[inline]
    pub fn accepts(self, principal: Option<u64>) -> bool {
        match self {
            PrincipalKind::Any => true,
            PrincipalKind::Anon => principal.is_none(),
            PrincipalKind::Authenticated => principal.is_some(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    Install,
    Operator,
    Spark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DistinctField {
    BoundId,
    Route,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `^[a-z0-9][a-z0-9-]{2,63}$`; the primary key, never changes across versions.
    pub id: String,
    /// 1..=200 chars; what the rule is for.
    pub note: String,
    /// The rule's own ceiling; the effective mode is `min(global, rule)`.
    pub mode: Mode,
    pub action: Action,
    /// 1..=86400; required with `rate_limit`, rejected otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
    /// 1..=1440 minutes a `block` sticks to the session; only with `block`.
    /// Absent = the conversation's 24 h cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_min: Option<u32>,
    /// Which probes the rule is evaluated for.
    #[serde(rename = "match")]
    pub matcher: Match,
    /// What the window must show; absent means the rule fires on every matching probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<When>,
    /// Unix seconds; past this the rule evaluates as shadow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// 1..=16 route templates, exact match; `"*"` means any and is allowed only alone.
    pub route: Vec<String>,
    /// 1..=8 verbs.
    pub verb: Vec<Verb>,
    pub principal: PrincipalKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub kind: OriginKind,
    /// The incident id behind a Spark proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident: Option<String>,
    /// The model name that wrote the proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// One condition, or `{ "all": [c1, c2, c3] }`. `All` is listed first so an
/// `all` object is never read as a `Condition` with an unknown field.
// Document types, not hot: the size skew between the variants is irrelevant.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields)]
pub enum When {
    All { all: Vec<Condition> },
    One(Condition),
}

impl When {
    pub fn conditions(&self) -> &[Condition] {
        match self {
            When::All { all } => all,
            When::One(c) => std::slice::from_ref(c),
        }
    }
}

/// Exactly one of `count`, `distinct`, `sequence`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// Defaults to `session`. Rejected with `sequence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// 1..=86400; turns older than `probe.ts - window_s` are ignored. Absent = the whole held window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_s: Option<u32>,
    /// Number of earlier turns in the window matching the filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<TurnFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gte: Option<u32>,
    /// Only with `count`; `lte: 0` means "no such turn".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lte: Option<u32>,
    /// Number of distinct values across the window; takes `gte` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct: Option<Distinct>,
    /// 2..=8 route templates; the probe's route is the last entry and the
    /// newest k-1 turns in the session match the rest, in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<Vec<String>>,
}

impl Condition {
    #[inline]
    pub fn scope(&self) -> Scope {
        self.scope.unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Distinct {
    pub field: DistinctField,
    /// Narrows `bound_id` to one model basename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Every field optional; OR inside a list, AND across fields. An empty
/// filter matches every turn.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<Vec<Verb>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<StatusSel>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_failed: Option<ValidationSel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_event: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_shape: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_model: Option<Vec<String>>,
}

/// A status code 0..=599 or a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum StatusSel {
    Code(u16),
    Class(StatusClass),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum StatusClass {
    #[serde(rename = "4xx")]
    C4xx,
    #[serde(rename = "5xx")]
    C5xx,
}

/// `true` (failed on any field) or a list of field names (failed on any of them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ValidationSel {
    Any(bool),
    Fields(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

pub const MAX_ROUTES: usize = 16;
pub const MAX_VERBS: usize = 8;
pub const MAX_CONDITIONS: usize = 3;
pub const MAX_SEQUENCE: usize = 8;
pub const MAX_FILTER_LIST: usize = 16;
pub const MAX_WINDOW_S: u32 = 86_400;
/// A window holds 64 turns, so a larger distinct count can never hold.
pub const MAX_DISTINCT: u32 = 64;
pub const MAX_RETRY_AFTER_S: u32 = 86_400;
pub const MAX_BLOCK_MIN: u32 = 1_440;
pub const MAX_NOTE_CHARS: usize = 200;
pub const MAX_STRING_CHARS: usize = 256;

#[derive(Default)]
struct Errs(Vec<ValidationError>);

impl Errs {
    fn push(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(ValidationError {
            path: path.into(),
            message: message.into(),
        });
    }
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    (3..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn check_list(path: &str, list: &[String], max: usize, e: &mut Errs) {
    if list.is_empty() || list.len() > max {
        e.push(path, format!("must have 1 to {max} entries"));
    }
    for (i, s) in list.iter().enumerate() {
        let n = s.chars().count();
        if n == 0 || n > MAX_STRING_CHARS {
            e.push(
                format!("{path}[{i}]"),
                format!("must be 1 to {MAX_STRING_CHARS} characters"),
            );
        }
    }
}

impl Rule {
    /// Deserialise and validate in one step; the error list is the parse
    /// error or the validation errors.
    pub fn parse(json: &str, now: i64) -> Result<Rule, Vec<ValidationError>> {
        let rule: Rule = serde_json::from_str(json).map_err(|err| {
            vec![ValidationError {
                path: String::new(),
                message: err.to_string(),
            }]
        })?;
        let errors = rule.validate(now);
        if errors.is_empty() {
            Ok(rule)
        } else {
            Err(errors)
        }
    }

    /// Every limit from docs/rules.md. Empty means valid. `now` is unix
    /// seconds, for `expires_at`.
    pub fn validate(&self, now: i64) -> Vec<ValidationError> {
        let mut e = Errs::default();
        if !valid_id(&self.id) {
            e.push("id", "must match ^[a-z0-9][a-z0-9-]{2,63}$");
        }
        let note_len = self.note.chars().count();
        if note_len == 0 || note_len > MAX_NOTE_CHARS {
            e.push("note", format!("must be 1 to {MAX_NOTE_CHARS} characters"));
        }
        match (self.action, self.retry_after_s) {
            (Action::RateLimit, None) => e.push("retry_after_s", "required with action rate_limit"),
            (Action::RateLimit, Some(s)) if !(1..=MAX_RETRY_AFTER_S).contains(&s) => {
                e.push("retry_after_s", format!("must be 1 to {MAX_RETRY_AFTER_S}"))
            }
            (_, Some(_)) if self.action != Action::RateLimit => {
                e.push("retry_after_s", "only allowed with action rate_limit")
            }
            _ => {}
        }
        match (self.action, self.block_min) {
            (Action::Block, Some(m)) if !(1..=MAX_BLOCK_MIN).contains(&m) => {
                e.push("block_min", format!("must be 1 to {MAX_BLOCK_MIN}"))
            }
            (_, Some(_)) if self.action != Action::Block => {
                e.push("block_min", "only allowed with action block")
            }
            _ => {}
        }
        self.matcher.validate(&mut e);
        match &self.when {
            None => {}
            Some(When::One(c)) => c.validate("when", &self.matcher, &mut e),
            Some(When::All { all }) => {
                if all.is_empty() || all.len() > MAX_CONDITIONS {
                    e.push(
                        "when.all",
                        format!("must have 1 to {MAX_CONDITIONS} conditions"),
                    );
                }
                for (i, c) in all.iter().enumerate() {
                    c.validate(&format!("when.all[{i}]"), &self.matcher, &mut e);
                }
            }
        }
        if let Some(x) = self.expires_at {
            if x <= now {
                e.push("expires_at", "must be in the future");
            }
        }
        if let Some(m) = &self.origin.model {
            if m.is_empty() || m.chars().count() > MAX_STRING_CHARS {
                e.push(
                    "origin.model",
                    format!("must be 1 to {MAX_STRING_CHARS} characters"),
                );
            }
        }
        if let Some(m) = &self.origin.incident {
            if m.is_empty() || m.chars().count() > MAX_STRING_CHARS {
                e.push(
                    "origin.incident",
                    format!("must be 1 to {MAX_STRING_CHARS} characters"),
                );
            }
        }
        e.0
    }
}

impl Match {
    pub fn is_wildcard(&self) -> bool {
        self.route.len() == 1 && self.route[0] == "*"
    }

    fn validate(&self, e: &mut Errs) {
        check_list("match.route", &self.route, MAX_ROUTES, e);
        if self.route.len() > 1 && self.route.iter().any(|r| r == "*") {
            e.push("match.route", "\"*\" is allowed only alone");
        }
        if self.verb.is_empty() || self.verb.len() > MAX_VERBS {
            e.push("match.verb", format!("must have 1 to {MAX_VERBS} entries"));
        }
        let mut seen = 0u8;
        for (i, v) in self.verb.iter().enumerate() {
            if seen & v.bit() != 0 {
                e.push(format!("match.verb[{i}]"), "duplicate verb");
            }
            seen |= v.bit();
        }
    }
}

impl Condition {
    fn validate(&self, path: &str, matcher: &Match, e: &mut Errs) {
        let kinds = self.count.is_some() as u8
            + self.distinct.is_some() as u8
            + self.sequence.is_some() as u8;
        if kinds != 1 {
            e.push(path, "exactly one of count, distinct, sequence");
        }
        if let Some(w) = self.window_s {
            if !(1..=MAX_WINDOW_S).contains(&w) {
                e.push(
                    format!("{path}.window_s"),
                    format!("must be 1 to {MAX_WINDOW_S}"),
                );
            }
        }
        if let Some(f) = &self.count {
            f.validate(&format!("{path}.count"), e);
            match (self.gte, self.lte) {
                (None, None) => e.push(path, "count needs gte or lte"),
                (Some(g), Some(l)) if g > l => e.push(path, "gte must not exceed lte"),
                _ => {}
            }
        }
        if let Some(d) = &self.distinct {
            match self.gte {
                None => e.push(path, "distinct needs gte"),
                Some(g) if !(1..=MAX_DISTINCT).contains(&g) => e.push(
                    format!("{path}.gte"),
                    format!("must be 1 to {MAX_DISTINCT}"),
                ),
                Some(_) => {}
            }
            if self.lte.is_some() {
                e.push(format!("{path}.lte"), "not allowed with distinct");
            }
            if let Some(m) = &d.model {
                if d.field != DistinctField::BoundId {
                    e.push(format!("{path}.distinct.model"), "only with field bound_id");
                }
                if m.is_empty() || m.chars().count() > MAX_STRING_CHARS {
                    e.push(
                        format!("{path}.distinct.model"),
                        format!("must be 1 to {MAX_STRING_CHARS} characters"),
                    );
                }
            }
        }
        if let Some(seq) = &self.sequence {
            let p = format!("{path}.sequence");
            if self.scope.is_some() {
                e.push(format!("{path}.scope"), "not allowed with sequence");
            }
            if self.window_s.is_some() {
                e.push(format!("{path}.window_s"), "not allowed with sequence");
            }
            if self.gte.is_some() || self.lte.is_some() {
                e.push(path, "gte and lte are not allowed with sequence");
            }
            if seq.len() < 2 || seq.len() > MAX_SEQUENCE {
                e.push(&p, format!("must have 2 to {MAX_SEQUENCE} routes"));
            }
            for (i, r) in seq.iter().enumerate() {
                if r.is_empty() || r == "*" || r.chars().count() > MAX_STRING_CHARS {
                    e.push(format!("{p}[{i}]"), "must be a route template");
                }
            }
            if let Some(last) = seq.last() {
                if !matcher.is_wildcard() && !matcher.route.iter().any(|r| r == last) {
                    e.push(&p, "must end with a route listed in match.route");
                }
            }
        }
    }
}

impl TurnFilter {
    fn validate(&self, path: &str, e: &mut Errs) {
        for (name, list) in [
            ("route", &self.route),
            ("exception", &self.exception),
            ("auth_event", &self.auth_event),
            ("req_shape", &self.req_shape),
            ("bound_model", &self.bound_model),
        ] {
            if let Some(list) = list {
                check_list(&format!("{path}.{name}"), list, MAX_FILTER_LIST, e);
            }
        }
        if let Some(v) = &self.verb {
            if v.is_empty() || v.len() > MAX_VERBS {
                e.push(
                    format!("{path}.verb"),
                    format!("must have 1 to {MAX_VERBS} entries"),
                );
            }
        }
        if let Some(s) = &self.status {
            if s.is_empty() || s.len() > MAX_FILTER_LIST {
                e.push(
                    format!("{path}.status"),
                    format!("must have 1 to {MAX_FILTER_LIST} entries"),
                );
            }
            for (i, sel) in s.iter().enumerate() {
                if let StatusSel::Code(c) = sel {
                    if *c > 599 {
                        e.push(format!("{path}.status[{i}]"), "must be 0 to 599");
                    }
                }
            }
        }
        match &self.validation_failed {
            Some(ValidationSel::Any(false)) => e.push(
                format!("{path}.validation_failed"),
                "must be true or a list of fields",
            ),
            Some(ValidationSel::Fields(f)) => {
                check_list(&format!("{path}.validation_failed"), f, MAX_FILTER_LIST, e)
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_761_600_000;

    fn install(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/rules/install/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "id": "test-rule", "note": "a test", "mode": "shadow", "action": "watch",
            "match": { "route": ["home"], "verb": ["GET"], "principal": "any" },
            "origin": { "kind": "operator" }
        })
    }

    fn with(edit: impl FnOnce(&mut serde_json::Value)) -> Result<Rule, Vec<ValidationError>> {
        let mut v = base();
        edit(&mut v);
        Rule::parse(&v.to_string(), NOW)
    }

    fn paths(r: Result<Rule, Vec<ValidationError>>) -> Vec<String> {
        r.err()
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    #[test]
    fn install_rules_parse_and_round_trip() {
        for name in [
            "portal-otp-burst",
            "venue-enumeration",
            "visit-straight-to-login",
        ] {
            let text = install(name);
            let rule = Rule::parse(&text, NOW).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(rule.id, name);
            let again: Rule = serde_json::from_str(&serde_json::to_string(&rule).unwrap()).unwrap();
            assert_eq!(rule, again);
        }
    }

    #[test]
    fn orderings_are_the_ladder() {
        assert!(Mode::Monitor < Mode::Shadow && Mode::Shadow < Mode::Enforce);
        assert!(Action::Log < Action::Watch);
        assert!(Action::Watch < Action::RateLimit);
        assert!(Action::RateLimit < Action::Challenge);
        assert!(Action::Challenge < Action::Block);
    }

    #[test]
    fn unknown_fields_rejected_at_every_level() {
        assert!(with(|v| v["extra"] = 1.into()).is_err());
        assert!(with(|v| v["match"]["extra"] = 1.into()).is_err());
        assert!(with(|v| v["origin"]["extra"] = 1.into()).is_err());
        assert!(
            with(|v| v["when"] = serde_json::json!({"count": {}, "gte": 1, "extra": 1})).is_err()
        );
        assert!(
            with(|v| v["when"] = serde_json::json!({"count": {"extra": 1}, "gte": 1})).is_err()
        );
        assert!(with(
            |v| v["when"] = serde_json::json!({"all": [{"count": {}, "gte": 1}], "extra": 1})
        )
        .is_err());
        assert!(with(
            |v| v["when"] = serde_json::json!({"distinct": {"field": "route", "x": 1}, "gte": 1})
        )
        .is_err());
    }

    #[test]
    fn no_when_is_valid() {
        assert!(with(|_| {}).is_ok());
    }

    #[test]
    fn id_and_note_limits() {
        assert_eq!(paths(with(|v| v["id"] = "ab".into())), ["id"]);
        assert_eq!(paths(with(|v| v["id"] = "-abc".into())), ["id"]);
        assert_eq!(paths(with(|v| v["id"] = "Abc".into())), ["id"]);
        assert_eq!(paths(with(|v| v["id"] = "a".repeat(65).into())), ["id"]);
        assert!(with(|v| v["id"] = "a".repeat(64).into()).is_ok());
        assert_eq!(paths(with(|v| v["note"] = "".into())), ["note"]);
        assert_eq!(
            paths(with(|v| v["note"] = "x".repeat(201).into())),
            ["note"]
        );
    }

    #[test]
    fn retry_after_only_and_always_with_rate_limit() {
        assert_eq!(
            paths(with(|v| v["retry_after_s"] = 30.into())),
            ["retry_after_s"]
        );
        assert_eq!(
            paths(with(|v| v["action"] = "rate_limit".into())),
            ["retry_after_s"]
        );
        assert_eq!(
            paths(with(|v| {
                v["action"] = "rate_limit".into();
                v["retry_after_s"] = 0.into();
            })),
            ["retry_after_s"]
        );
        assert!(with(|v| {
            v["action"] = "rate_limit".into();
            v["retry_after_s"] = 86400.into();
        })
        .is_ok());
    }

    #[test]
    fn block_min_only_with_block() {
        assert_eq!(paths(with(|v| v["block_min"] = 10.into())), ["block_min"]);
        assert!(with(|v| v["action"] = "block".into()).is_ok());
        for bad in [0, 1441] {
            assert_eq!(
                paths(with(|v| {
                    v["action"] = "block".into();
                    v["block_min"] = bad.into();
                })),
                ["block_min"]
            );
        }
        assert!(with(|v| {
            v["action"] = "block".into();
            v["block_min"] = 1440.into();
        })
        .is_ok());
    }

    #[test]
    fn route_and_verb_limits() {
        assert_eq!(
            paths(with(|v| v["match"]["route"] = serde_json::json!([]))),
            ["match.route"]
        );
        assert_eq!(
            paths(with(
                |v| v["match"]["route"] = serde_json::json!(["*", "home"])
            )),
            ["match.route"]
        );
        assert!(with(|v| v["match"]["route"] = serde_json::json!(["*"])).is_ok());
        let seventeen: Vec<String> = (0..17).map(|i| format!("r{i}")).collect();
        assert_eq!(
            paths(with(|v| v["match"]["route"] = serde_json::json!(seventeen))),
            ["match.route"]
        );
        assert_eq!(
            paths(with(|v| v["match"]["verb"] = serde_json::json!([]))),
            ["match.verb"]
        );
        assert_eq!(
            paths(with(
                |v| v["match"]["verb"] = serde_json::json!(["GET", "GET"])
            )),
            ["match.verb[1]"]
        );
        assert!(with(|v| v["match"]["verb"] = serde_json::json!(["get"])).is_err());
    }

    #[test]
    fn exactly_one_test_per_condition() {
        assert_eq!(
            paths(with(|v| v["when"] = serde_json::json!({"gte": 1}))),
            ["when"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] =
                    serde_json::json!({"count": {}, "distinct": {"field": "route"}, "gte": 1})
            )),
            ["when"]
        );
        assert!(with(|v| v["when"] = serde_json::json!({"count": {}, "gte": 1})).is_ok());
        assert!(with(|v| v["when"] = serde_json::json!({"count": {}, "lte": 0})).is_ok());
        assert_eq!(
            paths(with(|v| v["when"] = serde_json::json!({"count": {}}))),
            ["when"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"count": {}, "gte": 5, "lte": 2})
            )),
            ["when"]
        );
    }

    #[test]
    fn distinct_takes_gte_only() {
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"distinct": {"field": "route"}})
            )),
            ["when"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"distinct": {"field": "route"}, "gte": 0})
            )),
            ["when.gte"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] =
                    serde_json::json!({"distinct": {"field": "route"}, "gte": 1, "lte": 3})
            )),
            ["when.lte"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] =
                    serde_json::json!({"distinct": {"field": "route", "model": "Venue"}, "gte": 1})
            )),
            ["when.distinct.model"]
        );
        assert!(with(|v| v["when"] =
            serde_json::json!({"scope": "peer", "distinct": {"field": "bound_id", "model": "Venue"}, "gte": 3}))
        .is_ok());
    }

    #[test]
    fn sequence_rejects_scope_window_and_bounds() {
        let ok = |v: &mut serde_json::Value| {
            v["when"] = serde_json::json!({"sequence": ["login", "home"]})
        };
        assert!(with(ok).is_ok());
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"sequence": ["login", "home"], "scope": "peer"})
            )),
            ["when.scope"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"sequence": ["login", "home"], "window_s": 5})
            )),
            ["when.window_s"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"sequence": ["login", "home"], "gte": 1})
            )),
            ["when"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"sequence": ["home"]})
            )),
            ["when.sequence"]
        );
        let nine: Vec<String> = (0..9)
            .map(|i| format!("r{i}"))
            .chain(["home".into()])
            .collect();
        assert_eq!(
            paths(with(|v| v["when"] = serde_json::json!({"sequence": nine}))),
            ["when.sequence"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"sequence": ["login", "other"]})
            )),
            ["when.sequence"]
        );
        assert!(with(|v| {
            v["match"]["route"] = serde_json::json!(["*"]);
            v["when"] = serde_json::json!({"sequence": ["login", "other"]});
        })
        .is_ok());
    }

    #[test]
    fn all_takes_one_to_three() {
        assert_eq!(
            paths(with(|v| v["when"] = serde_json::json!({"all": []}))),
            ["when.all"]
        );
        let four: Vec<_> = (0..4)
            .map(|_| serde_json::json!({"count": {}, "gte": 1}))
            .collect();
        assert_eq!(
            paths(with(|v| v["when"] = serde_json::json!({"all": four}))),
            ["when.all"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"all": [{"count": {}, "gte": 1}, {"gte": 2}]})
            )),
            ["when.all[1]"]
        );
    }

    #[test]
    fn window_and_filter_limits() {
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"count": {}, "gte": 1, "window_s": 0})
            )),
            ["when.window_s"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"count": {}, "gte": 1, "window_s": 86401})
            )),
            ["when.window_s"]
        );
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"count": {"status": [600]}, "gte": 1})
            )),
            ["when.count.status[0]"]
        );
        assert!(with(
            |v| v["when"] = serde_json::json!({"count": {"status": [404, "5xx"]}, "gte": 1})
        )
        .is_ok());
        assert!(
            with(|v| v["when"] = serde_json::json!({"count": {"status": ["3xx"]}, "gte": 1}))
                .is_err()
        );
        assert_eq!(
            paths(with(
                |v| v["when"] =
                    serde_json::json!({"count": {"validation_failed": false}, "gte": 1})
            )),
            ["when.count.validation_failed"]
        );
        assert!(with(
            |v| v["when"] = serde_json::json!({"count": {"validation_failed": true}, "gte": 1})
        )
        .is_ok());
        assert!(with(
            |v| v["when"] = serde_json::json!({"count": {"validation_failed": ["otp"]}, "gte": 1})
        )
        .is_ok());
        assert_eq!(
            paths(with(
                |v| v["when"] = serde_json::json!({"count": {"route": []}, "gte": 1})
            )),
            ["when.count.route"]
        );
    }

    #[test]
    fn expires_at_must_be_future() {
        assert_eq!(
            paths(with(|v| v["expires_at"] = NOW.into())),
            ["expires_at"]
        );
        assert!(with(|v| v["expires_at"] = (NOW + 1).into()).is_ok());
    }
}
