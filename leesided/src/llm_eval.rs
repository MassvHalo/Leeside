//! Golden-set evals (docs/llm-evals.md sections 1-2): `llm eval-build`
//! exports candidate rows from a store for hand labelling; `llm eval`
//! runs a set in dry-send mode (live calls, nothing written to the
//! product tables) and logs one `llm_evals` row per run.
//!
//! Agreement grades what prod would write: label rows compare the
//! post-faithfulness label, with the raw proposal's agreement kept
//! beside it so the cost of the checks stays visible. Transport and
//! HTTP errors are excluded from agreement and listed first among
//! the worst rows.

use crate::llm::{
    apply_faithfulness, budget_check, build_draft_envelope, build_label_envelope_at,
    execute_call_with_system, log_exchanges, validate_classify, validate_draft, validate_explain,
    validate_label, Exec, ExecutionOutcome, JsonMode, LlmError, WindowSel,
};
use crate::rules::model::{Rule, Scope, StatusClass, StatusSel, Surface, TurnFilter, Verb};
use crate::store::now_s;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const POINTS: [&str; 4] = ["label", "explain", "classify", "draft"];

pub fn check_point(point: &str) -> Result<(), LlmError> {
    if POINTS.contains(&point) {
        Ok(())
    } else {
        Err(LlmError::Point(point.to_string()))
    }
}

// ---------- Golden rows ----------

#[derive(Debug, Deserialize)]
pub struct LabelRow {
    pub envelope: serde_json::Value,
    pub expected_label: Option<String>,
    #[serde(default)]
    pub allowed_signals: Option<Vec<String>>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub prefilled_from: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClassifyRow {
    pub method: String,
    pub path_pattern: String,
    #[serde(default)]
    pub sample_query: Option<String>,
    #[serde(default)]
    pub body_slice: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    pub expected_category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExplainRow {
    #[serde(default)]
    pub surface: Option<String>,
    pub score: f64,
    #[serde(default)]
    pub threshold: Option<f64>,
    pub top3: serde_json::Value,
    pub window: serde_json::Value,
    #[serde(default)]
    pub must_mention: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DraftRow {
    pub envelope: serde_json::Value,
    #[serde(default)]
    pub expected_scope: Option<String>,
    #[serde(default)]
    pub expected_surface: Option<String>,
    #[serde(default)]
    pub must_parse: bool,
    #[serde(default)]
    pub turns: Vec<serde_json::Value>,
}

fn read_rows(path: &Path) -> Result<Vec<(usize, serde_json::Value)>, LlmError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| LlmError::Eval(format!("{}: cannot read: {e}", path.display())))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            LlmError::Eval(format!("{} line {}: bad JSON: {e}", path.display(), n + 1))
        })?;
        out.push((n + 1, v));
    }
    Ok(out)
}

fn parse_row<T: serde::de::DeserializeOwned>(
    path: &Path,
    n: usize,
    v: serde_json::Value,
) -> Result<T, LlmError> {
    serde_json::from_value(v)
        .map_err(|e| LlmError::Eval(format!("{} line {n}: bad row: {e}", path.display())))
}

// ---------- Draft dry-run ----------

/// Count what a draft rule would have matched among the row's turns,
/// as one window: turns matching the `match` block and the
/// condition's turn filter. `sequence` counts ordered k-windows;
/// `score` needs a live score and yields `None`; `all` takes the
/// minimum over countable conditions, `None` when any is not.
pub fn dry_run_matches(rule: &Rule, turns: &[serde_json::Value]) -> Option<usize> {
    let matched: Vec<&serde_json::Value> =
        turns.iter().filter(|t| match_matches(rule, t)).collect();
    let Some(when) = rule.when.as_ref() else {
        return Some(matched.len());
    };
    let mut counts = Vec::new();
    for c in when.conditions() {
        if let Some(f) = c.count.as_ref() {
            counts.push(matched.iter().filter(|t| filter_matches(f, t)).count());
        } else if let Some(d) = c.distinct.as_ref() {
            let mut vals = HashSet::new();
            for t in matched
                .iter()
                .filter(|t| d.filter.as_ref().is_none_or(|f| filter_matches(f, t)))
            {
                match d.field {
                    crate::rules::model::DistinctField::BoundId => {
                        for (model, id) in bound_entries(t) {
                            if d.model.as_ref().is_none_or(|m| m == model) {
                                vals.insert(id.to_string());
                            }
                        }
                    }
                    crate::rules::model::DistinctField::Route => {
                        if let Some(r) = str_field(t, "route") {
                            vals.insert(r.to_string());
                        }
                    }
                    crate::rules::model::DistinctField::Credential => {
                        if let Some(h) = str_field(t, "credential_hash") {
                            vals.insert(h.to_string());
                        }
                    }
                }
            }
            counts.push(vals.len());
        } else if let Some(seq) = c.sequence.as_ref() {
            // The probe (last template) matches the `match` block;
            // earlier templates match any earlier turns in order.
            let k = seq.len().max(1);
            let mut n = 0;
            for w in turns.windows(k) {
                if w.len() == k
                    && match_matches(rule, &w[k - 1])
                    && w.iter()
                        .zip(seq.iter())
                        .all(|(t, s)| str_field(t, "route") == Some(s))
                {
                    n += 1;
                }
            }
            counts.push(n);
        } else if c.score.is_some() {
            return None;
        } else {
            counts.push(matched.len());
        }
    }
    counts.into_iter().min()
}

fn str_field<'a>(t: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    t.get(name)?.as_str()
}

fn route_matches(templates: &[String], t: &serde_json::Value) -> bool {
    templates.iter().any(|tpl| {
        tpl == "*"
            || Some(tpl.as_str()) == str_field(t, "route")
            || Some(tpl.as_str()) == str_field(t, "path_pattern")
    })
}

fn match_matches(rule: &Rule, t: &serde_json::Value) -> bool {
    if !route_matches(&rule.matcher.route, t) {
        return false;
    }
    if !rule.matcher.verb.iter().any(|v| match v {
        Verb::Get => str_field(t, "verb") == Some("GET"),
        Verb::Post => str_field(t, "verb") == Some("POST"),
        Verb::Put => str_field(t, "verb") == Some("PUT"),
        Verb::Patch => str_field(t, "verb") == Some("PATCH"),
        Verb::Delete => str_field(t, "verb") == Some("DELETE"),
        Verb::Head => str_field(t, "verb") == Some("HEAD"),
        Verb::Options => str_field(t, "verb") == Some("OPTIONS"),
    }) {
        return false;
    }
    match rule.matcher.principal {
        crate::rules::model::PrincipalKind::Any => {}
        crate::rules::model::PrincipalKind::Anon => {
            if str_field(t, "principal") != Some("anon") {
                return false;
            }
        }
        crate::rules::model::PrincipalKind::Authenticated => {
            if str_field(t, "principal") == Some("anon") {
                return false;
            }
        }
    }
    if !rule.matcher.surface.is_empty()
        && !rule
            .matcher
            .surface
            .iter()
            .any(|s| Some(surface_str(*s)) == str_field(t, "surface"))
    {
        return false;
    }
    true
}

fn surface_str(s: Surface) -> &'static str {
    match s {
        Surface::Honeypot => "honeypot",
        Surface::Webhook => "webhook",
        Surface::Api => "api",
        Surface::Web => "web",
    }
}

fn filter_matches(f: &TurnFilter, t: &serde_json::Value) -> bool {
    if f.route.as_ref().is_some_and(|r| !route_matches(r, t)) {
        return false;
    }
    if f.verb.as_ref().is_some_and(|verbs| {
        !verbs
            .iter()
            .any(|v| Some(v.as_str()) == str_field(t, "verb"))
    }) {
        return false;
    }
    if f.status.as_ref().is_some_and(|statuses| {
        !statuses.iter().any(|s| match s {
            StatusSel::Code(c) => t.get("status").and_then(|v| v.as_u64()) == Some(u64::from(*c)),
            StatusSel::Class(StatusClass::C4xx) => t
                .get("status")
                .and_then(|v| v.as_u64())
                .is_some_and(|s| (400..500).contains(&s)),
            StatusSel::Class(StatusClass::C5xx) => t
                .get("status")
                .and_then(|v| v.as_u64())
                .is_some_and(|s| (500..600).contains(&s)),
        })
    }) {
        return false;
    }
    if let Some(sel) = f.validation_failed.as_ref() {
        let fields: Vec<&str> = t
            .get("validation_failed")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let hit = match sel {
            crate::rules::model::ValidationSel::Any(_) => !fields.is_empty(),
            crate::rules::model::ValidationSel::Fields(names) => {
                fields.iter().any(|f| names.iter().any(|n| n == f))
            }
        };
        if !hit {
            return false;
        }
    }
    if f.exception.as_ref().is_some_and(|excs| {
        !excs
            .iter()
            .any(|e| Some(e.as_str()) == str_field(t, "exception"))
    }) {
        return false;
    }
    if f.auth_event.as_ref().is_some_and(|evs| {
        !evs.iter()
            .any(|e| Some(e.as_str()) == str_field(t, "auth_event"))
    }) {
        return false;
    }
    if f.req_shape.as_ref().is_some_and(|shapes| {
        !shapes
            .iter()
            .any(|s| Some(s.as_str()) == str_field(t, "req_shape"))
    }) {
        return false;
    }
    if f.bound_model
        .as_ref()
        .is_some_and(|models| !bound_entries(t).any(|(m, _)| models.iter().any(|want| want == m)))
    {
        return false;
    }
    if let Some(statuses) = f.credential_status.as_ref() {
        let got = str_field(t, "credential_status");
        if got.is_none() {
            return false;
        }
        let ok = statuses.iter().any(|s| {
            serde_json::to_value(s)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .as_deref()
                == got
        });
        if !ok {
            return false;
        }
    }
    true
}

fn bound_entries(t: &serde_json::Value) -> impl Iterator<Item = (&str, &str)> {
    t.get("bound")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|e| Some((e.get("model")?.as_str()?, e.get("id_hash")?.as_str()?)))
}

pub fn rule_scope(rule: &Rule) -> String {
    rule.when
        .as_ref()
        .and_then(|w| w.conditions().first())
        .and_then(|c| c.scope)
        .unwrap_or(Scope::Session)
        .as_str()
        .to_string()
}

pub fn rule_surfaces(rule: &Rule) -> Vec<String> {
    rule.matcher
        .surface
        .iter()
        .map(|s| surface_str(*s).to_string())
        .collect()
}

// ---------- Eval run ----------

pub struct EvalInput<'a> {
    pub exec: &'a Exec,
    pub system: Option<&'a str>,
    pub prompt_hash: String,
    pub model: String,
    pub json_mode: JsonMode,
    pub effort: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Default)]
pub struct EvalSummary {
    pub eval_id: i64,
    pub point: String,
    pub model: String,
    pub prompt_hash: String,
    pub json_mode: String,
    pub rows: usize,
    pub skipped: usize,
    pub errors: usize,
    pub agreement: Option<f64>,
    pub agreement_raw: Option<f64>,
    pub groups: serde_json::Value,
    pub calibration: serde_json::Value,
    pub faithfulness_failures: usize,
    pub parse_failures: usize,
    pub tokens_per_row: Option<f64>,
    pub latency_ms_per_row: Option<f64>,
    pub cost_usd: Option<f64>,
    pub worst: serde_json::Value,
}

impl EvalSummary {
    pub fn print(&self) {
        println!(
            "eval {} model={} prompt={} json_mode={}",
            self.point,
            self.model,
            &self.prompt_hash[..12.min(self.prompt_hash.len())],
            self.json_mode
        );
        println!(
            "rows={} skipped={} errors={} agreement={} agreement_raw={} faithfulness_failures={} parse_failures={}",
            self.rows,
            self.skipped,
            self.errors,
            fmt_opt(self.agreement, 4),
            fmt_opt(self.agreement_raw, 4),
            self.faithfulness_failures,
            self.parse_failures,
        );
        println!(
            "tokens_per_row={} latency_ms_per_row={} cost_usd={}",
            fmt_opt(self.tokens_per_row, 1),
            fmt_opt(self.latency_ms_per_row, 0),
            fmt_opt(self.cost_usd, 4),
        );
        if !self.groups.is_null() {
            println!(
                "groups={}",
                serde_json::to_string(&self.groups).unwrap_or_default()
            );
        }
        if !self.calibration.is_null() {
            println!(
                "calibration={}",
                serde_json::to_string(&self.calibration).unwrap_or_default()
            );
        }
        println!("eval_id={}", self.eval_id);
        if let Some(worst) = self.worst.as_array() {
            if !worst.is_empty() {
                println!("worst rows:");
                for w in worst {
                    println!("  {}", serde_json::to_string(w).unwrap_or_default());
                }
            }
        }
    }
}

fn fmt_opt(v: Option<f64>, places: usize) -> String {
    v.map(|x| format!("{x:.places$}"))
        .unwrap_or_else(|| "-".to_string())
}

fn open_db(db: &Path) -> Result<Connection, LlmError> {
    if !db.exists() {
        return Err(LlmError::MissingDb(db.display().to_string()));
    }
    let mut conn = Connection::open(db)?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    crate::store::migrate(&mut conn).map_err(|e| LlmError::Eval(e.to_string()))?;
    Ok(conn)
}

/// `LEESIDED_LLM_USD_PER_MTOK="prompt,completion"`, per million
/// tokens; unset or malformed means cost stays null, honestly.
fn usd_per_mtok() -> Option<(f64, f64)> {
    let v = std::env::var("LEESIDED_LLM_USD_PER_MTOK").ok()?;
    let (a, b) = v.split_once(',')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

struct Acc {
    graded: usize,
    agree: usize,
    agree_raw: usize,
    faithfulness_failures: usize,
    parse_failures: usize,
    errors: usize,
    skipped: usize,
    prompt_tokens: i64,
    completion_tokens: i64,
    latency_ms: i64,
    worst: Vec<serde_json::Value>,
    // label: (graded, agree, agree_raw) per group
    kind_n: HashMap<String, (usize, usize, usize)>,
    scope_n: HashMap<String, (usize, usize, usize)>,
    bins: [(usize, usize); 5],
    unknown: usize,
    signal_violations: usize,
    dropped: HashMap<String, usize>,
    // classify
    cat: HashMap<String, (usize, usize, usize)>,
    // explain
    length_violations: usize,
    // draft
    dry_matches: usize,
    dry_rows: usize,
}

impl Acc {
    fn new() -> Acc {
        Acc {
            graded: 0,
            agree: 0,
            agree_raw: 0,
            faithfulness_failures: 0,
            parse_failures: 0,
            errors: 0,
            skipped: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: 0,
            worst: Vec::new(),
            kind_n: HashMap::new(),
            scope_n: HashMap::new(),
            bins: [(0, 0); 5],
            unknown: 0,
            signal_violations: 0,
            dropped: HashMap::new(),
            cat: HashMap::new(),
            length_violations: 0,
            dry_matches: 0,
            dry_rows: 0,
        }
    }

    fn push_worst(&mut self, row: usize, expected: &str, got: &str, detail: String) {
        if self.worst.len() >= 30 {
            return;
        }
        self.worst.push(serde_json::json!({
            "row": row, "expected": expected, "got": got, "detail": detail,
        }));
    }
}

/// Run one golden set in dry-send mode: live calls, logged to
/// `llm_calls`, nothing written to the product tables, one
/// `llm_evals` row at the end.
pub fn evaluate(
    db: &Path,
    set: &Path,
    point: &str,
    input: &EvalInput,
) -> Result<EvalSummary, LlmError> {
    check_point(point)?;
    let conn = open_db(db)?;
    let rows = read_rows(set)?;
    let rows: Vec<(usize, serde_json::Value)> = match input.limit {
        Some(n) => rows.into_iter().take(n).collect(),
        None => rows,
    };
    let mut acc = Acc::new();
    for (n, v) in &rows {
        if skippable(point, set, *n, v)? {
            acc.skipped += 1;
            continue;
        }
        let envelope = envelope_for(point, set, *n, v)?;
        let now = now_s();
        budget_check(
            &conn,
            point,
            now,
            input.exec.daily_calls,
            input.exec.daily_tokens,
        )?;
        let execution = execute_call_with_system(
            &input.exec.url,
            &input.exec.key,
            &input.model,
            point,
            input.system,
            &envelope,
            input.json_mode,
            input.effort.as_deref(),
        )?;
        for e in &execution.exchanges {
            let (pt, ct, lat) = e.cost();
            acc.prompt_tokens += pt;
            acc.completion_tokens += ct;
            acc.latency_ms += lat;
        }
        let summary = serde_json::json!({"eval_row": n, "point": point}).to_string();
        let call_ids = log_exchanges(
            &conn,
            point,
            &input.model,
            &input.prompt_hash,
            input.json_mode,
            &summary,
            &execution.exchanges,
            now,
        )?;
        let call_id = call_ids.last().copied().unwrap_or(0);
        grade(
            &conn,
            point,
            set,
            *n,
            v,
            &envelope,
            &execution.outcome,
            call_id,
            &input.exec.honeytoken_routes,
            &mut acc,
        )?;
    }
    let now = now_s();
    let (groups, calibration) = report_groups(point, &acc);
    let graded = acc.graded as f64;
    let agreement = if acc.graded > 0 {
        Some(acc.agree as f64 / graded)
    } else {
        None
    };
    let agreement_raw = if point == "label" && acc.graded > 0 {
        Some(acc.agree_raw as f64 / graded)
    } else {
        None
    };
    let sent = rows.len() - acc.skipped;
    let tokens_per_row = if sent > 0 {
        Some((acc.prompt_tokens + acc.completion_tokens) as f64 / sent as f64)
    } else {
        None
    };
    let latency_ms_per_row = if sent > 0 {
        Some(acc.latency_ms as f64 / sent as f64)
    } else {
        None
    };
    let cost_usd = usd_per_mtok().map(|(pi, po)| {
        acc.prompt_tokens as f64 / 1_000_000.0 * pi
            + acc.completion_tokens as f64 / 1_000_000.0 * po
    });
    // Worst first: errors, then parse failures, then disagreements.
    let mut worst = std::mem::take(&mut acc.worst);
    worst.sort_by_key(|w| {
        let got = w.get("got").and_then(|v| v.as_str()).unwrap_or("");
        if got.starts_with("error:") {
            0
        } else if got == "unparsed" {
            1
        } else {
            2
        }
    });
    worst.truncate(10);
    let worst = serde_json::Value::Array(worst);
    conn.execute(
        "INSERT INTO llm_evals (created_at, point, prompt_hash, model, json_mode, rows, skipped, \
         agreement, agreement_raw, groups, calibration, faithfulness_failures, parse_failures, \
         tokens_per_row, latency_ms_per_row, cost_usd, worst) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            now,
            point,
            input.prompt_hash,
            input.model,
            input.json_mode.as_str(),
            rows.len() as i64,
            acc.skipped as i64,
            agreement,
            agreement_raw,
            serde_json::to_string(&groups).unwrap_or_else(|_| "null".to_string()),
            serde_json::to_string(&calibration).unwrap_or_else(|_| "null".to_string()),
            acc.faithfulness_failures as i64,
            acc.parse_failures as i64,
            tokens_per_row,
            latency_ms_per_row,
            cost_usd,
            serde_json::to_string(&worst).unwrap_or_else(|_| "[]".to_string()),
        ],
    )?;
    Ok(EvalSummary {
        eval_id: conn.last_insert_rowid(),
        point: point.to_string(),
        model: input.model.clone(),
        prompt_hash: input.prompt_hash.clone(),
        json_mode: input.json_mode.as_str().to_string(),
        rows: rows.len(),
        skipped: acc.skipped,
        errors: acc.errors,
        agreement,
        agreement_raw,
        groups,
        calibration,
        faithfulness_failures: acc.faithfulness_failures,
        parse_failures: acc.parse_failures,
        tokens_per_row,
        latency_ms_per_row,
        cost_usd,
        worst,
    })
}

/// Rows with nothing to grade against skip before any call goes
/// out: no money spent on ungradable rows.
fn skippable(point: &str, set: &Path, n: usize, v: &serde_json::Value) -> Result<bool, LlmError> {
    match point {
        "label" => Ok(parse_row::<LabelRow>(set, n, v.clone())?
            .expected_label
            .is_none()),
        "classify" => Ok(parse_row::<ClassifyRow>(set, n, v.clone())?
            .expected_category
            .is_none()),
        "explain" => Ok(false),
        "draft" => {
            let row: DraftRow = parse_row(set, n, v.clone())?;
            Ok(row.expected_scope.is_none() && row.expected_surface.is_none() && !row.must_parse)
        }
        _ => Err(LlmError::Point(point.to_string())),
    }
}

fn envelope_for(
    point: &str,
    set: &Path,
    n: usize,
    v: &serde_json::Value,
) -> Result<serde_json::Value, LlmError> {
    match point {
        "label" => {
            let row: LabelRow = parse_row(set, n, v.clone())?;
            Ok(row.envelope)
        }
        "classify" => {
            let row: ClassifyRow = parse_row(set, n, v.clone())?;
            Ok(serde_json::json!({
                "task": "classify",
                "method": row.method,
                "path_pattern": row.path_pattern,
                "sample_query": row.sample_query,
                "body_slice": row.body_slice,
                "content_type": row.content_type,
            }))
        }
        "explain" => {
            let row: ExplainRow = parse_row(set, n, v.clone())?;
            Ok(serde_json::json!({
                "task": "explain",
                "surface": row.surface,
                "score": row.score,
                "threshold": row.threshold,
                "top3": row.top3,
                "window": row.window,
            }))
        }
        "draft" => {
            let row: DraftRow = parse_row(set, n, v.clone())?;
            Ok(row.envelope)
        }
        _ => Err(LlmError::Point(point.to_string())),
    }
}

#[allow(clippy::too_many_arguments)]
fn grade(
    conn: &Connection,
    point: &str,
    set: &Path,
    n: usize,
    v: &serde_json::Value,
    envelope: &serde_json::Value,
    outcome: &ExecutionOutcome,
    call_id: i64,
    honeytoken_routes: &[String],
    acc: &mut Acc,
) -> Result<(), LlmError> {
    let parsed = match outcome {
        ExecutionOutcome::Validated { parsed } => parsed,
        ExecutionOutcome::Invalid { first_error } => {
            acc.parse_failures += 1;
            acc.push_worst(n, "valid", "unparsed", first_error.clone());
            return Ok(());
        }
        ExecutionOutcome::LengthExhausted => {
            acc.parse_failures += 1;
            acc.push_worst(n, "valid", "unparsed", "length exhausted".to_string());
            return Ok(());
        }
        ExecutionOutcome::Http { status } => {
            acc.errors += 1;
            acc.push_worst(n, "valid", &format!("error:http {status}"), String::new());
            return Ok(());
        }
        ExecutionOutcome::Transport { error } => {
            acc.errors += 1;
            acc.push_worst(n, "valid", "error:transport", error.clone());
            return Ok(());
        }
    };
    let pv: serde_json::Value = serde_json::from_str(parsed).map_err(|e| {
        LlmError::Eval(format!(
            "{} line {n}: validated JSON unreadable: {e}",
            set.display()
        ))
    })?;
    match point {
        "label" => {
            let row: LabelRow = parse_row(set, n, v.clone())?;
            let Some(expected) = row.expected_label.as_deref() else {
                acc.skipped += 1;
                return Ok(());
            };
            let mut p = validate_label(&pv).map_err(LlmError::Validate)?;
            let raw = p.label.clone();
            let claimed = p.signal_names();
            let failed = apply_faithfulness(envelope, &mut p, honeytoken_routes);
            let agree_raw = raw == expected;
            let agree = p.label == expected;
            acc.graded += 1;
            if agree {
                acc.agree += 1;
            } else {
                acc.push_worst(
                    n,
                    expected,
                    &p.label,
                    format!(
                        "raw={raw} conf={:.2} failed={failed:?} signals={:?}",
                        p.confidence,
                        p.signal_names(),
                    ),
                );
            }
            if agree_raw {
                acc.agree_raw += 1;
            }
            let kind = row.kind.as_deref().unwrap_or("unknown").to_string();
            let scope = envelope
                .get("subject")
                .and_then(|s| s.get("scope"))
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            for (map, key) in [(&mut acc.kind_n, kind), (&mut acc.scope_n, scope)] {
                let e = map.entry(key).or_insert((0, 0, 0));
                e.0 += 1;
                if agree {
                    e.1 += 1;
                }
                if agree_raw {
                    e.2 += 1;
                }
            }
            let bin = ((p.confidence * 5.0) as usize).min(4);
            acc.bins[bin].0 += 1;
            if agree {
                acc.bins[bin].1 += 1;
            }
            if p.label == "unknown" {
                acc.unknown += 1;
            }
            if let Some(allowed) = row.allowed_signals.as_ref() {
                let bad: Vec<&str> = claimed
                    .iter()
                    .filter(|s| !allowed.iter().any(|a| a == *s))
                    .map(String::as_str)
                    .collect();
                if !bad.is_empty() {
                    acc.signal_violations += 1;
                    acc.push_worst(
                        n,
                        expected,
                        &p.label,
                        format!("signals outside allowed: {bad:?}"),
                    );
                }
            }
            if !failed.is_empty() {
                acc.faithfulness_failures += 1;
                for f in &failed {
                    *acc.dropped.entry(f.clone()).or_insert(0) += 1;
                }
                conn.execute(
                    "UPDATE llm_calls SET faithfulness_failed = ?1 WHERE id = ?2",
                    params![
                        serde_json::to_string(&failed).unwrap_or_else(|_| "[]".to_string()),
                        call_id
                    ],
                )?;
            }
            Ok(())
        }
        "classify" => {
            let row: ClassifyRow = parse_row(set, n, v.clone())?;
            let Some(expected) = row.expected_category.as_deref() else {
                acc.skipped += 1;
                return Ok(());
            };
            let (got, conf) = validate_classify(&pv).map_err(LlmError::Validate)?;
            let agree = got == expected;
            acc.graded += 1;
            if agree {
                acc.agree += 1;
            } else {
                acc.push_worst(n, expected, &got, format!("conf={conf:.2}"));
            }
            for cat in [expected, got.as_str()] {
                acc.cat.entry(cat.to_string()).or_insert((0, 0, 0));
            }
            for (cat, (tp, fp, f)) in acc.cat.iter_mut() {
                if got == *cat && expected == cat {
                    *tp += 1;
                } else if got == *cat {
                    *fp += 1;
                } else if expected == cat {
                    *f += 1;
                }
            }
            Ok(())
        }
        "explain" => {
            let row: ExplainRow = parse_row(set, n, v.clone())?;
            let text = validate_explain(&pv).map_err(LlmError::Validate)?;
            let lower = text.to_lowercase();
            let missing: Vec<&str> = row
                .must_mention
                .iter()
                .filter(|m| !lower.contains(&m.to_lowercase()))
                .map(String::as_str)
                .collect();
            let too_long = text.chars().count() > 240;
            if too_long {
                acc.length_violations += 1;
            }
            let agree = missing.is_empty() && !too_long;
            acc.graded += 1;
            if agree {
                acc.agree += 1;
            } else {
                acc.push_worst(
                    n,
                    &format!("mentions {:?}", row.must_mention),
                    &text,
                    format!("missing={missing:?} too_long={too_long}"),
                );
            }
            Ok(())
        }
        "draft" => {
            let row: DraftRow = parse_row(set, n, v.clone())?;
            if row.expected_scope.is_none() && row.expected_surface.is_none() && !row.must_parse {
                acc.skipped += 1;
                return Ok(());
            }
            let (rule_text, _) = validate_draft(&pv).map_err(LlmError::Validate)?;
            let now = now_s();
            let rule = Rule::parse(&rule_text, now);
            let parses = rule.is_ok();
            let mut ok = !row.must_parse || parses;
            let mut detail = Vec::new();
            match rule {
                Ok(r) => {
                    if let Some(exp) = row.expected_scope.as_deref() {
                        let got = rule_scope(&r);
                        if got != exp {
                            ok = false;
                            detail.push(format!("scope {got} != {exp}"));
                        }
                    }
                    if let Some(exp) = row.expected_surface.as_deref() {
                        let got = rule_surfaces(&r);
                        let hit = if exp == "any" {
                            got.is_empty()
                        } else {
                            got == vec![exp.to_string()]
                        };
                        if !hit {
                            ok = false;
                            detail.push(format!("surface {got:?} != {exp}"));
                        }
                    }
                    if let Some(m) = dry_run_matches(&r, &row.turns) {
                        acc.dry_rows += 1;
                        acc.dry_matches += m;
                        detail.push(format!("dry_run={m}"));
                    }
                }
                Err(errors) => {
                    detail.push(format!(
                        "parse: {}",
                        errors
                            .iter()
                            .map(|e| e.message.clone())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ));
                }
            }
            acc.graded += 1;
            if ok {
                acc.agree += 1;
            } else {
                acc.push_worst(n, "draft as expected", "draft off", detail.join(", "));
            }
            Ok(())
        }
        _ => Err(LlmError::Point(point.to_string())),
    }
}

fn report_groups(point: &str, acc: &Acc) -> (serde_json::Value, serde_json::Value) {
    match point {
        "label" => {
            let tab = |m: &HashMap<String, (usize, usize, usize)>| {
                m.iter()
                    .map(|(k, (n, a, r))| {
                        (
                            k.clone(),
                            serde_json::json!({"n": n, "agree": a, "agree_raw": r}),
                        )
                    })
                    .collect::<serde_json::Map<String, serde_json::Value>>()
            };
            let kind = tab(&acc.kind_n);
            let scope = tab(&acc.scope_n);
            let groups = serde_json::json!({
                "kind": kind, "scope": scope,
                "unknown_rate": rate(acc.unknown, acc.graded),
                "signal_violations": acc.signal_violations,
                "dropped_signals": acc.dropped,
            });
            let bins: Vec<serde_json::Value> = acc
                .bins
                .iter()
                .enumerate()
                .map(|(i, (n, c))| {
                    serde_json::json!({
                        "lo": i as f64 / 5.0, "hi": (i + 1) as f64 / 5.0,
                        "n": n, "correct": c,
                    })
                })
                .collect();
            (groups, serde_json::Value::Array(bins))
        }
        "classify" => {
            let mut cats = serde_json::Map::new();
            for (c, (tp, fp, f)) in &acc.cat {
                cats.insert(
                    c.clone(),
                    serde_json::json!({
                        "precision": pr(*tp, *fp), "recall": pr(*tp, *f),
                        "support": tp + f,
                    }),
                );
            }
            (
                serde_json::json!({"categories": cats}),
                serde_json::Value::Null,
            )
        }
        "explain" => (
            serde_json::json!({"length_violations": acc.length_violations}),
            serde_json::Value::Null,
        ),
        "draft" => (
            serde_json::json!({
                "dry_run_rows": acc.dry_rows, "dry_run_matches": acc.dry_matches,
            }),
            serde_json::Value::Null,
        ),
        _ => (serde_json::Value::Null, serde_json::Value::Null),
    }
}

fn rate(n: usize, d: usize) -> Option<f64> {
    if d > 0 {
        Some(n as f64 / d as f64)
    } else {
        None
    }
}

fn pr(tp: usize, other: usize) -> Option<f64> {
    if tp + other > 0 {
        Some(tp as f64 / (tp + other) as f64)
    } else {
        None
    }
}

// ---------- Compare ----------

pub struct EvalRowView {
    pub id: i64,
    pub created_at: i64,
    pub point: String,
    pub prompt_hash: String,
    pub model: String,
    pub json_mode: String,
    pub rows: i64,
    pub agreement: Option<f64>,
    pub agreement_raw: Option<f64>,
    pub faithfulness_failures: i64,
    pub parse_failures: i64,
    pub tokens_per_row: Option<f64>,
    pub latency_ms_per_row: Option<f64>,
    pub cost_usd: Option<f64>,
}

pub fn latest_for_hash(db: &Path, hash: &str) -> Result<Option<EvalRowView>, LlmError> {
    let conn = open_db(db)?;
    let mut stmt = conn.prepare(
        "SELECT id, created_at, point, prompt_hash, model, json_mode, rows, agreement, agreement_raw, \
         faithfulness_failures, parse_failures, tokens_per_row, latency_ms_per_row, cost_usd \
         FROM llm_evals WHERE prompt_hash LIKE ?1 || '%' ORDER BY id DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![hash], |r| {
        Ok(EvalRowView {
            id: r.get(0)?,
            created_at: r.get(1)?,
            point: r.get(2)?,
            prompt_hash: r.get(3)?,
            model: r.get(4)?,
            json_mode: r.get(5)?,
            rows: r.get(6)?,
            agreement: r.get(7)?,
            agreement_raw: r.get(8)?,
            faithfulness_failures: r.get(9)?,
            parse_failures: r.get(10)?,
            tokens_per_row: r.get(11)?,
            latency_ms_per_row: r.get(12)?,
            cost_usd: r.get(13)?,
        })
    })?;
    Ok(rows.next().transpose()?)
}

/// The latest eval row for one live prompt, for `/health`: id,
/// agreement, model and age, or `None` when the prompt never ran.
pub fn eval_for_prompt(conn: &Connection, point: &str, hash: &str) -> Option<serde_json::Value> {
    conn.query_row(
        "SELECT id, agreement, agreement_raw, model, created_at FROM llm_evals \
         WHERE point = ?1 AND prompt_hash = ?2 ORDER BY id DESC LIMIT 1",
        params![point, hash],
        |r| {
            Ok(serde_json::json!({
                "eval_id": r.get::<_, i64>(0)?,
                "agreement": r.get::<_, Option<f64>>(1)?,
                "agreement_raw": r.get::<_, Option<f64>>(2)?,
                "model": r.get::<_, String>(3)?,
                "created_at": r.get::<_, i64>(4)?,
            }))
        },
    )
    .ok()
}

pub fn compare_text(a: &EvalRowView, b: &EvalRowView) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<22} {:<24} {:<24}\n",
        "",
        short_hash(&a.prompt_hash),
        short_hash(&b.prompt_hash)
    ));
    for (name, x, y) in [
        ("point", a.point.clone(), b.point.clone()),
        ("model", a.model.clone(), b.model.clone()),
        ("json_mode", a.json_mode.clone(), b.json_mode.clone()),
        ("rows", a.rows.to_string(), b.rows.to_string()),
        (
            "agreement",
            fmt_opt(a.agreement, 4),
            fmt_opt(b.agreement, 4),
        ),
        (
            "agreement_raw",
            fmt_opt(a.agreement_raw, 4),
            fmt_opt(b.agreement_raw, 4),
        ),
        (
            "faithfulness",
            a.faithfulness_failures.to_string(),
            b.faithfulness_failures.to_string(),
        ),
        (
            "parse_failures",
            a.parse_failures.to_string(),
            b.parse_failures.to_string(),
        ),
        (
            "tokens_per_row",
            fmt_opt(a.tokens_per_row, 1),
            fmt_opt(b.tokens_per_row, 1),
        ),
        (
            "latency_ms_per_row",
            fmt_opt(a.latency_ms_per_row, 0),
            fmt_opt(b.latency_ms_per_row, 0),
        ),
        ("cost_usd", fmt_opt(a.cost_usd, 4), fmt_opt(b.cost_usd, 4)),
        ("eval_id", a.id.to_string(), b.id.to_string()),
    ] {
        out.push_str(&format!("{name:<22} {x:<24} {y:<24}\n"));
    }
    out
}

fn short_hash(h: &str) -> String {
    h.chars().take(12).collect()
}

// ---------- Eval build ----------

pub struct BuildOpts {
    pub kind: Option<String>,
    /// Earliest window per subject (cold-start rows) instead of latest.
    pub early: bool,
    /// Evenly spread windows per subject (first and last included).
    pub sample: Option<usize>,
    /// Cap on total rows (0 or None means all).
    pub limit: Option<usize>,
}

/// Export candidate golden rows from a store for hand labelling.
/// `classes` and `thresholds` shape the envelopes exactly as the
/// worker builds them. Returns the rows written.
pub fn eval_build(
    db: &Path,
    classes: &crate::tap::classes::Ja4Classes,
    thresholds: &HashMap<String, f64>,
    point: &str,
    out: &Path,
    opts: &BuildOpts,
) -> Result<usize, LlmError> {
    check_point(point)?;
    let conn = open_db(db)?;
    let now_us = now_s() * 1_000_000;
    let mut rows: Vec<String> = Vec::new();
    match point {
        "label" => {
            let subjects = subjects_with_windows(&conn)?;
            for (scope, id, stamps) in subjects {
                for ts in pick_windows(&stamps, opts) {
                    let subject = crate::llm::Subject {
                        scope: scope.clone(),
                        id: id.clone(),
                    };
                    let sel = if opts.early && opts.sample.is_none() {
                        WindowSel::Earliest
                    } else if opts.sample.is_none() {
                        WindowSel::Latest
                    } else {
                        WindowSel::At(ts)
                    };
                    let (envelope, meta) =
                        build_label_envelope_at(&conn, classes, &subject, thresholds, now_us, sel)?;
                    // A window under ten turns has no faithful label:
                    // the row expects unknown whatever the labels say.
                    let cold = envelope
                        .get("window")
                        .and_then(|w| w.get("turns_held"))
                        .and_then(serde_json::Value::as_f64)
                        .is_some_and(|t| t < 10.0);
                    let (expected, from) = if cold {
                        (
                            Some("unknown".to_string()),
                            Some("insufficient_data".to_string()),
                        )
                    } else {
                        prefill_label(&conn, &scope, &id, meta.window_end_ts)?
                    };
                    rows.push(
                        serde_json::json!({
                            "point": "label",
                            "kind": opts.kind,
                            "expected_label": expected,
                            "allowed_signals": serde_json::Value::Null,
                            "prefilled_from": from,
                            "envelope": envelope,
                        })
                        .to_string(),
                    );
                    if capped(&rows, opts) {
                        break;
                    }
                }
                if capped(&rows, opts) {
                    break;
                }
            }
        }
        "classify" => {
            let mut stmt = conn.prepare(
                "SELECT method, pattern, sample_query, body_slice FROM payload_patterns ORDER BY rowid",
            )?;
            let patterns: Vec<(String, String, Option<String>, Option<String>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .filter_map(|r| r.ok())
                .collect();
            for (method, pattern, sample_query, body_slice) in patterns {
                rows.push(
                    serde_json::json!({
                        "point": "classify",
                        "method": method,
                        "path_pattern": pattern,
                        "sample_query": sample_query,
                        "body_slice": body_slice,
                        "content_type": serde_json::Value::Null,
                        "expected_category": serde_json::Value::Null,
                    })
                    .to_string(),
                );
                if capped(&rows, opts) {
                    break;
                }
            }
        }
        "explain" => {
            let subjects = scored_subjects(&conn)?;
            for (scope, id) in subjects {
                for (score, top3_raw, ts, surface) in spread_scores(&conn, &scope, &id, opts)? {
                    let top3: Vec<serde_json::Value> =
                        serde_json::from_str(&top3_raw).unwrap_or_default();
                    let must_mention: Vec<String> = top3
                        .iter()
                        .filter_map(|e| e.get("name")?.as_str().map(str::to_string))
                        .collect();
                    let window = window_summary(&conn, &scope, &id, ts)?;
                    rows.push(
                        serde_json::json!({
                            "point": "explain",
                            "surface": surface,
                            "score": score,
                            "threshold": surface
                                .as_ref()
                                .and_then(|s| thresholds.get(s).copied()),
                            "top3": top3,
                            "window": window,
                            "must_mention": must_mention,
                        })
                        .to_string(),
                    );
                    if capped(&rows, opts) {
                        break;
                    }
                }
                if capped(&rows, opts) {
                    break;
                }
            }
        }
        "draft" => {
            let clusters = draft_clusters(&conn)?;
            for key in clusters {
                let (envelope, _) = build_draft_envelope(&conn, &key)?;
                let turns = cluster_turns(&conn, &key)?;
                rows.push(
                    serde_json::json!({
                        "point": "draft",
                        "expected_scope": serde_json::Value::Null,
                        "expected_surface": serde_json::Value::Null,
                        "must_parse": true,
                        "envelope": envelope,
                        "turns": turns,
                    })
                    .to_string(),
                );
                if capped(&rows, opts) {
                    break;
                }
            }
        }
        _ => return Err(LlmError::Point(point.to_string())),
    }
    std::fs::write(
        out,
        rows.join("\n") + if rows.is_empty() { "" } else { "\n" },
    )
    .map_err(|e| LlmError::Eval(format!("{}: cannot write: {e}", out.display())))?;
    Ok(rows.len())
}

fn capped(rows: &[String], opts: &BuildOpts) -> bool {
    opts.limit.is_some_and(|n| n > 0 && rows.len() >= n)
}

/// (scope, id, window stamps oldest-first) per subject with a v2 row.
fn subjects_with_windows(conn: &Connection) -> Result<Vec<(String, String, Vec<i64>)>, LlmError> {
    let mut stmt = conn.prepare(
        "SELECT fv.scope, fv.key, fv.ts_us FROM feature_vectors fv \
         JOIN turns t ON fv.turn_id = coalesce(t.turn_id, t.peer_key || ':' || t.ts_us) \
         WHERE fv.version = 2 ORDER BY fv.scope, fv.key, t.rowid",
    )?;
    let mut out: Vec<(String, String, Vec<i64>)> = Vec::new();
    let rows: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();
    for (scope, key, ts) in rows {
        match out.last_mut() {
            Some((s, k, stamps)) if s == &scope && k == &key => stamps.push(ts),
            _ => out.push((scope, key, vec![ts])),
        }
    }
    Ok(out)
}

fn pick_windows(stamps: &[i64], opts: &BuildOpts) -> Vec<i64> {
    if stamps.is_empty() {
        return Vec::new();
    }
    match opts.sample {
        None => vec![if opts.early {
            stamps[0]
        } else {
            stamps[stamps.len() - 1]
        }],
        Some(0) | Some(1) => vec![stamps[stamps.len() - 1]],
        Some(n) => {
            let n = n.min(stamps.len());
            (0..n)
                .map(|i| stamps[i * (stamps.len() - 1) / (n - 1).max(1)])
                .collect::<Vec<_>>()
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect()
        }
    }
}

/// The latest ground-truth label for one window: operator first, then
/// the machine labelers. `rule_decision` and `llm_proposed` never
/// prefill: the golden set grades the pipeline, not itself.
fn prefill_label(
    conn: &Connection,
    scope: &str,
    id: &str,
    window_ts: i64,
) -> Result<(Option<String>, Option<String>), LlmError> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT label, source FROM labels \
             WHERE scope = ?1 AND scope_id = ?2 AND window_end_ts = ?3 \
             AND source IN ('operator', 'tool_run', 'synthetic_benign', 'verified_business') \
             ORDER BY CASE source WHEN 'operator' THEN 0 WHEN 'tool_run' THEN 1 \
             WHEN 'synthetic_benign' THEN 2 ELSE 3 END, created_at DESC, id DESC LIMIT 1",
            params![scope, id, window_ts],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(LlmError::Sqlite(e)),
        })?;
    Ok(row.map(|(l, s)| (Some(l), Some(s))).unwrap_or((None, None)))
}

fn scored_subjects(conn: &Connection) -> Result<Vec<(String, String)>, LlmError> {
    let mut stmt = conn.prepare(
        "SELECT scope, scope_id FROM scores GROUP BY scope, scope_id ORDER BY scope, scope_id",
    )?;
    let out: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(out)
}

type SpreadRow = (f64, String, i64, Option<String>);

fn spread_scores(
    conn: &Connection,
    scope: &str,
    id: &str,
    opts: &BuildOpts,
) -> Result<Vec<SpreadRow>, LlmError> {
    let mut stmt = conn.prepare(
        "SELECT score, top3, ts_us, surface FROM scores \
         WHERE scope = ?1 AND scope_id = ?2 ORDER BY ts_us",
    )?;
    let all: Vec<(f64, String, i64, Option<String>)> = stmt
        .query_map(params![scope, id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .filter_map(|r| r.ok())
        .collect();
    if all.is_empty() {
        return Ok(Vec::new());
    }
    let n = opts.sample.unwrap_or(3).clamp(1, all.len());
    if n >= all.len() {
        return Ok(all);
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(all[i * (all.len() - 1) / (n - 1).max(1)].clone());
    }
    Ok(out)
}

/// The five-field window summary of the explain envelope, for the
/// feature row at or before one score.
fn window_summary(
    conn: &Connection,
    scope: &str,
    id: &str,
    ts_us: i64,
) -> Result<serde_json::Value, LlmError> {
    let vector: Option<String> = conn
        .query_row(
            "SELECT vector FROM feature_vectors \
             WHERE scope = ?1 AND key = ?2 AND ts_us <= ?3 ORDER BY ts_us DESC LIMIT 1",
            params![scope, id, ts_us],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(LlmError::Sqlite(e)),
        })?;
    let values: Vec<f32> = vector
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_default();
    let at = |name: &str| -> serde_json::Value {
        crate::rules::features::NAMES
            .iter()
            .position(|n| *n == name)
            .and_then(|i| values.get(i).copied())
            .map_or(serde_json::Value::Null, Into::into)
    };
    let turn_col = if scope == "actor" {
        "actor_id"
    } else {
        "cluster_key"
    };
    let asset_ratio: Option<f64> = conn
        .query_row(
            &format!(
                "SELECT avg(is_asset = 1) FROM (SELECT is_asset FROM turns \
                 WHERE {turn_col} = ?1 ORDER BY ts_us DESC LIMIT 64)"
            ),
            params![id],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    Ok(serde_json::json!({
        "turns_held": at("turns_held"),
        "ratio_4xx": at("ratio_4xx"),
        "distinct_routes": at("distinct_routes"),
        "iri_cv": at("gap_cv"),
        "asset_ratio": asset_ratio,
    }))
}

/// Cluster keys with at least ten rows and a malicious claim, the
/// shape the draft trigger asks about.
fn draft_clusters(conn: &Connection) -> Result<Vec<String>, LlmError> {
    let mut stmt = conn.prepare(
        "SELECT fv.key FROM feature_vectors fv \
         WHERE fv.scope = 'cluster' \
         GROUP BY fv.key HAVING count(*) >= 10 \
         AND EXISTS (SELECT 1 FROM labels l WHERE l.scope = 'cluster' AND l.scope_id = fv.key \
             AND l.label = 'malicious' AND l.source IN ('operator', 'tool_run')) \
         ORDER BY fv.key",
    )?;
    let out: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(out)
}

/// The cluster's last 30 turns, oldest first, with the fields the
/// dry-run matcher reads.
fn cluster_turns(conn: &Connection, key: &str) -> Result<Vec<serde_json::Value>, LlmError> {
    let mut stmt = conn.prepare(
        "SELECT route, verb, status, surface, principal, credential_status, validation_failed, \
         exception, auth_event, req_shape, bound, path_pattern, credential_hash \
         FROM turns WHERE cluster_key = ?1 ORDER BY rowid DESC LIMIT 30",
    )?;
    let mut turns: Vec<serde_json::Value> = stmt
        .query_map(params![key], |r| {
            let bound: String = r.get(10)?;
            Ok(serde_json::json!({
                "route": r.get::<_, String>(0)?,
                "verb": r.get::<_, String>(1)?,
                "status": r.get::<_, i64>(2)?,
                "surface": r.get::<_, Option<String>>(3)?,
                "principal": r.get::<_, String>(4)?,
                "credential_status": r.get::<_, Option<String>>(5)?,
                "validation_failed": r.get::<_, Option<String>>(6)?
                    .map(|f| serde_json::json!([f])).unwrap_or(serde_json::Value::Null),
                "exception": r.get::<_, Option<String>>(7)?,
                "auth_event": r.get::<_, Option<String>>(8)?,
                "req_shape": r.get::<_, String>(9)?,
                "bound": serde_json::from_str::<serde_json::Value>(&bound).unwrap_or(serde_json::Value::Null),
                "path_pattern": r.get::<_, Option<String>>(11)?,
                "credential_hash": r.get::<_, Option<String>>(12)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    turns.reverse();
    Ok(turns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LlmMode;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::Duration;

    fn mock_server(
        responses: Vec<(u16, String)>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_in = seen.clone();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() || buf.len() > 65_536 {
                        return;
                    }
                    buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&buf);
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if len > 0 {
                    let mut rest = vec![0u8; len];
                    if stream.read_exact(&mut rest).is_ok() {
                        seen_in
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&rest).into_owned());
                    }
                }
                let out = format!(
                    "HTTP/1.1 {status} x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(out.as_bytes());
            }
        });
        (url, seen)
    }

    fn completion(content: &str) -> String {
        serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        })
        .to_string()
    }

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("leesided-eval-{}-{name}", std::process::id()))
    }

    fn exec_for(url: &str) -> Exec {
        Exec {
            url: url.to_string(),
            key: "k".to_string(),
            model: "m".to_string(),
            model_overrides: HashMap::new(),
            mode: LlmMode::Live,
            daily_calls: 500,
            daily_tokens: 500_000,
            honeytoken_routes: Vec::new(),
        }
    }

    fn turn(path: &str, status: i64) -> serde_json::Value {
        serde_json::json!({
            "method": "GET", "path": path, "status": status,
            "ua_class": "browser", "flags": [],
            "credential_status": null, "tag_status": "absent",
            "ja4_class": "unknown", "surface": "web",
            "is_asset": 0, "cred": null,
        })
    }

    fn label_row(
        kind: &str,
        scope: &str,
        expected: Option<&str>,
        turns: Vec<serde_json::Value>,
        window: serde_json::Value,
    ) -> String {
        serde_json::json!({
            "point": "label", "kind": kind,
            "expected_label": expected,
            "allowed_signals": null, "prefilled_from": "tool_run",
            "envelope": {
                "task": "propose_label",
                "subject": {"scope": scope, "id": "aa"},
                "window": window, "turns": turns, "labels_so_far": [],
            },
        })
        .to_string()
    }

    #[test]
    fn eval_label_grades_agreement_and_writes_the_row() {
        let set = tmp_path("label.jsonl");
        let db = tmp_path("label.sqlite");
        let _ = std::fs::remove_file(&db);
        std::fs::write(&db, b"").unwrap();
        let scan_turns = vec![turn("/a", 404), turn("/b", 404), turn("/c", 404)];
        let quiet_turns = vec![turn("/", 200)];
        std::fs::write(
            &set,
            format!(
                "{}\n{}\n{}\n",
                label_row(
                    "attack-ffuf",
                    "actor",
                    Some("malicious"),
                    scan_turns.clone(),
                    serde_json::json!({"turns_held": 64.0, "iri_cv": 0.02, "asset_ratio": 0.0}),
                ),
                label_row(
                    "attack-ffuf",
                    "cluster",
                    Some("malicious"),
                    scan_turns,
                    serde_json::json!({"turns_held": 64.0, "iri_cv": 0.02, "asset_ratio": 0.0}),
                ),
                label_row(
                    "benign-chromium",
                    "actor",
                    Some("benign"),
                    quiet_turns,
                    serde_json::json!({"turns_held": 64.0, "iri_cv": 0.9, "asset_ratio": 0.8}),
                ),
            ),
        )
        .unwrap();
        let hit = r#"{"label":"malicious","confidence":0.9,"reason":"404 sweep.","signals":[{"name":"high_404_rate","turns":[0,1,2]}]}"#;
        // Right label, unsupported signal: one cited turn is no
        // scanner, so the row lands unknown and only the raw agrees.
        let thin = r#"{"label":"malicious","confidence":0.9,"reason":"one 404.","signals":[{"name":"scanner_paths","turns":[0]}]}"#;
        let calm = r#"{"label":"benign","confidence":0.9,"reason":"quiet.","signals":[{"name":"normal_browsing","turns":[0]}]}"#;
        let (url, seen) = mock_server(vec![
            (200, completion(hit)),
            (200, completion(thin)),
            (200, completion(calm)),
        ]);
        let exec = exec_for(&url);
        let input = EvalInput {
            exec: &exec,
            system: None,
            prompt_hash: "h".to_string(),
            model: "m".to_string(),
            json_mode: JsonMode::Prompt,
            effort: None,
            limit: None,
        };
        let summary = evaluate(&db, &set, "label", &input).unwrap();
        assert_eq!(summary.rows, 3);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.errors, 0);
        assert_eq!(summary.agreement, Some(2.0 / 3.0));
        assert_eq!(summary.agreement_raw, Some(1.0));
        assert_eq!(summary.parse_failures, 0);
        assert_eq!(summary.faithfulness_failures, 1);
        assert_eq!(seen.lock().unwrap().len(), 3);
        assert_eq!(summary.groups["kind"]["attack-ffuf"]["agree"], 1);
        assert_eq!(summary.groups["kind"]["attack-ffuf"]["agree_raw"], 2);
        assert_eq!(summary.groups["scope"]["actor"]["n"], 2);
        assert_eq!(summary.groups["scope"]["cluster"]["agree"], 0);
        assert_eq!(summary.groups["scope"]["cluster"]["agree_raw"], 1);
        assert_eq!(summary.groups["dropped_signals"]["scanner_paths"], 1);
        assert_eq!(summary.calibration.as_array().unwrap().len(), 5);
        assert!(summary.tokens_per_row.unwrap() > 0.0);
        let worst = summary.worst.as_array().unwrap();
        assert_eq!(worst.len(), 1);
        assert_eq!(worst[0]["got"], "unknown");
        assert!(worst[0]["detail"]
            .as_str()
            .unwrap()
            .contains("raw=malicious"));
        assert!(worst[0]["detail"]
            .as_str()
            .unwrap()
            .contains("scanner_paths"));
        let conn = Connection::open(&db).unwrap();
        let stored: (String, f64, f64, i64, i64) = conn
            .query_row(
                "SELECT point, agreement, agreement_raw, faithfulness_failures, parse_failures FROM llm_evals",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(stored, ("label".to_string(), 2.0 / 3.0, 1.0, 1, 0));
        let calls: i64 = conn
            .query_row("SELECT count(*) FROM llm_calls", [], |r| r.get(0))
            .unwrap();
        assert_eq!(calls, 3, "dry-send logs the calls");
        let failed: Option<String> = conn
            .query_row(
                "SELECT faithfulness_failed FROM llm_calls WHERE faithfulness_failed IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(failed.as_deref(), Some(r#"["scanner_paths"]"#));
        let labels: i64 = conn
            .query_row("SELECT count(*) FROM labels", [], |r| r.get(0))
            .unwrap();
        assert_eq!(labels, 0, "dry-send writes no labels");
    }

    #[test]
    fn eval_skips_unlabelled_rows_without_sending() {
        let set = tmp_path("skip.jsonl");
        let db = tmp_path("skip.sqlite");
        let _ = std::fs::remove_file(&db);
        std::fs::write(&db, b"").unwrap();
        std::fs::write(
            &set,
            format!(
                "{}\n",
                label_row(
                    "k",
                    "actor",
                    None,
                    vec![turn("/", 200)],
                    serde_json::json!({})
                ),
            ),
        )
        .unwrap();
        // No queued response: any request fails the run.
        let (url, seen) = mock_server(vec![]);
        let exec = exec_for(&url);
        let input = EvalInput {
            exec: &exec,
            system: None,
            prompt_hash: "h".to_string(),
            model: "m".to_string(),
            json_mode: JsonMode::Prompt,
            effort: None,
            limit: None,
        };
        let summary = evaluate(&db, &set, "label", &input).unwrap();
        assert_eq!(summary.rows, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.agreement, None);
        assert!(seen.lock().unwrap().is_empty(), "no call for a skipped row");
        let conn = Connection::open(&db).unwrap();
        let calls: i64 = conn
            .query_row("SELECT count(*) FROM llm_calls", [], |r| r.get(0))
            .unwrap();
        assert_eq!(calls, 0);
    }

    #[test]
    fn dry_run_counts_matching_turns() {
        let now = now_s() + 10_000;
        let rule: Rule = Rule::parse(
            &serde_json::json!({
                "id": "t-404-watch", "note": "n", "mode": "shadow", "action": "watch",
                "origin": {"kind": "operator"},
                "match": {"route": ["*"], "verb": ["GET"], "principal": "any"},
                "when": {"scope": "session", "count": {"status": ["4xx"]}, "gte": 2},
            })
            .to_string(),
            now,
        )
        .unwrap();
        let turns = vec![
            serde_json::json!({"route": "home", "verb": "GET", "status": 200, "principal": "anon"}),
            serde_json::json!({"route": "_unrouted", "verb": "GET", "status": 404, "principal": "anon", "path_pattern": "/wp-login.php"}),
            serde_json::json!({"route": "_unrouted", "verb": "GET", "status": 404, "principal": "anon", "path_pattern": "/.env"}),
        ];
        assert_eq!(dry_run_matches(&rule, &turns), Some(2));
        assert_eq!(rule_scope(&rule), "session");
        assert_eq!(rule_surfaces(&rule), Vec::<String>::new());

        let seq: Rule = Rule::parse(
            &serde_json::json!({
                "id": "t-seq", "note": "n", "mode": "shadow", "action": "watch",
                "origin": {"kind": "operator"},
                "match": {"route": ["portal.login"], "verb": ["POST"], "principal": "any"},
                "when": {"sequence": ["home", "portal.login"]},
            })
            .to_string(),
            now,
        )
        .unwrap();
        let turns = vec![
            serde_json::json!({"route": "home", "verb": "GET", "status": 200, "principal": "anon"}),
            serde_json::json!({"route": "portal.login", "verb": "POST", "status": 401, "principal": "anon"}),
        ];
        assert_eq!(dry_run_matches(&seq, &turns), Some(1));

        let score: Rule = Rule::parse(
            &serde_json::json!({
                "id": "t-score", "note": "n", "mode": "shadow", "action": "watch",
                "origin": {"kind": "operator"},
                "match": {"route": ["*"], "verb": ["GET"], "principal": "any"},
                "when": {"scope": "actor", "score": {"gte": 0.9}},
            })
            .to_string(),
            now,
        )
        .unwrap();
        assert_eq!(dry_run_matches(&score, &turns), None);
    }
}
