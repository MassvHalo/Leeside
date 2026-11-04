//! The dashboard's JSON API under `/windside/api/v1/`: summary,
//! episodes, traffic, and episode decisions. Auth is the A-0 login's
//! session cookie (viewers read, admins decide); the cookie is
//! `SameSite=Strict`, the API sends no CORS headers, and the one
//! mutation takes JSON, so no CSRF token is needed.

use crate::console::queries::{self, Ctx};
use crate::engine::Engine;
use crate::store::{self, StoreOp};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

fn jerr(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn qerr(e: queries::QueryError) -> Response {
    match e {
        queries::QueryError::NoCall(id) => {
            jerr(StatusCode::NOT_FOUND, &format!("no llm call {id}"))
        }
        queries::QueryError::NoJob(id) => jerr(StatusCode::NOT_FOUND, &format!("no llm job {id}")),
        queries::QueryError::NoTurn(id) => jerr(StatusCode::NOT_FOUND, &format!("no turn {id}")),
        queries::QueryError::NoActor(id) => jerr(StatusCode::NOT_FOUND, &format!("no actor {id}")),
        queries::QueryError::NoCluster(key) => {
            jerr(StatusCode::NOT_FOUND, &format!("no cluster {key}"))
        }
        queries::QueryError::NoRule(id) => jerr(StatusCode::NOT_FOUND, &format!("no rule {id}")),
        queries::QueryError::NoPayload(hash) => {
            jerr(StatusCode::NOT_FOUND, &format!("no payload pattern {hash}"))
        }
        queries::QueryError::UnknownApp(app) => {
            jerr(StatusCode::BAD_REQUEST, &format!("unknown app `{app}`"))
        }
        e => jerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("windside error: {e}"),
        ),
    }
}

fn read_json<T>(
    e: &Engine,
    f: impl FnOnce(&Ctx) -> Result<T, queries::QueryError>,
) -> Result<T, Box<Response>> {
    e.store
        .read(|conn| Ctx::new(conn, &e.cfg.app_id).and_then(|ctx| f(&ctx)))
        .map_err(|e| Box::new(qerr(e)))
}

fn session_of(e: &Engine, headers: &HeaderMap) -> Result<crate::console::Session, Box<Response>> {
    super::session_of(e, headers)
        .ok_or_else(|| Box::new(jerr(StatusCode::UNAUTHORIZED, "login required")))
}

fn require_admin_json(session: &crate::console::Session) -> Result<(), Box<Response>> {
    if session.role == crate::console::Role::Admin {
        Ok(())
    } else {
        Err(Box::new(jerr(
            StatusCode::FORBIDDEN,
            "viewers cannot change anything",
        )))
    }
}

#[derive(Deserialize)]
pub struct ApiQuery {
    window: Option<String>,
    bucket: Option<String>,
}

fn window_of(q: &ApiQuery) -> Result<i64, Box<Response>> {
    let raw = q.window.as_deref().unwrap_or("24h");
    queries::parse_window(raw).ok_or_else(|| {
        Box::new(jerr(
            StatusCode::BAD_REQUEST,
            "window must be 24h, 7d or 30d",
        ))
    })
}

pub async fn api_summary(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Query(q): Query<ApiQuery>,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let window_s = match window_of(&q) {
        Ok(w) => w,
        Err(r) => return *r,
    };
    let now = store::now_s();
    let mode = e.windside.mode.as_str().to_string();
    let summary = match read_json(&e, |ctx| {
        ctx.dashboard_summary(window_s, now, &super::thresholds(&e), &mode)
    }) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let mut v = serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null);
    v["role"] = serde_json::Value::String(session.role.as_str().to_string());
    v["assistant"] = serde_json::json!({
        "model": e.cfg.llm_model,
        "mode": e.cfg.llm_mode.as_str(),
    });
    Json(v).into_response()
}

/// The daemon's health JSON plus one read-only per-rule modes
/// list, session-gated for the Settings Status page (the browser
/// cannot reach the local API).
pub async fn api_status(State(e): State<Arc<Engine>>, headers: HeaderMap) -> Response {
    if let Err(r) = session_of(&e, &headers) {
        return *r;
    }
    let mut v = e.health();
    let global = e.mode();
    let detail: Vec<serde_json::Value> = e
        .rules
        .loaded()
        .iter()
        .map(|(r, m)| {
            serde_json::json!({
                "id": r.id,
                "state": m.state.as_str(),
                "mode": r.mode.as_str(),
                "effective": global.min(r.mode).as_str(),
            })
        })
        .collect();
    v["rules_detail"] = serde_json::Value::Array(detail);
    Json(v).into_response()
}

pub async fn api_episodes(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Query(q): Query<ApiQuery>,
) -> Response {
    if let Err(r) = session_of(&e, &headers) {
        return *r;
    }
    let window_s = match window_of(&q) {
        Ok(w) => w,
        Err(r) => return *r,
    };
    let now = store::now_s();
    let shadow = e.windside.mode == crate::config::WindsideMode::Shadow;
    let prefix = e.cfg.console_path.clone();
    match read_json(&e, |ctx| {
        ctx.episodes(window_s, now, &super::thresholds(&e), shadow)
    }) {
        Ok(mut episodes) => {
            for ep in &mut episodes {
                for chip in &mut ep.chips {
                    if let Some(h) = chip.href.take() {
                        chip.href = Some(format!("{prefix}{h}"));
                    }
                }
            }
            Json(episodes).into_response()
        }
        Err(r) => *r,
    }
}

pub async fn api_traffic(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Query(q): Query<ApiQuery>,
) -> Response {
    if let Err(r) = session_of(&e, &headers) {
        return *r;
    }
    let window_s = match window_of(&q) {
        Ok(w) => w,
        Err(r) => return *r,
    };
    let bucket_s = queries::parse_bucket(q.bucket.as_deref().unwrap_or("1h"));
    let bucket_s = match bucket_s {
        Some(b) => b,
        None => {
            return jerr(
                StatusCode::BAD_REQUEST,
                "bucket must be 1h, 6h, 12h, 1d or 7d",
            );
        }
    };
    if bucket_s > window_s || window_s % bucket_s != 0 {
        return jerr(
            StatusCode::BAD_REQUEST,
            "the window must divide evenly into buckets no bigger than itself",
        );
    }
    let now = store::now_s();
    let shadow = e.windside.mode == crate::config::WindsideMode::Shadow;
    match read_json(&e, |ctx| {
        ctx.traffic(window_s, bucket_s, now, &super::thresholds(&e), shadow)
    }) {
        Ok(t) => Json(t).into_response(),
        Err(r) => *r,
    }
}

#[derive(Deserialize)]
struct DecideBody {
    decision: Option<String>,
    window_end_ts: Option<i64>,
}

/// Write the operator's decision for an episode's subject: the same
/// `StoreOp::Label` the inspector's label form and the review console
/// write (operator, 1.0, freshness-checked window). `confirm` takes
/// the standing proposal's label; without one there is nothing to
/// confirm.
pub async fn api_decide(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = require_admin_json(&session) {
        return *r;
    }
    let rest = id.strip_prefix("ep_").unwrap_or("");
    let (scope, subject) = if let Some(s) = rest.strip_prefix("actor_") {
        ("actor", s)
    } else if let Some(s) = rest.strip_prefix("cluster_") {
        ("cluster", s)
    } else {
        return jerr(StatusCode::NOT_FOUND, "no such episode");
    };
    if subject.is_empty() {
        return jerr(StatusCode::NOT_FOUND, "no such episode");
    }
    let parsed: DecideBody = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(_) => return jerr(StatusCode::BAD_REQUEST, "invalid JSON"),
    };
    let (Some(decision), Some(window_end_ts)) = (parsed.decision, parsed.window_end_ts) else {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "decision and window_end_ts are required",
        );
    };
    if !matches!(decision.as_str(), "confirm" | "benign" | "unknown") {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "decision must be confirm, benign or unknown",
        );
    }
    let now = store::now_s();
    let detail = read_json(&e, |ctx| {
        if scope == "actor" {
            ctx.actor_detail(subject, 0, now, &super::thresholds(&e))
                .map(|d| {
                    (
                        d.head.id,
                        d.window_end_ts,
                        d.window_surface,
                        d.proposal.map(|p| p.label.label),
                    )
                })
        } else {
            ctx.cluster_detail(subject, 0, &super::thresholds(&e))
                .map(|d| {
                    (
                        d.row.key,
                        d.window_end_ts,
                        d.window_surface,
                        d.proposal.map(|p| p.label.label),
                    )
                })
        }
    });
    let (canonical, current_ts, surface, proposal) = match detail {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let Some(current_ts) = current_ts else {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no window to label: the subject has no feature rows",
        );
    };
    if current_ts != window_end_ts {
        return jerr(
            StatusCode::CONFLICT,
            "stale window: a newer window landed since the episode rendered; reload and decide again",
        );
    }
    let (label, note): (&'static str, String) = match decision.as_str() {
        "confirm" => match proposal.as_deref() {
            Some("benign") => ("benign", "confirmed llm_proposed".to_string()),
            Some("malicious") => ("malicious", "confirmed llm_proposed".to_string()),
            Some("unknown") => ("unknown", "confirmed llm_proposed".to_string()),
            Some(other) => {
                return jerr(
                    StatusCode::BAD_REQUEST,
                    &format!("stored proposal unreadable: {other:?}"),
                );
            }
            None => {
                return jerr(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "nothing to confirm: this subject has no proposal",
                );
            }
        },
        "benign" => ("benign", "dashboard".to_string()),
        "unknown" => ("unknown", "dashboard".to_string()),
        _ => {
            return jerr(
                StatusCode::UNPROCESSABLE_ENTITY,
                "decision must be confirm, benign or unknown",
            );
        }
    };
    let scope_static: &'static str = if scope == "actor" { "actor" } else { "cluster" };
    e.store.send(StoreOp::Label(store::LabelRow {
        scope: scope_static,
        scope_id: canonical.clone(),
        surface,
        window_end_ts: current_ts,
        label,
        source: "operator",
        confidence: 1.0,
        kind: None,
        note: Some(note),
        created_at: now,
        signals: None,
        daily_calls: super::llm_budgets(&e).0,
        daily_tokens: super::llm_budgets(&e).1,
    }));
    e.store.flush().await;
    Json(json!({
        "ok": true,
        "scope": scope_static,
        "scope_id": canonical,
        "label": label,
    }))
    .into_response()
}

// ---------- Round A-2: review + actor pages ----------

/// The Review page's two tabs: the queue in the CLI's order with its
/// agree/disagree split, and the Decided tab over the window.
pub async fn api_review_queue(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Query(q): Query<ApiQuery>,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let window_s = match window_of(&q) {
        Ok(w) => w,
        Err(r) => return *r,
    };
    let now = store::now_s();
    let mut v = match read_json(&e, |ctx| {
        ctx.review_queue_json(&super::thresholds(&e), now - window_s)
    }) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    v["role"] = serde_json::Value::String(session.role.as_str().to_string());
    Json(v).into_response()
}

/// One review item: model verdict, proposal with cited signals, the
/// evidence table, the decision state, queue neighbours.
pub async fn api_review_item(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Path((scope, id)): Path<(String, String)>,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let now = store::now_s();
    let mut v = match read_json(&e, |ctx| {
        ctx.review_item_json(&scope, &id, &super::thresholds(&e), now)
    }) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    v["role"] = serde_json::Value::String(session.role.as_str().to_string());
    Json(v).into_response()
}

#[derive(Deserialize)]
pub struct ReviewBody {
    decision: Option<String>,
    window_end_ts: Option<i64>,
}

/// Decide a review item, with the design's `data-action` vocabulary:
/// `confirm` ("It's an attack") writes the malicious label and the
/// block together, `benign` ("It's fine") and `unknown` ("Not sure")
/// write the label alone. Unlike the dashboard decision, `confirm`
/// does not take the proposal's label: it asserts malicious. The
/// window is freshness-checked like the dashboard decision; a stale
/// render re-reads and decides again. Clusters take the label only:
/// blocks are actor-scope, like the inspector's.
pub async fn api_review_decide(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Path((scope, id)): Path<(String, String)>,
    body: String,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = require_admin_json(&session) {
        return *r;
    }
    if scope != "actor" && scope != "cluster" {
        return jerr(StatusCode::NOT_FOUND, "no such subject");
    }
    let parsed: ReviewBody = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(_) => return jerr(StatusCode::BAD_REQUEST, "invalid JSON"),
    };
    let (Some(decision), Some(window_end_ts)) = (parsed.decision, parsed.window_end_ts) else {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "decision and window_end_ts are required",
        );
    };
    if !matches!(decision.as_str(), "confirm" | "benign" | "unknown") {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "decision must be confirm, benign or unknown",
        );
    }
    let now = store::now_s();
    let detail = read_json(&e, |ctx| {
        if scope == "actor" {
            ctx.actor_detail(&id, 0, now, &super::thresholds(&e))
                .map(|d| (d.head.id, d.window_end_ts, d.window_surface))
        } else {
            ctx.cluster_detail(&id, 0, &super::thresholds(&e))
                .map(|d| (d.row.key, d.window_end_ts, d.window_surface))
        }
    });
    let (canonical, current_ts, surface) = match detail {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let Some(current_ts) = current_ts else {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no window to label: the subject has no feature rows",
        );
    };
    if current_ts != window_end_ts {
        return jerr(
            StatusCode::CONFLICT,
            "stale window: a newer window landed since the item rendered; reload and decide again",
        );
    }
    // Resolve the block key before writing anything: an
    // unparseable id 404s with no label half-written.
    let key = if decision == "confirm" && scope == "actor" {
        match crate::rules::windows::key16(&canonical) {
            Some(k) => Some(k),
            None => return jerr(StatusCode::NOT_FOUND, &format!("no actor {canonical}")),
        }
    } else {
        None
    };
    let label = match decision.as_str() {
        "confirm" => "malicious",
        "unknown" => "unknown",
        _ => "benign",
    };
    let scope_static: &'static str = if scope == "actor" { "actor" } else { "cluster" };
    e.store.send(StoreOp::Label(store::LabelRow {
        scope: scope_static,
        scope_id: canonical.clone(),
        surface,
        window_end_ts: current_ts,
        label,
        source: "operator",
        confidence: 1.0,
        kind: None,
        note: Some("review".to_string()),
        created_at: now,
        signals: None,
        daily_calls: super::llm_budgets(&e).0,
        daily_tokens: super::llm_budgets(&e).1,
    }));
    let blocked = match key {
        Some(k) => {
            let d = crate::rules::decisions::Decision {
                scope: crate::rules::model::Scope::Actor,
                key: k,
                action: crate::rules::model::Action::Block,
                mode: e.mode(),
                rule: std::sync::Arc::from("operator"),
                rule_version: 0,
                created_at: now,
                expires_at: now + crate::rules::compile::BLOCK_TTL_S as i64,
            };
            e.decisions.insert(d.clone());
            e.store.send(StoreOp::DecisionUpsert(d));
            true
        }
        None => false,
    };
    e.store.flush().await;
    Json(json!({
        "ok": true,
        "scope": scope_static,
        "scope_id": canonical,
        "label": label,
        "blocked": blocked,
    }))
    .into_response()
}

/// One actor page: headline, client, activity, score, labels,
/// proposal, decisions, similar actors, turns.
pub async fn api_actor(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let now = store::now_s();
    let mut v = match read_json(&e, |ctx| {
        ctx.actor_json(&id, &super::thresholds(&e), &e.ja4_classes, now)
    }) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    v["role"] = serde_json::Value::String(session.role.as_str().to_string());
    Json(v).into_response()
}

#[derive(Deserialize)]
pub struct TurnsQuery {
    flag: Option<String>,
    status: Option<String>,
    route: Option<String>,
    limit: Option<i64>,
}

/// The actor turn table with its filters: flag, status (an exact
/// code or an `Nxx` class), route, limit.
pub async fn api_actor_turns(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TurnsQuery>,
) -> Response {
    if let Err(r) = session_of(&e, &headers) {
        return *r;
    }
    if let Some(s) = q.status.as_deref() {
        let class = s.len() == 3 && s.ends_with("xx") && s.as_bytes()[0].is_ascii_digit();
        let exact = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !class && !exact {
            return jerr(
                StatusCode::BAD_REQUEST,
                "status must be a code or an Nxx class",
            );
        }
    }
    match read_json(&e, |ctx| {
        ctx.actor_turns_json(
            &id,
            q.flag.as_deref(),
            q.status.as_deref(),
            q.route.as_deref(),
            q.limit.unwrap_or(20),
        )
    }) {
        Ok(v) => Json(v).into_response(),
        Err(r) => *r,
    }
}

#[derive(Deserialize)]
pub struct BlockBody {
    action: Option<String>,
}

/// Block or unblock an actor: the sticky `operator` decision plus
/// the operator label together, since a label at or after the
/// proposal is what removes the item from the queue. Unblocking
/// with no live block 404s like the inspector's, with no label.
pub async fn api_actor_block(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let session = match session_of(&e, &headers) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(r) = require_admin_json(&session) {
        return *r;
    }
    let parsed: BlockBody = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(_) => return jerr(StatusCode::BAD_REQUEST, "invalid JSON"),
    };
    let Some(action) = parsed.action else {
        return jerr(StatusCode::UNPROCESSABLE_ENTITY, "action is required");
    };
    if !matches!(action.as_str(), "block" | "unblock") {
        return jerr(
            StatusCode::UNPROCESSABLE_ENTITY,
            "action must be block or unblock",
        );
    }
    let now = store::now_s();
    let resolved = read_json(&e, |ctx| {
        let ids = ctx.actor_ids(&id)?;
        let window = ctx.latest_window("actor", &ids[0])?;
        Ok::<_, queries::QueryError>((ids[0].clone(), window))
    });
    let (canonical, window) = match resolved {
        Ok(d) => d,
        Err(r) => return *r,
    };
    let key = match crate::rules::windows::key16(&canonical) {
        Some(k) => k,
        None => return jerr(StatusCode::NOT_FOUND, &format!("no actor {canonical}")),
    };
    if action == "unblock" && !e.decisions.remove(crate::rules::model::Scope::Actor, key) {
        return jerr(StatusCode::NOT_FOUND, "no live block on this actor");
    }
    let (label, blocked) = if action == "block" {
        let d = crate::rules::decisions::Decision {
            scope: crate::rules::model::Scope::Actor,
            key,
            action: crate::rules::model::Action::Block,
            mode: e.mode(),
            rule: std::sync::Arc::from("operator"),
            rule_version: 0,
            created_at: now,
            expires_at: now + crate::rules::compile::BLOCK_TTL_S as i64,
        };
        e.decisions.insert(d.clone());
        e.store.send(StoreOp::DecisionUpsert(d));
        ("malicious", true)
    } else {
        e.store.send(StoreOp::DecisionDelete {
            scope: crate::rules::model::Scope::Actor,
            key,
        });
        ("benign", false)
    };
    e.store.send(StoreOp::Label(store::LabelRow {
        scope: "actor",
        scope_id: canonical.clone(),
        surface: window.as_ref().and_then(|(_, s)| s.clone()),
        window_end_ts: window.map(|(ts, _)| ts).unwrap_or(0),
        label,
        source: "operator",
        confidence: 1.0,
        kind: None,
        note: Some("actor page".to_string()),
        created_at: now,
        signals: None,
        daily_calls: super::llm_budgets(&e).0,
        daily_tokens: super::llm_budgets(&e).1,
    }));
    e.store.flush().await;
    Json(json!({
        "ok": true,
        "scope_id": canonical,
        "label": label,
        "blocked": blocked,
    }))
    .into_response()
}
