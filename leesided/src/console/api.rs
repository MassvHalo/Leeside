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
                    chip.href = format!("{prefix}{}", chip.href);
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
