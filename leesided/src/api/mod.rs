//! The local HTTP API on 127.0.0.1: rules, mode, health. No auth in v1; the
//! day the UI moves off-host this gets a token, written into the brief first.

use crate::engine::Engine;
use crate::rules::compile::State;
use crate::rules::model::{Mode, Rule};
use crate::store::{self, StoreError};
use axum::extract::{Path, Query, State as AxState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/rules", get(list).post(create))
        .route("/rules/schema", get(schema))
        .route("/rules/export", get(export))
        .route("/rules/validate", post(validate))
        .route("/rules/reload", post(reload))
        .route("/rules/{id}", get(show).put(update))
        .route("/rules/{id}/accept", post(accept))
        .route("/rules/{id}/retire", post(retire))
        .route("/mode", get(mode_get).put(mode_put))
        .with_state(engine)
}

pub async fn serve(engine: Arc<Engine>, listener: TcpListener) {
    if let Err(e) = axum::serve(listener, router(engine)).await {
        tracing::error!(error = %e, "api server stopped");
    }
}

struct ApiError(StatusCode, Value);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Invalid(errors) => ApiError(
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({ "error": "invalid rule", "errors": errors }),
            ),
            StoreError::NotFound => {
                ApiError(StatusCode::NOT_FOUND, json!({ "error": "not found" }))
            }
            e => ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": e.to_string() }),
            ),
        }
    }
}

fn conflict(msg: &str) -> ApiError {
    ApiError(StatusCode::CONFLICT, json!({ "error": msg }))
}

fn bad_request(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, json!({ "error": msg }))
}

type ApiResult = Result<Response, ApiError>;

async fn health(AxState(e): AxState<Arc<Engine>>) -> Json<Value> {
    Json(e.health())
}

#[derive(Deserialize)]
struct ListQuery {
    state: Option<String>,
    invalid: Option<bool>,
}

async fn list(AxState(e): AxState<Arc<Engine>>, Query(q): Query<ListQuery>) -> ApiResult {
    let states: Vec<State> = match q.state.as_deref() {
        None | Some("active") => vec![State::Active],
        Some("proposed") => vec![State::Proposed],
        Some("retired") => vec![State::Retired],
        Some("all") => vec![State::Active, State::Proposed, State::Retired],
        Some(_) => {
            return Err(bad_request(
                "state must be active, proposed, retired or all",
            ))
        }
    };
    let rows = e.store.load_rules(&states)?;
    let rules: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id, "version": r.version, "state": r.state, "mode": r.mode, "action": r.action,
                "origin_kind": r.origin_kind, "expires_at": r.expires_at,
                "created_at": r.created_at, "updated_at": r.updated_at,
            })
        })
        .collect();
    let mut body = json!({ "rules": rules, "generation": e.rules.generation() });
    if q.invalid.unwrap_or(false) {
        body["invalid"] = serde_json::to_value(e.rules.invalid()).unwrap_or(Value::Null);
    }
    Ok(Json(body).into_response())
}

async fn create(AxState(e): AxState<Arc<Engine>>, Json(rule): Json<Rule>) -> ApiResult {
    if e.store.load_rule(&rule.id)?.is_some() {
        return Err(conflict("rule exists; use PUT /rules/{id}"));
    }
    let id = rule.id.clone();
    let version = e.write_rule(rule, State::Active, "operator", None).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "version": version, "state": "active" })),
    )
        .into_response())
}

async fn show(AxState(e): AxState<Arc<Engine>>, Path(id): Path<String>) -> ApiResult {
    let row = e.store.load_rule(&id)?.ok_or(StoreError::NotFound)?;
    let body: Value = serde_json::from_str(&row.body).unwrap_or(Value::Null);
    let versions = e.store.rule_versions(&id)?;
    let stats = e
        .store
        .rule_stats_since(&id, store::now_s().div_euclid(3600) - 24)?;
    Ok(Json(json!({
        "id": row.id, "version": row.version, "state": row.state,
        "created_at": row.created_at, "updated_at": row.updated_at,
        "rule": body, "versions": versions, "stats_24h": stats,
    }))
    .into_response())
}

async fn update(
    AxState(e): AxState<Arc<Engine>>,
    Path(id): Path<String>,
    Json(rule): Json<Rule>,
) -> ApiResult {
    if rule.id != id {
        return Err(bad_request("body id must match the path"));
    }
    let row = e.store.load_rule(&id)?.ok_or(StoreError::NotFound)?;
    if row.state == State::Retired {
        return Err(conflict("rule is retired"));
    }
    let version = e.write_rule(rule, row.state, "operator", None).await?;
    Ok(Json(json!({ "id": id, "version": version, "state": row.state })).into_response())
}

#[derive(Deserialize, Default)]
struct AcceptBody {
    mode: Option<Mode>,
}

async fn accept(
    AxState(e): AxState<Arc<Engine>>,
    Path(id): Path<String>,
    body: Option<Json<AcceptBody>>,
) -> ApiResult {
    let row = e.store.load_rule(&id)?.ok_or(StoreError::NotFound)?;
    if row.state != State::Proposed {
        return Err(conflict("rule is not proposed"));
    }
    let mut rule: Rule =
        serde_json::from_str(&row.body).map_err(|_| conflict("stored body unreadable"))?;
    rule.mode = body.and_then(|b| b.0.mode).unwrap_or(Mode::Shadow);
    let version = e
        .write_rule(rule, State::Active, "operator", Some("accepted".into()))
        .await?;
    Ok(Json(json!({ "id": id, "version": version, "state": "active" })).into_response())
}

async fn retire(AxState(e): AxState<Arc<Engine>>, Path(id): Path<String>) -> ApiResult {
    let row = e.store.load_rule(&id)?.ok_or(StoreError::NotFound)?;
    if row.state == State::Retired {
        return Ok(
            Json(json!({ "id": id, "version": row.version, "state": "retired" })).into_response(),
        );
    }
    let mut rule: Rule =
        serde_json::from_str(&row.body).map_err(|_| conflict("stored body unreadable"))?;
    // A retired body is kept as written, minus an expiry that would fail
    // validation once it has passed.
    if rule.expires_at.is_some_and(|x| x <= store::now_s()) {
        rule.expires_at = None;
    }
    let version = e
        .write_rule(rule, State::Retired, "operator", Some("retired".into()))
        .await?;
    Ok(Json(json!({ "id": id, "version": version, "state": "retired" })).into_response())
}

async fn reload(AxState(e): AxState<Arc<Engine>>) -> ApiResult {
    e.rules.load()?;
    let rs = e.rules.current();
    Ok(
        Json(json!({ "generation": rs.generation, "hash": &*rs.hash_hex, "rules": rs.len() }))
            .into_response(),
    )
}

async fn schema() -> Json<Value> {
    Json(serde_json::to_value(crate::rules::schema::rule_schema()).unwrap_or(Value::Null))
}

async fn export(AxState(e): AxState<Arc<Engine>>) -> Json<Value> {
    let rules: Vec<Rule> = e
        .rules
        .loaded()
        .into_iter()
        .filter(|(_, m)| m.state == State::Active)
        .map(|(r, _)| r)
        .collect();
    Json(serde_json::to_value(rules).unwrap_or(Value::Null))
}

async fn validate(Json(body): Json<Value>) -> Json<Value> {
    match Rule::parse(&body.to_string(), store::now_s()) {
        Ok(_) => Json(json!({ "ok": true, "errors": [] })),
        Err(errors) => Json(json!({ "ok": false, "errors": errors })),
    }
}

async fn mode_get(AxState(e): AxState<Arc<Engine>>) -> Json<Value> {
    Json(json!({ "mode": e.mode().as_str(), "enforce_allowed": e.cfg.enforce }))
}

#[derive(Deserialize)]
struct ModeBody {
    mode: Mode,
}

async fn mode_put(AxState(e): AxState<Arc<Engine>>, Json(body): Json<ModeBody>) -> ApiResult {
    e.set_mode(body.mode)
        .map_err(|_| conflict("enforce is pinned off by LEESIDED_ENFORCE=false"))?;
    Ok(Json(json!({ "mode": e.mode().as_str() })).into_response())
}
