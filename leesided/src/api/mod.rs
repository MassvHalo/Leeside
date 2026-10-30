//! The local HTTP API on 127.0.0.1: rules, mode, decisions, turns, health.
//! With `LEESIDED_API_TOKEN` set, every route but `/health` needs
//! `Authorization: Bearer <token>`; the UI reaches it through nginx.

use crate::engine::Engine;
use crate::rules::compile::State;
use crate::rules::model::{Mode, Rule, Scope};
use crate::rules::windows::key16;
use crate::store::{self, StoreError, StoreOp, TurnQuery};
use axum::extract::{Path, Query, Request, State as AxState};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;

pub fn router(engine: Arc<Engine>) -> Router {
    let token: Option<Arc<str>> = engine.cfg.api_token.as_deref().map(Arc::from);
    Router::new()
        .route("/rules", get(list).post(create))
        .route("/rules/schema", get(schema))
        .route("/rules/export", get(export))
        .route("/rules/validate", post(validate))
        .route("/rules/reload", post(reload))
        .route("/rules/{id}", get(show).put(update))
        .route("/rules/{id}/accept", post(accept))
        .route("/rules/{id}/retire", post(retire))
        .route("/mode", get(mode_get).put(mode_put))
        .route("/decisions", get(decisions))
        .route("/decisions/{scope}/{key}", delete(unblock))
        .route("/turns", get(turns))
        .route_layer(middleware::from_fn(move |req: Request, next: Next| {
            let token = token.clone();
            async move { authorize(token.as_deref(), req, next).await }
        }))
        .route("/health", get(health))
        .with_state(engine)
}

async fn authorize(token: Option<&str>, req: Request, next: Next) -> Response {
    let Some(want) = token else {
        return next.run(req).await;
    };
    let got = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got.is_some_and(|g| same(g.as_bytes(), want.as_bytes())) {
        next.run(req).await
    } else {
        ApiError(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "bearer token required" }),
        )
        .into_response()
    }
}

/// Constant time in the length of `want`, so the token cannot be guessed a
/// byte at a time from response timing.
fn same(got: &[u8], want: &[u8]) -> bool {
    let mut diff = (got.len() != want.len()) as u8;
    for (i, w) in want.iter().enumerate() {
        diff |= got.get(i).copied().unwrap_or(0) ^ w;
    }
    diff == 0
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

async fn decisions(AxState(e): AxState<Arc<Engine>>) -> Json<Value> {
    let now = store::now_s();
    Json(json!({ "now": now, "decisions": e.decisions.live(now) }))
}

/// Lifts one sticky decision: a block or a rate limit ends now.
async fn unblock(
    AxState(e): AxState<Arc<Engine>>,
    Path((scope, key)): Path<(String, String)>,
) -> ApiResult {
    let scope = match scope.as_str() {
        "session" => Scope::Session,
        "peer" => Scope::Peer,
        "principal" => Scope::Principal,
        _ => return Err(bad_request("scope must be session, peer or principal")),
    };
    let key = key16(&key).ok_or_else(|| bad_request("key must be 16 hex"))?;
    if !e.decisions.remove(scope, key) {
        return Err(StoreError::NotFound.into());
    }
    e.store.send(StoreOp::DecisionDelete { scope, key });
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn turns(AxState(e): AxState<Arc<Engine>>, Query(mut q): Query<TurnQuery>) -> ApiResult {
    q.limit = if q.limit <= 0 { 100 } else { q.limit.min(500) };
    Ok(Json(json!({ "turns": e.store.recent_turns(&q)? })).into_response())
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
