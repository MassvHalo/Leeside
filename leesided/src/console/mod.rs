//! The inspector (docs/inspector.md): server-rendered `/ui/` pages on
//! the shared [`queries`] data layer. Session login with the existing
//! operator token; the token is admin (docs/console.md section 1), so
//! every session may re-send. Reviewer and viewer tokens arrive with
//! the designed console.

pub mod pages;
pub mod queries;

use crate::engine::Engine;
use crate::store::{self, StoreOp};
use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use queries::{Ctx, QueryError};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

const SESSION_COOKIE: &str = "leeside_ui";
const SESSION_SECS: u64 = 12 * 3600;

struct Session {
    csrf: String,
    expires: u64,
}

/// The live sessions, held on the engine.
#[derive(Default)]
pub struct Console {
    sessions: parking_lot::Mutex<HashMap<String, Session>>,
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let mut filled = false;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read as _;
        filled = f.read_exact(&mut buf).is_ok();
    }
    if !filled {
        // /dev/urandom is never missing on the box; if it is, mix
        // time, pid and a counter through sha256 rather than fail.
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let mut h = Sha256::new();
        h.update(store::now_s().to_le_bytes());
        h.update(std::process::id().to_le_bytes());
        h.update(CTR.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        let d = h.finalize();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = d[i % d.len()];
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn session_of(e: &Engine, headers: &HeaderMap) -> Option<Session> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    let id = cookies.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == SESSION_COOKIE).then(|| v.trim().to_string())
    })?;
    let sessions = e.console.sessions.lock();
    let s = sessions.get(&id)?;
    if s.expires <= store::now_s() as u64 {
        return None;
    }
    Some(Session {
        csrf: s.csrf.clone(),
        expires: s.expires,
    })
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn login_redirect(uri: &Uri) -> Response {
    Redirect::to(&format!(
        "/ui/login?next={}",
        percent_encode(
            uri.path_and_query()
                .map(|q| q.as_str())
                .unwrap_or("/ui/llm")
        )
    ))
    .into_response()
}

fn page(status: StatusCode, body: String) -> Response {
    (status, Html(body)).into_response()
}

fn login_page(next: &str, error: Option<&str>, status: StatusCode) -> Response {
    page(status, pages::login_page(next, error))
}

fn ui_error(e: QueryError) -> Response {
    match e {
        QueryError::NoCall(id) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such call", &format!("no llm call {id}")),
        ),
        QueryError::NoJob(id) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such job", &format!("no llm job {id}")),
        ),
        QueryError::NoTurn(id) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such turn", &format!("no turn {id}")),
        ),
        QueryError::NoActor(id) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such actor", &format!("no actor {id}")),
        ),
        QueryError::NoCluster(key) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such cluster", &format!("no cluster {key}")),
        ),
        QueryError::NoRule(id) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such rule", &format!("no rule {id}")),
        ),
        QueryError::NoPayload(hash) => page(
            StatusCode::NOT_FOUND,
            pages::error_page(
                404,
                "No such pattern",
                &format!("no payload pattern {hash}"),
            ),
        ),
        e => page(
            StatusCode::INTERNAL_SERVER_ERROR,
            pages::error_page(500, "Inspector error", &e.to_string()),
        ),
    }
}

fn read<T>(e: &Engine, f: impl FnOnce(&Ctx) -> Result<T, QueryError>) -> Result<T, Box<Response>> {
    e.store
        .read(|conn| Ctx::new(conn, &e.cfg.app_id).and_then(|ctx| f(&ctx)))
        .map_err(|e| Box::new(ui_error(e)))
}

#[derive(Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
}

pub async fn login_get(Query(q): Query<LoginQuery>) -> Response {
    login_page(q.next.as_deref().unwrap_or("/ui/llm"), None, StatusCode::OK)
}

#[derive(Deserialize)]
pub struct LoginForm {
    token: String,
    next: Option<String>,
}

fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with("/ui/") => n.to_string(),
        _ => "/ui/llm".to_string(),
    }
}

pub async fn login_post(State(e): State<Arc<Engine>>, Form(f): Form<LoginForm>) -> Response {
    let next = safe_next(f.next.as_deref());
    let Some(want) = e.cfg.api_token.as_deref() else {
        return login_page(
            &next,
            Some("no operator token is configured"),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    if !crate::api::same(f.token.as_bytes(), want.as_bytes()) {
        return login_page(&next, Some("wrong token"), StatusCode::UNAUTHORIZED);
    }
    let now = store::now_s() as u64;
    let mut sessions = e.console.sessions.lock();
    sessions.retain(|_, s| s.expires > now);
    let id = random_hex(32);
    sessions.insert(
        id.clone(),
        Session {
            csrf: random_hex(32),
            expires: now + SESSION_SECS,
        },
    );
    (
        StatusCode::SEE_OTHER,
        [(
            header::SET_COOKIE,
            format!(
                "{SESSION_COOKIE}={id}; Path=/ui; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECS}"
            ),
        )],
        [(header::LOCATION, next)],
    )
        .into_response()
}

fn require(e: &Engine, headers: &HeaderMap, uri: &Uri) -> Result<Session, Box<Response>> {
    session_of(e, headers).ok_or_else(|| Box::new(login_redirect(uri)))
}

/// Unwrap a helper result inside a handler: the error is already a
/// rendered response.
macro_rules! or_return {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return *r,
        }
    };
}

fn csrf_ok(session: &Session, got: &str) -> bool {
    crate::api::same(got.as_bytes(), session.csrf.as_bytes())
}

fn forbidden() -> Response {
    page(
        StatusCode::FORBIDDEN,
        pages::error_page(
            403,
            "Bad CSRF token",
            "the form's token does not match the session",
        ),
    )
}

pub async fn ui_root(State(e): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let now = store::now_s();
    let health = e.health();
    let dash = or_return!(read(&e, |ctx| ctx.dashboard(now)));
    page(StatusCode::OK, pages::dashboard(&health, &dash, now))
}

#[derive(Deserialize)]
pub struct PageQuery {
    page: Option<i64>,
}

pub async fn llm_list(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<PageQuery>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let page_no = q.page.unwrap_or(0).max(0);
    let (calls, total) = or_return!(read(&e, |ctx| {
        Ok((ctx.llm_calls(page_no)?, ctx.llm_call_count()?))
    }));
    page(StatusCode::OK, pages::llm_list(&calls, page_no, total))
}

pub async fn llm_detail(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    let call = or_return!(read(&e, |ctx| ctx.llm_call(id)));
    page(StatusCode::OK, pages::llm_detail(&call, &session.csrf))
}

#[derive(Deserialize)]
pub struct JobsQuery {
    status: Option<String>,
    page: Option<i64>,
}

pub async fn jobs_list(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<JobsQuery>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    let status = q.status.as_deref().filter(|s| *s != "all");
    if let Some(s) = status {
        if !["queued", "running", "done", "failed"].contains(&s) {
            return page(
                StatusCode::BAD_REQUEST,
                pages::error_page(
                    400,
                    "Bad status",
                    "status must be queued, running, done or failed",
                ),
            );
        }
    }
    let page_no = q.page.unwrap_or(0).max(0);
    let (jobs, total) = or_return!(read(&e, |ctx| {
        Ok((ctx.llm_jobs(status, page_no)?, ctx.llm_job_count(status)?))
    }));
    page(
        StatusCode::OK,
        pages::jobs_list(&jobs, status, page_no, total, &session.csrf),
    )
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn job_retry(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    or_return!(read(&e, |ctx| ctx.llm_job(id)));
    e.store.send(StoreOp::LlmJobRetry {
        id,
        now_s: store::now_s(),
    });
    e.store.flush().await;
    Redirect::to("/ui/jobs").into_response()
}

pub async fn job_cancel(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    or_return!(read(&e, |ctx| ctx.llm_job(id)));
    e.store.send(StoreOp::LlmJobCancel {
        id,
        now_s: store::now_s(),
    });
    e.store.flush().await;
    Redirect::to("/ui/jobs").into_response()
}

/// One new live call with the old call's envelope and the current
/// prompt, logged as a new row linked to the old one. The only page
/// that calls the model, and only on this explicit button.
pub async fn resend(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let call = or_return!(read(&e, |ctx| ctx.llm_call(id)));
    if !["label", "explain", "classify", "draft"].contains(&call.point.as_str()) {
        return page(
            StatusCode::UNPROCESSABLE_ENTITY,
            pages::error_page(
                422,
                "Cannot re-send",
                &format!("re-send does not support the {} point", call.point),
            ),
        );
    }
    let Some(subject) = &call.subject else {
        return page(
            StatusCode::UNPROCESSABLE_ENTITY,
            pages::error_page(422, "Cannot re-send", "the old call has no subject"),
        );
    };
    let subject = match crate::llm::parse_subject(&format!("{}:{}", subject.scope, subject.id)) {
        Ok(s) => s,
        Err(err) => {
            return page(
                StatusCode::UNPROCESSABLE_ENTITY,
                pages::error_page(422, "Cannot re-send", &err.to_string()),
            );
        }
    };
    let Some(exec) = e.llm.exec.clone() else {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::error_page(
                503,
                "LLM unconfigured",
                "LEESIDED_LLM_URL or LEESIDED_LLM_KEY is unset",
            ),
        );
    };
    // The variable under test is the prompt, so the effort rides
    // along from the old call; no probe on this path.
    let effort = call.effort.clone();
    let db = e.cfg.db.clone();
    let classes = e.ja4_classes.clone();
    let thresholds = e
        .windside
        .loaded
        .as_ref()
        .map(|l| l.manifest.thresholds.clone())
        .unwrap_or_default();
    let point = call.point.clone();
    let out = tokio::task::spawn_blocking(move || {
        crate::llm::send_point(
            &db,
            &exec,
            &classes,
            &thresholds,
            &point,
            &subject,
            effort.as_deref(),
            Some(id),
        )
    })
    .await;
    let out = match out {
        Ok(Ok(out)) => out,
        Ok(Err(err)) => {
            return page(
                StatusCode::BAD_GATEWAY,
                pages::error_page(
                    502,
                    "Re-send failed",
                    &format!(
                        "{err} (the failed attempt is logged; find it newest-first on /ui/llm)"
                    ),
                ),
            );
        }
        Err(err) => {
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                pages::error_page(500, "Re-send failed", &err.to_string()),
            );
        }
    };
    match out.call_id {
        Some(new) => Redirect::to(&format!("/ui/llm/{new}")).into_response(),
        None => page(
            StatusCode::INTERNAL_SERVER_ERROR,
            pages::error_page(500, "Re-send failed", "the call went out but logged no row"),
        ),
    }
}

/// The writer-thread triggers' budgets: the configured daily
/// allowances, or zero (which stays silent) without an LLM.
fn llm_budgets(e: &Engine) -> (u32, u32) {
    e.llm
        .exec
        .as_ref()
        .map(|x| (x.daily_calls, x.daily_tokens))
        .unwrap_or((0, 0))
}

fn thresholds(e: &Engine) -> std::collections::HashMap<String, f64> {
    e.windside
        .loaded
        .as_ref()
        .map(|l| l.manifest.thresholds.clone())
        .unwrap_or_default()
}

pub async fn turn_detail(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(turn_id): Path<String>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let turn = or_return!(read(&e, |ctx| ctx.turn(&turn_id)));
    let tap = queries::tap_info(
        &e.ja4_classes,
        turn.ja4.as_deref(),
        turn.ua_class.as_deref(),
    );
    let (features, scores) = or_return!(read(&e, |ctx| ctx.trace_features(&turn)));
    page(
        StatusCode::OK,
        pages::turn_detail(&turn, &tap, &features, &scores, &thresholds(&e)),
    )
}

pub async fn trace_view(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(turn_id): Path<String>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let turn = or_return!(read(&e, |ctx| ctx.turn(&turn_id)));
    let idents = queries::idents_for_turn(&e.resolver, &turn);
    let now = store::now_s();
    let trace = or_return!(read(&e, |ctx| ctx.trace(&turn, &idents, now)));
    page(
        StatusCode::OK,
        pages::trace_view(&trace, &thresholds(&e), now),
    )
}

pub async fn actors_list(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<PageQuery>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let page_no = q.page.unwrap_or(0).max(0);
    let now = store::now_s();
    let (rows, total) = or_return!(read(&e, |ctx| Ok((
        ctx.actors(page_no, now)?,
        ctx.actor_count()?
    ))));
    page(
        StatusCode::OK,
        pages::actors_list(&rows, page_no, total, &thresholds(&e)),
    )
}

pub async fn actor_detail(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    let now = store::now_s();
    let detail = or_return!(read(&e, |ctx| {
        ctx.actor_detail(&id, q.page.unwrap_or(0), now, &thresholds(&e))
    }));
    let tap = queries::tap_info(
        &e.ja4_classes,
        detail.client.ja4.as_deref(),
        detail.client.ua_class.as_deref(),
    );
    page(
        StatusCode::OK,
        pages::actor_detail_page(&detail, &tap, &thresholds(&e), &session.csrf, now),
    )
}

pub async fn clusters_list(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<PageQuery>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let page_no = q.page.unwrap_or(0).max(0);
    let (rows, total) = or_return!(read(&e, |ctx| Ok((
        ctx.clusters(page_no)?,
        ctx.cluster_count()?
    ))));
    page(
        StatusCode::OK,
        pages::clusters_list(&rows, page_no, total, &thresholds(&e)),
    )
}

pub async fn cluster_detail(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(key): Path<String>,
    Query(q): Query<PageQuery>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    let detail = or_return!(read(&e, |ctx| {
        ctx.cluster_detail(&key, q.page.unwrap_or(0), &thresholds(&e))
    }));
    page(
        StatusCode::OK,
        pages::cluster_detail_page(&detail, &thresholds(&e), &session.csrf),
    )
}

#[derive(Deserialize)]
pub struct LabelForm {
    csrf: String,
    label: String,
    note: Option<String>,
    window_end_ts: i64,
}

fn bad_label(value: &str) -> Response {
    page(
        StatusCode::BAD_REQUEST,
        pages::error_page(
            400,
            "Bad label",
            &format!("label must be benign, malicious or unknown, not {value:?}"),
        ),
    )
}

fn stale_window() -> Response {
    page(
        StatusCode::CONFLICT,
        pages::error_page(
            409,
            "Window moved",
            "a newer window landed since the form rendered; reload and label again",
        ),
    )
}

/// One operator verdict on the subject's latest window. The form's
/// window must still be the latest, or the label would land on the
/// wrong one.
pub async fn actor_label(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Form(f): Form<LabelForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let label: &'static str = match f.label.as_str() {
        "benign" => "benign",
        "malicious" => "malicious",
        "unknown" => "unknown",
        _ => return bad_label(&f.label),
    };
    let now = store::now_s();
    let detail = or_return!(read(&e, |ctx| ctx.actor_detail(
        &id,
        0,
        now,
        &HashMap::new()
    )));
    let (Some(window_end_ts), surface) = (detail.window_end_ts, detail.window_surface) else {
        return stale_window();
    };
    if window_end_ts != f.window_end_ts {
        return stale_window();
    }
    e.store.send(StoreOp::Label(store::LabelRow {
        scope: "actor",
        scope_id: detail.head.id.clone(),
        surface,
        window_end_ts,
        label,
        source: "operator",
        confidence: 1.0,
        kind: None,
        note: f.note.filter(|n| !n.trim().is_empty()),
        created_at: now,
        signals: None,
        daily_calls: llm_budgets(&e).0,
        daily_tokens: llm_budgets(&e).1,
    }));
    e.store.flush().await;
    Redirect::to(&format!("/ui/actors/{}", detail.head.id)).into_response()
}

pub async fn cluster_label(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(key): Path<String>,
    Form(f): Form<LabelForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let label: &'static str = match f.label.as_str() {
        "benign" => "benign",
        "malicious" => "malicious",
        "unknown" => "unknown",
        _ => return bad_label(&f.label),
    };
    let detail = or_return!(read(&e, |ctx| {
        ctx.cluster_detail(&key, 0, &HashMap::new())
    }));
    let (Some(window_end_ts), surface) = (detail.window_end_ts, detail.window_surface) else {
        return stale_window();
    };
    if window_end_ts != f.window_end_ts {
        return stale_window();
    }
    e.store.send(StoreOp::Label(store::LabelRow {
        scope: "cluster",
        scope_id: detail.row.key.clone(),
        surface,
        window_end_ts,
        label,
        source: "operator",
        confidence: 1.0,
        kind: None,
        note: f.note.filter(|n| !n.trim().is_empty()),
        created_at: store::now_s(),
        signals: None,
        daily_calls: llm_budgets(&e).0,
        daily_tokens: llm_budgets(&e).1,
    }));
    e.store.flush().await;
    Redirect::to(&format!("/ui/clusters/{}", detail.row.key)).into_response()
}

/// Queue one draft job for a cluster: the button on either page. The
/// queue guard dedups, so repeats are harmless.
async fn draft_for(e: &Arc<Engine>, cluster: String, back_to: String) -> Response {
    let Some(exec) = e.llm.exec.clone() else {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::error_page(
                503,
                "LLM unconfigured",
                "LEESIDED_LLM_URL or LEESIDED_LLM_KEY is unset",
            ),
        );
    };
    e.store.send(StoreOp::LlmEnqueuePoint {
        point: "draft".to_string(),
        scope: "cluster".to_string(),
        subject_id: cluster,
        enqueued_by: "console".to_string(),
        now_s: store::now_s(),
        daily_calls: exec.daily_calls,
        daily_tokens: exec.daily_tokens,
    });
    e.store.flush().await;
    Redirect::to(&back_to).into_response()
}

pub async fn actor_draft(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let detail = or_return!(read(&e, |ctx| ctx.actor_detail(
        &id,
        0,
        store::now_s(),
        &HashMap::new()
    )));
    let Some(cluster) = detail.row.cluster.clone() else {
        return page(
            StatusCode::UNPROCESSABLE_ENTITY,
            pages::error_page(
                422,
                "Nothing to draft over",
                "this actor's turns carry no cluster key",
            ),
        );
    };
    let back_to = format!("/ui/actors/{}", detail.head.id);
    draft_for(&e, cluster, back_to).await
}

pub async fn cluster_draft(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(key): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let detail = or_return!(read(&e, |ctx| {
        ctx.cluster_detail(&key, 0, &HashMap::new())
    }));
    let back_to = format!("/ui/clusters/{}", detail.row.key);
    draft_for(&e, detail.row.key.clone(), back_to).await
}

/// A sticky actor-scope block, rule "operator", 24 h like the rule
/// default. Re-blocking refreshes the expiry; the answer still honors
/// the global mode.
pub async fn actor_block(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let ids = or_return!(read(&e, |ctx| ctx.actor_ids(&id)));
    let key = match crate::rules::windows::key16(&ids[0]) {
        Some(k) => k,
        None => {
            return page(
                StatusCode::NOT_FOUND,
                pages::error_page(404, "No such actor", &format!("no actor {id}")),
            );
        }
    };
    let now = store::now_s();
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
    e.store.flush().await;
    Redirect::to(&format!("/ui/actors/{}", ids[0])).into_response()
}

pub async fn actor_unblock(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let ids = or_return!(read(&e, |ctx| ctx.actor_ids(&id)));
    let key = match crate::rules::windows::key16(&ids[0]) {
        Some(k) => k,
        None => {
            return page(
                StatusCode::NOT_FOUND,
                pages::error_page(404, "No such actor", &format!("no actor {id}")),
            );
        }
    };
    if !e.decisions.remove(crate::rules::model::Scope::Actor, key) {
        return page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "Nothing to lift", "no live block on this actor"),
        );
    }
    e.store.send(StoreOp::DecisionDelete {
        scope: crate::rules::model::Scope::Actor,
        key,
    });
    e.store.flush().await;
    Redirect::to(&format!("/ui/actors/{}", ids[0])).into_response()
}

pub async fn review_list(State(e): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    let rows = or_return!(read(&e, |ctx| ctx.review_queue(&thresholds(&e), 20)));
    page(
        StatusCode::OK,
        pages::review_list(&rows, &thresholds(&e), &session.csrf),
    )
}

#[derive(Deserialize)]
pub struct DecideForm {
    csrf: String,
    scope_id: String,
    window_end_ts: i64,
    verdict: String,
}

/// One review decision: confirm takes the proposed value (noted as
/// confirmed), the verdicts take theirs (noted as the console). CLI
/// parity, through the writer.
pub async fn review_decide(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Form(f): Form<DecideForm>,
) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    if !csrf_ok(&session, &f.csrf) {
        return forbidden();
    }
    let now = store::now_s();
    let detail = or_return!(read(&e, |ctx| ctx.actor_detail(
        &f.scope_id,
        0,
        now,
        &thresholds(&e)
    )));
    let (Some(window_end_ts), surface) = (detail.window_end_ts, detail.window_surface) else {
        return stale_window();
    };
    if window_end_ts != f.window_end_ts {
        return stale_window();
    }
    let (label, note): (&'static str, String) = match f.verdict.as_str() {
        "confirm" => match &detail.proposal {
            Some(p) => match p.label.label.as_str() {
                "benign" => ("benign", "confirmed llm_proposed".to_string()),
                "malicious" => ("malicious", "confirmed llm_proposed".to_string()),
                "unknown" => ("unknown", "confirmed llm_proposed".to_string()),
                _ => return bad_label(&p.label.label),
            },
            None => {
                return page(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    pages::error_page(422, "Nothing to confirm", "this row has no proposal"),
                );
            }
        },
        "benign" => ("benign", "review console".to_string()),
        "malicious" => ("malicious", "review console".to_string()),
        "unknown" => ("unknown", "review console".to_string()),
        _ => return bad_label(&f.verdict),
    };
    e.store.send(StoreOp::Label(store::LabelRow {
        scope: "actor",
        scope_id: detail.head.id.clone(),
        surface,
        window_end_ts,
        label,
        source: "operator",
        confidence: 1.0,
        kind: None,
        note: Some(note),
        created_at: now,
        signals: None,
        daily_calls: llm_budgets(&e).0,
        daily_tokens: llm_budgets(&e).1,
    }));
    e.store.flush().await;
    Redirect::to("/ui/review").into_response()
}

#[derive(Deserialize)]
pub struct LabelsQuery {
    source: Option<String>,
    label: Option<String>,
    page: Option<i64>,
}

pub async fn labels_list(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<LabelsQuery>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    if let Some(l) = q.label.as_deref() {
        if !["benign", "malicious", "unknown"].contains(&l) {
            return bad_label(l);
        }
    }
    let page_no = q.page.unwrap_or(0).max(0);
    let (labels, total, sources) = or_return!(read(&e, |ctx| {
        Ok((
            ctx.labels(q.source.as_deref(), q.label.as_deref(), page_no)?,
            ctx.label_count(q.source.as_deref(), q.label.as_deref())?,
            ctx.label_sources()?,
        ))
    }));
    page(
        StatusCode::OK,
        pages::labels_list(
            &labels,
            &sources,
            q.source.as_deref(),
            q.label.as_deref(),
            page_no,
            total,
        ),
    )
}

pub async fn rules_list(State(e): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    let session = or_return!(require(&e, &headers, &uri));
    let now = store::now_s();
    let (rules, drafts) = or_return!(read(&e, |ctx| Ok((ctx.rules(now)?, ctx.rule_drafts()?))));
    page(
        StatusCode::OK,
        pages::rules_list(&rules, &drafts, &session.csrf),
    )
}

async fn rule_flip(
    e: &Arc<Engine>,
    headers: &HeaderMap,
    uri: &Uri,
    id: &str,
    csrf: &str,
    enabled: bool,
) -> Response {
    let session = or_return!(require(e, headers, uri));
    if !csrf_ok(&session, csrf) {
        return forbidden();
    }
    let exists = or_return!(read(e, |ctx| ctx.rule_exists(id)));
    if !exists {
        return page(
            StatusCode::NOT_FOUND,
            pages::error_page(404, "No such rule", &format!("no rule {id}")),
        );
    }
    e.store.send(StoreOp::RuleState {
        rule_id: id.to_string(),
        app_id: e.cfg.app_id.clone(),
        enabled,
        by: "console".to_string(),
        at_s: store::now_s(),
    });
    e.store.flush().await;
    // The flag lands in the compiled set on reload; a failed reload
    // leaves the row written but not live, and says so.
    if let Err(err) = e.rules.load() {
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            pages::error_page(500, "Reload failed", &err.to_string()),
        );
    }
    Redirect::to("/ui/rules").into_response()
}

pub async fn rule_enable(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    rule_flip(&e, &headers, &uri, &id, &f.csrf, true).await
}

pub async fn rule_disable(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    rule_flip(&e, &headers, &uri, &id, &f.csrf, false).await
}

pub async fn payloads_list(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<PageQuery>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let page_no = q.page.unwrap_or(0).max(0);
    let (rows, total) = or_return!(read(&e, |ctx| Ok((
        ctx.payload_patterns(page_no)?,
        ctx.payload_count()?
    ))));
    page(StatusCode::OK, pages::payloads_list(&rows, page_no, total))
}

pub async fn payload_detail(
    State(e): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(hash): Path<String>,
) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let row = or_return!(read(&e, |ctx| ctx.payload_detail(&hash)));
    page(StatusCode::OK, pages::payload_detail_page(&row))
}

pub async fn model_page(State(e): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    let loaded = e.windside.loaded.as_ref();
    let thresholds: Vec<(String, f64)> = loaded
        .map(|l| {
            l.manifest
                .thresholds
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect()
        })
        .unwrap_or_default();
    let manifest_pretty: Option<String> = e.cfg.windside_model.as_deref().and_then(|dir| {
        let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        // The file carries the metrics; the model keeps the thresholds.
        let metrics = v.get("metrics").unwrap_or(&v);
        serde_json::to_string_pretty(metrics).ok()
    });
    let db = e.cfg.db.clone();
    let model_dir = e.cfg.windside_model.clone();
    let shadow =
        tokio::task::spawn_blocking(move || crate::report::shadow(&db, model_dir.as_deref(), 0))
            .await;
    let (shadow, shadow_error) = match shadow {
        Ok(Ok(r)) => (Some(r), None),
        Ok(Err(err)) => (None, Some(err.to_string())),
        Err(err) => (None, Some(err.to_string())),
    };
    page(
        StatusCode::OK,
        pages::model_page(&queries::ModelView {
            windside_mode: e.windside.mode.as_str().to_string(),
            model_version: loaded.map(|l| l.manifest.model_version.clone()),
            features_version: loaded.map(|l| l.manifest.features_version),
            thresholds,
            manifest_pretty,
            shadow,
            shadow_error,
        }),
    )
}

pub async fn features_page(State(e): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    let _ = or_return!(require(&e, &headers, &uri));
    page(
        StatusCode::OK,
        pages::features_page(&queries::feature_table()),
    )
}
