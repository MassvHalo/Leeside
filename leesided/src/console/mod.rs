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
        e => page(
            StatusCode::INTERNAL_SERVER_ERROR,
            pages::error_page(500, "Inspector error", &e.to_string()),
        ),
    }
}

fn read<T>(e: &Engine, f: impl FnOnce(&Ctx) -> Result<T, QueryError>) -> Result<T, Box<Response>> {
    e.store
        .read(|conn| Ctx::new(conn, "default").and_then(|ctx| f(&ctx)))
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
    // The dashboard is step 4; until then the root forwards.
    let _ = or_return!(require(&e, &headers, &uri));
    Redirect::to("/ui/llm").into_response()
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
    if call.point != "label" {
        return page(
            StatusCode::UNPROCESSABLE_ENTITY,
            pages::error_page(
                422,
                "Cannot re-send",
                "re-send only supports the label point",
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
    let out = tokio::task::spawn_blocking(move || {
        crate::llm::send_label(
            &db,
            &exec,
            &classes,
            &thresholds,
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
