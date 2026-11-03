//! The inspector's data layer (docs/inspector.md section 1): every
//! `/ui/` page reads through here now, and the JSON API of
//! `docs/console.md` follows on the same queries. Pages never run SQL
//! of their own.
//!
//! Every query runs inside an app scope. The tenancy rule (console.md
//! section 1) puts `app_id` on new tables; no v0 table carries one
//! yet, so the scope validates the name and every query runs against
//! the single tenant.

use rusqlite::{params, Connection};

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("unknown app `{0}` (only `default` exists)")]
    UnknownApp(String),
    #[error("no llm call {0}")]
    NoCall(i64),
    #[error("no llm job {0}")]
    NoJob(i64),
    #[error("no turn {0}")]
    NoTurn(String),
    #[error("no actor {0}")]
    NoActor(String),
    #[error("no cluster {0}")]
    NoCluster(String),
    #[error("no rule {0}")]
    NoRule(String),
    #[error("no payload pattern {0}")]
    NoPayload(String),
}

/// An app-scoped query context over one read connection.
pub struct Ctx<'a> {
    conn: &'a Connection,
    app_id: String,
}

impl<'a> Ctx<'a> {
    pub fn new(conn: &'a Connection, app_id: &str) -> Result<Ctx<'a>, QueryError> {
        if app_id.is_empty() {
            return Err(QueryError::UnknownApp(app_id.to_string()));
        }
        Ok(Ctx {
            conn,
            app_id: app_id.to_string(),
        })
    }

    fn conn(&self) -> &Connection {
        self.conn
    }

    fn app(&self) -> &str {
        &self.app_id
    }
}

/// A point-1 subject: an actor id or a cluster key hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectRef {
    pub scope: String,
    pub id: String,
}

/// What one `llm_calls` row came to, derived from the row plus its job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Parsed,
    ValidationFailed,
    LengthDropped,
    HttpError,
    TransportError,
    DryRun,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Parsed => "parsed",
            Outcome::ValidationFailed => "validation failed",
            Outcome::LengthDropped => "dropped (length)",
            Outcome::HttpError => "http error",
            Outcome::TransportError => "transport error",
            Outcome::DryRun => "dry run (not sent)",
        }
    }

    /// The chip colour: semantic colour only on outcomes.
    pub fn chip(self) -> &'static str {
        match self {
            Outcome::Parsed => "good",
            Outcome::DryRun => "muted",
            Outcome::ValidationFailed | Outcome::LengthDropped => "warn",
            Outcome::HttpError | Outcome::TransportError => "bad",
        }
    }
}

fn derive_outcome(
    parsed: &Option<String>,
    response: &Option<String>,
    finish_reason: &Option<String>,
    prompt_tokens: &Option<i64>,
    job_status: Option<&str>,
) -> Outcome {
    if parsed.is_some() {
        return Outcome::Parsed;
    }
    let Some(body) = response else {
        // A response-less row is either dry (its job is done) or a
        // transport failure (`send` has no job and never writes dry).
        if job_status == Some("done") {
            return Outcome::DryRun;
        }
        return Outcome::TransportError;
    };
    if finish_reason.as_deref() == Some("length") {
        return Outcome::LengthDropped;
    }
    if finish_reason.is_none() && prompt_tokens.is_none() {
        // No usage: either a non-200 error body or a 200 that is not a
        // completion. A completion-shaped body went down the validation
        // path; anything else is an HTTP error.
        if crate::llm::parse_completion_200(body).is_ok() {
            return Outcome::ValidationFailed;
        }
        return Outcome::HttpError;
    }
    Outcome::ValidationFailed
}

/// One row of `/ui/llm`: the call plus its subject and outcome.
#[derive(Debug, Clone)]
pub struct CallRow {
    pub id: i64,
    pub created_at: i64,
    pub point: String,
    pub subject: Option<SubjectRef>,
    pub model: String,
    pub json_mode: String,
    pub effort: Option<String>,
    pub finish_reason: Option<String>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub latency_ms: Option<i64>,
    pub outcome: Outcome,
}

/// Parse `subject` out of a row: the job when the call has one, else
/// the `input_summary` the worker and `send` both write.
fn subject_of(
    job_scope: Option<String>,
    job_subject: Option<String>,
    input_summary: &str,
) -> Option<SubjectRef> {
    if let (Some(scope), Some(id)) = (job_scope, job_subject) {
        return Some(SubjectRef { scope, id });
    }
    let summary: serde_json::Value = serde_json::from_str(input_summary).ok()?;
    let subject = summary.get("subject")?.as_str()?;
    let (scope, id) = subject.split_once(':')?;
    Some(SubjectRef {
        scope: scope.to_string(),
        id: id.to_string(),
    })
}

fn effort_of(request: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(request)
        .ok()?
        .get("reasoning_effort")?
        .as_str()
        .map(str::to_string)
}

fn budget_of(request: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(request)
        .ok()?
        .get("max_tokens")?
        .as_i64()
}

/// Page size everywhere in the inspector.
pub const PAGE_SIZE: i64 = 100;

impl Ctx<'_> {
    /// Every `llm_calls` row, newest first, paged.
    pub fn llm_calls(&self, page: i64) -> Result<Vec<CallRow>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let mut stmt = self.conn().prepare(
            "SELECT c.id, c.created_at, c.point, c.model, c.json_mode, c.request, \
             c.response, c.parsed, c.finish_reason, c.prompt_tokens, c.completion_tokens, \
             c.reasoning_tokens, c.latency_ms, c.input_summary, \
             j.scope, j.subject_id, j.status \
             FROM llm_calls c LEFT JOIN llm_jobs j ON c.job_id = j.id \
             ORDER BY c.id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![PAGE_SIZE, offset], |r| {
            let response: Option<String> = r.get(6)?;
            let parsed: Option<String> = r.get(7)?;
            let finish_reason: Option<String> = r.get(8)?;
            let prompt_tokens: Option<i64> = r.get(9)?;
            let job_status: Option<String> = r.get(16)?;
            let request: String = r.get(5)?;
            let input_summary: String = r.get(13)?;
            Ok(CallRow {
                id: r.get(0)?,
                created_at: r.get(1)?,
                point: r.get(2)?,
                subject: subject_of(r.get(14)?, r.get(15)?, &input_summary),
                model: r.get(3)?,
                json_mode: r.get(4)?,
                effort: effort_of(&request),
                finish_reason,
                prompt_tokens,
                completion_tokens: r.get(10)?,
                reasoning_tokens: r.get(11)?,
                latency_ms: r.get(12)?,
                outcome: derive_outcome(
                    &parsed,
                    &response,
                    &r.get::<_, Option<String>>(8)?,
                    &prompt_tokens,
                    job_status.as_deref(),
                ),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    /// How many `llm_calls` rows exist, for paging.
    pub fn llm_call_count(&self) -> Result<i64, QueryError> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM llm_calls", [], |r| r.get(0))?)
    }

    /// One job of `/ui/jobs`, with the call it produced, if any.
    pub fn llm_job(&self, id: i64) -> Result<Job, QueryError> {
        self.conn()
            .query_row(
                "SELECT j.id, j.point, j.scope, j.subject_id, j.status, j.attempts, \
                 j.enqueued_by, j.created_at, j.updated_at, j.not_before, j.last_error, \
                 (SELECT c.id FROM llm_calls c WHERE c.job_id = j.id ORDER BY c.id DESC LIMIT 1) \
                 FROM llm_jobs j WHERE j.id = ?1",
                params![id],
                |r| {
                    Ok(Job {
                        id: r.get(0)?,
                        point: r.get(1)?,
                        subject: SubjectRef {
                            scope: r.get(2)?,
                            id: r.get(3)?,
                        },
                        status: r.get(4)?,
                        attempts: r.get(5)?,
                        enqueued_by: r.get(6)?,
                        created_at: r.get(7)?,
                        updated_at: r.get(8)?,
                        not_before: r.get(9)?,
                        last_error: r.get(10)?,
                        produced_call: r.get(11)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => QueryError::NoJob(id),
                e => QueryError::Sqlite(e),
            })
    }

    /// Every `llm_jobs` row, newest first, optionally one status, paged.
    pub fn llm_jobs(&self, status: Option<&str>, page: i64) -> Result<Vec<Job>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let mut stmt = self.conn().prepare(
            "SELECT j.id, j.point, j.scope, j.subject_id, j.status, j.attempts, \
             j.enqueued_by, j.created_at, j.updated_at, j.not_before, j.last_error, \
             (SELECT c.id FROM llm_calls c WHERE c.job_id = j.id ORDER BY c.id DESC LIMIT 1) \
             FROM llm_jobs j \
             WHERE (?1 IS NULL OR j.status = ?1) \
             ORDER BY j.id DESC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![status, PAGE_SIZE, offset], |r| {
            Ok(Job {
                id: r.get(0)?,
                point: r.get(1)?,
                subject: SubjectRef {
                    scope: r.get(2)?,
                    id: r.get(3)?,
                },
                status: r.get(4)?,
                attempts: r.get(5)?,
                enqueued_by: r.get(6)?,
                created_at: r.get(7)?,
                updated_at: r.get(8)?,
                not_before: r.get(9)?,
                last_error: r.get(10)?,
                produced_call: r.get(11)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    pub fn llm_job_count(&self, status: Option<&str>) -> Result<i64, QueryError> {
        Ok(self.conn().query_row(
            "SELECT count(*) FROM llm_jobs WHERE (?1 IS NULL OR status = ?1)",
            params![status],
            |r| r.get(0),
        )?)
    }
}

/// One `llm_jobs` row plus the call it produced.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: i64,
    pub point: String,
    pub subject: SubjectRef,
    pub status: String,
    pub attempts: i64,
    pub enqueued_by: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub not_before: i64,
    pub last_error: Option<String>,
    pub produced_call: Option<i64>,
}

/// One `labels` row, every column.
#[derive(Debug, Clone)]
pub struct LabelRef {
    pub id: i64,
    pub scope: String,
    pub scope_id: String,
    pub surface: Option<String>,
    pub window_end_ts: i64,
    pub label: String,
    pub source: String,
    pub confidence: f64,
    pub kind: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
    pub signals: Option<String>,
}

fn label_from_row(r: &rusqlite::Row) -> Result<LabelRef, rusqlite::Error> {
    Ok(LabelRef {
        id: r.get(0)?,
        scope: r.get(1)?,
        scope_id: r.get(2)?,
        surface: r.get(3)?,
        window_end_ts: r.get(4)?,
        label: r.get(5)?,
        source: r.get(6)?,
        confidence: r.get(7)?,
        kind: r.get(8)?,
        note: r.get(9)?,
        created_at: r.get(10)?,
        signals: r.get(11)?,
    })
}

/// The schema validation outcome for one call, recomputed from the
/// stored response with the point's validator.
#[derive(Debug, Clone)]
pub struct Validation {
    /// Which schema ran, by point.
    pub schema: String,
    pub ok: bool,
    pub error: Option<String>,
}

/// One step of the retry history: a sibling call with its budget.
#[derive(Debug, Clone)]
pub struct SiblingCall {
    pub id: i64,
    pub created_at: i64,
    pub budget: Option<i64>,
    pub outcome: Outcome,
    pub is_self: bool,
}

/// The operator's later word on a proposal: the same label confirms
/// it, anything else rejects it in favour of the chosen label.
#[derive(Debug, Clone)]
pub struct OperatorFollowup {
    pub label: String,
    pub created_at: i64,
    pub confirmed: bool,
}

/// Everything `/ui/llm/{id}` shows: the stored row, the job, the
/// request decoded, the response interpreted, and what followed.
#[derive(Debug, Clone)]
pub struct Call {
    pub id: i64,
    pub created_at: i64,
    pub point: String,
    pub subject: Option<SubjectRef>,
    pub model: String,
    pub prompt_hash: String,
    pub json_mode: String,
    pub effort: Option<String>,
    pub input_summary: String,
    /// The request bytes pretty-printed (raw when not JSON).
    pub request_pretty: String,
    /// The system prompt out of the stored request.
    pub system_prompt: Option<String>,
    /// The envelope decoded one level out of the request.
    pub envelope_pretty: Option<String>,
    pub response: Option<String>,
    /// The content decoded and pretty-printed when it is JSON.
    pub content_pretty: Option<String>,
    /// The full `reasoning_content` from the stored response.
    pub reasoning_full: Option<String>,
    /// Whether the stored 2 KB excerpt hit its cap.
    pub excerpt_capped: bool,
    pub finish_reason: Option<String>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub latency_ms: Option<i64>,
    pub outcome: Outcome,
    pub parsed_pretty: Option<String>,
    pub validation: Validation,
    pub siblings: Vec<SiblingCall>,
    pub produced_label: Option<LabelRef>,
    pub followup: Option<OperatorFollowup>,
    pub job: Option<Job>,
    pub resend_parent: Option<i64>,
    pub resend_children: Vec<i64>,
}

/// Pretty-print stored JSON bytes; raw bytes when they are not JSON.
fn pretty(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .map(|v| serde_json::to_string_pretty(&v).unwrap_or_else(|_| raw.to_string()))
        .unwrap_or_else(|_| raw.to_string())
}

/// The envelope decoded one level out of a stored request: the user
/// message's JSON string parsed back into a document.
fn envelope_of(request: &str) -> Option<String> {
    let body: serde_json::Value = serde_json::from_str(request).ok()?;
    let inner = body.pointer("/messages/1/content")?.as_str()?;
    let doc: serde_json::Value = serde_json::from_str(inner).ok()?;
    serde_json::to_string_pretty(&doc).ok()
}

/// The system prompt out of a stored request.
fn system_of(request: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(request)
        .ok()?
        .pointer("/messages/0/content")?
        .as_str()
        .map(str::to_string)
}

/// The assistant message's content from a stored response.
fn content_of(response: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(response)
        .ok()?
        .pointer("/choices/0/message/content")?
        .as_str()
        .map(str::to_string)
}

/// The full `reasoning_content` from a stored response, when the
/// model thinks aloud.
fn reasoning_of(response: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(response)
        .ok()?
        .pointer("/choices/0/message/reasoning_content")?
        .as_str()
        .map(str::to_string)
}

fn validate_content(point: &str, content: Option<&str>) -> Validation {
    let schema = match point {
        "label" => "label (docs/llm.md §8.1)".to_string(),
        "explain" => "explain (docs/llm.md §8.2)".to_string(),
        "classify" => "classify (docs/llm.md §8.3)".to_string(),
        "draft" => "draft (docs/llm.md §8.4)".to_string(),
        p => {
            return Validation {
                schema: format!("{p} (unknown point)"),
                ok: false,
                error: Some(format!("no validator for point `{p}`")),
            }
        }
    };
    let Some(text) = content else {
        return Validation {
            schema,
            ok: false,
            error: Some("no response was received".to_string()),
        };
    };
    let err = (|| -> Result<(), String> {
        let obj = crate::llm::extract_json(text)
            .ok_or_else(|| "no JSON object in the completion".to_string())?;
        let v: serde_json::Value = serde_json::from_str(obj)
            .map_err(|e| format!("the completion's JSON does not parse: {e}"))?;
        match point {
            "label" => crate::llm::validate_label(&v).map(|_| ()),
            "explain" => crate::llm::validate_explain(&v).map(|_| ()),
            "classify" => crate::llm::validate_classify(&v).map(|_| ()),
            "draft" => crate::llm::validate_draft(&v).map(|_| ()),
            _ => unreachable!(),
        }
    })();
    match err {
        Ok(()) => Validation {
            schema,
            ok: true,
            error: None,
        },
        Err(e) => Validation {
            schema,
            ok: false,
            error: Some(e),
        },
    }
}

/// One `llm_calls` row as selected for the exchange page.
type StoredCall = (
    i64,
    Option<i64>,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<String>,
    i64,
    Option<i64>,
);

impl Ctx<'_> {
    /// The full exchange for `/ui/llm/{id}`.
    pub fn llm_call(&self, id: i64) -> Result<Call, QueryError> {
        let row: StoredCall = self
            .conn()
            .query_row(
                "SELECT id, job_id, point, model, prompt_hash, json_mode, input_summary, \
                 request, response, parsed, latency_ms, prompt_tokens, completion_tokens, \
                 finish_reason, reasoning_tokens, reasoning_excerpt, created_at, resend_of \
                 FROM llm_calls WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                        r.get(13)?,
                        r.get(14)?,
                        r.get(15)?,
                        r.get(16)?,
                        r.get(17)?,
                    ))
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => QueryError::NoCall(id),
                e => QueryError::Sqlite(e),
            })?;
        let (
            id,
            job_id,
            point,
            model,
            prompt_hash,
            json_mode,
            input_summary,
            request,
            response,
            parsed,
            latency_ms,
            prompt_tokens,
            completion_tokens,
            finish_reason,
            reasoning_tokens,
            reasoning_excerpt,
            created_at,
            resend_of,
        ) = row;
        let job = job_id.map(|j| self.llm_job(j)).transpose()?;
        let subject = subject_of(
            job.as_ref().map(|j| j.subject.scope.clone()),
            job.as_ref().map(|j| j.subject.id.clone()),
            &input_summary,
        );
        let outcome = derive_outcome(
            &parsed,
            &response,
            &finish_reason,
            &prompt_tokens,
            job.as_ref().map(|j| j.status.as_str()),
        );
        let content = response.as_deref().and_then(content_of);
        let reasoning_full = response.as_deref().and_then(reasoning_of);
        // The cap hit when the full transcript exceeds what fits, or
        // when only a full-length excerpt survived (no response).
        let excerpt_capped = reasoning_full
            .as_ref()
            .map(|f| f.len() > 2048)
            .unwrap_or_else(|| reasoning_excerpt.as_ref().is_some_and(|e| e.len() >= 2048));
        let content_pretty = content.as_ref().map(|c| {
            crate::llm::extract_json(c)
                .map(pretty)
                .unwrap_or_else(|| c.clone())
        });
        let siblings = self.siblings(id, job_id.as_ref(), &subject, created_at)?;
        let produced_label = self.produced_label(id)?;
        let followup = match &produced_label {
            Some(l) => self.operator_followup(l)?,
            None => None,
        };
        let resend_children = self
            .conn()
            .prepare("SELECT id FROM llm_calls WHERE resend_of = ?1 ORDER BY id")?
            .query_map(params![id], |r| r.get(0))?
            .collect::<Result<Vec<i64>, _>>()?;
        Ok(Call {
            id,
            created_at,
            point: point.clone(),
            subject,
            model,
            prompt_hash,
            json_mode,
            effort: effort_of(&request),
            input_summary,
            request_pretty: pretty(&request),
            system_prompt: system_of(&request),
            envelope_pretty: envelope_of(&request),
            response,
            content_pretty,
            reasoning_full,
            excerpt_capped,
            finish_reason,
            prompt_tokens,
            completion_tokens,
            reasoning_tokens,
            latency_ms,
            outcome,
            parsed_pretty: parsed.as_deref().map(pretty),
            validation: validate_content(&point, content.as_deref()),
            siblings,
            produced_label,
            followup,
            job,
            resend_parent: resend_of,
            resend_children,
        })
    }

    /// The retry history: the job's calls in order, or, for a jobless
    /// `send`, the nearby calls for the same subject (same input
    /// subject within two minutes either way).
    fn siblings(
        &self,
        id: i64,
        job_id: Option<&i64>,
        subject: &Option<SubjectRef>,
        created_at: i64,
    ) -> Result<Vec<SiblingCall>, QueryError> {
        if let Some(j) = job_id {
            let mut stmt = self.conn().prepare(
                "SELECT c.id, c.created_at, c.request, c.response, c.parsed, c.finish_reason, \
                 c.prompt_tokens, j.status \
                 FROM llm_calls c JOIN llm_jobs j ON c.job_id = j.id \
                 WHERE c.job_id = ?1 ORDER BY c.id",
            )?;
            return stmt
                .query_map(params![j], |r| {
                    let parsed: Option<String> = r.get(4)?;
                    let response: Option<String> = r.get(3)?;
                    let finish: Option<String> = r.get(5)?;
                    let prompt_tokens: Option<i64> = r.get(6)?;
                    let status: String = r.get(7)?;
                    let request: String = r.get(2)?;
                    let sid: i64 = r.get(0)?;
                    Ok(SiblingCall {
                        id: sid,
                        created_at: r.get(1)?,
                        budget: budget_of(&request),
                        outcome: derive_outcome(
                            &parsed,
                            &response,
                            &finish,
                            &prompt_tokens,
                            Some(&status),
                        ),
                        is_self: sid == id,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(QueryError::from);
        }
        let Some(s) = subject else {
            return Ok(Vec::new());
        };
        let want = format!("{}:{}", s.scope, s.id);
        let mut stmt = self.conn().prepare(
            "SELECT c.id, c.created_at, c.request, c.response, c.parsed, c.finish_reason, \
             c.prompt_tokens, c.input_summary \
             FROM llm_calls c \
             WHERE c.job_id IS NULL AND c.created_at BETWEEN ?1 - 120 AND ?1 + 120 \
             ORDER BY c.id",
        )?;
        let mut out = Vec::new();
        for row in stmt.query_map(params![created_at], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })? {
            let (sid, ts, request, response, parsed, finish, prompt_tokens, summary) = row?;
            let same = serde_json::from_str::<serde_json::Value>(&summary)
                .ok()
                .and_then(|v| v.get("subject")?.as_str().map(str::to_string))
                .as_deref()
                == Some(want.as_str());
            if !same {
                continue;
            }
            out.push(SiblingCall {
                id: sid,
                created_at: ts,
                budget: budget_of(&request),
                outcome: derive_outcome(&parsed, &response, &finish, &prompt_tokens, None),
                is_self: sid == id,
            });
        }
        Ok(out)
    }

    /// The label the call produced, linked through the call id the
    /// worker stamps into the note.
    fn produced_label(&self, call_id: i64) -> Result<Option<LabelRef>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, scope, scope_id, surface, window_end_ts, label, source, confidence, \
             kind, note, created_at, signals FROM labels \
             WHERE note LIKE ?1 ORDER BY id LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![format!("%[llm_call:{call_id}]")], label_from_row)?;
        match rows.next() {
            None => Ok(None),
            Some(r) => r.map(Some).map_err(QueryError::from),
        }
    }

    /// The operator's later word on the proposal's window, if any.
    fn operator_followup(&self, label: &LabelRef) -> Result<Option<OperatorFollowup>, QueryError> {
        self.conn()
            .query_row(
                "SELECT label, created_at FROM labels \
                 WHERE scope = ?1 AND scope_id = ?2 AND window_end_ts = ?3 \
                 AND source = 'operator' AND created_at > ?4 \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![
                    label.scope,
                    label.scope_id,
                    label.window_end_ts,
                    label.created_at
                ],
                |r| {
                    let verdict: String = r.get(0)?;
                    Ok(OperatorFollowup {
                        confirmed: verdict == label.label,
                        label: verdict,
                        created_at: r.get(1)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })
    }
}

// ---------- turns ----------

/// One `turns` row, every stored column.
#[derive(Debug, Clone)]
pub struct Turn {
    pub session_key: String,
    pub ts_us: i64,
    pub ts: f64,
    pub peer_key: String,
    pub principal: String,
    pub verb: String,
    pub route: String,
    pub status: i64,
    pub latency_ms: f64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub req_shape: String,
    pub resp_shape: String,
    pub bound: String,
    pub validation_failed: Option<String>,
    pub exception: Option<String>,
    pub auth_event: Option<String>,
    pub gate: Option<String>,
    pub ua_hash: String,
    pub dropped_since_last: i64,
    pub rules_matched: Option<String>,
    pub verdict: Option<String>,
    pub ruleset_hash: Option<Vec<u8>>,
    pub surface: Option<String>,
    pub is_asset: Option<i64>,
    pub credential_kind: Option<String>,
    pub credential_hash: Option<String>,
    pub tag_id: Option<String>,
    pub tag_status: Option<String>,
    pub ip_hash: Option<String>,
    pub net_hash: Option<String>,
    pub asn: Option<i64>,
    pub ip_trust: Option<String>,
    pub ua_class: Option<String>,
    pub shape_hash: Option<String>,
    pub shape: Option<String>,
    pub flags: Option<String>,
    pub ja4: Option<String>,
    pub ja4t: Option<String>,
    pub h2_fp: Option<String>,
    pub remote_port: Option<i64>,
    pub ts_ms: Option<i64>,
    pub credential_status: Option<String>,
    pub turn_id: Option<String>,
    pub actor_id: Option<String>,
    pub country: Option<String>,
    pub cluster_key: Option<String>,
    pub ingest_seq: Option<i64>,
}

const TURN_COLS: &str = "session_key, ts_us, ts, peer_key, principal, verb, route, status, \
    latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, validation_failed, \
    exception, auth_event, gate, ua_hash, dropped_since_last, rules_matched, verdict, \
    ruleset_hash, surface, is_asset, credential_kind, credential_hash, tag_id, tag_status, \
    ip_hash, net_hash, asn, ip_trust, ua_class, shape_hash, shape, flags, ja4, ja4t, h2_fp, \
    remote_port, ts_ms, credential_status, turn_id, actor_id, country, cluster_key, ingest_seq";

fn turn_from_row(r: &rusqlite::Row) -> Result<Turn, rusqlite::Error> {
    Ok(Turn {
        session_key: r.get(0)?,
        ts_us: r.get(1)?,
        ts: r.get(2)?,
        peer_key: r.get(3)?,
        principal: r.get(4)?,
        verb: r.get(5)?,
        route: r.get(6)?,
        status: r.get(7)?,
        latency_ms: r.get(8)?,
        bytes_in: r.get(9)?,
        bytes_out: r.get(10)?,
        req_shape: r.get(11)?,
        resp_shape: r.get(12)?,
        bound: r.get(13)?,
        validation_failed: r.get(14)?,
        exception: r.get(15)?,
        auth_event: r.get(16)?,
        gate: r.get(17)?,
        ua_hash: r.get(18)?,
        dropped_since_last: r.get(19)?,
        rules_matched: r.get(20)?,
        verdict: r.get(21)?,
        ruleset_hash: r.get(22)?,
        surface: r.get(23)?,
        is_asset: r.get(24)?,
        credential_kind: r.get(25)?,
        credential_hash: r.get(26)?,
        tag_id: r.get(27)?,
        tag_status: r.get(28)?,
        ip_hash: r.get(29)?,
        net_hash: r.get(30)?,
        asn: r.get(31)?,
        ip_trust: r.get(32)?,
        ua_class: r.get(33)?,
        shape_hash: r.get(34)?,
        shape: r.get(35)?,
        flags: r.get(36)?,
        ja4: r.get(37)?,
        ja4t: r.get(38)?,
        h2_fp: r.get(39)?,
        remote_port: r.get(40)?,
        ts_ms: r.get(41)?,
        credential_status: r.get(42)?,
        turn_id: r.get(43)?,
        actor_id: r.get(44)?,
        country: r.get(45)?,
        cluster_key: r.get(46)?,
        ingest_seq: r.get(47)?,
    })
}

/// One row of an actor's or cluster's turn list.
#[derive(Debug, Clone)]
pub struct TurnLite {
    pub turn_id: Option<String>,
    pub ts_us: i64,
    pub route: String,
    pub verb: String,
    pub status: i64,
    pub surface: Option<String>,
    pub verdict: Option<String>,
    pub actor_id: Option<String>,
}

fn turn_lite_from_row(r: &rusqlite::Row) -> Result<TurnLite, rusqlite::Error> {
    Ok(TurnLite {
        turn_id: r.get(0)?,
        ts_us: r.get(1)?,
        route: r.get(2)?,
        verb: r.get(3)?,
        status: r.get(4)?,
        surface: r.get(5)?,
        verdict: r.get(6)?,
        actor_id: r.get(7)?,
    })
}

const TURN_LITE_COLS: &str = "turn_id, ts_us, route, verb, status, surface, verdict, actor_id";

impl Ctx<'_> {
    /// One turn by its package-minted id.
    pub fn turn(&self, turn_id: &str) -> Result<Turn, QueryError> {
        let sql = format!(
            "SELECT {TURN_COLS} FROM turns WHERE turn_id = ?1 ORDER BY ingest_seq DESC LIMIT 1"
        );
        self.conn()
            .query_row(&sql, params![turn_id], turn_from_row)
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => QueryError::NoTurn(turn_id.to_string()),
                e => QueryError::Sqlite(e),
            })
    }

    fn turns_where(&self, pred: &str, param: &str, page: i64) -> Result<Vec<TurnLite>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let sql = format!(
            "SELECT {TURN_LITE_COLS} FROM turns WHERE {pred} \
             ORDER BY ts_us DESC LIMIT ?2 OFFSET ?3"
        );
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map(params![param, PAGE_SIZE, offset], turn_lite_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    fn turns_count_where(&self, pred: &str, param: &str) -> Result<i64, QueryError> {
        let sql = format!("SELECT count(*) FROM turns WHERE {pred}");
        Ok(self.conn().query_row(&sql, params![param], |r| r.get(0))?)
    }

    /// An actor's turns, newest first, paged. `ids` is the canonical id
    /// plus every id merged into it.
    pub fn turns_for_actor(&self, ids: &[String], page: i64) -> Result<Vec<TurnLite>, QueryError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let offset = page.max(0) * PAGE_SIZE;
        let marks = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        // Numbered past the anonymous marks: a bare `?` takes the next
        // free number, so `?1` here would rebind the first id.
        let sql = format!(
            "SELECT {TURN_LITE_COLS} FROM turns WHERE actor_id IN ({marks}) \
             ORDER BY ts_us DESC LIMIT ?{} OFFSET ?{}",
            ids.len() + 1,
            ids.len() + 2,
        );
        let mut stmt = self.conn().prepare(&sql)?;
        let mut params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        params.push(&PAGE_SIZE);
        params.push(&offset);
        let rows = stmt.query_map(params.as_slice(), turn_lite_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    pub fn turn_count_for_actor(&self, ids: &[String]) -> Result<i64, QueryError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let marks = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT count(*) FROM turns WHERE actor_id IN ({marks})");
        let mut stmt = self.conn().prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        Ok(stmt.query_row(params.as_slice(), |r| r.get(0))?)
    }

    /// A cluster's turns, newest first, paged.
    pub fn turns_for_cluster(&self, key: &str, page: i64) -> Result<Vec<TurnLite>, QueryError> {
        self.turns_where("cluster_key = ?1", key, page)
    }

    pub fn turn_count_for_cluster(&self, key: &str) -> Result<i64, QueryError> {
        self.turns_count_where("cluster_key = ?1", key)
    }
}

// ---------- trace ----------

/// One binding of the turn's actor: live state plus whether the turn
/// carried that identifier.
#[derive(Debug, Clone)]
pub struct TraceBinding {
    pub kind: String,
    pub value: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub expires_at: i64,
    pub returned: bool,
    pub on_this_turn: bool,
}

/// The `actors` row, without the live resolver state.
#[derive(Debug, Clone)]
pub struct ActorHead {
    pub id: String,
    pub opened_us: i64,
    pub last_us: i64,
    pub turns: i64,
    pub confirmed: bool,
    pub merged_into: Option<String>,
}

/// Step 2 of the trace: where the turn resolved.
#[derive(Debug, Clone)]
pub struct TraceResolution {
    pub actor: Option<ActorHead>,
    pub merged_from: Vec<String>,
    pub cluster_key: Option<String>,
    pub bindings: Vec<TraceBinding>,
}

/// One `feature_vectors` row with its 38 values named.
#[derive(Debug, Clone)]
pub struct FeatureRowView {
    pub scope: String,
    pub key: String,
    pub ts_us: i64,
    pub version: i64,
    pub surface: Option<String>,
    pub clock_anomalies: i64,
    pub values: Vec<(String, f32)>,
}

/// One `scores` row with its top-3 path gains decoded.
#[derive(Debug, Clone)]
pub struct ScoreView {
    pub scope: String,
    pub scope_id: String,
    pub surface: Option<String>,
    pub ts_us: i64,
    pub score: f64,
    pub model_version: String,
    pub top3: Vec<(String, f64)>,
}

/// Step 5 of the trace: the latest proposal for the subject.
#[derive(Debug, Clone)]
pub struct TraceProposal {
    pub label: LabelRef,
    pub call_id: Option<i64>,
    pub reason: String,
}

/// One live-or-stored sticky decision.
#[derive(Debug, Clone)]
pub struct DecisionView {
    pub scope: String,
    pub key: String,
    pub action: String,
    pub mode: String,
    pub rule: String,
    pub rule_version: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Step 7 of the trace: the verdict and what sticks.
#[derive(Debug, Clone)]
pub struct TraceDecision {
    pub verdict: Option<String>,
    pub gate_pretty: Option<String>,
    pub rules_pretty: Option<String>,
    pub actor_decision: Option<DecisionView>,
}

/// The seven steps for one request, each with its source.
#[derive(Debug, Clone)]
pub struct Trace {
    pub turn: Turn,
    pub resolution: TraceResolution,
    pub features: Vec<FeatureRowView>,
    pub scores: Vec<ScoreView>,
    pub proposal: Option<TraceProposal>,
    pub labels: Vec<LabelRef>,
    pub decision: TraceDecision,
}

/// The identifiers one turn carried, as (kind, 16-hex value): the same
/// derivation ingest runs, replayed from the stored columns, so the
/// trace can say which identifier decided. Needs the live resolver
/// for the `ja4` namespace hash.
pub fn idents_for_turn(resolver: &crate::actors::Resolver, turn: &Turn) -> Vec<(String, String)> {
    use crate::actors::{Ident, Kind};
    use crate::rules::windows::{key16, principal_key};
    let mut out = Vec::new();
    let mut push = |kind: Kind, v: u64| {
        out.push((kind.as_str().to_string(), format!("{v:016x}")));
    };
    if let Ok(Some(p)) = principal_key(&turn.principal) {
        push(Kind::Principal, p);
    }
    if turn.credential_status.as_deref() == Some("verified") {
        if let Some(h) = turn.credential_hash.as_deref().and_then(key16) {
            push(Kind::Credential, h);
        }
    }
    if let (Some(s), Some(p)) = (key16(&turn.session_key), key16(&turn.peer_key)) {
        if s != p {
            push(Kind::Session, s);
        }
    }
    match turn.tag_status.as_deref() {
        Some("valid") | Some("issued") => {
            if let Some(t) = turn.tag_id.as_deref().and_then(key16) {
                push(Kind::Tag, t);
            }
        }
        _ => {}
    }
    if let Some(n) = turn.net_hash.as_deref().and_then(key16) {
        push(Kind::Net, n);
        if let Some(ja4) = turn.ja4.as_deref() {
            let asn = turn.asn.map(|a| a as u64).unwrap_or(0);
            push(
                Kind::Ja4Asn,
                Ident::pair(Kind::Ja4Asn, resolver.key("ja4", ja4), asn).value,
            );
        }
        if let Some(s) = turn.shape_hash.as_deref().and_then(key16) {
            push(Kind::ShapeNet, Ident::pair(Kind::ShapeNet, s, n).value);
        }
        if let Some(u) = key16(&turn.ua_hash) {
            push(Kind::UaNet, Ident::pair(Kind::UaNet, u, n).value);
        }
    }
    out
}

fn feature_row_from_parts(
    scope: String,
    key: String,
    ts_us: i64,
    version: i64,
    surface: Option<String>,
    clock_anomalies: i64,
    vector: &str,
) -> FeatureRowView {
    let values: Vec<f32> = serde_json::from_str(vector).unwrap_or_default();
    let values = crate::rules::features::NAMES
        .iter()
        .zip(values)
        .map(|(n, v)| (n.to_string(), v))
        .collect();
    FeatureRowView {
        scope,
        key,
        ts_us,
        version,
        surface,
        clock_anomalies,
        values,
    }
}

fn top3_of(raw: &str) -> Vec<(String, f64)> {
    serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map(|v| {
            v.iter()
                .filter_map(|e| {
                    Some((
                        e.get("name")?.as_str()?.to_string(),
                        e.get("path_gain")?.as_f64()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn call_id_of(note: &Option<String>) -> Option<i64> {
    let note = note.as_deref()?;
    let (_, rest) = note.rsplit_once("[llm_call:")?;
    rest.strip_suffix(']')?.parse().ok()
}

fn reason_of(note: &Option<String>) -> String {
    note.as_deref()
        .and_then(|n| n.rsplit_once(" [llm_call:").map(|(r, _)| r.to_string()))
        .or_else(|| note.clone())
        .unwrap_or_default()
}

impl Ctx<'_> {
    /// Step 2: the actor row, the ids merged into it, and the live
    /// bindings with the turn's identifiers marked.
    pub fn trace_resolution(
        &self,
        turn: &Turn,
        idents: &[(String, String)],
    ) -> Result<TraceResolution, QueryError> {
        let actor: Option<ActorHead> = match &turn.actor_id {
            None => None,
            Some(id) => Some(
                self.conn()
                    .query_row(
                        "SELECT id, opened_us, last_us, turns, confirmed, merged_into \
                         FROM actors WHERE id = ?1",
                        params![id],
                        |r| {
                            Ok(ActorHead {
                                id: r.get(0)?,
                                opened_us: r.get(1)?,
                                last_us: r.get(2)?,
                                turns: r.get(3)?,
                                confirmed: r.get::<_, i64>(4)? != 0,
                                merged_into: r.get(5)?,
                            })
                        },
                    )
                    .map_err(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => QueryError::NoActor(id.clone()),
                        e => QueryError::Sqlite(e),
                    })?,
            ),
        };
        // A merged-away id still resolves: follow it to the canonical row.
        let canonical = actor
            .as_ref()
            .and_then(|a| a.merged_into.clone().or(Some(a.id.clone())));
        let merged_from: Vec<String> = match &canonical {
            None => Vec::new(),
            Some(c) => self
                .conn()
                .prepare("SELECT merged_id FROM actor_merges WHERE into_id = ?1 ORDER BY at_us")?
                .query_map(params![c], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?,
        };
        let bindings: Vec<TraceBinding> = match &canonical {
            None => Vec::new(),
            Some(c) => self
                .conn()
                .prepare(
                    "SELECT kind, value, first_seen, last_seen, expires_at, returned \
                     FROM actor_bindings WHERE actor_id = ?1 ORDER BY kind, last_seen DESC",
                )?
                .query_map(params![c], |r| {
                    let kind: String = r.get(0)?;
                    let value: String = r.get(1)?;
                    Ok(TraceBinding {
                        kind: kind.clone(),
                        value: value.clone(),
                        first_seen: r.get(2)?,
                        last_seen: r.get(3)?,
                        expires_at: r.get(4)?,
                        returned: r.get::<_, i64>(5)? != 0,
                        on_this_turn: idents.iter().any(|(k, v)| *k == kind && *v == value),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(TraceResolution {
            actor,
            merged_from,
            cluster_key: turn.cluster_key.clone(),
            bindings,
        })
    }

    /// Steps 3–4: the feature rows and scores the turn produced. v2
    /// turns join on `turn_id`; a v1 turn has none, so its rows join
    /// on the exact stamp plus scope and key.
    pub fn trace_features(
        &self,
        turn: &Turn,
    ) -> Result<(Vec<FeatureRowView>, Vec<ScoreView>), QueryError> {
        let mut features = Vec::new();
        let mut scores = Vec::new();
        if let Some(tid) = &turn.turn_id {
            let mut stmt = self.conn().prepare(
                "SELECT scope, key, ts_us, version, surface, clock_anomalies, vector \
                 FROM feature_vectors WHERE turn_id = ?1 ORDER BY scope",
            )?;
            for row in stmt.query_map(params![tid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })? {
                let (scope, key, ts_us, version, surface, anomalies, vector) = row?;
                features.push(feature_row_from_parts(
                    scope, key, ts_us, version, surface, anomalies, &vector,
                ));
            }
            let mut stmt = self.conn().prepare(
                "SELECT scope, scope_id, surface, ts_us, score, model_version, top3 \
                 FROM scores WHERE turn_id = ?1 ORDER BY scope",
            )?;
            for row in stmt.query_map(params![tid], |r| {
                Ok(ScoreView {
                    scope: r.get(0)?,
                    scope_id: r.get(1)?,
                    surface: r.get(2)?,
                    ts_us: r.get(3)?,
                    score: r.get(4)?,
                    model_version: r.get(5)?,
                    top3: top3_of(&r.get::<_, String>(6)?),
                })
            })? {
                scores.push(row?);
            }
        } else {
            for (scope, key) in [
                ("actor", turn.actor_id.clone()),
                ("cluster", turn.cluster_key.clone()),
            ] {
                let Some(key) = key else { continue };
                let mut stmt = self.conn().prepare(
                    "SELECT scope, key, ts_us, version, surface, clock_anomalies, vector \
                     FROM feature_vectors \
                     WHERE scope = ?1 AND key = ?2 AND ts_us = ?3",
                )?;
                for row in stmt.query_map(params![scope, key, turn.ts_us], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                })? {
                    let (scope, key, ts_us, version, surface, anomalies, vector) = row?;
                    features.push(feature_row_from_parts(
                        scope, key, ts_us, version, surface, anomalies, &vector,
                    ));
                }
            }
        }
        Ok((features, scores))
    }

    /// All labels for one subject, newest first.
    pub fn labels_for(
        &self,
        scope: &str,
        scope_id: &str,
        limit: i64,
    ) -> Result<Vec<LabelRef>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, scope, scope_id, surface, window_end_ts, label, source, confidence, \
             kind, note, created_at, signals FROM labels \
             WHERE scope = ?1 AND scope_id = ?2 \
             ORDER BY created_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![scope, scope_id, limit], label_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    /// Steps 5–6: the latest proposal and every label for the turn's
    /// subject (its actor, else its cluster).
    pub fn trace_proposal_labels(
        &self,
        turn: &Turn,
    ) -> Result<(Option<TraceProposal>, Vec<LabelRef>), QueryError> {
        let subject: Option<(&str, &str)> = turn
            .actor_id
            .as_deref()
            .map(|id| ("actor", id))
            .or_else(|| turn.cluster_key.as_deref().map(|k| ("cluster", k)));
        let Some((scope, id)) = subject else {
            return Ok((None, Vec::new()));
        };
        let labels = self.labels_for(scope, id, 50)?;
        let proposal = labels
            .iter()
            .find(|l| l.source == "llm_proposed")
            .map(|l| TraceProposal {
                label: l.clone(),
                call_id: call_id_of(&l.note),
                reason: reason_of(&l.note),
            });
        Ok((proposal, labels))
    }

    /// Step 7: the verdict, the gate answer, the matched rules, and the
    /// live sticky decision on the actor, if any.
    pub fn trace_decision(&self, turn: &Turn, now_s: i64) -> Result<TraceDecision, QueryError> {
        let actor_decision: Option<DecisionView> = match &turn.actor_id {
            None => None,
            Some(id) => self
                .conn()
                .query_row(
                    "SELECT scope, key, action, mode, rule, rule_version, created_at, expires_at \
                     FROM decisions WHERE scope = 'actor' AND key = ?1 AND expires_at > ?2",
                    params![id, now_s],
                    |r| {
                        Ok(DecisionView {
                            scope: r.get(0)?,
                            key: r.get(1)?,
                            action: r.get(2)?,
                            mode: r.get(3)?,
                            rule: r.get(4)?,
                            rule_version: r.get(5)?,
                            created_at: r.get(6)?,
                            expires_at: r.get(7)?,
                        })
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(QueryError::Sqlite(e)),
                })?,
        };
        Ok(TraceDecision {
            verdict: turn.verdict.clone(),
            gate_pretty: turn.gate.as_deref().map(pretty),
            rules_pretty: turn.rules_matched.as_deref().map(pretty),
            actor_decision,
        })
    }

    /// The whole chain for one request.
    pub fn trace(
        &self,
        turn: &Turn,
        idents: &[(String, String)],
        now_s: i64,
    ) -> Result<Trace, QueryError> {
        let resolution = self.trace_resolution(turn, idents)?;
        let (features, scores) = self.trace_features(turn)?;
        let (proposal, labels) = self.trace_proposal_labels(turn)?;
        let decision = self.trace_decision(turn, now_s)?;
        Ok(Trace {
            turn: turn.clone(),
            resolution,
            features,
            scores,
            proposal,
            labels,
            decision,
        })
    }
}

// ---------- actors ----------

/// One row of `/ui/actors`: the head plus its latest score.
#[derive(Debug, Clone)]
pub struct ActorRow {
    pub id: String,
    pub kind: String,
    pub surfaces: Vec<String>,
    pub confirmed: bool,
    pub turns_held: Option<i64>,
    pub score: Option<f64>,
    pub score_surface: Option<String>,
    pub blocked: bool,
    pub proposal_pending: bool,
    pub latest_label: Option<String>,
    pub cluster: Option<String>,
    pub last_us: i64,
}

/// The derived kind (console.md §1): a principal binding is a signed-in
/// user, a verified credential an API client (a webhook signer when the
/// credential kind is `webhook_sig`), else a browser.
fn kind_of(bindings: &[String], verified_kind: Option<&str>) -> String {
    if bindings.iter().any(|k| k == "principal") {
        return "signed-in user".to_string();
    }
    if let Some(kind) = verified_kind {
        if kind == "webhook_sig" {
            return "webhook sender".to_string();
        }
        return "API client".to_string();
    }
    "browser only".to_string()
}

impl Ctx<'_> {
    fn actor_row(&self, id: &str, now_s: i64) -> Result<ActorRow, QueryError> {
        let head: ActorHead = self
            .conn()
            .query_row(
                "SELECT id, opened_us, last_us, turns, confirmed, merged_into \
                 FROM actors WHERE id = ?1",
                params![id],
                |r| {
                    Ok(ActorHead {
                        id: r.get(0)?,
                        opened_us: r.get(1)?,
                        last_us: r.get(2)?,
                        turns: r.get(3)?,
                        confirmed: r.get::<_, i64>(4)? != 0,
                        merged_into: r.get(5)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => QueryError::NoActor(id.to_string()),
                e => QueryError::Sqlite(e),
            })?;
        let bindings: Vec<String> = self
            .conn()
            .prepare("SELECT DISTINCT kind FROM actor_bindings WHERE actor_id = ?1")?
            .query_map(params![id], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let verified_kind: Option<String> = self
            .conn()
            .query_row(
                "SELECT credential_kind FROM turns \
                 WHERE actor_id = ?1 AND credential_status = 'verified' \
                 AND credential_kind IS NOT NULL LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let surfaces: Vec<String> = self
            .conn()
            .prepare(
                "SELECT DISTINCT surface FROM turns WHERE actor_id = ?1 AND surface IS NOT NULL",
            )?
            .query_map(params![id], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let score: Option<(f64, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT score, surface FROM scores \
                 WHERE scope = 'actor' AND scope_id = ?1 ORDER BY ts_us DESC LIMIT 1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let turns_held: Option<i64> = self
            .conn()
            .query_row(
                "SELECT vector FROM feature_vectors \
                 WHERE scope = 'actor' AND key = ?1 ORDER BY ts_us DESC LIMIT 1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?
            .and_then(|v| {
                let values: Vec<f32> = serde_json::from_str(&v).ok()?;
                let i = crate::rules::features::NAMES
                    .iter()
                    .position(|n| *n == "turns_held")?;
                values.get(i).map(|h| *h as i64)
            });
        let blocked: bool = self
            .conn()
            .query_row(
                "SELECT 1 FROM decisions \
                 WHERE scope = 'actor' AND key = ?1 AND action = 'block' AND expires_at > ?2",
                params![id, now_s],
                |r| r.get::<_, i64>(0),
            )
            .map(|_| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let latest_proposed: Option<i64> = self
            .conn()
            .query_row(
                "SELECT created_at FROM labels \
                 WHERE scope = 'actor' AND scope_id = ?1 AND source = 'llm_proposed' \
                 ORDER BY created_at DESC LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let latest_operator: Option<i64> = self
            .conn()
            .query_row(
                "SELECT created_at FROM labels \
                 WHERE scope = 'actor' AND scope_id = ?1 AND source = 'operator' \
                 ORDER BY created_at DESC LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let latest_label: Option<String> = self
            .conn()
            .query_row(
                "SELECT label || ' (' || source || ')' FROM labels \
                 WHERE scope = 'actor' AND scope_id = ?1 \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let cluster: Option<String> = self
            .conn()
            .query_row(
                "SELECT cluster_key FROM turns \
                 WHERE actor_id = ?1 AND cluster_key IS NOT NULL \
                 ORDER BY ts_us DESC LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        Ok(ActorRow {
            id: head.id,
            kind: kind_of(&bindings, verified_kind.as_deref()),
            surfaces,
            confirmed: head.confirmed,
            turns_held,
            score: score.as_ref().map(|(s, _)| *s),
            score_surface: score.and_then(|(_, s)| s),
            blocked,
            proposal_pending: latest_proposed
                .is_some_and(|p| latest_operator.is_none_or(|o| p > o)),
            latest_label,
            cluster,
            last_us: head.last_us,
        })
    }

    /// Actors by latest score, unscored last, paged.
    pub fn actors(&self, page: i64, now_s: i64) -> Result<Vec<ActorRow>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let mut stmt = self.conn().prepare(
            "SELECT a.id FROM actors a \
             LEFT JOIN (SELECT scope_id, max(ts_us) AS ts FROM scores \
                        WHERE scope = 'actor' GROUP BY scope_id) s ON s.scope_id = a.id \
             LEFT JOIN scores sc ON sc.scope = 'actor' AND sc.scope_id = a.id AND sc.ts_us = s.ts \
             ORDER BY sc.score DESC, a.last_us DESC LIMIT ?1 OFFSET ?2",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![PAGE_SIZE, offset], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.actor_row(id, now_s)).collect()
    }

    pub fn actor_count(&self) -> Result<i64, QueryError> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM actors", [], |r| r.get(0))?)
    }

    /// Every id folded into one canonical actor, canonical first.
    pub fn actor_ids(&self, id: &str) -> Result<Vec<String>, QueryError> {
        let head: ActorHead = self
            .conn()
            .query_row(
                "SELECT id, opened_us, last_us, turns, confirmed, merged_into \
                 FROM actors WHERE id = ?1",
                params![id],
                |r| {
                    Ok(ActorHead {
                        id: r.get(0)?,
                        opened_us: r.get(1)?,
                        last_us: r.get(2)?,
                        turns: r.get(3)?,
                        confirmed: r.get::<_, i64>(4)? != 0,
                        merged_into: r.get(5)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => QueryError::NoActor(id.to_string()),
                e => QueryError::Sqlite(e),
            })?;
        let canonical = head.merged_into.clone().unwrap_or(head.id);
        let mut merged: Vec<String> = self
            .conn()
            .prepare("SELECT merged_id FROM actor_merges WHERE into_id = ?1 ORDER BY at_us")?
            .query_map(params![&canonical], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        merged.insert(0, canonical);
        Ok(merged)
    }
}

/// One binding with its stored state.
#[derive(Debug, Clone)]
pub struct BindingView {
    pub kind: String,
    pub value: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub expires_at: i64,
    pub returned: bool,
    pub provisional: bool,
}

/// The client block: UA and TLS shape, shapes seen, flag rates.
#[derive(Debug, Clone)]
pub struct ClientView {
    pub ua_class: Option<String>,
    pub ja4: Option<String>,
    pub ja4t: Option<String>,
    pub shape_prefix: Option<String>,
    pub shape_count: i64,
    pub flag_rates: Vec<(String, f64)>,
    pub turns_sampled: i64,
}

/// The activity block: volume, pace, outcomes.
#[derive(Debug, Clone)]
pub struct ActivityView {
    pub turns: i64,
    pub active_s: i64,
    pub assets: i64,
    pub ok_2xx: i64,
    pub redirects: i64,
    pub not_found: i64,
    pub denied: i64,
    pub limited: i64,
    pub errors_5xx: i64,
    pub iri_median_ms: Option<f64>,
    pub iri_cv: Option<f64>,
    pub distinct_routes: i64,
}

/// The score block: latest plus history.
#[derive(Debug, Clone)]
pub struct ScoreBlock {
    pub latest: Option<ScoreView>,
    pub history: Vec<(i64, f64)>,
    pub explanation: String,
    pub scored_rows: i64,
}

/// The newest turn's client columns: UA class, JA4, JA4T, shape hash.
type ClientCols = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The activity aggregate: turns, first/last stamp, assets, six status
/// buckets, distinct routes.
type ActivityCols = (
    i64,
    Option<i64>,
    Option<i64>,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
);

/// One similar actor: same cluster, by recency.
#[derive(Debug, Clone)]
pub struct SimilarActor {
    pub id: String,
    pub kind: String,
    pub score: Option<f64>,
    pub turns: i64,
    pub last_us: i64,
}

/// Everything `/ui/actors/{id}` shows.
/// The point-2 one-liner riding the latest explained score row.
#[derive(Debug, Clone)]
pub struct ExplanationView {
    pub text: String,
    pub turn_id: String,
    pub ts_us: i64,
    pub score: f64,
}

pub struct ActorDetail {
    pub head: ActorHead,
    pub row: ActorRow,
    pub merged_from: Vec<String>,
    pub bindings: Vec<BindingView>,
    pub client: ClientView,
    pub cluster_actors: i64,
    pub activity: ActivityView,
    pub scores: ScoreBlock,
    pub explanation: Option<ExplanationView>,
    pub labels: Vec<LabelRef>,
    pub proposal: Option<TraceProposal>,
    pub decisions: Vec<DecisionView>,
    pub similar: Vec<SimilarActor>,
    pub turns: Vec<TurnLite>,
    pub turn_total: i64,
    pub page: i64,
    /// The latest window, for the label form.
    pub window_end_ts: Option<i64>,
    pub window_surface: Option<String>,
}

impl Ctx<'_> {
    fn bindings_for(&self, id: &str) -> Result<Vec<BindingView>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT kind, value, first_seen, last_seen, expires_at, returned \
             FROM actor_bindings WHERE actor_id = ?1 ORDER BY kind, last_seen DESC",
        )?;
        let rows = stmt.query_map(params![id], |r| {
            let kind: String = r.get(0)?;
            let provisional = crate::actors::Kind::parse(&kind).is_some_and(|k| k.is_provisional());
            Ok(BindingView {
                kind,
                value: r.get(1)?,
                first_seen: r.get(2)?,
                last_seen: r.get(3)?,
                expires_at: r.get(4)?,
                returned: r.get::<_, i64>(5)? != 0,
                provisional,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    fn client_for(&self, ids: &[String]) -> Result<ClientView, QueryError> {
        let marks = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let latest: Option<ClientCols> = self
            .conn()
            .prepare(&format!(
                "SELECT ua_class, ja4, ja4t, shape_hash FROM turns \
                     WHERE actor_id IN ({marks}) ORDER BY ts_us DESC LIMIT 1"
            ))?
            .query_row(params.as_slice(), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let shape_count: i64 = self
            .conn()
            .prepare(&format!(
                "SELECT count(DISTINCT shape_hash) FROM turns \
                 WHERE actor_id IN ({marks}) AND shape_hash IS NOT NULL"
            ))?
            .query_row(params.as_slice(), |r| r.get(0))?;
        // Flag rates over the latest 500 turns: enough for a shape,
        // bounded for the page.
        let flags: Vec<Option<String>> = self
            .conn()
            .prepare(&format!(
                "SELECT flags FROM turns WHERE actor_id IN ({marks}) \
                 ORDER BY ts_us DESC LIMIT 500"
            ))?
            .query_map(params.as_slice(), |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut counts: std::collections::BTreeMap<String, i64> = Default::default();
        let mut n = 0i64;
        for f in &flags {
            let Some(f) = f else { continue };
            let Ok(list) = serde_json::from_str::<Vec<String>>(f) else {
                continue;
            };
            n += 1;
            for flag in list {
                *counts.entry(flag).or_default() += 1;
            }
        }
        let flag_rates: Vec<(String, f64)> = counts
            .into_iter()
            .map(|(k, c)| (k, c as f64 / n.max(1) as f64))
            .collect();
        Ok(ClientView {
            ua_class: latest.as_ref().and_then(|l| l.0.clone()),
            ja4: latest.as_ref().and_then(|l| l.1.clone()),
            ja4t: latest.as_ref().and_then(|l| l.2.clone()),
            shape_prefix: latest
                .as_ref()
                .and_then(|l| l.3.as_ref().map(|s| s.chars().take(4).collect())),
            shape_count,
            flag_rates,
            turns_sampled: n,
        })
    }

    fn activity_for(&self, ids: &[String]) -> Result<ActivityView, QueryError> {
        let marks = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let row: ActivityCols = self
            .conn()
            .prepare(&format!(
                "SELECT count(*), min(ts_us), max(ts_us), \
                 coalesce(sum(is_asset = 1), 0), \
                 coalesce(sum(status BETWEEN 200 AND 299), 0), \
                 coalesce(sum(status BETWEEN 300 AND 399), 0), \
                 coalesce(sum(status = 404), 0), coalesce(sum(status IN (401, 403)), 0), \
                 coalesce(sum(status = 429), 0), \
                 coalesce(sum(status BETWEEN 500 AND 599), 0), count(DISTINCT route) \
                 FROM turns WHERE actor_id IN ({marks})"
            ))?
            .query_row(params.as_slice(), |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            })?;
        let stamps: Vec<i64> = self
            .conn()
            .prepare(&format!(
                "SELECT ts_us FROM turns WHERE actor_id IN ({marks}) \
                 ORDER BY ts_us DESC LIMIT 1000"
            ))?
            .query_map(params.as_slice(), |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let (iri_median_ms, iri_cv) = iri_stats(&stamps);
        Ok(ActivityView {
            turns: row.0,
            active_s: match (row.1, row.2) {
                (Some(a), Some(b)) => (b - a).max(0) / 1_000_000,
                _ => 0,
            },
            assets: row.3,
            ok_2xx: row.4,
            redirects: row.5,
            not_found: row.6,
            denied: row.7,
            limited: row.8,
            errors_5xx: row.9,
            iri_median_ms,
            iri_cv,
            distinct_routes: row.10,
        })
    }

    fn scores_for(
        &self,
        scope: &str,
        id: &str,
        thresholds: &std::collections::HashMap<String, f64>,
    ) -> Result<ScoreBlock, QueryError> {
        let history: Vec<(i64, f64)> = self
            .conn()
            .prepare(
                "SELECT ts_us, score FROM scores WHERE scope = ?1 AND scope_id = ?2 \
                 ORDER BY ts_us DESC LIMIT 100",
            )?
            .query_map(params![scope, id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        let latest: Option<ScoreView> = self
            .conn()
            .query_row(
                "SELECT scope, scope_id, surface, ts_us, score, model_version, top3 \
                 FROM scores WHERE scope = ?1 AND scope_id = ?2 ORDER BY ts_us DESC LIMIT 1",
                params![scope, id],
                |r| {
                    Ok(ScoreView {
                        scope: r.get(0)?,
                        scope_id: r.get(1)?,
                        surface: r.get(2)?,
                        ts_us: r.get(3)?,
                        score: r.get(4)?,
                        model_version: r.get(5)?,
                        top3: top3_of(&r.get::<_, String>(6)?),
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let explanation = match &latest {
            None => "no score yet for this subject".to_string(),
            Some(s) => match s
                .surface
                .as_deref()
                .and_then(|surface| thresholds.get(surface))
            {
                None if thresholds.is_empty() => {
                    format!("p = {:.4}, no model loaded so nothing decides", s.score)
                }
                None => format!(
                    "p = {:.4}, no threshold for surface {}",
                    s.score,
                    s.surface.as_deref().unwrap_or("?")
                ),
                Some(t) if s.score >= *t => {
                    format!(
                        "p = {:.4} ≥ threshold {t} ({})",
                        s.score,
                        s.surface.as_deref().unwrap_or("?")
                    )
                }
                Some(t) => {
                    format!(
                        "p = {:.4} < threshold {t} ({})",
                        s.score,
                        s.surface.as_deref().unwrap_or("?")
                    )
                }
            },
        };
        Ok(ScoreBlock {
            latest,
            history,
            explanation,
            scored_rows: self.conn().query_row(
                "SELECT count(*) FROM scores WHERE scope = ?1 AND scope_id = ?2",
                params![scope, id],
                |r| r.get(0),
            )?,
        })
    }

    fn decisions_for(&self, scope: &str, id: &str) -> Result<Vec<DecisionView>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT scope, key, action, mode, rule, rule_version, created_at, expires_at \
             FROM decisions WHERE scope = ?1 AND key = ?2 ORDER BY expires_at DESC",
        )?;
        let rows = stmt.query_map(params![scope, id], |r| {
            Ok(DecisionView {
                scope: r.get(0)?,
                key: r.get(1)?,
                action: r.get(2)?,
                mode: r.get(3)?,
                rule: r.get(4)?,
                rule_version: r.get(5)?,
                created_at: r.get(6)?,
                expires_at: r.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    /// The full actor detail. Thresholds come from the loaded model
    /// (empty when Windside is off), for the score explanation.
    pub fn actor_detail(
        &self,
        id: &str,
        page: i64,
        now_s: i64,
        thresholds: &std::collections::HashMap<String, f64>,
    ) -> Result<ActorDetail, QueryError> {
        let ids = self.actor_ids(id)?;
        let canonical = ids[0].clone();
        let head: ActorHead = self.conn().query_row(
            "SELECT id, opened_us, last_us, turns, confirmed, merged_into \
                 FROM actors WHERE id = ?1",
            params![canonical],
            |r| {
                Ok(ActorHead {
                    id: r.get(0)?,
                    opened_us: r.get(1)?,
                    last_us: r.get(2)?,
                    turns: r.get(3)?,
                    confirmed: r.get::<_, i64>(4)? != 0,
                    merged_into: r.get(5)?,
                })
            },
        )?;
        let row = self.actor_row(&canonical, now_s)?;
        let labels = self.labels_for("actor", &canonical, 50)?;
        let proposal = labels
            .iter()
            .find(|l| l.source == "llm_proposed")
            .map(|l| TraceProposal {
                label: l.clone(),
                call_id: call_id_of(&l.note),
                reason: reason_of(&l.note),
            });
        let similar: Vec<SimilarActor> = match &row.cluster {
            None => Vec::new(),
            Some(cluster) => {
                let mut stmt = self.conn().prepare(
                    "SELECT DISTINCT actor_id FROM turns \
                     WHERE cluster_key = ?1 AND actor_id IS NOT NULL AND actor_id != ?2 LIMIT 11",
                )?;
                let mut out = Vec::new();
                for other in
                    stmt.query_map(params![cluster, canonical], |r| r.get::<_, String>(0))?
                {
                    let other = other?;
                    let r = self.actor_row(&other, now_s)?;
                    out.push(SimilarActor {
                        id: other,
                        kind: r.kind,
                        score: r.score,
                        turns: r.turns_held.unwrap_or(0),
                        last_us: r.last_us,
                    });
                    if out.len() >= 10 {
                        break;
                    }
                }
                out.sort_by_key(|s| std::cmp::Reverse(s.last_us));
                out
            }
        };
        let cluster_actors: i64 = match &row.cluster {
            None => 0,
            Some(cluster) => self.conn().query_row(
                "SELECT count(DISTINCT actor_id) FROM turns WHERE cluster_key = ?1",
                params![cluster],
                |r| r.get(0),
            )?,
        };
        let window: Option<(i64, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT ts_us, surface FROM feature_vectors \
                 WHERE scope = 'actor' AND key = ?1 ORDER BY ts_us DESC LIMIT 1",
                params![canonical],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let page_no = page.max(0);
        let explanation: Option<ExplanationView> = self
            .conn()
            .query_row(
                "SELECT explanation, turn_id, ts_us, score FROM scores \
                 WHERE scope = 'actor' AND scope_id = ?1 AND explanation IS NOT NULL \
                 ORDER BY ts_us DESC LIMIT 1",
                params![canonical],
                |r| {
                    Ok(ExplanationView {
                        text: r.get(0)?,
                        turn_id: r.get(1)?,
                        ts_us: r.get(2)?,
                        score: r.get(3)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        Ok(ActorDetail {
            head,
            row,
            merged_from: ids[1..].to_vec(),
            bindings: self.bindings_for(&canonical)?,
            client: self.client_for(&ids)?,
            cluster_actors,
            activity: self.activity_for(&ids)?,
            scores: self.scores_for("actor", &canonical, thresholds)?,
            explanation,
            labels,
            proposal,
            decisions: self.decisions_for("actor", &canonical)?,
            similar,
            turns: self.turns_for_actor(&ids, page_no)?,
            turn_total: self.turn_count_for_actor(&ids)?,
            page: page_no,
            window_end_ts: window.as_ref().map(|(ts, _)| *ts),
            window_surface: window.and_then(|(_, s)| s),
        })
    }
}

/// The tap join interpreted: the JA4 class plus whether the
/// `ua_vs_ja4_mismatch` flag fires (a known library stack under a
/// browser UA).
#[derive(Debug, Clone)]
pub struct TapInfo {
    pub class: String,
    pub mismatch: bool,
}

pub fn tap_info(
    classes: &crate::tap::classes::Ja4Classes,
    ja4: Option<&str>,
    ua_class: Option<&str>,
) -> TapInfo {
    use crate::tap::classes::{is_browser_ua, Class};
    let class = ja4.map(|j| classes.classify(j)).unwrap_or(Class::Unknown);
    let name = match class {
        Class::Browser => "browser",
        Class::Library => "library",
        Class::Unknown => "unknown",
    };
    TapInfo {
        class: name.to_string(),
        mismatch: class == Class::Library && is_browser_ua(ua_class),
    }
}

/// Median and coefficient of variation of the inter-request gaps, in
/// milliseconds, over stamps newest first. Clamped at zero like the
/// windows: a backward clock step is not a negative gap.
fn iri_stats(stamps: &[i64]) -> (Option<f64>, Option<f64>) {
    if stamps.len() < 2 {
        return (None, None);
    }
    let mut gaps: Vec<f64> = stamps
        .windows(2)
        .map(|w| (w[0] - w[1]).max(0) as f64 / 1000.0)
        .collect();
    gaps.sort_by(f64::total_cmp);
    let median = gaps[gaps.len() / 2];
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean == 0.0 {
        return (Some(median), None);
    }
    let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    (Some(median), Some(var.sqrt() / mean))
}

// ---------- clusters ----------

/// One row of `/ui/clusters`.
#[derive(Debug, Clone)]
pub struct ClusterRow {
    pub key: String,
    pub turns: i64,
    pub actors: i64,
    pub surfaces: Vec<String>,
    pub score: Option<f64>,
    pub score_surface: Option<String>,
    pub proposal_pending: bool,
    pub latest_label: Option<String>,
    pub last_us: i64,
}

/// Everything `/ui/clusters/{key}` shows.
#[derive(Debug, Clone)]
pub struct ClusterDetail {
    pub row: ClusterRow,
    pub activity: ActivityView,
    pub scores: ScoreBlock,
    pub labels: Vec<LabelRef>,
    pub proposal: Option<TraceProposal>,
    pub actor_ids: Vec<String>,
    pub turns: Vec<TurnLite>,
    pub turn_total: i64,
    pub page: i64,
    pub window_end_ts: Option<i64>,
    pub window_surface: Option<String>,
}

impl Ctx<'_> {
    fn cluster_row(&self, key: &str) -> Result<ClusterRow, QueryError> {
        let row: Option<(i64, i64, Option<i64>)> = self
            .conn()
            .query_row(
                "SELECT count(*), count(DISTINCT actor_id), max(ts_us) FROM turns \
                 WHERE cluster_key = ?1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let Some((turns, actors, last)) = row else {
            return Err(QueryError::NoCluster(key.to_string()));
        };
        if turns == 0 {
            return Err(QueryError::NoCluster(key.to_string()));
        }
        let surfaces: Vec<String> = self
            .conn()
            .prepare(
                "SELECT DISTINCT surface FROM turns WHERE cluster_key = ?1 AND surface IS NOT NULL",
            )?
            .query_map(params![key], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let score: Option<(f64, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT score, surface FROM scores \
                 WHERE scope = 'cluster' AND scope_id = ?1 ORDER BY ts_us DESC LIMIT 1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let latest_proposed: Option<i64> = self
            .conn()
            .query_row(
                "SELECT created_at FROM labels \
                 WHERE scope = 'cluster' AND scope_id = ?1 AND source = 'llm_proposed' \
                 ORDER BY created_at DESC LIMIT 1",
                params![key],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let latest_operator: Option<i64> = self
            .conn()
            .query_row(
                "SELECT created_at FROM labels \
                 WHERE scope = 'cluster' AND scope_id = ?1 AND source = 'operator' \
                 ORDER BY created_at DESC LIMIT 1",
                params![key],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let latest_label: Option<String> = self
            .conn()
            .query_row(
                "SELECT label || ' (' || source || ')' FROM labels \
                 WHERE scope = 'cluster' AND scope_id = ?1 \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![key],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        Ok(ClusterRow {
            key: key.to_string(),
            turns,
            actors,
            surfaces,
            score: score.as_ref().map(|(s, _)| *s),
            score_surface: score.and_then(|(_, s)| s),
            proposal_pending: latest_proposed
                .is_some_and(|p| latest_operator.is_none_or(|o| p > o)),
            latest_label,
            last_us: last.unwrap_or(0),
        })
    }

    /// Clusters by latest score, unscored last, paged.
    pub fn clusters(&self, page: i64) -> Result<Vec<ClusterRow>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let mut stmt = self.conn().prepare(
            "SELECT t.cluster_key FROM (SELECT DISTINCT cluster_key FROM turns WHERE cluster_key IS NOT NULL) t \
             LEFT JOIN (SELECT scope_id, max(ts_us) AS ts FROM scores \
                        WHERE scope = 'cluster' GROUP BY scope_id) s ON s.scope_id = t.cluster_key \
             LEFT JOIN scores sc ON sc.scope = 'cluster' AND sc.scope_id = t.cluster_key AND sc.ts_us = s.ts \
             GROUP BY t.cluster_key ORDER BY sc.score DESC LIMIT ?1 OFFSET ?2",
        )?;
        let keys: Vec<String> = stmt
            .query_map(params![PAGE_SIZE, offset], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        keys.iter().map(|k| self.cluster_row(k)).collect()
    }

    pub fn cluster_count(&self) -> Result<i64, QueryError> {
        Ok(self.conn().query_row(
            "SELECT count(DISTINCT cluster_key) FROM turns WHERE cluster_key IS NOT NULL",
            [],
            |r| r.get(0),
        )?)
    }

    fn cluster_activity(&self, key: &str) -> Result<ActivityView, QueryError> {
        let row: ActivityCols = self.conn().query_row(
            "SELECT count(*), min(ts_us), max(ts_us), \
                 coalesce(sum(is_asset = 1), 0), \
                 coalesce(sum(status BETWEEN 200 AND 299), 0), \
                 coalesce(sum(status BETWEEN 300 AND 399), 0), \
                 coalesce(sum(status = 404), 0), coalesce(sum(status IN (401, 403)), 0), \
                 coalesce(sum(status = 429), 0), \
                 coalesce(sum(status BETWEEN 500 AND 599), 0), count(DISTINCT route) \
                 FROM turns WHERE cluster_key = ?1",
            params![key],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )?;
        let stamps: Vec<i64> = self
            .conn()
            .prepare(
                "SELECT ts_us FROM turns WHERE cluster_key = ?1 ORDER BY ts_us DESC LIMIT 1000",
            )?
            .query_map(params![key], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let (iri_median_ms, iri_cv) = iri_stats(&stamps);
        Ok(ActivityView {
            turns: row.0,
            active_s: match (row.1, row.2) {
                (Some(a), Some(b)) => (b - a).max(0) / 1_000_000,
                _ => 0,
            },
            assets: row.3,
            ok_2xx: row.4,
            redirects: row.5,
            not_found: row.6,
            denied: row.7,
            limited: row.8,
            errors_5xx: row.9,
            iri_median_ms,
            iri_cv,
            distinct_routes: row.10,
        })
    }

    pub fn cluster_detail(
        &self,
        key: &str,
        page: i64,
        thresholds: &std::collections::HashMap<String, f64>,
    ) -> Result<ClusterDetail, QueryError> {
        let row = self.cluster_row(key)?;
        let labels = self.labels_for("cluster", key, 50)?;
        let proposal = labels
            .iter()
            .find(|l| l.source == "llm_proposed")
            .map(|l| TraceProposal {
                label: l.clone(),
                call_id: call_id_of(&l.note),
                reason: reason_of(&l.note),
            });
        let actor_ids: Vec<String> = self
            .conn()
            .prepare("SELECT DISTINCT actor_id FROM turns WHERE cluster_key = ?1 AND actor_id IS NOT NULL")?
            .query_map(params![key], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let window: Option<(i64, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT ts_us, surface FROM feature_vectors \
                 WHERE scope = 'cluster' AND key = ?1 ORDER BY ts_us DESC LIMIT 1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let page_no = page.max(0);
        Ok(ClusterDetail {
            row,
            activity: self.cluster_activity(key)?,
            scores: self.scores_for("cluster", key, thresholds)?,
            labels,
            proposal,
            actor_ids,
            turns: self.turns_for_cluster(key, page_no)?,
            turn_total: self.turn_count_for_cluster(key)?,
            page: page_no,
            window_end_ts: window.as_ref().map(|(ts, _)| *ts),
            window_surface: window.and_then(|(_, s)| s),
        })
    }
}

// ---------- review ----------

/// The operator's latest word on a review row, if any.
#[derive(Debug, Clone)]
pub struct OperatorMark {
    pub label: String,
    pub note: Option<String>,
    pub created_at: i64,
}

/// One review row with its queue reasons and operator mark.
#[derive(Debug, Clone)]
pub struct ReviewFull {
    pub row: crate::review::ReviewRow,
    pub why: Vec<String>,
    pub operator: Option<OperatorMark>,
}

impl Ctx<'_> {
    /// The review queue in the CLI's order: disagreements first,
    /// then uncertain, unlabelled proposals, and the rest. Each row
    /// carries the queue reason and the rule hits; decided rows leave
    /// until new evidence re-queues them.
    pub fn review_queue(
        &self,
        thresholds: &std::collections::HashMap<String, f64>,
        top: usize,
    ) -> Result<Vec<ReviewFull>, QueryError> {
        let rows =
            crate::review::review_rows(self.conn(), top, thresholds).map_err(|e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            })?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut why = vec![format!("why_in_queue: {}", row.why.as_str())];
            if !row.rule_hits.is_empty() {
                why.push(format!("rule hits: {}", row.rule_hits.join(", ")));
            }
            match row.surface.as_deref().and_then(|s| thresholds.get(s)) {
                Some(t) if row.score >= *t => {
                    why.push(format!("p = {:.4} ≥ threshold {t}", row.score));
                }
                Some(t) => {
                    why.push(format!(
                        "p = {:.4} < threshold {t} (in the top {top})",
                        row.score
                    ));
                }
                None => why.push(format!("p = {:.4}, no threshold loaded", row.score)),
            }
            if row.proposal.is_some() {
                why.push("the model proposes a label".to_string());
            }
            if row.held < 5 {
                why.push(format!("only {} turns held (below the floor)", row.held));
            }
            let operator: Option<OperatorMark> = self
                .conn()
                .query_row(
                    "SELECT label, note, created_at FROM labels \
                     WHERE scope = ?1 AND scope_id = ?2 AND source = 'operator' \
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![row.scope, row.scope_id],
                    |r| {
                        Ok(OperatorMark {
                            label: r.get(0)?,
                            note: r.get(1)?,
                            created_at: r.get(2)?,
                        })
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(QueryError::Sqlite(e)),
                })?;
            out.push(ReviewFull { row, why, operator });
        }
        Ok(out)
    }
}

// ---------- labels ----------

impl Ctx<'_> {
    /// Every label, newest first, with source and value filters, paged.
    pub fn labels(
        &self,
        source: Option<&str>,
        label: Option<&str>,
        page: i64,
    ) -> Result<Vec<LabelRef>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let mut stmt = self.conn().prepare(
            "SELECT id, scope, scope_id, surface, window_end_ts, label, source, confidence, \
             kind, note, created_at, signals FROM labels \
             WHERE (?1 IS NULL OR source = ?1) AND (?2 IS NULL OR label = ?2) \
             ORDER BY created_at DESC, id DESC LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt.query_map(params![source, label, PAGE_SIZE, offset], label_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    pub fn label_count(
        &self,
        source: Option<&str>,
        label: Option<&str>,
    ) -> Result<i64, QueryError> {
        Ok(self.conn().query_row(
            "SELECT count(*) FROM labels \
             WHERE (?1 IS NULL OR source = ?1) AND (?2 IS NULL OR label = ?2)",
            params![source, label],
            |r| r.get(0),
        )?)
    }

    pub fn label_sources(&self) -> Result<Vec<String>, QueryError> {
        let mut stmt = self
            .conn()
            .prepare("SELECT DISTINCT source FROM labels ORDER BY source")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }
}

// ---------- rules ----------

/// One rule with its 24 h hit counts and its flag for this app.
#[derive(Debug, Clone)]
pub struct RuleView {
    pub id: String,
    pub version: i64,
    pub state: String,
    pub mode: String,
    pub action: String,
    pub origin_kind: String,
    pub note: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub matched_24h: i64,
    pub would_act_24h: i64,
    pub acted_24h: i64,
    pub enabled: bool,
}

impl Ctx<'_> {
    /// The install set and the overrides, with 24 h hit counts.
    pub fn rules(&self, now_s: i64) -> Result<Vec<RuleView>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, version, state, mode, action, origin_kind, body, \
             expires_at, created_at, updated_at FROM rules ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Option<i64>>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, version, state, mode, action, origin, body, expires, created, updated) = row?;
            let note = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("note")?.as_str().map(str::to_string))
                .unwrap_or_default();
            let hour_from = now_s.div_euclid(3600) - 24;
            let (matched, would_act, acted): (i64, i64, i64) = self.conn().query_row(
                "SELECT coalesce(sum(matched), 0), coalesce(sum(would_act), 0), \
                     coalesce(sum(acted), 0) FROM rule_stats WHERE rule = ?1 AND hour >= ?2",
                params![id, hour_from],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            let enabled: Option<i64> = self
                .conn()
                .query_row(
                    "SELECT enabled FROM rule_state WHERE rule_id = ?1 AND app_id = ?2",
                    params![id, self.app()],
                    |r| r.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(QueryError::Sqlite(e)),
                })?;
            out.push(RuleView {
                id,
                version,
                state,
                mode,
                action,
                origin_kind: origin,
                note,
                expires_at: expires,
                created_at: created,
                updated_at: updated,
                matched_24h: matched,
                would_act_24h: would_act,
                acted_24h: acted,
                enabled: enabled.is_none_or(|v| v != 0),
            });
        }
        Ok(out)
    }

    pub fn rule_exists(&self, id: &str) -> Result<bool, QueryError> {
        self.conn()
            .query_row("SELECT 1 FROM rules WHERE id = ?1", params![id], |r| {
                r.get::<_, i64>(0)
            })
            .map(|_| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                e => Err(QueryError::Sqlite(e)),
            })
    }

    /// Rule drafts from the LLM. No table yet: the draft point is
    /// unbuilt, so this is empty until point 4 lands.
    /// Rule drafts from the draft point, newest first.
    pub fn rule_drafts(&self) -> Result<Vec<DraftView>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, cluster_key, rule, reason, parse_ok, parse_error, call_id, status, created_at \
             FROM rule_drafts ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(DraftView {
                id: r.get(0)?,
                cluster_key: r.get(1)?,
                rule: r.get(2)?,
                reason: r.get(3)?,
                parse_ok: r.get::<_, i64>(4)? != 0,
                parse_error: r.get(5)?,
                call_id: r.get(6)?,
                status: r.get(7)?,
                created_at: r.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }
}

/// One row of `rule_drafts`: what the draft point wrote, verbatim.
#[derive(Debug, Clone)]
pub struct DraftView {
    pub id: i64,
    pub cluster_key: String,
    pub rule: String,
    pub reason: String,
    pub parse_ok: bool,
    pub parse_error: Option<String>,
    pub call_id: Option<i64>,
    pub status: String,
    pub created_at: i64,
}

// ---------- payloads ----------

/// One payload pattern with its class, if the classify point judged it.
#[derive(Debug, Clone)]
pub struct PayloadRow {
    pub pattern_hash: String,
    pub method: String,
    pub pattern: String,
    pub turns: i64,
    pub first_seen_s: i64,
    pub last_seen_s: i64,
    pub category: Option<String>,
    pub confidence: Option<f64>,
    pub call_id: Option<i64>,
}

fn payload_from_row(r: &rusqlite::Row<'_>) -> Result<PayloadRow, rusqlite::Error> {
    Ok(PayloadRow {
        pattern_hash: r.get(0)?,
        method: r.get(1)?,
        pattern: r.get(2)?,
        turns: r.get(3)?,
        first_seen_s: r.get(4)?,
        last_seen_s: r.get(5)?,
        category: r.get(6)?,
        confidence: r.get(7)?,
        call_id: r.get(8)?,
    })
}

const PAYLOAD_COLS: &str = "p.pattern_hash, p.method, p.pattern, p.turns, p.first_seen_s, \
     p.last_seen_s, c.category, c.confidence, c.call_id FROM payload_patterns p \
     LEFT JOIN payload_classes c ON c.pattern_hash = p.pattern_hash";

impl Ctx<'_> {
    pub fn payload_patterns(&self, page: i64) -> Result<Vec<PayloadRow>, QueryError> {
        let offset = page.max(0) * PAGE_SIZE;
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {PAYLOAD_COLS} ORDER BY p.last_seen_s DESC LIMIT ?1 OFFSET ?2"
        ))?;
        let rows = stmt.query_map(params![PAGE_SIZE, offset], payload_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    pub fn payload_count(&self) -> Result<i64, QueryError> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM payload_patterns", [], |r| r.get(0))?)
    }

    pub fn payload_detail(&self, hash: &str) -> Result<PayloadRow, QueryError> {
        self.conn()
            .query_row(
                &format!("SELECT {PAYLOAD_COLS} WHERE p.pattern_hash = ?1"),
                params![hash],
                payload_from_row,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => QueryError::NoPayload(hash.to_string()),
                e => QueryError::Sqlite(e),
            })
    }
}

// ---------- model ----------

/// Everything `/ui/model` shows. The engine assembles it: the loaded
/// manifest, the thresholds, the manifest file's metrics, and the
/// shadow report over all time.
#[derive(Debug, Clone, Default)]
pub struct ModelView {
    pub windside_mode: String,
    pub model_version: Option<String>,
    pub features_version: Option<u32>,
    pub thresholds: Vec<(String, f64)>,
    pub manifest_pretty: Option<String>,
    pub shadow: Option<crate::report::ShadowReport>,
    pub shadow_error: Option<String>,
}

// ---------- features ----------

/// The feature names in order with their one-line descriptions, read
/// from the code's tables.
pub fn feature_table() -> Vec<(String, String)> {
    crate::rules::features::NAMES
        .iter()
        .zip(crate::rules::features::DESCRIPTIONS)
        .map(|(n, d)| (n.to_string(), d.to_string()))
        .collect()
}

/// The LLM dashboard numbers (docs/llm-evals.md section 5): proposal
/// precision and coverage, queue speed, live calibration, failure
/// rates, token cost, the classify golden agreement, and the draft
/// funnel with shadow false positives for moved drafts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LlmMetrics {
    pub proposals_decided: usize,
    pub proposal_precision: Option<f64>,
    pub coverage: Option<f64>,
    pub seconds_per_label: Option<f64>,
    pub calibration: Vec<CalBin>,
    pub faithfulness_per_100: Option<f64>,
    pub parse_per_100: Option<f64>,
    pub tokens_per_label: Option<f64>,
    pub classify_golden_agreement: Option<f64>,
    pub drafts_parsed: usize,
    pub drafts_moved: usize,
    pub shadow_fp_moved_drafts: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CalBin {
    pub lo: f64,
    pub hi: f64,
    pub n: usize,
    pub correct: usize,
}

impl Ctx<'_> {
    pub fn llm_metrics(&self) -> Result<LlmMetrics, QueryError> {
        // Decided proposals: the earliest operator label at or after
        // each proposal on the same window.
        let mut stmt = self.conn().prepare(
            "SELECT p.confidence, p.created_at, \
             (SELECT o.label FROM labels o \
              WHERE o.scope = p.scope AND o.scope_id = p.scope_id \
              AND o.window_end_ts = p.window_end_ts AND o.source = 'operator' \
              AND o.created_at >= p.created_at \
              ORDER BY o.created_at ASC, o.id ASC LIMIT 1), \
             (SELECT o.created_at FROM labels o \
              WHERE o.scope = p.scope AND o.scope_id = p.scope_id \
              AND o.window_end_ts = p.window_end_ts AND o.source = 'operator' \
              AND o.created_at >= p.created_at \
              ORDER BY o.created_at ASC, o.id ASC LIMIT 1), \
             p.label \
             FROM labels p WHERE p.source = 'llm_proposed'",
        )?;
        type FaithPair = (f64, i64, Option<String>, Option<i64>, String);
        let pairs: Vec<FaithPair> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut decided = 0usize;
        let mut agreed = 0usize;
        let mut secs_total = 0i64;
        let mut bins = [(0usize, 0usize); 5];
        for (conf, created, label, o_created, proposed) in &pairs {
            let (Some(got), Some(at)) = (label, o_created) else {
                continue;
            };
            decided += 1;
            let ok = got == proposed;
            if ok {
                agreed += 1;
            }
            secs_total += at - created;
            let bin = ((conf * 5.0) as usize).min(4);
            bins[bin].0 += 1;
            if ok {
                bins[bin].1 += 1;
            }
        }
        let calibration = bins
            .iter()
            .enumerate()
            .map(|(i, (n, c))| CalBin {
                lo: i as f64 / 5.0,
                hi: (i + 1) as f64 / 5.0,
                n: *n,
                correct: *c,
            })
            .collect();
        let over_half: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM ( \
                   SELECT scope, scope_id FROM scores \
                   GROUP BY scope, scope_id \
                   HAVING max(score) > 0.5 \
                 )",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let covered: i64 = self
            .conn()
            .query_row(
                "SELECT count(DISTINCT p.scope || ':' || p.scope_id) FROM labels p \
                 WHERE p.source = 'llm_proposed' AND EXISTS ( \
                   SELECT 1 FROM scores s \
                   WHERE s.scope = p.scope AND s.scope_id = p.scope_id AND s.score > 0.5 \
                 )",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let label_sent: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM llm_calls WHERE point = 'label' AND response IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let faith_fail: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM llm_calls \
                 WHERE point = 'label' AND faithfulness_failed IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let sent: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM llm_calls WHERE response IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let parse_fail: i64 = self
            .conn()
            .query_row(
                "SELECT count(*) FROM llm_calls WHERE response IS NOT NULL AND parsed IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let label_tokens: i64 = self
            .conn()
            .query_row(
                "SELECT coalesce(sum(coalesce(prompt_tokens, 0) + coalesce(completion_tokens, 0)), 0) \
                 FROM llm_calls WHERE point = 'label'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let classify_golden: Option<f64> = self
            .conn()
            .query_row(
                "SELECT agreement FROM llm_evals WHERE point = 'classify' \
                 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(None);
        // The draft funnel: parse every stored draft, count the moved,
        // and sum shadow would-act for the moved rules' ids.
        let drafts: Vec<(String, String)> = self
            .conn()
            .prepare("SELECT rule, status FROM rule_drafts")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        let now = crate::store::now_s();
        let mut parsed = 0usize;
        let mut moved = 0usize;
        let mut moved_ids: Vec<String> = Vec::new();
        for (text, status) in &drafts {
            if let Ok(rule) = crate::rules::model::Rule::parse(text, now) {
                parsed += 1;
                if status == "moved" {
                    moved += 1;
                    moved_ids.push(rule.id.clone());
                }
            } else if status == "moved" {
                moved += 1;
            }
        }
        let mut shadow_fp = 0i64;
        for id in &moved_ids {
            let n: i64 = self
                .conn()
                .query_row(
                    "SELECT coalesce(sum(would_act), 0) FROM rule_stats \
                     WHERE rule = ?1 AND mode = 'shadow'",
                    params![id],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            shadow_fp += n;
        }
        let ratio = |n: usize, d: usize| {
            if d > 0 {
                Some(n as f64 / d as f64)
            } else {
                None
            }
        };
        let per100 = |n: i64, d: i64| {
            if d > 0 {
                Some(n as f64 * 100.0 / d as f64)
            } else {
                None
            }
        };
        Ok(LlmMetrics {
            proposals_decided: decided,
            proposal_precision: ratio(agreed, decided),
            coverage: if over_half > 0 {
                Some(covered as f64 / over_half as f64)
            } else {
                None
            },
            seconds_per_label: if decided > 0 {
                Some(secs_total as f64 / decided as f64)
            } else {
                None
            },
            calibration,
            faithfulness_per_100: per100(faith_fail, label_sent),
            parse_per_100: per100(parse_fail, sent),
            tokens_per_label: if agreed > 0 {
                Some(label_tokens as f64 / agreed as f64)
            } else {
                None
            },
            classify_golden_agreement: classify_golden,
            drafts_parsed: parsed,
            drafts_moved: moved,
            shadow_fp_moved_drafts: shadow_fp,
        })
    }
}

// ---------- episodes ----------

/// The dashboard window, validated. The API rejects anything else.
pub fn parse_window(s: &str) -> Option<i64> {
    match s {
        "24h" => Some(86_400),
        "7d" => Some(604_800),
        "30d" => Some(2_592_000),
        _ => None,
    }
}

/// The window in headline words. Call only with `parse_window` output.
pub fn window_label(window_s: i64) -> &'static str {
    match window_s {
        86_400 => "24 hours",
        604_800 => "7 days",
        2_592_000 => "30 days",
        _ => "24 hours",
    }
}

const EPISODE_TITLES_JSON: &str = include_str!("../../data/episode-titles.json");

struct Titles {
    rules: std::collections::HashMap<String, String>,
    signals: std::collections::HashMap<String, String>,
    fallback: String,
}

fn episode_titles() -> &'static Titles {
    static ONCE: std::sync::OnceLock<Titles> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let v: serde_json::Value = serde_json::from_str(EPISODE_TITLES_JSON).unwrap_or_default();
        let map = |k: &str| {
            v.get(k)
                .and_then(|o| o.as_object())
                .map(|o| {
                    o.iter()
                        .map(|(kk, vv)| (kk.clone(), vv.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };
        Titles {
            rules: map("rules"),
            signals: map("signals"),
            fallback: v
                .get("fallback")
                .and_then(|s| s.as_str())
                .unwrap_or("Unusual activity")
                .to_string(),
        }
    })
}

/// The four-step story: who came, what they tried, what Leeside did,
/// what's next. For a waiting episode `next` is the evidence line the
/// design shows under the three decision buttons.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EpisodeStory {
    pub who: String,
    pub what: String,
    pub did: String,
    pub next: String,
}

/// One "look closer" chip. `href` is the path under the console
/// prefix; the API layer prepends `LEESIDED_CONSOLE_PATH`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EpisodeChip {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    pub href: String,
}

/// One episode: a subject (actor or cluster), a time span, and what
/// defined it. `explained_by` is set exactly when `summary` is the
/// subject's latest LLM explanation rather than a template.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Episode {
    pub id: String,
    pub scope: String,
    pub subject: String,
    pub state: String,
    pub title: String,
    pub span_start: i64,
    pub span_end: i64,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explained_by: Option<String>,
    pub story: EpisodeStory,
    pub chips: Vec<EpisodeChip>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    pub window_end_ts: Option<i64>,
    pub score: Option<f64>,
    pub threshold: Option<f64>,
}

/// The newest acting decision on the subject, if any.
struct StoppedBy {
    action: String,
    rule: String,
}

/// The latest `llm_proposed` label with its call's model, if any.
struct SubjectProposal {
    label: String,
    confidence: f64,
    reason: String,
    signals: Vec<String>,
    cited: usize,
    model: Option<String>,
}

fn fmt_n(n: i64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn plural(n: i64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{} {many}", fmt_n(n))
    }
}

/// What they tried: the turn count with the dominant route, or the
/// surface when the route is missing or an internal sentinel
/// (`_unrouted` never reaches the headline).
fn story_what(turns: i64, dominant_route: &str, surface: &str) -> String {
    if dominant_route.is_empty() || dominant_route.starts_with('_') {
        format!("{} on {surface}", plural(turns, "request", "requests"))
    } else {
        format!(
            "{}, mostly {dominant_route}",
            plural(turns, "request", "requests")
        )
    }
}

impl Ctx<'_> {
    /// The window's activity grouped into episodes, newest first,
    /// capped at 100. Stopped beats waiting beats watched: an active
    /// (unexpired, enforce-mode) decision on the subject, else review
    /// queue membership, else a window score, window feature row or
    /// monitor/shadow rule observation.
    pub fn episodes(
        &self,
        window_s: i64,
        now_s: i64,
        thresholds: &std::collections::HashMap<String, f64>,
        windside_shadow: bool,
    ) -> Result<Vec<Episode>, QueryError> {
        let since_us = (now_s - window_s).max(0) * 1_000_000;
        let queue = crate::review::review_rows(self.conn(), usize::MAX, thresholds).map_err(
            |e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            },
        )?;
        let mut queued: std::collections::HashMap<(String, String), crate::review::ReviewRow> =
            std::collections::HashMap::new();
        for row in queue {
            queued.insert((row.scope.clone(), row.scope_id.clone()), row);
        }
        let mut subjects: Vec<(String, String)> = Vec::new();
        for (scope, col) in [("actor", "actor_id"), ("cluster", "cluster_key")] {
            let mut stmt = self.conn().prepare(&format!(
                "SELECT DISTINCT {col} FROM turns WHERE {col} IS NOT NULL AND ts_us >= ?1"
            ))?;
            let ids: Vec<String> = stmt
                .query_map(params![since_us], |r| r.get(0))?
                .filter_map(|r| r.ok())
                .collect();
            for id in ids {
                subjects.push((scope.to_string(), id));
            }
        }
        let mut out = Vec::new();
        for (scope, id) in &subjects {
            if let Some(ep) = self.episode_for(
                scope,
                id,
                since_us,
                now_s,
                thresholds,
                &queued,
                windside_shadow,
            )? {
                out.push(ep);
            }
        }
        out.sort_by(|a: &Episode, b: &Episode| {
            b.span_end
                .cmp(&a.span_end)
                .then_with(|| b.span_start.cmp(&a.span_start))
                .then_with(|| a.id.cmp(&b.id))
        });
        out.truncate(100);
        Ok(out)
    }

    /// The latest feature window, for the decision POST's freshness
    /// check. Same lookup the inspector's label form uses.
    fn episode_window(&self, scope: &str, id: &str) -> Result<Option<i64>, QueryError> {
        self.conn()
            .query_row(
                "SELECT ts_us FROM feature_vectors WHERE scope = ?1 AND key = ?2 \
                 ORDER BY ts_us DESC LIMIT 1",
                params![scope, id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })
    }

    /// The newest unexpired enforce-mode decision touching the
    /// subject: an actor-scope decision on an actor, or any decision
    /// whose key appears on one of the subject's window turns.
    fn stopped_by(
        &self,
        scope: &str,
        id: &str,
        since_us: i64,
        now_s: i64,
    ) -> Result<Option<StoppedBy>, QueryError> {
        let col = if scope == "actor" {
            "actor_id"
        } else {
            "cluster_key"
        };
        let own = if scope == "actor" {
            "(scope = 'actor' AND key = ?2) OR "
        } else {
            ""
        };
        self.conn()
            .query_row(
                &format!(
                    "SELECT action, rule FROM decisions \
                     WHERE expires_at > ?1 AND mode = 'enforce' AND ({own}EXISTS ( \
                       SELECT 1 FROM turns t WHERE t.{col} = ?2 AND t.ts_us >= ?3 AND ( \
                         (decisions.scope = 'session' AND t.session_key = decisions.key) \
                         OR (decisions.scope = 'peer' AND t.peer_key = decisions.key) \
                         OR (decisions.scope = 'principal' AND t.principal = decisions.key) \
                         OR (decisions.scope = 'credential' AND t.credential_hash = decisions.key)))) \
                     ORDER BY created_at DESC LIMIT 1"
                ),
                params![now_s, id, since_us],
                |r| {
                    Ok(StoppedBy {
                        action: r.get(0)?,
                        rule: r.get(1)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })
    }

    fn latest_proposal(
        &self,
        scope: &str,
        id: &str,
    ) -> Result<Option<SubjectProposal>, QueryError> {
        type ProposalCols = (String, f64, Option<String>, Option<String>, Option<String>);
        let row: Option<ProposalCols> = self
            .conn()
            .query_row(
                "SELECT label, confidence, note, signals, cited_turns FROM labels \
                 WHERE scope = ?1 AND scope_id = ?2 AND source = 'llm_proposed' \
                 ORDER BY window_end_ts DESC, created_at DESC, id DESC LIMIT 1",
                params![scope, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let Some((label, confidence, note, signals, cited)) = row else {
            return Ok(None);
        };
        let note = note.unwrap_or_default();
        let reason = crate::review::Proposal::display(&note);
        let signals: Vec<String> = signals
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let cited: Vec<serde_json::Value> = cited
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let model = note
            .rsplit_once(" [llm_call:")
            .and_then(|(_, rest)| rest.strip_suffix(']'))
            .and_then(|n| n.parse::<i64>().ok())
            .and_then(|call| {
                self.conn()
                    .query_row(
                        "SELECT model FROM llm_calls WHERE id = ?1",
                        params![call],
                        |r| r.get(0),
                    )
                    .ok()
            });
        Ok(Some(SubjectProposal {
            label,
            confidence,
            reason,
            signals,
            cited: cited.len(),
            model,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn episode_for(
        &self,
        scope: &str,
        id: &str,
        since_us: i64,
        now_s: i64,
        thresholds: &std::collections::HashMap<String, f64>,
        queued: &std::collections::HashMap<(String, String), crate::review::ReviewRow>,
        windside_shadow: bool,
    ) -> Result<Option<Episode>, QueryError> {
        let col = if scope == "actor" {
            "actor_id"
        } else {
            "cluster_key"
        };
        let (turns, first_us, last_us): (i64, i64, i64) = self.conn().query_row(
            &format!(
                "SELECT count(*), min(ts_us), max(ts_us) FROM turns WHERE {col} = ?1 AND ts_us >= ?2"
            ),
            params![id, since_us],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if turns == 0 {
            return Ok(None);
        }
        let dominant_route: String = self
            .conn()
            .query_row(
                &format!(
                    "SELECT route FROM turns WHERE {col} = ?1 AND ts_us >= ?2 \
                     GROUP BY route ORDER BY count(*) DESC LIMIT 1"
                ),
                params![id, since_us],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let dominant_surface: Option<String> = self
            .conn()
            .query_row(
                &format!(
                    "SELECT surface FROM turns WHERE {col} = ?1 AND ts_us >= ?2 \
                     GROUP BY surface ORDER BY count(*) DESC LIMIT 1"
                ),
                params![id, since_us],
                |r| r.get(0),
            )
            .unwrap_or(None);
        let surface = dominant_surface.as_deref().unwrap_or("web");
        let stopped = self.stopped_by(scope, id, since_us, now_s)?;
        let queue_row = queued.get(&(scope.to_string(), id.to_string()));
        let score: Option<(f64, Option<String>, i64)> = self
            .conn()
            .query_row(
                "SELECT score, surface, ts_us FROM scores WHERE scope = ?1 AND scope_id = ?2 \
                 ORDER BY ts_us DESC LIMIT 1",
                params![scope, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let (rules, observe) =
            crate::review::subject_hits(self.conn(), scope, id, now_s).map_err(|e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            })?;
        let has_features: bool = self.conn().query_row(
            "SELECT 1 FROM feature_vectors WHERE scope = ?1 AND key = ?2 AND ts_us >= ?3 LIMIT 1",
            params![scope, id, since_us],
            |_| Ok(true),
        ).or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(false),
            e => Err(QueryError::Sqlite(e)),
        })?;
        let scored_in_window = score.as_ref().is_some_and(|(_, _, ts)| *ts >= since_us);
        let state = if stopped.is_some() {
            "stopped"
        } else if queue_row.is_some() {
            "waiting"
        } else if scored_in_window || has_features || !observe.is_empty() {
            "watched"
        } else {
            return Ok(None);
        };
        let proposal = self.latest_proposal(scope, id)?;
        let titles = episode_titles();
        let newest_hit = rules
            .iter()
            .chain(observe.iter())
            .max_by_key(|h| h.ts)
            .map(|h| h.rule.as_str());
        let newest_observe = observe.iter().max_by_key(|h| h.ts).map(|h| h.rule.as_str());
        let title = if let Some(s) = &stopped {
            titles.rules.get(&s.rule).cloned()
        } else if state == "waiting" {
            newest_hit
                .and_then(|r| titles.rules.get(r).cloned())
                .or_else(|| {
                    proposal.as_ref().and_then(|p| {
                        p.signals
                            .iter()
                            .filter_map(|s| titles.signals.get(s).cloned())
                            .next()
                    })
                })
        } else {
            newest_observe.and_then(|r| titles.rules.get(r).cloned())
        }
        .unwrap_or_else(|| titles.fallback.replace("{surface}", surface));
        let rule_chip = if let Some(s) = &stopped {
            Some(s.rule.clone())
        } else if state == "waiting" {
            newest_hit.map(str::to_string)
        } else {
            newest_observe.map(str::to_string)
        };
        let who = self.episode_who(scope, id, since_us)?;
        let what = story_what(turns, &dominant_route, surface);
        let action_word = stopped.as_ref().map(|s| match s.action.as_str() {
            "block" => "Blocked",
            "rate_limit" => "Rate limited",
            "challenge" => "Challenged",
            a => a,
        });
        let did = match (&stopped, state) {
            (Some(s), _) => match action_word {
                Some(w) => format!("{w} by {}", s.rule),
                None => format!("Stopped by {}", s.rule),
            },
            (None, "waiting") if windside_shadow => "Nothing yet. It only logged them.".to_string(),
            (None, "waiting") => "Nothing yet. Waiting on a decision.".to_string(),
            _ => "Watched. Nothing was stopped.".to_string(),
        };
        let next = match state {
            "waiting" => {
                let mut parts = Vec::new();
                if let Some((s, _, _)) = &score {
                    parts.push(format!("Windside score {s:.2}"));
                }
                if let Some(p) = &proposal {
                    parts.push(format!(
                        "proposed {} at {:.2}, cited {} turns",
                        p.label, p.confidence, p.cited
                    ));
                }
                if parts.is_empty() {
                    "Not scored yet, no proposal yet".to_string()
                } else {
                    parts.join(", ")
                }
            }
            "stopped" => {
                let hold = stopped.as_ref().map(|s| match s.action.as_str() {
                    "block" => "block",
                    "rate_limit" => "rate limit",
                    "challenge" => "challenge",
                    a => a,
                });
                match hold {
                    Some(h) => format!("Nothing. The {h} is still holding."),
                    None => "Nothing. It is still holding.".to_string(),
                }
            }
            _ => "Nothing yet. Windside is still watching.".to_string(),
        };
        let (summary, explained_by) = match &proposal {
            Some(p) if !p.reason.trim().is_empty() && p.model.is_some() => {
                (p.reason.clone(), p.model.clone())
            }
            _ => {
                let mut t = format!("{what}. {did}");
                if !did.ends_with('.') {
                    t.push('.');
                }
                (t, None)
            }
        };
        let episode_id = format!("ep_{scope}_{id}");
        let mut chips = Vec::new();
        if scope == "cluster" {
            let actors: i64 = self.conn().query_row(
                "SELECT count(DISTINCT actor_id) FROM turns WHERE cluster_key = ?1 AND ts_us >= ?2",
                params![id, since_us],
                |r| r.get(0),
            )?;
            if actors > 0 {
                chips.push(EpisodeChip {
                    label: "actors".to_string(),
                    count: Some(actors),
                    href: format!("/ui/actors?episode={episode_id}"),
                });
            }
        } else {
            chips.push(EpisodeChip {
                label: "actor".to_string(),
                count: None,
                href: format!("/ui/actors/{id}"),
            });
        }
        chips.push(EpisodeChip {
            label: "requests".to_string(),
            count: Some(turns),
            href: format!("/ui/traffic?episode={episode_id}"),
        });
        if let Some(rule) = rule_chip {
            chips.push(EpisodeChip {
                label: format!("Rule {rule}"),
                count: None,
                href: format!("/ui/rules/{rule}"),
            });
        }
        Ok(Some(Episode {
            id: episode_id,
            scope: scope.to_string(),
            subject: id.to_string(),
            state: state.to_string(),
            title,
            span_start: first_us / 1_000_000,
            span_end: last_us / 1_000_000,
            summary,
            explained_by,
            story: EpisodeStory {
                who,
                what,
                did,
                next,
            },
            chips,
            why: queue_row.map(|r| r.why.as_str().to_string()),
            window_end_ts: self.episode_window(scope, id)?,
            score: score.as_ref().map(|(s, _, _)| *s),
            threshold: score.as_ref().and_then(|(_, s, _)| {
                s.as_deref()
                    .and_then(|surface| thresholds.get(surface).copied())
            }),
        }))
    }
}

/// The dashboard headline numbers plus the three tiles.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActorTile {
    pub total: i64,
    pub normal: i64,
}

/// Active rules act; ready ones observe (monitor or shadow) and wait
/// to be turned on. Proposed drafts are neither.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RulesTile {
    pub active: i64,
    pub ready: i64,
}

/// Operator decisions in the window, and how many agreed with the
/// proposal standing when they were made.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReviewTile {
    pub total: i64,
    pub agreed: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SummaryTiles {
    pub actors: ActorTile,
    pub rules: RulesTile,
    pub reviews: ReviewTile,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DashboardSummary {
    pub window: String,
    pub mode: String,
    pub attacks: i64,
    pub stopped: i64,
    pub waiting: i64,
    pub watched: i64,
    pub would_have_stopped: i64,
    pub requests: i64,
    pub fingerprinted: Option<u8>,
    pub tiles: SummaryTiles,
    pub pending: i64,
}

/// One histogram bucket: the window slice starting here, in unix
/// seconds, with its total and hostile turn counts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficBucket {
    pub start: i64,
    pub total: i64,
    pub hostile: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Traffic {
    pub buckets: Vec<TrafficBucket>,
    pub window_total: i64,
}

/// The traffic bucket, validated. The API also requires the window
/// to divide evenly into buckets no bigger than itself.
pub fn parse_bucket(s: &str) -> Option<i64> {
    match s {
        "1h" => Some(3_600),
        "6h" => Some(21_600),
        "12h" => Some(43_200),
        "1d" => Some(86_400),
        "7d" => Some(604_800),
        _ => None,
    }
}

impl Ctx<'_> {
    /// The dashboard summary: episode counts by state, the mode, the
    /// three tiles, and the sidebar queue pill.
    pub fn dashboard_summary(
        &self,
        window_s: i64,
        now_s: i64,
        thresholds: &std::collections::HashMap<String, f64>,
        windside_mode: &str,
    ) -> Result<DashboardSummary, QueryError> {
        let shadow = windside_mode == "shadow";
        let episodes = self.episodes(window_s, now_s, thresholds, shadow)?;
        let mut stopped = 0;
        let mut waiting = 0;
        let mut watched = 0;
        for e in &episodes {
            match e.state.as_str() {
                "stopped" => stopped += 1,
                "waiting" => waiting += 1,
                "watched" => watched += 1,
                _ => {}
            }
        }
        let since_us = (now_s - window_s).max(0) * 1_000_000;
        let mut would_have_stopped = 0;
        if shadow {
            let mut stmt = self.conn().prepare(
                "SELECT scope, scope_id, surface, score FROM ( \
                   SELECT *, ROW_NUMBER() OVER \
                     (PARTITION BY scope, scope_id ORDER BY ts_us DESC) AS rn \
                   FROM scores WHERE scope IN ('actor', 'cluster') \
                 ) WHERE rn = 1",
            )?;
            let latest: Vec<(String, String, Option<String>, f64)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .filter_map(|r| r.ok())
                .collect();
            for (scope, scope_id, surface, score) in latest {
                let t = surface
                    .as_deref()
                    .and_then(|s| thresholds.get(s).copied())
                    .unwrap_or(0.5);
                if score < t {
                    continue;
                }
                // Windowed like everything else in the summary: a quiet
                // subject is not part of this window's story.
                let col = if scope == "actor" {
                    "actor_id"
                } else {
                    "cluster_key"
                };
                let active: bool = self
                    .conn()
                    .query_row(
                        &format!("SELECT 1 FROM turns WHERE {col} = ?1 AND ts_us >= ?2 LIMIT 1"),
                        params![scope_id, since_us],
                        |_| Ok(true),
                    )
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(false),
                        e => Err(QueryError::Sqlite(e)),
                    })?;
                if active
                    && self
                        .stopped_by(&scope, &scope_id, since_us, now_s)?
                        .is_none()
                {
                    would_have_stopped += 1;
                }
            }
        }
        let requests: i64 = self.conn().query_row(
            "SELECT count(*) FROM turns WHERE ts_us >= ?1",
            params![since_us],
            |r| r.get(0),
        )?;
        let fingerprinted = if requests == 0 {
            None
        } else {
            let with_ja4: i64 = self.conn().query_row(
                "SELECT count(*) FROM turns WHERE ts_us >= ?1 AND ja4 IS NOT NULL",
                params![since_us],
                |r| r.get(0),
            )?;
            Some((with_ja4 as f64 * 100.0 / requests as f64).round() as u8)
        };
        let mut stmt = self.conn().prepare(
            "SELECT s.score, s.surface FROM \
               (SELECT DISTINCT actor_id AS id FROM turns \
                WHERE actor_id IS NOT NULL AND ts_us >= ?1) a \
             LEFT JOIN (SELECT scope_id, surface, score, ROW_NUMBER() OVER \
                          (PARTITION BY scope_id ORDER BY ts_us DESC) AS rn \
                        FROM scores WHERE scope = 'actor') s \
             ON s.scope_id = a.id AND s.rn = 1",
        )?;
        let actor_scores: Vec<(Option<f64>, Option<String>)> = stmt
            .query_map(params![since_us], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        let actors_total = actor_scores.len() as i64;
        let mut actors_normal = 0;
        for (score, surface) in actor_scores {
            let hostile = score.is_some_and(|s| {
                s >= surface
                    .as_deref()
                    .and_then(|sf| thresholds.get(sf).copied())
                    .unwrap_or(0.5)
            });
            if !hostile {
                actors_normal += 1;
            }
        }
        let mut stmt = self
            .conn()
            .prepare("SELECT mode, count(*) FROM rules WHERE state = 'active' GROUP BY mode")?;
        let modes: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        let mut rules_active = 0;
        let mut rules_ready = 0;
        for (mode, n) in modes {
            if mode == "enforce" {
                rules_active += n;
            } else {
                rules_ready += n;
            }
        }
        let mut stmt = self.conn().prepare(
            "SELECT scope, scope_id, label, created_at FROM labels \
             WHERE source = 'operator' AND created_at >= ?1",
        )?;
        let decided: Vec<(String, String, String, i64)> = stmt
            .query_map(params![now_s - window_s], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut reviews_agreed = 0;
        for (scope, scope_id, label, at) in &decided {
            let proposal: Option<String> = self
                .conn()
                .query_row(
                    "SELECT label FROM labels \
                     WHERE scope = ?1 AND scope_id = ?2 AND source = 'llm_proposed' \
                     AND created_at <= ?3 ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![scope, scope_id, at],
                    |r| r.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(QueryError::Sqlite(e)),
                })?;
            if proposal.as_deref() == Some(label.as_str()) {
                reviews_agreed += 1;
            }
        }
        let queue = crate::review::review_rows(self.conn(), usize::MAX, thresholds).map_err(
            |e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            },
        )?;
        Ok(DashboardSummary {
            window: window_label(window_s).to_string(),
            mode: windside_mode.to_string(),
            attacks: episodes.len() as i64,
            stopped,
            waiting,
            watched,
            would_have_stopped,
            requests,
            fingerprinted,
            tiles: SummaryTiles {
                actors: ActorTile {
                    total: actors_total,
                    normal: actors_normal,
                },
                rules: RulesTile {
                    active: rules_active,
                    ready: rules_ready,
                },
                reviews: ReviewTile {
                    total: decided.len() as i64,
                    agreed: reviews_agreed,
                },
            },
            pending: queue.len() as i64,
        })
    }

    /// The traffic histogram: per bucket the total turns and the
    /// hostile turns (turns of stopped or waiting subjects).
    /// `window_total` is the sum of the buckets.
    pub fn traffic(
        &self,
        window_s: i64,
        bucket_s: i64,
        now_s: i64,
        thresholds: &std::collections::HashMap<String, f64>,
        windside_shadow: bool,
    ) -> Result<Traffic, QueryError> {
        let episodes = self.episodes(window_s, now_s, thresholds, windside_shadow)?;
        let mut hostile_actors: Vec<String> = Vec::new();
        let mut hostile_clusters: Vec<String> = Vec::new();
        for e in &episodes {
            if e.state == "stopped" || e.state == "waiting" {
                if e.scope == "actor" {
                    hostile_actors.push(e.subject.clone());
                } else {
                    hostile_clusters.push(e.subject.clone());
                }
            }
        }
        // An empty IN list is a syntax error; the sentinel never
        // matches a real 16-hex id.
        if hostile_actors.is_empty() {
            hostile_actors.push("\0".to_string());
        }
        if hostile_clusters.is_empty() {
            hostile_clusters.push("\0".to_string());
        }
        let holes = |n: usize| vec!["?"; n].join(", ");
        let sql = format!(
            "SELECT count(*), count(CASE WHEN coalesce(actor_id, '') IN ({}) \
             OR coalesce(cluster_key, '') IN ({}) THEN 1 END) \
             FROM turns WHERE ts_us >= ? AND ts_us < ?",
            holes(hostile_actors.len()),
            holes(hostile_clusters.len())
        );
        let n = (window_s / bucket_s).max(1);
        let mut buckets = Vec::with_capacity(n as usize);
        let mut window_total = 0;
        for j in 0..n {
            let start = now_s - window_s + j * bucket_s;
            let mut args: Vec<rusqlite::types::Value> = Vec::new();
            for id in hostile_actors.iter().chain(hostile_clusters.iter()) {
                args.push(rusqlite::types::Value::Text(id.clone()));
            }
            args.push(rusqlite::types::Value::Integer(start * 1_000_000));
            args.push(rusqlite::types::Value::Integer(
                (start + bucket_s) * 1_000_000,
            ));
            let (total, hostile): (i64, i64) =
                self.conn()
                    .query_row(&sql, rusqlite::params_from_iter(args), |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })?;
            window_total += total;
            buckets.push(TrafficBucket {
                start,
                total,
                hostile,
            });
        }
        Ok(Traffic {
            buckets,
            window_total,
        })
    }

    /// Who came: the cluster's clients and networks, or the actor's
    /// derived kind with its network context.
    fn episode_who(&self, scope: &str, id: &str, since_us: i64) -> Result<String, QueryError> {
        if scope == "cluster" {
            let (actors, clients, nets, signed): (i64, i64, i64, i64) = self.conn().query_row(
                "SELECT count(DISTINCT actor_id), count(DISTINCT peer_key), \
                 count(DISTINCT net_hash), max(principal != 'anon') \
                 FROM turns WHERE cluster_key = ?1 AND ts_us >= ?2",
                params![id, since_us],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            // Clients are actors, matching the actors chip; cookie-less
            // turns fall back to the peer count, marked unidentified.
            let mut who = if actors > 0 {
                plural(actors, "client", "clients")
            } else if clients == 1 {
                "1 unidentified client".to_string()
            } else {
                format!("{} unidentified clients", fmt_n(clients))
            };
            if nets > 0 {
                who.push_str(&format!(" on {}", plural(nets, "network", "networks")));
            }
            if signed == 0 {
                who.push_str(", none signed in");
            }
            return Ok(who);
        }
        let bindings: Vec<String> = self
            .conn()
            .prepare("SELECT DISTINCT kind FROM actor_bindings WHERE actor_id = ?1")?
            .query_map(params![id], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        let verified: Option<String> = self
            .conn()
            .query_row(
                "SELECT credential_kind FROM turns \
                 WHERE actor_id = ?1 AND credential_status = 'verified' \
                 AND credential_kind IS NOT NULL LIMIT 1",
                params![id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let mut who = match kind_of(&bindings, verified.as_deref()).as_str() {
            "browser only" => "one visitor with no login or key".to_string(),
            k => format!("one {k}"),
        };
        let cluster: Option<String> = self
            .conn()
            .query_row(
                "SELECT cluster_key FROM turns WHERE actor_id = ?1 AND ts_us >= ?2 \
                 AND cluster_key IS NOT NULL ORDER BY ts_us DESC LIMIT 1",
                params![id, since_us],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        if let Some(key) = cluster {
            let others: i64 = self.conn().query_row(
                "SELECT count(DISTINCT actor_id) FROM turns WHERE cluster_key = ?1 AND ts_us >= ?2",
                params![key, since_us],
                |r| r.get(0),
            )?;
            if others > 1 {
                who.push_str(&format!(
                    ", on a network with {}",
                    plural(others - 1, "other", "others")
                ));
            }
        }
        Ok(who)
    }
}

// ---------- Round A-2: review + actor phrases ----------

/// Plain words for every stored flag name: the ten the package
/// computes (`Flags.php`), the two leesided adds at ingest, and the
/// `ua_inconsistent` signal name defensively, in case it ever lands
/// on a turn. Unmapped names fall back to the raw name: a flag is a
/// bare name with no value to show.
pub fn flag_phrase(name: &str) -> String {
    match name {
        "ua_chromium_no_ch" => "says Chrome, sends no client hints",
        "browser_no_sec_fetch" => "browser sends no fetch metadata",
        "browser_no_accept_language" => "browser sends no language",
        "html_get_no_html_accept" => "page fetch won't take HTML",
        "library_ua_on_web" => "script UA on a web page",
        "cookies_on_api" => "cookies on an API call",
        "bearer_with_sec_fetch" => "API key with browser headers",
        "tag_bad_mac" => "tag signature invalid",
        "proxy_header_untrusted" => "proxy headers untrusted",
        "unrouted" => "no route matched",
        "ua_vs_ja4_mismatch" => "user agent and TLS disagree",
        "ua_changes" => "user agent changed mid-window",
        "ua_inconsistent" => "client inconsistent",
        _ => name,
    }
    .to_string()
}

/// Plain words for every label signal name (the schema enum in
/// `llm.rs` plus the cold-start `insufficient_data`). Unmapped names
/// fall back to the raw name.
pub fn signal_phrase(name: &str) -> String {
    match name {
        "attack_payload" => "attack payload",
        "scanner_paths" => "scanner paths",
        "high_404_rate" => "mostly missing pages",
        "machine_cadence" => "machine cadence",
        "ua_inconsistent" => "client inconsistent",
        "credential_stuffing" => "credential stuffing",
        "webhook_forgery" => "webhook forgery",
        "honeytoken_hit" => "hidden trap touched",
        "normal_browsing" => "normal browsing",
        "verified_partner" => "verified partner",
        "human_cadence" => "human cadence",
        "client_consistent" => "client consistent",
        "insufficient_data" => "too few requests",
        _ => name,
    }
    .to_string()
}

/// Plain words for every v2 model feature name, in the manifest's
/// order. `None` for anything unmapped: the caller falls back to
/// "name value".
pub fn feature_phrase(name: &str) -> Option<&'static str> {
    Some(match name {
        "turns_total" => "requests in the window",
        "turns_held" => "requests held",
        "age_s" => "window age",
        "idle_s" => "time idle",
        "turns_last_60s" => "requests in the last minute",
        "turns_last_600s" => "requests in ten minutes",
        "gap_mean_ms" => "mean gap between requests",
        "gap_cv" => "gap variation",
        "ratio_4xx" => "4xx share",
        "ratio_5xx" => "5xx share",
        "ratio_404" => "404 share",
        "ratio_422" => "422 share",
        "count_not_found_exc" => "missing pages",
        "login_failed_total" => "failed logins",
        "login_ok_total" => "successful logins",
        "distinct_routes" => "distinct routes",
        "distinct_routes_ratio" => "route variety",
        "distinct_bound_ids" => "distinct ids touched",
        "unrouted_ratio" => "unrouted share",
        "distinct_req_shapes" => "distinct request shapes",
        "bytes_out_mean" => "mean response size",
        "bytes_out_max" => "largest response",
        "latency_mean_ms" => "mean latency",
        "latency_max_ms" => "slowest request",
        "verb_post_ratio" => "POST share",
        "repeat_route_ratio" => "repeat-route share",
        "ua_changes" => "user-agent changes",
        "peer_turns_600s" => "network requests in ten minutes",
        "peer_ratio_4xx" => "network 4xx share",
        "is_anon" => "no login or key",
        "cluster_actors_net" => "actors sharing the network",
        "shape_cluster_size" => "lookalike clients",
        "tag_dropped" => "tag issued then dropped",
        "credential_moved" => "credential on two networks",
        "surface_web" => "web surface",
        "surface_api" => "API surface",
        "surface_webhook" => "webhook surface",
        "surface_honeypot" => "honeypot surface",
        _ => return None,
    })
}

/// One top-3 contributor as the model cell shows it: the phrase and
/// the gain, or "name value" for anything unmapped.
pub fn feature_display(name: &str, value: f64) -> String {
    match feature_phrase(name) {
        Some(p) => format!("{p} {value:.2}"),
        None => format!("{name} {value:.2}"),
    }
}

/// The actor page headline from a template (Round A-2): the kind
/// phrase, the first-seen day, and the decision state. No LLM call.
pub fn headline(kind: &str, first_seen_us: i64, state: &str) -> String {
    let day = chrono_date(first_seen_us / 1_000_000);
    let tail = match state {
        "stopped" => "currently blocked",
        "waiting" => "waiting for a decision",
        _ => "under watch",
    };
    format!("A {kind} first seen {day}, {tail}")
}

/// A unix timestamp as `3 Nov 2026`, UTC. The dashboard formats its
/// own clocks; the headline needs just the day.
fn chrono_date(ts_s: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = ts_s.div_euclid(86_400);
    // Howard Hinnant's civil-from-days, for the headline only.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{} {} {}", d, MONTHS[(m - 1) as usize], y)
}

// ---------- Round A-2: review + actor JSON ----------

/// One claimed signal from a label call's parsed completion, with
/// its cited envelope indices resolved to turn rowids.
#[derive(Debug, Clone, serde::Deserialize)]
struct CitedSignal {
    name: String,
    #[serde(default)]
    turns: Vec<usize>,
    #[serde(skip)]
    rowids: Vec<i64>,
}

/// The route name when a route matched, else the folded path: the
/// same rule the label envelope shows the model (llm.md 8.1), so the
/// evidence table reads like the proposal's citations.
fn route_display(route: &str, pattern: Option<&str>) -> String {
    if route == "_unrouted" {
        pattern.unwrap_or(route).to_string()
    } else {
        route.to_string()
    }
}

/// One turn's verdict from its `rules_matched` entries: the first
/// enforce-mode acting match blocks, else the first monitor/shadow
/// match observes, else the turn passed with no rule fired. An
/// operator block reads "blocked by your decision", never a rule name.
fn turn_verdict(matched: Option<&str>) -> (Vec<serde_json::Value>, String, String) {
    let entries: Vec<serde_json::Value> = matched
        .and_then(|m| serde_json::from_str(m).ok())
        .unwrap_or_default();
    let mut rules = Vec::new();
    let mut blocked: Option<String> = None;
    let mut watched: Option<String> = None;
    for e in &entries {
        let rule = e.get("rule").and_then(|v| v.as_str()).unwrap_or("?");
        let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let mode = e.get("mode").and_then(|v| v.as_str()).unwrap_or("");
        rules.push(serde_json::json!({"rule": rule, "action": action, "mode": mode}));
        if mode == "enforce" && crate::review::acting(action) && blocked.is_none() {
            blocked = Some(rule.to_string());
        } else if (mode == "monitor" || mode == "shadow") && watched.is_none() {
            watched = Some(rule.to_string());
        }
    }
    if let Some(rule) = blocked {
        let note = if rule == "operator" {
            "blocked by your decision".to_string()
        } else {
            format!("blocked by {rule}")
        };
        (rules, "blocked".to_string(), note)
    } else if let Some(rule) = watched {
        (rules, "observed".to_string(), format!("watched by {rule}"))
    } else {
        (rules, "allowed".to_string(), "no rule fired".to_string())
    }
}

impl<'a> Ctx<'a> {
    /// The A-2 subject state, reading exactly as the A-1 episodes
    /// do: stopped is an active enforce decision (`stopped_by`),
    /// waiting is scored and undecided (the review queue's own
    /// rule), everything else is watched.
    pub fn subject_state(
        &self,
        scope: &str,
        id: &str,
        since_us: i64,
        now_s: i64,
    ) -> Result<String, QueryError> {
        if self.stopped_by(scope, id, since_us, now_s)?.is_some() {
            return Ok("stopped".to_string());
        }
        let scored: bool = self
            .conn()
            .query_row(
                "SELECT 1 FROM scores WHERE scope = ?1 AND scope_id = ?2 LIMIT 1",
                params![scope, id],
                |r| r.get::<_, i64>(0),
            )
            .map(|_| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                e => Err(QueryError::Sqlite(e)),
            })?;
        if !scored {
            return Ok("watched".to_string());
        }
        let label_ts = |source: &str| -> Result<i64, QueryError> {
            self.conn()
                .query_row(
                    "SELECT created_at FROM labels \
                     WHERE scope = ?1 AND scope_id = ?2 AND source = ?3 \
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![scope, id, source],
                    |r| r.get(0),
                )
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(0),
                    e => Err(QueryError::Sqlite(e)),
                })
        };
        let operator_ts = label_ts("operator")?;
        let proposal_ts = label_ts("llm_proposed")?;
        let (rule_hits, observe_hits) = crate::review::subject_hits(self.conn(), scope, id, now_s)
            .map_err(|e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            })?;
        let last_hit = rule_hits
            .iter()
            .chain(observe_hits.iter())
            .map(|h| h.ts)
            .max()
            .unwrap_or(0);
        if operator_ts > 0 && operator_ts >= proposal_ts.max(last_hit) {
            return Ok("watched".to_string());
        }
        Ok("waiting".to_string())
    }

    /// The Review page's two tabs in one round trip: the queue in the
    /// CLI's order (capped at 100 rows, counts over the uncapped
    /// 1000) with its agree/disagree split, and the Decided tab over
    /// the window.
    pub fn review_queue_json(
        &self,
        thresholds: &std::collections::HashMap<String, f64>,
        since_s: i64,
    ) -> Result<serde_json::Value, QueryError> {
        let rows =
            crate::review::review_rows(self.conn(), 1000, thresholds).map_err(|e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            })?;
        let disagree = rows.iter().filter(|r| r.why.disagree()).count();
        let items: Vec<serde_json::Value> = rows
            .iter()
            .take(100)
            .map(|r| {
                serde_json::json!({
                    "scope": r.scope,
                    "id": r.scope_id,
                    "score": r.score,
                    "threshold": r.threshold,
                    "why": r.why.as_str(),
                    "why_phrase": r.why.phrase(),
                    "disagree": r.why.disagree(),
                    "proposal": r.proposal.as_ref().map(|p| serde_json::json!({
                        "label": p.label,
                        "confidence": p.confidence,
                    })),
                })
            })
            .collect();
        let decided = crate::review::decided_list(self.conn(), since_s).map_err(|e| match e {
            crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
            e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
        })?;
        let agreed = decided.iter().filter(|d| d.agreed).count();
        let decided_items: Vec<serde_json::Value> = decided
            .iter()
            .map(|d| {
                serde_json::json!({
                    "scope": d.scope,
                    "id": d.scope_id,
                    "operator": d.operator_label,
                    "proposal": d.proposal,
                    "proposal_confidence": d.proposal_confidence,
                    "agreed": d.agreed,
                    "at": d.operator_ts,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "total": rows.len(),
            "agree": rows.len() - disagree,
            "disagree": disagree,
            "items": items,
            "decided": {
                "total": decided.len(),
                "agreed": agreed,
                "items": decided_items,
            },
        }))
    }

    /// The proposal's signals with their cited turns resolved to turn
    /// rows. The stored proposal keeps signal names only; the
    /// per-signal turns come from the call's parsed completion
    /// (written before faithfulness drops failures), and the envelope
    /// indices resolve by re-running the envelope's own turn query:
    /// the last 30 at or before the window's turn, oldest first.
    /// Failed names come from the call's `faithfulness_failed` list.
    /// All read-only re-derivation; out-of-range indices drop.
    fn cited_signals(
        &self,
        scope: &str,
        id: &str,
    ) -> Result<(Vec<CitedSignal>, Vec<String>), QueryError> {
        let prop: Option<(i64, Option<String>, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT window_end_ts, note, signals FROM labels \
                 WHERE scope = ?1 AND scope_id = ?2 AND source = 'llm_proposed' \
                 ORDER BY window_end_ts DESC, created_at DESC, id DESC LIMIT 1",
                params![scope, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let Some((window_end_ts, note, surviving)) = prop else {
            return Ok((Vec::new(), Vec::new()));
        };
        let surviving: Vec<String> = surviving
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let call_id = call_id_of(&note);
        let (claimed, failed): (Vec<CitedSignal>, Vec<String>) = match call_id {
            Some(call) => {
                let parsed: Option<String> = self
                    .conn()
                    .query_row(
                        "SELECT parsed FROM llm_calls WHERE id = ?1",
                        params![call],
                        |r| r.get(0),
                    )
                    .ok()
                    .flatten();
                let failed: Vec<String> = self
                    .conn()
                    .query_row(
                        "SELECT faithfulness_failed FROM llm_calls WHERE id = ?1",
                        params![call],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .ok()
                    .flatten()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                let claimed: Vec<CitedSignal> = parsed
                    .and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok())
                    .and_then(|v| serde_json::from_value(v.get("signals")?.clone()).ok())
                    .unwrap_or_default();
                (claimed, failed)
            }
            None => (Vec::new(), Vec::new()),
        };
        // No parsed completion (old rows, dry runs): the surviving
        // names stand alone, all passed, with no cited turns.
        if claimed.is_empty() && !surviving.is_empty() {
            return Ok((
                surviving
                    .into_iter()
                    .map(|name| CitedSignal {
                        name,
                        turns: Vec::new(),
                        rowids: Vec::new(),
                    })
                    .collect(),
                failed,
            ));
        }
        let col = if scope == "actor" {
            "actor_id"
        } else {
            "cluster_key"
        };
        let anchor: Option<i64> = self
            .conn()
            .query_row(
                "SELECT t.rowid FROM feature_vectors fv \
                 JOIN turns t ON fv.turn_id = coalesce(t.turn_id, t.peer_key || ':' || t.ts_us) \
                 WHERE fv.scope = ?1 AND fv.key = ?2 AND fv.version = ?3 AND fv.ts_us = ?4 \
                 ORDER BY t.rowid DESC LIMIT 1",
                params![scope, id, crate::rules::features::VERSION, window_end_ts],
                |r| r.get(0),
            )
            .ok();
        let mut order: Vec<i64> = match anchor {
            Some(a) => self
                .conn()
                .prepare(&format!(
                    "SELECT rowid FROM turns WHERE {col} = ?1 AND rowid <= ?2 \
                     ORDER BY rowid DESC LIMIT {}",
                    crate::llm::ENVELOPE_TURNS
                ))?
                .query_map(params![id, a], |r| r.get(0))?
                .filter_map(|r| r.ok())
                .collect(),
            None => Vec::new(),
        };
        order.reverse();
        let mut out = claimed;
        for s in &mut out {
            s.rowids = s
                .turns
                .iter()
                .filter_map(|i| order.get(*i).copied())
                .collect();
        }
        Ok((out, failed))
    }

    /// One turn row for the evidence and actor tables, with its flags
    /// phrased, its verdict derived, and its cited signals attached.
    #[allow(clippy::too_many_arguments)]
    fn turn_json(
        &self,
        rowid: i64,
        turn_id: Option<String>,
        ts_us: i64,
        verb: &str,
        route: &str,
        pattern: Option<&str>,
        status: i64,
        flags: Option<&str>,
        matched: Option<&str>,
        signals: &[String],
    ) -> serde_json::Value {
        let names: Vec<String> = flags
            .and_then(|f| serde_json::from_str(f).ok())
            .unwrap_or_default();
        let flag_list: Vec<serde_json::Value> = names
            .iter()
            .map(|n| serde_json::json!({"name": n, "phrase": flag_phrase(n)}))
            .collect();
        let (rules, verdict, note) = turn_verdict(matched);
        serde_json::json!({
            "row": rowid,
            "trace": turn_id,
            "at": ts_us,
            "method": verb,
            "route": route_display(route, pattern),
            "status": status,
            "flags": flag_list,
            "verdict": verdict,
            "note": note,
            "rules": rules,
            "cited": !signals.is_empty(),
            "signals": signals,
        })
    }

    /// The newest turns of a subject, newest first, with flag, status
    /// (exact code or `Nxx` class) and route filters. `cited` maps
    /// turn rowids to the signal names that cite them. Returns the
    /// rows and the filtered total.
    #[allow(clippy::too_many_arguments)]
    fn subject_turns(
        &self,
        scope: &str,
        id: &str,
        limit: i64,
        flag: Option<&str>,
        status: Option<&str>,
        route: Option<&str>,
        cited: &std::collections::HashMap<i64, Vec<String>>,
    ) -> Result<(Vec<serde_json::Value>, i64), QueryError> {
        let col = if scope == "actor" {
            "actor_id"
        } else {
            "cluster_key"
        };
        let mut pred = format!("{col} = ?1");
        let mut args: Vec<String> = vec![id.to_string()];
        if let Some(f) = flag {
            pred.push_str(" AND flags LIKE '%' || ? || '%'");
            args.push(format!("\"{f}\""));
        }
        if let Some(s) = status {
            if s.len() == 3 && s.ends_with("xx") && s.as_bytes()[0].is_ascii_digit() {
                let base = (s.as_bytes()[0] - b'0') as i64 * 100;
                pred.push_str(" AND status >= ? AND status < ?");
                args.push(base.to_string());
                args.push((base + 100).to_string());
            } else if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
                pred.push_str(" AND status = ?");
                args.push(s.to_string());
            } else {
                return Ok((Vec::new(), 0));
            }
        }
        if let Some(r) = route {
            pred.push_str(" AND (route = ? OR path_pattern = ?)");
            args.push(r.to_string());
            args.push(r.to_string());
        }
        let total: i64 = self.conn().query_row(
            &format!("SELECT count(*) FROM turns WHERE {pred}"),
            rusqlite::params_from_iter(args.iter()),
            |r| r.get(0),
        )?;
        let clamped = limit.clamp(1, 100);
        let mut stmt = self.conn().prepare(&format!(
            "SELECT rowid, turn_id, ts_us, verb, route, path_pattern, status, flags, rules_matched \
             FROM turns WHERE {pred} ORDER BY rowid DESC LIMIT {clamped}"
        ))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (rowid, turn_id, ts_us, verb, route, pattern, status, flags, matched) = r?;
            let empty = Vec::new();
            let signals = cited.get(&rowid).unwrap_or(&empty);
            out.push(self.turn_json(
                rowid,
                turn_id,
                ts_us,
                &verb,
                &route,
                pattern.as_deref(),
                status,
                flags.as_deref(),
                matched.as_deref(),
                signals,
            ));
        }
        Ok((out, total))
    }

    /// One review item: the model verdict with its top contributors,
    /// the proposal with its cited signals, the evidence table, the
    /// decision state, and the queue neighbours. `since_us` bounds
    /// the stopped check's turn-mediated decisions; pass 0 for all
    /// time. Unknown scope 404s like an unknown subject.
    pub fn review_item_json(
        &self,
        scope: &str,
        id: &str,
        thresholds: &std::collections::HashMap<String, f64>,
        now_s: i64,
    ) -> Result<serde_json::Value, QueryError> {
        if scope != "actor" && scope != "cluster" {
            return Err(QueryError::NoCluster(id.to_string()));
        }
        let canonical = if scope == "actor" {
            self.actor_ids(id)?[0].clone()
        } else {
            let exists: bool = self
                .conn()
                .query_row(
                    "SELECT 1 FROM turns WHERE cluster_key = ?1 LIMIT 1",
                    params![id],
                    |r| r.get::<_, i64>(0),
                )
                .map(|_| true)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(false),
                    e => Err(QueryError::Sqlite(e)),
                })?;
            if !exists {
                return Err(QueryError::NoCluster(id.to_string()));
            }
            id.to_string()
        };
        let score: Option<(f64, Option<String>, String, String)> = self
            .conn()
            .query_row(
                "SELECT score, surface, model_version, top3 FROM scores \
                 WHERE scope = ?1 AND scope_id = ?2 ORDER BY ts_us DESC LIMIT 1",
                params![scope, canonical],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let Some((value, surface, model_version, top3)) = score else {
            let err = if scope == "actor" {
                QueryError::NoActor(format!("{canonical} has no score"))
            } else {
                QueryError::NoCluster(format!("{canonical} has no score"))
            };
            return Err(err);
        };
        let threshold = surface
            .as_deref()
            .and_then(|s| thresholds.get(s).copied())
            .unwrap_or(0.5);
        let top: Vec<serde_json::Value> = top3_of(&top3)
            .into_iter()
            .map(|(name, gain)| {
                serde_json::json!({
                    "name": name,
                    "display": feature_display(&name, gain),
                    "value": gain,
                })
            })
            .collect();
        let rows =
            crate::review::review_rows(self.conn(), 1000, thresholds).map_err(|e| match e {
                crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
                e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
            })?;
        let pos = rows
            .iter()
            .position(|r| r.scope == scope && r.scope_id == canonical);
        let (why, why_phrase, disagree, rule_hits) = match pos {
            Some(i) => {
                let r = &rows[i];
                (
                    Some(r.why.as_str()),
                    Some(r.why.phrase()),
                    r.why.disagree(),
                    r.rule_hits.clone(),
                )
            }
            None => (None, None, false, Vec::new()),
        };
        let neighbour = |i: usize| {
            rows.get(i)
                .map(|r| serde_json::json!({"scope": r.scope, "id": r.scope_id}))
        };
        let (prev, next) = match pos {
            Some(0) => (None, neighbour(1)),
            Some(i) => (neighbour(i - 1), neighbour(i + 1)),
            None => (None, None),
        };
        let window: Option<(i64, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT ts_us, surface FROM feature_vectors \
                 WHERE scope = ?1 AND key = ?2 ORDER BY ts_us DESC LIMIT 1",
                params![scope, canonical],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let proposal: Option<(String, f64, String, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT label, confidence, note FROM labels \
                 WHERE scope = ?1 AND scope_id = ?2 AND source = 'llm_proposed' \
                 ORDER BY window_end_ts DESC, created_at DESC, id DESC LIMIT 1",
                params![scope, canonical],
                |r| {
                    let note: Option<String> = r.get(2)?;
                    Ok((r.get(0)?, r.get(1)?, note))
                },
            )
            .map(|(label, confidence, note)| {
                let reason = note
                    .as_deref()
                    .map(crate::review::Proposal::display)
                    .unwrap_or_default();
                let model = call_id_of(&note).and_then(|call| {
                    self.conn()
                        .query_row(
                            "SELECT model FROM llm_calls WHERE id = ?1",
                            params![call],
                            |r| r.get(0),
                        )
                        .ok()
                });
                (label, confidence, reason, model)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let (signals, failed) = self.cited_signals(scope, &canonical)?;
        let mut mini_stmt = self.conn().prepare(
            "SELECT rowid, turn_id, ts_us, verb, route, path_pattern, status \
             FROM turns WHERE rowid = ?1",
        )?;
        let mut cited_union: Vec<i64> = signals.iter().flat_map(|s| s.rowids.clone()).collect();
        cited_union.sort_unstable();
        cited_union.dedup();
        let mut cited_by: std::collections::HashMap<i64, Vec<String>> =
            std::collections::HashMap::new();
        for s in &signals {
            // Failed claims keep their turn links on the signal row,
            // but only surviving signals mark the table rows cited.
            if failed.contains(&s.name) {
                continue;
            }
            for rowid in &s.rowids {
                cited_by.entry(*rowid).or_default().push(s.name.clone());
            }
        }
        let mini = |rowid: i64, stmt: &mut rusqlite::Statement| -> Option<serde_json::Value> {
            stmt.query_row(params![rowid], |r| {
                let route: String = r.get(4)?;
                let pattern: Option<String> = r.get(5)?;
                Ok(serde_json::json!({
                    "row": r.get::<_, i64>(0)?,
                    "trace": r.get::<_, Option<String>>(1)?,
                    "at": r.get::<_, i64>(2)?,
                    "method": r.get::<_, String>(3)?,
                    "route": route_display(&route, pattern.as_deref()),
                    "status": r.get::<_, i64>(6)?,
                }))
            })
            .ok()
        };
        let signal_list: Vec<serde_json::Value> = signals
            .iter()
            .map(|s| {
                let passed = !failed.contains(&s.name);
                let turns: Vec<serde_json::Value> = s
                    .rowids
                    .iter()
                    .filter_map(|rowid| mini(*rowid, &mut mini_stmt))
                    .collect();
                serde_json::json!({
                    "name": s.name,
                    "phrase": signal_phrase(&s.name),
                    "side": crate::faithfulness::side(&s.name),
                    "passed": passed,
                    "failed_reason": if passed { None } else { Some("did not survive the evidence check") },
                    "turns": turns,
                })
            })
            .collect();
        let cited_turns: Vec<serde_json::Value> = cited_union
            .iter()
            .filter_map(|rowid| mini(*rowid, &mut mini_stmt))
            .collect();
        drop(mini_stmt);
        let (turns, turn_total) =
            self.subject_turns(scope, &canonical, 20, None, None, None, &cited_by)?;
        let cluster_size: i64 = if scope == "actor" {
            let key: Option<String> = self
                .conn()
                .query_row(
                    "SELECT cluster_key FROM turns \
                     WHERE actor_id = ?1 AND cluster_key IS NOT NULL \
                     ORDER BY rowid DESC LIMIT 1",
                    params![canonical],
                    |r| r.get(0),
                )
                .ok();
            match key {
                Some(k) => self.conn().query_row(
                    "SELECT count(DISTINCT actor_id) FROM turns WHERE cluster_key = ?1",
                    params![k],
                    |r| r.get(0),
                )?,
                None => 0,
            }
        } else {
            self.conn().query_row(
                "SELECT count(DISTINCT actor_id) FROM turns WHERE cluster_key = ?1",
                params![canonical],
                |r| r.get(0),
            )?
        };
        let operator: Option<(String, i64)> = self
            .conn()
            .query_row(
                "SELECT label, created_at FROM labels \
                 WHERE scope = ?1 AND scope_id = ?2 AND source = 'operator' \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![scope, canonical],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })?;
        let state = self.subject_state(scope, &canonical, 0, now_s)?;
        let agreed = match (&proposal, &operator) {
            (Some((label, _, _, _)), Some((op, _))) => Some(label == op),
            _ => None,
        };
        let kind = if scope == "actor" {
            self.actor_row(&canonical, now_s)
                .map(|r| r.kind)
                .unwrap_or_else(|_| "actor".to_string())
        } else {
            "cluster".to_string()
        };
        Ok(serde_json::json!({
            "scope": scope,
            "id": canonical,
            "kind": kind,
            "state": state,
            "queue": {
                "total": rows.len(),
                "position": pos.map(|i| i + 1),
                "prev": prev,
                "next": next,
            },
            "why": why,
            "why_phrase": why_phrase,
            "disagree": disagree,
            "model": {
                "score": value,
                "threshold": threshold,
                "verdict": if value >= threshold { "hostile" } else { "benign" },
                "by": format!("Windside {model_version}"),
                "top": top,
                "rules_fired": {
                    "count": rule_hits.len(),
                    "names": rule_hits,
                },
            },
            "proposal": proposal.map(|(label, confidence, reason, model)| serde_json::json!({
                "label": label,
                "confidence": confidence,
                "reason": reason,
                "model": model,
            })),
            "signals": signal_list,
            "evidence": {
                "turns": turns,
                "total": turn_total,
                "cited": cited_turns,
                "cluster_size": cluster_size,
            },
            "decision": {
                "operator": operator.as_ref().map(|(label, _)| label),
                "decided_at": operator.as_ref().map(|(_, at)| at),
                "agreed": agreed,
            },
            "window": {
                "window_end_ts": window.as_ref().map(|(ts, _)| *ts),
                "surface": window.as_ref().and_then(|(_, s)| s.clone()),
            },
        }))
    }

    /// One actor page: the headline, client and activity rows, the
    /// score block with its explanation, labels, the proposal with
    /// its cited signals, decisions, same-cluster actors with their
    /// states, and the newest turns. `classes` classifies the newest
    /// JA4 for the client row.
    pub fn actor_json(
        &self,
        id: &str,
        thresholds: &std::collections::HashMap<String, f64>,
        classes: &crate::tap::classes::Ja4Classes,
        now_s: i64,
    ) -> Result<serde_json::Value, QueryError> {
        let d = self.actor_detail(id, 0, now_s, thresholds)?;
        let canonical = d.head.id.clone();
        let state = self.subject_state("actor", &canonical, 0, now_s)?;
        let threshold = d
            .row
            .score_surface
            .as_deref()
            .and_then(|s| thresholds.get(s).copied())
            .unwrap_or(0.5);
        let score = d.scores.latest.as_ref().map(|s| {
            serde_json::json!({
                "value": s.score,
                "threshold": threshold,
                "verdict": if s.score >= threshold { "hostile" } else { "benign" },
                "by": format!("Windside {}", s.model_version),
                "at": s.ts_us,
                "top": s.top3.iter().map(|(name, gain)| serde_json::json!({
                    "name": name,
                    "display": feature_display(name, *gain),
                    "value": gain,
                })).collect::<Vec<_>>(),
            })
        });
        let history: Vec<serde_json::Value> = d
            .scores
            .history
            .iter()
            .map(|(ts, p)| serde_json::json!({"at": ts, "score": p}))
            .collect();
        let bindings: Vec<serde_json::Value> = d
            .bindings
            .iter()
            .map(|b| {
                serde_json::json!({
                    "kind": b.kind,
                    "first_seen": b.first_seen,
                    "last_seen": b.last_seen,
                    "returned": b.returned,
                    "provisional": b.provisional,
                })
            })
            .collect();
        let ja4_class = d.client.ja4.as_deref().map(|j| match classes.classify(j) {
            crate::tap::classes::Class::Browser => "browser",
            crate::tap::classes::Class::Library => "library",
            crate::tap::classes::Class::Unknown => "unknown",
        });
        let ja4_hostile = ja4_class == Some("library")
            && crate::tap::classes::is_browser_ua(d.client.ua_class.as_deref());
        let flags: Vec<serde_json::Value> = d
            .client
            .flag_rates
            .iter()
            .map(|(name, rate)| {
                serde_json::json!({"name": name, "phrase": flag_phrase(name), "rate": rate})
            })
            .collect();
        let labels: Vec<serde_json::Value> = d
            .labels
            .iter()
            .map(|l| {
                serde_json::json!({
                    "source": l.source,
                    "label": l.label,
                    "confidence": l.confidence,
                    "at": l.created_at,
                })
            })
            .collect();
        let proposal = d.proposal.as_ref().map(|p| {
            let model: Option<String> = p.call_id.and_then(|call| {
                self.conn()
                    .query_row(
                        "SELECT model FROM llm_calls WHERE id = ?1",
                        params![call],
                        |r| r.get(0),
                    )
                    .ok()
            });
            serde_json::json!({
                "label": p.label.label,
                "confidence": p.label.confidence,
                "reason": p.reason,
                "model": model,
            })
        });
        let (signals, failed) = self.cited_signals("actor", &canonical)?;
        let signal_list: Vec<serde_json::Value> = signals
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "phrase": signal_phrase(&s.name),
                    "side": crate::faithfulness::side(&s.name),
                    "passed": !failed.contains(&s.name),
                    "cited": s.rowids.len(),
                })
            })
            .collect();
        let mut cited_by: std::collections::HashMap<i64, Vec<String>> =
            std::collections::HashMap::new();
        for s in &signals {
            // Failed claims keep their turn links on the signal row,
            // but only surviving signals mark the table rows cited.
            if failed.contains(&s.name) {
                continue;
            }
            for rowid in &s.rowids {
                cited_by.entry(*rowid).or_default().push(s.name.clone());
            }
        }
        let decisions: Vec<serde_json::Value> = d
            .decisions
            .iter()
            .map(|x| {
                serde_json::json!({
                    "action": x.action,
                    "mode": x.mode,
                    "rule": x.rule,
                    "created": x.created_at,
                    "expires": x.expires_at,
                    "active": x.expires_at > now_s,
                })
            })
            .collect();
        let blocked = d
            .decisions
            .iter()
            .any(|x| x.action == "block" && x.mode == "enforce" && x.expires_at > now_s);
        let mut similar = Vec::with_capacity(d.similar.len());
        for s in &d.similar {
            let st = self.subject_state("actor", &s.id, 0, now_s)?;
            similar.push(serde_json::json!({
                "id": s.id,
                "kind": s.kind,
                "score": s.score,
                "turns": s.turns,
                "last": s.last_us,
                "state": st,
            }));
        }
        let (turns, turn_total) =
            self.subject_turns("actor", &canonical, 20, None, None, None, &cited_by)?;
        Ok(serde_json::json!({
            "id": canonical,
            "kind": d.row.kind,
            "state": state,
            "headline": headline(&d.row.kind, d.head.opened_us, &state),
            "opened": d.head.opened_us,
            "last": d.head.last_us,
            "turns_held": d.head.turns,
            "merged_from": d.merged_from,
            "bindings": bindings,
            "client": {
                "ua_class": d.client.ua_class,
                "ja4": d.client.ja4,
                "ja4t": d.client.ja4t,
                "ja4_class": ja4_class,
                "ja4_hostile": ja4_hostile,
                "shape_prefix": d.client.shape_prefix,
                "shape_count": d.client.shape_count,
                "turns_sampled": d.client.turns_sampled,
                "flags": flags,
            },
            "activity": {
                "turns": d.activity.turns,
                "active_s": d.activity.active_s,
                "assets": d.activity.assets,
                "ok_2xx": d.activity.ok_2xx,
                "redirects": d.activity.redirects,
                "not_found": d.activity.not_found,
                "denied": d.activity.denied,
                "limited": d.activity.limited,
                "errors_5xx": d.activity.errors_5xx,
                "iri_median_ms": d.activity.iri_median_ms,
                "iri_cv": d.activity.iri_cv,
                "distinct_routes": d.activity.distinct_routes,
            },
            "score": score,
            "score_history": history,
            "score_note": d.scores.explanation,
            "scored_rows": d.scores.scored_rows,
            "explanation": d.explanation.as_ref().map(|e| serde_json::json!({
                "text": e.text,
                "turn_id": e.turn_id,
                "at": e.ts_us,
                "score": e.score,
            })),
            "labels": labels,
            "proposal": proposal,
            "signals": signal_list,
            "decisions": decisions,
            "blocked": blocked,
            "cluster": d.row.cluster,
            "cluster_actors": d.cluster_actors,
            "similar": similar,
            "turns": turns,
            "turn_total": turn_total,
            "window": {
                "window_end_ts": d.window_end_ts,
                "surface": d.window_surface,
            },
        }))
    }

    /// The subject's latest feature window, for labels that carry
    /// the current window without a freshness check (block/unblock).
    pub fn latest_window(
        &self,
        scope: &str,
        id: &str,
    ) -> Result<Option<(i64, Option<String>)>, QueryError> {
        self.conn()
            .query_row(
                "SELECT ts_us, surface FROM feature_vectors \
                 WHERE scope = ?1 AND key = ?2 ORDER BY ts_us DESC LIMIT 1",
                params![scope, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(QueryError::Sqlite(e)),
            })
    }

    /// The actor turn table with its filters, newest first: flag (a
    /// stored flag name), status (an exact code or an `Nxx` class),
    /// route (a route name or folded path), limit (1 to 100,
    /// default 20).
    pub fn actor_turns_json(
        &self,
        id: &str,
        flag: Option<&str>,
        status: Option<&str>,
        route: Option<&str>,
        limit: i64,
    ) -> Result<serde_json::Value, QueryError> {
        let canonical = self.actor_ids(id)?[0].clone();
        let (signals, failed) = self.cited_signals("actor", &canonical)?;
        let mut cited_by: std::collections::HashMap<i64, Vec<String>> =
            std::collections::HashMap::new();
        for s in &signals {
            // Failed claims keep their turn links on the signal row,
            // but only surviving signals mark the table rows cited.
            if failed.contains(&s.name) {
                continue;
            }
            for rowid in &s.rowids {
                cited_by.entry(*rowid).or_default().push(s.name.clone());
            }
        }
        let (turns, total) =
            self.subject_turns("actor", &canonical, limit, flag, status, route, &cited_by)?;
        Ok(serde_json::json!({
            "id": canonical,
            "total": total,
            "turns": turns,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_db(name: &str) -> Connection {
        let path = std::env::temp_dir().join(format!("leesided-q-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = Connection::open(&path).unwrap();
        crate::store::migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3) VALUES \
             ('actor', 'a1', 't1', 'web', 1000, 0.9, 'm', '[]'), \
             ('actor', 'a2', 't2', 'web', 1000, 0.8, 'm', '[]'); \
             INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, note, created_at) VALUES \
             ('actor', 'a1', 'web', 9, 'malicious', 'llm_proposed', 0.9, 'r [llm_call:1]', 100), \
             ('actor', 'a1', 'web', 9, 'malicious', 'operator', 1.0, 'review CLI', 160), \
             ('actor', 'a2', 'web', 9, 'benign', 'llm_proposed', 0.7, 'r [llm_call:2]', 100), \
             ('actor', 'a2', 'web', 9, 'malicious', 'operator', 1.0, 'review CLI', 220); \
             INSERT INTO llm_calls (point, model, prompt_hash, json_mode, input_summary, request, response, parsed, \
             faithfulness_failed, prompt_tokens, completion_tokens, created_at) VALUES \
             ('label', 'm', 'h', 'prompt', '{}', '{}', '{\"ok\":true}', '{\"label\":\"x\"}', NULL, 100, 50, 100), \
             ('label', 'm', 'h', 'prompt', '{}', '{}', '{\"ok\":true}', '{\"label\":\"x\"}', '[\"client_consistent\"]', 100, 50, 100), \
             ('classify', 'm', 'h', 'prompt', '{}', '{}', '{\"ok\":true}', NULL, NULL, 10, 5, 100); \
             INSERT INTO llm_evals (created_at, point, prompt_hash, model, json_mode, rows, agreement) VALUES \
             (100, 'classify', 'h', 'm', 'prompt', 10, 0.8);",
        )
        .unwrap();
        conn
    }

    fn episode_db(name: &str) -> (Connection, i64) {
        let now: i64 = 1_800_000_000;
        let us = |s: i64| s * 1_000_000;
        let path = std::env::temp_dir().join(format!("leesided-q-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = Connection::open(&path).unwrap();
        crate::store::migrate(&mut conn).unwrap();
        // a_stop: three window turns on one session, stopped by a
        // session-scope rate limit. a_stop2: stopped by an actor-scope
        // block. a_wait: scored high with a proposal, queued. c_watch:
        // cookie-less cluster turns with a shadow observation. a_plain:
        // turns and nothing else (no episode). a_quiet: an old score,
        // no window turns (no episode).
        conn.execute_batch(&format!(
            "INSERT INTO turns (session_key, ts_us, ts, peer_key, principal, verb, route, status, \
             latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, ua_hash, \
             dropped_since_last, actor_id, surface, rules_matched) VALUES \
             ('s1', {t1}, {now}, 'p1', 'anon', 'POST', 'portal.login', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_stop', 'web', NULL), \
             ('s1', {t2}, {now}, 'p1', 'anon', 'POST', 'portal.login', 429, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_stop', 'web', NULL), \
             ('s1', {t3}, {now}, 'p1', 'anon', 'POST', 'portal.login', 429, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_stop', 'web', NULL), \
             ('s2', {t3}, {now}, 'p2', 'anon', 'GET', 'venues.show', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_stop2', 'web', NULL), \
             ('s3', {t2}, {now}, 'p3', 'anon', 'POST', 'portal.login', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_wait', 'web', NULL), \
             ('s3', {t3}, {now}, 'p3', 'anon', 'POST', 'portal.login', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_wait', 'web', NULL), \
             ('s4', {t2}, {now}, 'p4', 'anon', 'GET', 'x', 500, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, NULL, 'web', \
             '[{{\"rule\":\"server-error-watch\",\"action\":\"watch\",\"mode\":\"shadow\"}}]'), \
             ('s5', {t3}, {now}, 'p5', 'anon', 'GET', 'x', 500, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, NULL, 'web', NULL), \
             ('s6', {t3}, {now}, 'p6', 'anon', 'GET', 'home', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a_plain', 'web', NULL); \
             UPDATE turns SET cluster_key = 'c_watch' WHERE session_key IN ('s4', 's5'); \
             UPDATE turns SET net_hash = 'n1' WHERE session_key IN ('s4', 's5'); \
             INSERT INTO decisions (scope, key, action, mode, rule, rule_version, created_at, expires_at) VALUES \
             ('session', 's1', 'rate_limit', 'enforce', 'portal-otp-burst', 1, {c1}, {e1}), \
             ('actor', 'a_stop2', 'block', 'enforce', 'venue-enumeration', 1, {c1}, {e1}), \
             ('session', 's9', 'block', 'shadow', 'http-404-scan', 1, {c1}, {e1}); \
             INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3) VALUES \
             ('actor', 'a_wait', 't9', 'web', {t3}, 0.9, 'm', '[]'), \
             ('actor', 'a_quiet', 't0', 'web', {old}, 0.9, 'm', '[]'); \
             INSERT INTO feature_vectors (scope, key, turn_id, ts_us, version, vector, surface, clock_anomalies) VALUES \
             ('actor', 'a_wait', 't9', {t3}, 2, '[0.0]', 'web', 0); \
             INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, note, signals, cited_turns, created_at) VALUES \
             ('actor', 'a_wait', 'web', {t3}, 'malicious', 'llm_proposed', 0.91, \
             'A bot kept guessing. [llm_call:1]', '[\"credential_stuffing\"]', '[1,2]', {c1}); \
             INSERT INTO llm_calls (id, point, model, prompt_hash, json_mode, input_summary, request, created_at) VALUES \
             (1, 'label', 'Muse Spark', 'h', 'prompt', '{{}}', '{{}}', {c1});",
            t1 = us(now - 7200),
            t2 = us(now - 3600),
            t3 = us(now - 60),
            old = us(now - 90000),
            c1 = now - 50,
            e1 = now + 1000,
        ))
        .unwrap();
        (conn, now)
    }

    #[test]
    fn episodes_group_states_titles_and_stories() {
        let (conn, now) = episode_db("episodes");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let mut thresholds = std::collections::HashMap::new();
        thresholds.insert("web".to_string(), 0.5);
        let eps = ctx.episodes(86_400, now, &thresholds, true).unwrap();
        assert_eq!(eps.len(), 4);
        let by_id = |id: &str| eps.iter().find(|e| e.id == id).unwrap().clone();
        // Newest first: every span ends at t3 except a_stop2 (t3 too);
        // assert the order is non-increasing and stable.
        let ends: Vec<i64> = eps.iter().map(|e| e.span_end).collect();
        let mut sorted = ends.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(ends, sorted);

        let stopped = by_id("ep_actor_a_stop");
        assert_eq!(stopped.state, "stopped");
        assert_eq!(stopped.title, "Someone guessed login codes");
        assert_eq!(stopped.why, None);
        assert_eq!(stopped.story.did, "Rate limited by portal-otp-burst");
        assert_eq!(
            stopped.story.next,
            "Nothing. The rate limit is still holding."
        );
        assert_eq!(stopped.story.what, "3 requests, mostly portal.login");
        assert!(stopped.summary.ends_with('.'));
        assert!(
            !stopped.summary.contains(".."),
            "template takes one period: {}",
            stopped.summary
        );
        assert!(stopped.summary.contains("3 requests"));
        assert_eq!(stopped.explained_by, None);
        assert_eq!(stopped.chips.len(), 3);
        assert_eq!(stopped.chips[2].label, "Rule portal-otp-burst");
        assert_eq!(stopped.chips[2].href, "/ui/rules/portal-otp-burst");

        let blocked = by_id("ep_actor_a_stop2");
        assert_eq!(blocked.state, "stopped");
        assert_eq!(blocked.title, "Someone walked through venue ids");
        assert_eq!(blocked.story.did, "Blocked by venue-enumeration");

        let waiting = by_id("ep_actor_a_wait");
        assert_eq!(waiting.state, "waiting");
        assert_eq!(waiting.why.as_deref(), Some("above_threshold_no_rule"));
        assert_eq!(waiting.title, "Someone stuffed stolen passwords");
        assert_eq!(waiting.summary, "A bot kept guessing.");
        assert_eq!(waiting.explained_by.as_deref(), Some("Muse Spark"));
        assert_eq!(
            waiting.story.next,
            "Windside score 0.90, proposed malicious at 0.91, cited 2 turns"
        );
        assert_eq!(waiting.story.did, "Nothing yet. It only logged them.");
        assert_eq!(waiting.score, Some(0.9));
        assert_eq!(waiting.threshold, Some(0.5));
        assert!(waiting.window_end_ts.is_some());
        assert_eq!(waiting.chips[0].href, "/ui/actors/a_wait");
        assert_eq!(waiting.chips[1].count, Some(2));

        let watched = by_id("ep_cluster_c_watch");
        assert_eq!(watched.state, "watched");
        assert_eq!(watched.title, "Someone triggered server errors");
        assert_eq!(watched.story.did, "Watched. Nothing was stopped.");
        assert_eq!(
            watched.story.next,
            "Nothing yet. Windside is still watching."
        );
        assert_eq!(
            watched.story.who,
            "2 unidentified clients on 1 network, none signed in"
        );
        // No actor identity held: no actors chip, just requests and rule.
        assert_eq!(watched.chips.len(), 2);
        assert_eq!(watched.chips[0].label, "requests");

        // The shadow-mode decision on s9 stops nothing; the plain and
        // quiet actors have no episodes.
        assert!(!eps.iter().any(|e| e.subject == "a_plain"));
        assert!(!eps.iter().any(|e| e.subject == "a_quiet"));
    }

    #[test]
    fn episode_titles_cover_rules_signals_and_fallback() {
        let t = episode_titles();
        for rule in [
            "portal-otp-burst",
            "venue-enumeration",
            "visit-straight-to-login",
            "auth-burst-peer",
            "http-404-scan",
            "server-error-watch",
            "credential-spray",
        ] {
            assert!(t.rules.contains_key(rule), "{rule} has a title");
        }
        for signal in crate::faithfulness::SIGNALS {
            assert!(t.signals.contains_key(signal), "{signal} has a title");
        }
        assert!(t.fallback.contains("{surface}"));
        assert_eq!(parse_window("24h"), Some(86_400));
        assert_eq!(parse_window("7d"), Some(604_800));
        assert_eq!(parse_window("30d"), Some(2_592_000));
        assert_eq!(parse_window("1h"), None);
        assert_eq!(window_label(86_400), "24 hours");
    }

    #[test]
    fn story_what_hides_route_sentinels() {
        assert_eq!(story_what(14, "_unrouted", "web"), "14 requests on web");
        assert_eq!(story_what(1, "", "api"), "1 request on api");
        assert_eq!(
            story_what(3, "portal.login", "web"),
            "3 requests, mostly portal.login"
        );
    }

    #[test]
    fn summary_counts_states_tiles_and_would_have_stopped() {
        let (conn, now) = episode_db("summary");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let mut thresholds = std::collections::HashMap::new();
        thresholds.insert("web".to_string(), 0.5);
        let s = ctx
            .dashboard_summary(86_400, now, &thresholds, "shadow")
            .unwrap();
        assert_eq!(s.window, "24 hours");
        assert_eq!(s.mode, "shadow");
        assert_eq!(s.attacks, 4);
        assert_eq!(s.stopped, 2);
        assert_eq!(s.waiting, 1);
        assert_eq!(s.watched, 1);
        // a_wait is above threshold with no decision; a_quiet is
        // above threshold but has no window turns, so it stays out.
        assert_eq!(s.would_have_stopped, 1);
        assert_eq!(s.requests, 9);
        assert_eq!(s.fingerprinted, Some(0));
        assert_eq!(s.tiles.actors.total, 4);
        assert_eq!(s.tiles.actors.normal, 3);
        assert_eq!(s.tiles.rules.active, 0);
        assert_eq!(s.tiles.rules.ready, 0);
        assert_eq!(s.tiles.reviews.total, 0);
        assert_eq!(s.tiles.reviews.agreed, 0);
        assert_eq!(s.pending, 2);
        // Outside shadow there is no would-have.
        let s = ctx
            .dashboard_summary(86_400, now, &thresholds, "active")
            .unwrap();
        assert_eq!(s.would_have_stopped, 0);
        assert_eq!(parse_bucket("1h"), Some(3_600));
        assert_eq!(parse_bucket("7d"), Some(604_800));
        assert_eq!(parse_bucket("30m"), None);
    }

    #[test]
    fn traffic_buckets_total_and_hostile() {
        let (conn, now) = episode_db("traffic");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let mut thresholds = std::collections::HashMap::new();
        thresholds.insert("web".to_string(), 0.5);
        let t = ctx.traffic(86_400, 3_600, now, &thresholds, true).unwrap();
        assert_eq!(t.buckets.len(), 24);
        assert_eq!(t.window_total, 9);
        assert_eq!(
            t.window_total,
            t.buckets.iter().map(|b| b.total).sum::<i64>()
        );
        assert_eq!(
            6,
            t.buckets.iter().map(|b| b.hostile).sum::<i64>(),
            "stopped and waiting turns only"
        );
        let starts: Vec<i64> = t.buckets.iter().map(|b| b.start).collect();
        let mut ordered = starts.clone();
        ordered.sort();
        assert_eq!(starts, ordered);
        // t2 sits on the last bucket's lower edge (inclusive).
        let last = t.buckets.last().unwrap();
        assert_eq!(last.total, 8);
        assert_eq!(last.hostile, 5);
    }

    #[test]
    fn llm_metrics_reads_the_funnel() {
        let conn = fixture_db("metrics");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let m = ctx.llm_metrics().unwrap();
        assert_eq!(m.proposals_decided, 2);
        assert_eq!(m.proposal_precision, Some(0.5));
        assert_eq!(m.coverage, Some(1.0));
        assert_eq!(m.seconds_per_label, Some(90.0));
        assert_eq!(m.calibration.iter().map(|b| b.n).sum::<usize>(), 2);
        assert_eq!(m.faithfulness_per_100, Some(50.0));
        assert_eq!(m.parse_per_100, Some(100.0 / 3.0));
        assert_eq!(m.tokens_per_label, Some(300.0));
        assert_eq!(m.classify_golden_agreement, Some(0.8));
        assert_eq!(m.drafts_parsed, 0);
        assert_eq!(m.drafts_moved, 0);
        assert_eq!(m.shadow_fp_moved_drafts, 0);
    }

    // ---------- Round A-2 ----------

    /// a1: five scored turns in cluster c1, a proposal with two
    /// claimed signals (one failed), the window anchored at t5. a2:
    /// low score, nothing else. a3: mid score, shares c1. a4
    /// (16-hex): stopped by an operator block. a5: high score, no
    /// hits, no proposal. a6: low score, a watched rule. a7: low
    /// score, an enforce hit. a11: mid score with a watched rule
    /// (uncertain). a8/a9/a10: decided (disagree, agree, agree);
    /// a10 is scored, so it also tests the decided-out rule.
    fn review_db(name: &str) -> (Connection, i64) {
        let now: i64 = 1_800_000_000;
        let us = |s: i64| s * 1_000_000;
        let path = std::env::temp_dir().join(format!("leesided-q-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = Connection::open(&path).unwrap();
        crate::store::migrate(&mut conn).unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO actors (id, opened_us, last_us, turns) VALUES \
             ('a1', 0, {u5}, 5), ('a2', 0, {u5}, 1), ('a3', 0, {u5}, 1), \
             ('aaaabbbbccccdddd', 0, {u5}, 1), ('a5', 0, {u5}, 1), \
             ('a6', 0, {u5}, 1), ('a7', 0, {u5}, 1), ('a10', 0, {u5}, 1), ('a11', 0, {u5}, 1); \
             INSERT INTO turns (turn_id, session_key, ts_us, ts, peer_key, principal, verb, route, \
             status, latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, ua_hash, \
             dropped_since_last, actor_id, cluster_key, surface, flags, path_pattern, \
             rules_matched, ua_class, ja4) VALUES \
             ('t1', 's1', {u1}, {t1}, 'p1', 'anon', 'GET', 'home', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a1', 'c1', 'web', NULL, NULL, NULL, NULL, NULL), \
             ('t2', 's1', {u2}, {t2}, 'p1', 'anon', 'GET', '_unrouted', 404, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a1', 'c1', 'web', \
             '[\"browser_no_sec_fetch\"]', '/[id]', NULL, NULL, NULL), \
             ('t3', 's1', {u3}, {t3}, 'p1', 'anon', 'POST', 'portal.login', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a1', 'c1', 'web', NULL, NULL, \
             '[{{\"rule\":\"auth-burst-peer\",\"action\":\"watch\",\"mode\":\"shadow\"}}]', NULL, NULL), \
             ('t4', 's1', {u4}, {t4}, 'p1', 'anon', 'GET', '_unrouted', 404, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a1', 'c1', 'web', \
             '[\"ua_changes\"]', '/x', NULL, NULL, NULL), \
             ('t5', 's1', {u5}, {t5}, 'p1', 'anon', 'POST', 'portal.login', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a1', 'c1', 'web', NULL, NULL, NULL, \
             'chromium', 'j4x'), \
             ('t6', 's2', {u5}, {t5}, 'p2', 'anon', 'GET', 'home', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a2', NULL, 'web', NULL, NULL, NULL, NULL, NULL), \
             ('t7', 's3', {u5}, {t5}, 'p3', 'anon', 'GET', 'home', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a3', 'c1', 'web', NULL, NULL, NULL, NULL, NULL), \
             ('t8', 's4', {u5}, {t5}, 'p4', 'anon', 'GET', 'venues.show', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'aaaabbbbccccdddd', NULL, 'web', NULL, NULL, \
             '[{{\"rule\":\"operator\",\"action\":\"block\",\"mode\":\"enforce\"}}]', NULL, NULL), \
             ('t9', 's5', {u5}, {t5}, 'p5', 'anon', 'GET', 'home', 200, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a5', NULL, 'web', NULL, NULL, NULL, NULL, NULL), \
             ('t10', 's6', {u5}, {t5}, 'p6', 'anon', 'GET', 'x', 500, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a6', NULL, 'web', NULL, NULL, \
             '[{{\"rule\":\"server-error-watch\",\"action\":\"watch\",\"mode\":\"shadow\"}}]', NULL, NULL), \
             ('t11', 's7', {u5}, {t5}, 'p7', 'anon', 'GET', 'venues.show', 41, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a7', NULL, 'web', NULL, NULL, \
             '[{{\"rule\":\"venue-enumeration\",\"action\":\"block\",\"mode\":\"enforce\"}}]', NULL, NULL), \
             ('t13', 's8', {u5}, {t5}, 'p8', 'anon', 'GET', 'x', 500, \
             1.0, 10, 20, 'r', 'r', '{{}}', 'u', 0, 'a11', NULL, 'web', NULL, NULL, \
             '[{{\"rule\":\"server-error-watch\",\"action\":\"watch\",\"mode\":\"shadow\"}}]', NULL, NULL); \
             INSERT INTO decisions (scope, key, action, mode, rule, rule_version, created_at, expires_at) VALUES \
             ('actor', 'aaaabbbbccccdddd', 'block', 'enforce', 'operator', 0, {c0}, {e1}); \
             INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3) VALUES \
             ('actor', 'a1', 't5', 'web', {u5}, 0.95, '0.1.0', '[{{\"name\":\"ratio_404\",\"path_gain\":0.63}}]'), \
             ('actor', 'a2', 't6', 'web', {u5}, 0.2, '0.1.0', '[]'), \
             ('actor', 'a3', 't7', 'web', {u5}, 0.6, '0.1.0', '[]'), \
             ('actor', 'a5', 't9', 'web', {u5}, 0.9, '0.1.0', '[]'), \
             ('actor', 'a6', 't10', 'web', {u5}, 0.2, '0.1.0', '[]'), \
             ('actor', 'a7', 't11', 'web', {u5}, 0.2, '0.1.0', '[]'), \
             ('actor', 'a10', 't12', 'web', {u5}, 0.9, '0.1.0', '[]'), \
             ('actor', 'a11', 't13', 'web', {u5}, 0.6, '0.1.0', '[]'); \
             INSERT INTO feature_vectors (scope, key, turn_id, ts_us, version, vector, surface, clock_anomalies) VALUES \
             ('actor', 'a1', 't5', {u5}, 2, '[0.0]', 'web', 0); \
             INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, note, signals, cited_turns, created_at) VALUES \
             ('actor', 'a1', 'web', {u5}, 'malicious', 'llm_proposed', 0.91, \
             'Wordlist paths at machine cadence. [llm_call:1]', '[\"scanner_paths\"]', '[0, 3]', {c1}), \
             ('actor', 'a8', 'web', {u5}, 'malicious', 'llm_proposed', 0.8, 'r [llm_call:2]', '[]', '[]', {c1}), \
             ('actor', 'a8', 'web', {u5}, 'benign', 'operator', 1.0, 'review CLI', NULL, NULL, {c2}), \
             ('actor', 'a9', 'web', {u5}, 'malicious', 'llm_proposed', 0.8, 'r [llm_call:2]', '[]', '[]', {c1}), \
             ('actor', 'a9', 'web', {u5}, 'malicious', 'operator', 1.0, 'review CLI', NULL, NULL, {c2}), \
             ('actor', 'a10', 'web', {u5}, 'benign', 'llm_proposed', 0.7, 'r [llm_call:2]', '[]', '[]', {c0}), \
             ('actor', 'a10', 'web', {u5}, 'benign', 'operator', 1.0, 'review CLI', NULL, NULL, {c2}); \
             INSERT INTO llm_calls (id, point, model, prompt_hash, json_mode, input_summary, request, parsed, faithfulness_failed, prompt_tokens, completion_tokens, created_at) VALUES \
             (1, 'label', 'Muse Spark', 'h', 'prompt', '{{}}', '{{}}', \
             '{{\"label\":\"malicious\",\"confidence\":0.93,\"reason\":\"Wordlist paths.\", \
             \"signals\":[{{\"name\":\"scanner_paths\",\"turns\":[0,3]}},{{\"name\":\"machine_cadence\",\"turns\":[4]}}]}}', \
             '[\"machine_cadence\"]', 100, 50, {c1}), \
             (2, 'label', 'Muse Spark', 'h', 'prompt', '{{}}', '{{}}', NULL, NULL, 10, 5, {c1});",
            t1 = now - 400,
            t2 = now - 300,
            t3 = now - 200,
            t4 = now - 100,
            t5 = now - 60,
            u1 = us(now - 400),
            u2 = us(now - 300),
            u3 = us(now - 200),
            u4 = us(now - 100),
            u5 = us(now - 60),
            c0 = now - 200,
            c1 = now - 50,
            c2 = now - 10,
            e1 = now + 1000,
        ))
        .unwrap();
        (conn, now)
    }

    fn web_thresholds() -> std::collections::HashMap<String, f64> {
        let mut thresholds = std::collections::HashMap::new();
        thresholds.insert("web".to_string(), 0.5);
        thresholds
    }

    #[test]
    fn a2_phrases_cover_every_stored_name_with_fallbacks() {
        assert_eq!(
            flag_phrase("ua_chromium_no_ch"),
            "says Chrome, sends no client hints"
        );
        assert_eq!(
            flag_phrase("browser_no_sec_fetch"),
            "browser sends no fetch metadata"
        );
        assert_eq!(
            flag_phrase("browser_no_accept_language"),
            "browser sends no language"
        );
        assert_eq!(
            flag_phrase("ua_vs_ja4_mismatch"),
            "user agent and TLS disagree"
        );
        assert_eq!(flag_phrase("ua_changes"), "user agent changed mid-window");
        assert_eq!(flag_phrase("ua_inconsistent"), "client inconsistent");
        assert_eq!(flag_phrase("library_ua_on_web"), "script UA on a web page");
        assert_eq!(flag_phrase("whatever_new"), "whatever_new");
        assert_eq!(signal_phrase("honeytoken_hit"), "hidden trap touched");
        assert_eq!(signal_phrase("insufficient_data"), "too few requests");
        assert_eq!(signal_phrase("whatever_new"), "whatever_new");
        for name in crate::rules::features::NAMES {
            assert!(feature_phrase(name).is_some(), "{name}");
        }
        assert_eq!(feature_display("ratio_404", 0.63), "404 share 0.63");
        assert_eq!(feature_display("whatever_new", 0.5), "whatever_new 0.50");
    }

    #[test]
    fn a2_headline_templates_state_and_day() {
        assert_eq!(
            headline("browser only", 0, "waiting"),
            "A browser only first seen 1 Jan 1970, waiting for a decision"
        );
        assert_eq!(
            headline("API client", 0, "stopped"),
            "A API client first seen 1 Jan 1970, currently blocked"
        );
        assert_eq!(
            headline("signed-in user", 0, "watched"),
            "A signed-in user first seen 1 Jan 1970, under watch"
        );
    }

    #[test]
    fn a2_turn_verdicts_and_route_display() {
        assert_eq!(route_display("portal.login", None), "portal.login");
        assert_eq!(route_display("_unrouted", Some("/[id]")), "/[id]");
        assert_eq!(route_display("_unrouted", None), "_unrouted");
        let (_, verdict, note) = turn_verdict(None);
        assert_eq!(
            (verdict.as_str(), note.as_str()),
            ("allowed", "no rule fired")
        );
        let (rules, verdict, note) = turn_verdict(Some(
            "[{\"rule\":\"auth-burst-peer\",\"action\":\"watch\",\"mode\":\"shadow\"}]",
        ));
        assert_eq!(rules.len(), 1);
        assert_eq!(
            (verdict.as_str(), note.as_str()),
            ("observed", "watched by auth-burst-peer")
        );
        let (_, verdict, note) = turn_verdict(Some(
            "[{\"rule\":\"venue-enumeration\",\"action\":\"block\",\"mode\":\"enforce\"}]",
        ));
        assert_eq!(
            (verdict.as_str(), note.as_str()),
            ("blocked", "blocked by venue-enumeration")
        );
        let (_, verdict, note) = turn_verdict(Some(
            "[{\"rule\":\"operator\",\"action\":\"block\",\"mode\":\"enforce\"}]",
        ));
        assert_eq!(
            (verdict.as_str(), note.as_str()),
            ("blocked", "blocked by your decision")
        );
    }

    #[test]
    fn a2_subject_states_mirror_episodes_and_queue() {
        let (conn, now) = review_db("states");
        let ctx = Ctx::new(&conn, "default").unwrap();
        assert_eq!(
            ctx.subject_state("actor", "aaaabbbbccccdddd", 0, now)
                .unwrap(),
            "stopped"
        );
        assert_eq!(ctx.subject_state("actor", "a1", 0, now).unwrap(), "waiting");
        assert_eq!(ctx.subject_state("actor", "a2", 0, now).unwrap(), "waiting");
        assert_eq!(
            ctx.subject_state("actor", "a11", 0, now).unwrap(),
            "waiting"
        );
        // Decided out: the operator stands at or after the proposal.
        assert_eq!(
            ctx.subject_state("actor", "a10", 0, now).unwrap(),
            "watched"
        );
        // Unscored subjects are watched, decided or not.
        assert_eq!(ctx.subject_state("actor", "a8", 0, now).unwrap(), "watched");
    }

    #[test]
    fn a2_review_queue_orders_counts_and_decides() {
        let (conn, now) = review_db("queue");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let q = ctx
            .review_queue_json(&web_thresholds(), now - 86_400)
            .unwrap();
        assert_eq!(q["total"], 7);
        assert_eq!(q["agree"], 3);
        assert_eq!(q["disagree"], 4);
        let ids: Vec<&str> = q["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["a5", "a3", "a6", "a7", "a11", "a1", "a2"]);
        assert_eq!(q["items"][0]["why"], "above_threshold_no_rule");
        assert_eq!(q["items"][0]["why_phrase"], "score high, no rule fired");
        assert_eq!(q["items"][1]["why"], "above_threshold_no_rule");
        assert_eq!(q["items"][2]["why"], "observe_below_threshold");
        assert_eq!(q["items"][2]["disagree"], true);
        assert_eq!(q["items"][3]["why"], "rule_below_threshold");
        assert_eq!(q["items"][4]["why"], "uncertain");
        assert_eq!(q["items"][4]["disagree"], false);
        assert_eq!(q["items"][5]["why"], "unlabelled_proposal");
        assert_eq!(q["items"][5]["proposal"]["label"], "malicious");
        assert_eq!(q["items"][6]["why"], "score");
        assert_eq!(q["decided"]["total"], 3);
        assert_eq!(q["decided"]["agreed"], 2);
        let mut confs: Vec<f64> = q["decided"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["proposal_confidence"].as_f64().unwrap())
            .collect();
        confs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(confs, vec![0.7, 0.8, 0.8]);
    }

    #[test]
    fn a2_review_item_carries_signals_evidence_and_neighbours() {
        let (conn, now) = review_db("item");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let v = ctx
            .review_item_json("actor", "a1", &web_thresholds(), now)
            .unwrap();
        assert_eq!(v["id"], "a1");
        assert_eq!(v["kind"], "browser only");
        assert_eq!(v["state"], "waiting");
        assert_eq!(v["queue"]["total"], 7);
        assert_eq!(v["queue"]["position"], 6);
        assert_eq!(v["queue"]["prev"]["id"], "a11");
        assert_eq!(v["queue"]["next"]["id"], "a2");
        assert_eq!(v["why"], "unlabelled_proposal");
        assert_eq!(v["model"]["score"], 0.95);
        assert_eq!(v["model"]["verdict"], "hostile");
        assert_eq!(v["model"]["by"], "Windside 0.1.0");
        assert_eq!(v["model"]["top"][0]["display"], "404 share 0.63");
        assert_eq!(v["model"]["rules_fired"]["count"], 1);
        assert_eq!(v["model"]["rules_fired"]["names"][0], "auth-burst-peer");
        assert_eq!(v["proposal"]["label"], "malicious");
        assert_eq!(v["proposal"]["model"], "Muse Spark");
        assert_eq!(v["signals"].as_array().unwrap().len(), 2);
        assert_eq!(v["signals"][0]["name"], "scanner_paths");
        assert_eq!(v["signals"][0]["passed"], true);
        assert_eq!(v["signals"][0]["side"], "malicious");
        let rows: Vec<i64> = v["signals"][0]["turns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["row"].as_i64().unwrap())
            .collect();
        assert_eq!(rows, vec![1, 4]);
        assert_eq!(v["signals"][0]["turns"][0]["trace"], "t1");
        assert_eq!(v["signals"][1]["name"], "machine_cadence");
        assert_eq!(v["signals"][1]["passed"], false);
        assert_eq!(
            v["signals"][1]["failed_reason"],
            "did not survive the evidence check"
        );
        assert_eq!(v["evidence"]["total"], 5);
        assert_eq!(v["evidence"]["cited"].as_array().unwrap().len(), 3);
        assert_eq!(v["evidence"]["cluster_size"], 2);
        // Newest first; t5 is newest, t2 shows its folded path and flag.
        // t5's only claim failed, so it stays unmarked; t4 is surviving-cited.
        assert_eq!(v["evidence"]["turns"][0]["trace"], "t5");
        assert_eq!(v["evidence"]["turns"][0]["cited"], false);
        assert_eq!(
            v["evidence"]["turns"][0]["signals"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(v["evidence"]["turns"][1]["cited"], true);
        assert_eq!(v["evidence"]["turns"][1]["signals"][0], "scanner_paths");
        assert_eq!(v["evidence"]["turns"][3]["route"], "/[id]");
        assert_eq!(
            v["evidence"]["turns"][3]["flags"][0]["phrase"],
            "browser sends no fetch metadata"
        );
        assert_eq!(v["evidence"]["turns"][3]["cited"], false);
        assert_eq!(v["decision"]["operator"], serde_json::Value::Null);
        assert_eq!(v["window"]["window_end_ts"], (now - 60) * 1_000_000);
        // Unknown scope and unscored subjects 404 like unknown ones.
        assert!(ctx
            .review_item_json("peer", "a1", &web_thresholds(), now)
            .is_err());
        assert!(ctx
            .review_item_json("actor", "aaaabbbbccccdddd", &web_thresholds(), now)
            .is_err());
    }

    #[test]
    fn a2_actor_turns_filter_by_flag_status_and_route() {
        let (conn, _) = review_db("turns");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let v = ctx.actor_turns_json("a1", None, None, None, 20).unwrap();
        assert_eq!(v["total"], 5);
        assert_eq!(v["turns"].as_array().unwrap().len(), 5);
        let v = ctx
            .actor_turns_json("a1", Some("browser_no_sec_fetch"), None, None, 20)
            .unwrap();
        assert_eq!(v["total"], 1);
        assert_eq!(v["turns"][0]["trace"], "t2");
        let v = ctx
            .actor_turns_json("a1", None, Some("404"), None, 20)
            .unwrap();
        assert_eq!(v["total"], 2);
        assert_eq!(v["turns"][0]["trace"], "t4");
        let v = ctx
            .actor_turns_json("a1", None, Some("4xx"), None, 20)
            .unwrap();
        assert_eq!(v["total"], 2);
        let v = ctx
            .actor_turns_json("a1", None, Some("200"), None, 20)
            .unwrap();
        assert_eq!(v["total"], 3);
        let v = ctx
            .actor_turns_json("a1", None, None, Some("portal.login"), 20)
            .unwrap();
        assert_eq!(v["total"], 2);
        let v = ctx
            .actor_turns_json("a1", None, None, Some("/x"), 20)
            .unwrap();
        assert_eq!(v["total"], 1);
        assert_eq!(v["turns"][0]["trace"], "t4");
        let v = ctx.actor_turns_json("a1", None, None, None, 2).unwrap();
        assert_eq!(v["total"], 5);
        assert_eq!(v["turns"].as_array().unwrap().len(), 2);
        let v = ctx
            .actor_turns_json("a1", None, Some("bogus"), None, 20)
            .unwrap();
        assert_eq!(v["total"], 0);
        // The operator block reads as the operator's decision.
        let v = ctx
            .actor_turns_json("aaaabbbbccccdddd", None, None, None, 20)
            .unwrap();
        assert_eq!(v["turns"][0]["verdict"], "blocked");
        assert_eq!(v["turns"][0]["note"], "blocked by your decision");
    }

    #[test]
    fn a2_actor_page_carries_headline_client_and_score() {
        let (conn, now) = review_db("actor");
        let ctx = Ctx::new(&conn, "default").unwrap();
        let classes = crate::tap::classes::Ja4Classes::default();
        let v = ctx
            .actor_json("a1", &web_thresholds(), &classes, now)
            .unwrap();
        assert_eq!(v["id"], "a1");
        assert_eq!(v["state"], "waiting");
        assert_eq!(
            v["headline"],
            "A browser only first seen 1 Jan 1970, waiting for a decision"
        );
        assert_eq!(v["client"]["ua_class"], "chromium");
        assert_eq!(v["client"]["ja4"], "j4x");
        assert_eq!(v["client"]["ja4_class"], "unknown");
        assert_eq!(v["client"]["ja4_hostile"], false);
        assert_eq!(v["client"]["turns_sampled"], 2);
        assert_eq!(v["client"]["flags"].as_array().unwrap().len(), 2);
        assert_eq!(v["client"]["flags"][0]["name"], "browser_no_sec_fetch");
        assert_eq!(v["client"]["flags"][0]["rate"], 0.5);
        assert_eq!(v["activity"]["turns"], 5);
        assert_eq!(v["score"]["value"], 0.95);
        assert_eq!(v["score"]["verdict"], "hostile");
        assert_eq!(v["proposal"]["label"], "malicious");
        assert_eq!(v["signals"].as_array().unwrap().len(), 2);
        assert_eq!(v["blocked"], false);
        assert_eq!(v["cluster"], "c1");
        assert_eq!(v["cluster_actors"], 2);
        assert_eq!(v["similar"].as_array().unwrap().len(), 1);
        assert_eq!(v["similar"][0]["id"], "a3");
        assert_eq!(v["similar"][0]["state"], "waiting");
        assert_eq!(v["turn_total"], 5);
        let v = ctx
            .actor_json("aaaabbbbccccdddd", &web_thresholds(), &classes, now)
            .unwrap();
        assert_eq!(v["state"], "stopped");
        assert_eq!(v["blocked"], true);
        assert_eq!(v["score"], serde_json::Value::Null);
    }
}
