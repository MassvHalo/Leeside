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
}

/// An app-scoped query context over one read connection.
pub struct Ctx<'a> {
    conn: &'a Connection,
}

impl<'a> Ctx<'a> {
    pub fn new(conn: &'a Connection, app_id: &str) -> Result<Ctx<'a>, QueryError> {
        if app_id != "default" {
            return Err(QueryError::UnknownApp(app_id.to_string()));
        }
        Ok(Ctx { conn })
    }

    fn conn(&self) -> &Connection {
        self.conn
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
