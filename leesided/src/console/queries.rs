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
#[derive(Debug, Clone)]
pub struct ActorDetail {
    pub head: ActorHead,
    pub row: ActorRow,
    pub merged_from: Vec<String>,
    pub bindings: Vec<BindingView>,
    pub client: ClientView,
    pub cluster_actors: i64,
    pub activity: ActivityView,
    pub scores: ScoreBlock,
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
        Ok(ActorDetail {
            head,
            row,
            merged_from: ids[1..].to_vec(),
            bindings: self.bindings_for(&canonical)?,
            client: self.client_for(&ids)?,
            cluster_actors,
            activity: self.activity_for(&ids)?,
            scores: self.scores_for("actor", &canonical, thresholds)?,
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
    /// The review queue in the CLI's order: highest score first. Each
    /// row says why it is queued; decided rows keep their form, since
    /// labels are append-only and a correction is a new row.
    pub fn review_queue(
        &self,
        thresholds: &std::collections::HashMap<String, f64>,
        top: usize,
    ) -> Result<Vec<ReviewFull>, QueryError> {
        let rows = crate::review::review_rows(self.conn(), top).map_err(|e| match e {
            crate::review::ReviewError::Sqlite(inner) => QueryError::Sqlite(inner),
            e => QueryError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(e))),
        })?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut why = Vec::new();
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
                     WHERE scope = 'actor' AND scope_id = ?1 AND source = 'operator' \
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![row.scope_id],
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

/// One rule with its 24 h hit counts.
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
            });
        }
        Ok(out)
    }

    /// Rule drafts from the LLM. No table yet: the draft point is
    /// unbuilt, so this is empty until point 4 lands.
    pub fn rule_drafts(&self) -> Result<Vec<RuleView>, QueryError> {
        Ok(Vec::new())
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

// ---------- dashboard ----------

/// Tables the dashboard counts, in display order.
pub const COUNT_TABLES: &[&str] = &[
    "turns",
    "actors",
    "actor_bindings",
    "feature_vectors",
    "scores",
    "labels",
    "decisions",
    "rules",
    "llm_jobs",
    "llm_calls",
];

/// Everything `/ui/` shows below the health line.
#[derive(Debug, Clone)]
pub struct Dashboard {
    pub counts: Vec<(String, i64)>,
    pub today: crate::llm::PointTotals,
    pub turns: Vec<TurnLite>,
    pub decisions: Vec<DecisionView>,
    pub proposals: Vec<LabelRef>,
    pub labels: Vec<LabelRef>,
}

impl Ctx<'_> {
    /// Today's per-point LLM calls and tokens, for the dashboard.
    pub fn llm_today(&self, now: i64) -> Result<crate::llm::PointTotals, QueryError> {
        crate::llm::llm_today(self.conn(), now).map_err(QueryError::from)
    }

    pub fn dashboard(&self, now: i64) -> Result<Dashboard, QueryError> {
        Ok(Dashboard {
            counts: self.table_counts()?,
            today: self.llm_today(now)?,
            turns: self.recent_turns(20)?,
            decisions: self.recent_decisions(20)?,
            proposals: self.recent_labels(true, 20)?,
            labels: self.recent_labels(false, 20)?,
        })
    }

    pub fn table_counts(&self) -> Result<Vec<(String, i64)>, QueryError> {
        let mut out = Vec::with_capacity(COUNT_TABLES.len());
        for t in COUNT_TABLES {
            let sql = format!("SELECT count(*) FROM {t}");
            out.push((
                t.to_string(),
                self.conn().query_row(&sql, [], |r| r.get(0))?,
            ));
        }
        Ok(out)
    }

    /// The newest turns, for the dashboard's event list.
    pub fn recent_turns(&self, limit: i64) -> Result<Vec<TurnLite>, QueryError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {TURN_LITE_COLS} FROM turns ORDER BY ts_us DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map(params![limit], turn_lite_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }

    /// The newest sticky decisions, for the dashboard.
    pub fn recent_decisions(&self, limit: i64) -> Result<Vec<DecisionView>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT scope, key, action, mode, rule, rule_version, created_at, expires_at \
             FROM decisions ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
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

    /// The newest proposals and the newest labels, for the dashboard.
    pub fn recent_labels(
        &self,
        proposed_only: bool,
        limit: i64,
    ) -> Result<Vec<LabelRef>, QueryError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, scope, scope_id, surface, window_end_ts, label, source, confidence, \
             kind, note, created_at, signals FROM labels \
             WHERE (?1 = 0 OR source = 'llm_proposed') \
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![i64::from(proposed_only), limit], label_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(QueryError::from)
    }
}
