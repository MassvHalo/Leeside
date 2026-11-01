//! Step G, first half: the review CLI (docs/windside.md section 7),
//! with the point-1 label proposals beside each row (docs/llm.md).
//!
//! `leesided review [--top 20]` lists the highest-scored actors with a
//! window summary and top features, then takes one key per row: `b`
//! benign, `m` malicious, `u` unknown, Enter to skip, `q` to quit. Each
//! decision appends an `operator` label at confidence 1.0 (latest wins on
//! read: re-reviewing a window keeps both judgments). Kind stays null:
//! operator labels belong to no generator run.
//!
//! When the LLM is configured, opening the review enqueues a label job
//! for each shown row, and a row with a proposal offers `c` to confirm
//! it (an `operator` label with the proposed value, noted as confirmed).
//! Rejecting is entering your own verdict: the append-only log keeps
//! the proposal and the correction side by side.

use crate::rules::features;
use rusqlite::{params, Connection};
use std::io::{BufRead, Write};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("llm: {0}")]
    Llm(#[from] crate::llm::LlmError),
    #[error("database `{0}` does not exist")]
    MissingDb(String),
}

/// One review candidate: the actor's latest score plus its window.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewRow {
    pub scope_id: String,
    pub score: f64,
    pub surface: Option<String>,
    pub top: Vec<String>,
    pub held: u32,
    pub window_end_ts: i64,
    pub proposal: Option<Proposal>,
}

/// The latest `llm_proposed` label for the actor, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub label: String,
    pub confidence: f64,
    pub reason: String,
    pub signals: Vec<String>,
}

impl Proposal {
    /// The note is `{reason} [llm_call:{id}]`; the review shows the reason.
    fn display(reason_note: &str) -> String {
        reason_note
            .rsplit_once(" [llm_call:")
            .map(|(reason, _)| reason)
            .unwrap_or(reason_note)
            .replace('\n', " ")
    }
}

fn open_db(db: &Path) -> Result<Connection, ReviewError> {
    if !db.is_file() {
        return Err(ReviewError::MissingDb(db.display().to_string()));
    }
    let mut conn = Connection::open(db)?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    crate::store::migrate(&mut conn)?;
    Ok(conn)
}

/// The highest-scored actors, latest score each, with window summaries.
pub fn review_rows(conn: &Connection, top: usize) -> Result<Vec<ReviewRow>, ReviewError> {
    let mut stmt = conn.prepare(
        "SELECT scope_id, surface, ts_us, score, top3 FROM ( \
           SELECT *, ROW_NUMBER() OVER (PARTITION BY scope_id ORDER BY ts_us DESC) AS rn \
           FROM scores WHERE scope = 'actor' \
         ) WHERE rn = 1 ORDER BY score DESC LIMIT ?1",
    )?;
    let latest: Vec<(String, Option<String>, i64, f64, String)> = stmt
        .query_map(params![top as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .filter_map(|r| r.ok())
        .collect();
    let held_idx = features::NAMES.iter().position(|n| *n == "turns_held");
    let mut out = Vec::with_capacity(latest.len());
    for (scope_id, surface, _ts, score, top3) in latest {
        let top: Vec<String> = serde_json::from_str::<Vec<serde_json::Value>>(&top3)
            .map(|v| {
                v.iter()
                    .filter_map(|e| e.get("name")?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let (held, window_end_ts): (u32, i64) = conn
            .query_row(
                "SELECT vector, ts_us FROM feature_vectors \
                 WHERE scope = 'actor' AND key = ?1 ORDER BY ts_us DESC LIMIT 1",
                params![scope_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok()
            .and_then(|(vector, ts)| {
                held_idx
                    .and_then(|i| {
                        serde_json::from_str::<Vec<f32>>(&vector)
                            .ok()?
                            .get(i)
                            .copied()
                    })
                    .map(|h| (h as u32, ts))
            })
            .unwrap_or((0, 0));
        let proposal: Option<Proposal> = conn
            .query_row(
                "SELECT label, confidence, note, signals FROM labels \
                 WHERE scope = 'actor' AND scope_id = ?1 AND source = 'llm_proposed' \
                 ORDER BY window_end_ts DESC, created_at DESC, id DESC LIMIT 1",
                params![scope_id],
                |r| {
                    let note: Option<String> = r.get(2)?;
                    let signals: Option<String> = r.get(3)?;
                    Ok(Proposal {
                        label: r.get(0)?,
                        confidence: r.get(1)?,
                        reason: Proposal::display(note.as_deref().unwrap_or("")),
                        signals: signals
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default(),
                    })
                },
            )
            .ok();
        out.push(ReviewRow {
            scope_id,
            score,
            surface,
            top,
            held,
            window_end_ts,
            proposal,
        });
    }
    Ok(out)
}

/// Write the operator's decision for the reviewed window. Every judgment
/// appends a row (0013); readers take the latest per subject and source,
/// so a correction stays auditable and the newest stands.
pub fn write_operator_label(
    conn: &Connection,
    row: &ReviewRow,
    label: &str,
    note: &str,
    now_s: i64,
) -> Result<(), ReviewError> {
    conn.execute(
        "INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, \
         confidence, kind, note, created_at) \
         VALUES ('actor', ?1, ?2, ?3, ?4, 'operator', 1.0, NULL, ?5, ?6)",
        params![
            row.scope_id,
            row.surface,
            row.window_end_ts,
            label,
            note,
            now_s
        ],
    )?;
    Ok(())
}

/// Run the interactive loop. Returns the number of labels written.
pub fn run_review(
    db: &Path,
    top: usize,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<usize, ReviewError> {
    let conn = open_db(db)?;
    let rows = review_rows(&conn, top)?;
    if rows.is_empty() {
        writeln!(output, "review: no scored actors")?;
        return Ok(0);
    }
    // Opening the review asks for proposals; the queue guard dedups,
    // caps and budgets, and nothing is enqueued unconfigured.
    if let Some(exec) = crate::llm::Exec::from_config(&crate::config::Config::from_env()) {
        let now = crate::store::now_s();
        for row in &rows {
            crate::llm::enqueue_label(
                &conn,
                "actor",
                &row.scope_id,
                "review",
                now,
                exec.daily_calls,
                exec.daily_tokens,
            )?;
        }
    }
    let mut labeled = 0usize;
    let mut line = String::new();
    for (n, row) in rows.iter().enumerate() {
        writeln!(
            output,
            "{}. {} score={:.4} {} held={} top={}",
            n + 1,
            row.scope_id,
            row.score,
            row.surface.as_deref().unwrap_or("none"),
            row.held,
            if row.top.is_empty() {
                "-".to_string()
            } else {
                row.top.join(",")
            }
        )?;
        if let Some(p) = &row.proposal {
            writeln!(
                output,
                "  llm proposes {} ({:.2}) [{}]: {}",
                p.label,
                p.confidence,
                if p.signals.is_empty() {
                    "-".to_string()
                } else {
                    p.signals.join(",")
                },
                p.reason,
            )?;
        }
        loop {
            if row.proposal.is_some() {
                write!(
                    output,
                    "  [c]onfirm proposal [b]enign [m]alicious [u]nknown (Enter skips, q quits): "
                )?;
            } else {
                write!(
                    output,
                    "  [b]enign [m]alicious [u]nknown (Enter skips, q quits): "
                )?;
            }
            output.flush()?;
            line.clear();
            if input.read_line(&mut line)? == 0 {
                return Ok(labeled);
            }
            let now_s = crate::store::now_s();
            match line.trim().to_lowercase().as_str() {
                "c" if row.proposal.is_some() => {
                    let label = row.proposal.as_ref().expect("checked").label.clone();
                    write_operator_label(&conn, row, &label, "confirmed llm_proposed", now_s)?;
                    writeln!(output, "  labeled {label} (confirmed proposal)")?;
                    labeled += 1;
                    break;
                }
                verdict @ ("b" | "m" | "u") => {
                    let label = match verdict {
                        "b" => "benign",
                        "m" => "malicious",
                        _ => "unknown",
                    };
                    write_operator_label(&conn, row, label, "review CLI", now_s)?;
                    if row.proposal.as_ref().is_some_and(|p| p.label != label) {
                        writeln!(output, "  labeled {label} (differs from proposal)")?;
                    } else {
                        writeln!(output, "  labeled {label}")?;
                    }
                    labeled += 1;
                    break;
                }
                "" => break,
                "q" => return Ok(labeled),
                _ => continue,
            }
        }
    }
    Ok(labeled)
}
