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

/// Why a subject is queued (docs/llm-evals.md section 4): the
/// first matching tier, in order. The uncertain band is 0.3 to 0.7,
/// the brief's borderline band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhyInQueue {
    RuleBelowThreshold,
    ObserveBelowThreshold,
    AboveThresholdNoRule,
    Uncertain,
    UnlabelledProposal,
    Score,
}

impl WhyInQueue {
    pub fn as_str(self) -> &'static str {
        match self {
            WhyInQueue::RuleBelowThreshold => "rule_below_threshold",
            WhyInQueue::ObserveBelowThreshold => "observe_below_threshold",
            WhyInQueue::AboveThresholdNoRule => "above_threshold_no_rule",
            WhyInQueue::Uncertain => "uncertain",
            WhyInQueue::UnlabelledProposal => "unlabelled_proposal",
            WhyInQueue::Score => "score",
        }
    }

    fn tier(self) -> u8 {
        match self {
            WhyInQueue::RuleBelowThreshold
            | WhyInQueue::ObserveBelowThreshold
            | WhyInQueue::AboveThresholdNoRule => 1,
            WhyInQueue::Uncertain => 2,
            WhyInQueue::UnlabelledProposal => 3,
            WhyInQueue::Score => 4,
        }
    }

    /// The queue's short phrase, shared by the server review list and
    /// the Windside Review page (Round A-2). Four come from the
    /// review-actor handoff's queue column; `observe_below_threshold`
    /// and `score` extend the same voice.
    pub fn phrase(self) -> &'static str {
        match self {
            WhyInQueue::RuleBelowThreshold => "rule fired below threshold",
            WhyInQueue::ObserveBelowThreshold => "watched rule fired, score low",
            WhyInQueue::AboveThresholdNoRule => "score high, no rule fired",
            WhyInQueue::Uncertain => "score uncertain",
            WhyInQueue::UnlabelledProposal => "proposal unconfirmed",
            WhyInQueue::Score => "scored low, nothing fired",
        }
    }

    /// Tier 1 carries the "rule and model disagree" badge: a rule
    /// fired under a low score, or the score is high with no rule
    /// behind it. The queue's disagree count is tier-1 rows.
    pub fn disagree(self) -> bool {
        self.tier() == 1
    }
}

/// One review candidate: the subject's latest score with its window,
/// threshold, rule hits and proposal, plus why it is queued.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewRow {
    pub scope: String,
    pub scope_id: String,
    pub score: f64,
    pub surface: Option<String>,
    pub threshold: f64,
    pub top: Vec<String>,
    pub held: u32,
    pub window_end_ts: i64,
    pub rule_hits: Vec<String>,
    pub proposal: Option<Proposal>,
    pub why: WhyInQueue,
}

/// The latest `llm_proposed` label for the actor, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub label: String,
    pub confidence: f64,
    pub reason: String,
    pub signals: Vec<String>,
    pub cited_turns: Vec<usize>,
}

impl Proposal {
    /// The note is `{reason} [llm_call:{id}]`; the review shows the reason.
    /// Shared with the dashboard episodes query.
    pub(crate) fn display(reason_note: &str) -> String {
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

/// A rule or observe hit on the subject: the rule name and when
/// (unix seconds). Shared with the dashboard episodes query.
pub(crate) struct Hit {
    pub(crate) rule: String,
    pub(crate) ts: i64,
}

pub(crate) fn acting(action: &str) -> bool {
    matches!(action, "block" | "rate_limit" | "challenge")
}

/// Rule hits from three places: `rule_decision` labels (install-set
/// blocks), live sticky decisions, and the subject's recent turns'
/// `rules_matched` (enforce-mode acting matches). Observe hits are
/// matches in monitor or shadow mode. Turn scans cap at 64 rows.
pub(crate) fn subject_hits(
    conn: &Connection,
    scope: &str,
    scope_id: &str,
    now_s: i64,
) -> Result<(Vec<Hit>, Vec<Hit>), ReviewError> {
    let mut rules: Vec<Hit> = Vec::new();
    let mut observe: Vec<Hit> = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT note, created_at FROM labels \
         WHERE scope = ?1 AND scope_id = ?2 AND source = 'rule_decision' \
         ORDER BY created_at DESC LIMIT 16",
    )?;
    for row in stmt.query_map(params![scope, scope_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
        let (rule, ts) = row?;
        rules.push(Hit { rule, ts });
    }
    if scope == "actor" {
        let mut stmt = conn.prepare(
            "SELECT rule, created_at FROM decisions \
             WHERE scope = 'actor' AND key = ?1 AND expires_at > ?2 \
             ORDER BY created_at DESC LIMIT 16",
        )?;
        for row in stmt.query_map(params![scope_id, now_s], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (rule, ts) = row?;
            rules.push(Hit { rule, ts });
        }
    }
    let turn_col = if scope == "actor" {
        "actor_id"
    } else {
        "cluster_key"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT rules_matched, ts_us FROM turns \
         WHERE {turn_col} = ?1 AND rules_matched IS NOT NULL \
         AND rules_matched != '[]' ORDER BY rowid DESC LIMIT 64"
    ))?;
    let rows: Vec<(String, i64)> = stmt
        .query_map(params![scope_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    for (matched, ts_us) in rows {
        let entries: Vec<serde_json::Value> = serde_json::from_str(&matched).unwrap_or_default();
        for e in entries {
            let rule = e.get("rule").and_then(|v| v.as_str()).unwrap_or("?");
            let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let mode = e.get("mode").and_then(|v| v.as_str()).unwrap_or("");
            let hit = Hit {
                rule: rule.to_string(),
                ts: ts_us / 1_000_000,
            };
            if mode == "enforce" && acting(action) {
                rules.push(hit);
            } else if mode == "monitor" || mode == "shadow" {
                observe.push(hit);
            }
        }
    }
    Ok((rules, observe))
}

fn latest_label_ts(
    conn: &Connection,
    scope: &str,
    scope_id: &str,
    source: &str,
) -> Result<i64, ReviewError> {
    let mut stmt = conn.prepare(
        "SELECT created_at FROM labels \
         WHERE scope = ?1 AND scope_id = ?2 AND source = ?3 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![scope, scope_id, source], |r| r.get(0))?;
    Ok(rows.next().transpose()?.unwrap_or(0))
}

/// The review queue (docs/llm-evals.md section 4): every scored
/// subject, newest evidence first. A decided subject leaves the queue
/// and re-enters only on a newer rule or observe hit or a newer
/// proposal; scores alone do not re-queue. Thresholds come from the
/// loaded model manifest, 0.5 when none is loaded for the surface.
pub fn review_rows(
    conn: &Connection,
    top: usize,
    thresholds: &std::collections::HashMap<String, f64>,
) -> Result<Vec<ReviewRow>, ReviewError> {
    let mut stmt = conn.prepare(
        "SELECT scope, scope_id, surface, ts_us, score, top3 FROM ( \
           SELECT *, ROW_NUMBER() OVER (PARTITION BY scope, scope_id ORDER BY ts_us DESC) AS rn \
           FROM scores WHERE scope IN ('actor', 'cluster') \
         ) WHERE rn = 1",
    )?;
    let latest: Vec<(String, String, Option<String>, i64, f64, String)> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    let held_idx = features::NAMES.iter().position(|n| *n == "turns_held");
    let now_s = crate::store::now_s();
    let mut out = Vec::with_capacity(latest.len());
    for (scope, scope_id, surface, _ts, score, top3) in latest {
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
                 WHERE scope = ?1 AND key = ?2 ORDER BY ts_us DESC LIMIT 1",
                params![scope, scope_id],
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
        let (rule_hits, observe_hits) = subject_hits(conn, &scope, &scope_id, now_s)?;
        let last_hit = rule_hits
            .iter()
            .chain(observe_hits.iter())
            .map(|h| h.ts)
            .max()
            .unwrap_or(0);
        let (proposal, proposal_ts) = match conn.query_row(
            "SELECT label, confidence, note, signals, cited_turns, created_at FROM labels \
             WHERE scope = ?1 AND scope_id = ?2 AND source = 'llm_proposed' \
             ORDER BY window_end_ts DESC, created_at DESC, id DESC LIMIT 1",
            params![scope, scope_id],
            |r| {
                let note: Option<String> = r.get(2)?;
                let signals: Option<String> = r.get(3)?;
                let cited: Option<String> = r.get(4)?;
                Ok((
                    Proposal {
                        label: r.get(0)?,
                        confidence: r.get(1)?,
                        reason: Proposal::display(note.as_deref().unwrap_or("")),
                        signals: signals
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default(),
                        cited_turns: cited
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default(),
                    },
                    r.get::<_, i64>(5)?,
                ))
            },
        ) {
            Ok((p, ts)) => (Some(p), ts),
            Err(_) => (None, 0),
        };
        let operator_ts = latest_label_ts(conn, &scope, &scope_id, "operator")?;
        if operator_ts > 0 && operator_ts >= proposal_ts.max(last_hit) {
            continue;
        }
        let threshold = surface
            .as_deref()
            .and_then(|s| thresholds.get(s).copied())
            .unwrap_or(0.5);
        let has_rule = !rule_hits.is_empty();
        let has_observe = !observe_hits.is_empty();
        let why = if has_rule && score < threshold {
            WhyInQueue::RuleBelowThreshold
        } else if has_observe && score < threshold {
            WhyInQueue::ObserveBelowThreshold
        } else if score >= threshold && !has_rule && !has_observe {
            WhyInQueue::AboveThresholdNoRule
        } else if (0.3..=0.7).contains(&score) {
            WhyInQueue::Uncertain
        } else if proposal.is_some() && proposal_ts > operator_ts {
            WhyInQueue::UnlabelledProposal
        } else {
            WhyInQueue::Score
        };
        let mut rules: Vec<String> = rule_hits
            .iter()
            .chain(observe_hits.iter())
            .map(|h| h.rule.clone())
            .collect();
        rules.sort();
        rules.dedup();
        out.push((
            ReviewRow {
                scope,
                scope_id,
                score,
                surface,
                threshold,
                top,
                held,
                window_end_ts,
                rule_hits: rules,
                proposal,
                why,
            },
            proposal_ts,
        ));
    }
    out.sort_by(|(a, pa), (b, pb)| {
        a.why
            .tier()
            .cmp(&b.why.tier())
            .then_with(|| match a.why.tier() {
                1 => b
                    .score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
                2 => (a.score - 0.5)
                    .abs()
                    .partial_cmp(&(b.score - 0.5).abs())
                    .unwrap_or(std::cmp::Ordering::Equal),
                3 => pb.cmp(pa),
                _ => b
                    .score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            })
    });
    out.truncate(top);
    Ok(out.into_iter().map(|(r, _)| r).collect())
}

/// One decided subject: the operator's latest judgment in the tab's
/// window beside the proposal it judged.
#[derive(Debug, Clone, PartialEq)]
pub struct DecidedRow {
    pub scope: String,
    pub scope_id: String,
    pub operator_label: String,
    pub operator_ts: i64,
    pub proposal: Option<String>,
    pub agreed: bool,
}

/// The Decided tab (Round A-2): every subject whose latest operator
/// label landed at or after `since_s`, newest first. `agreed` is the
/// operator label equalling the then-latest proposal, with unknown
/// against unknown counting as agree; a subject with no proposal at
/// decision time never agrees. Human-scale, so uncapped: the tab's
/// totals are these rows.
pub fn decided_list(conn: &Connection, since_s: i64) -> Result<Vec<DecidedRow>, ReviewError> {
    let mut stmt = conn.prepare(
        "SELECT scope, scope_id, label, created_at FROM ( \
           SELECT scope, scope_id, label, created_at, \
             ROW_NUMBER() OVER (PARTITION BY scope, scope_id ORDER BY created_at DESC, id DESC) AS rn \
           FROM labels WHERE source = 'operator' \
         ) WHERE rn = 1 AND created_at >= ?1 ORDER BY created_at DESC",
    )?;
    let ops: Vec<(String, String, String, i64)> = stmt
        .query_map(params![since_s], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .filter_map(|r| r.ok())
        .collect();
    let mut out = Vec::with_capacity(ops.len());
    for (scope, scope_id, operator_label, operator_ts) in ops {
        let proposal: Option<String> = conn
            .query_row(
                "SELECT label FROM labels \
                 WHERE scope = ?1 AND scope_id = ?2 AND source = 'llm_proposed' AND created_at <= ?3 \
                 ORDER BY created_at DESC, id DESC LIMIT 1",
                params![scope, scope_id, operator_ts],
                |r| r.get(0),
            )
            .ok();
        let agreed = proposal.as_deref() == Some(operator_label.as_str());
        out.push(DecidedRow {
            scope,
            scope_id,
            operator_label,
            operator_ts,
            proposal,
            agreed,
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
         VALUES (?1, ?2, ?3, ?4, ?5, 'operator', 1.0, NULL, ?6, ?7)",
        params![
            row.scope,
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

/// After an operator label lands: a malicious verdict may earn the
/// subject's cluster a draft (docs/llm.md 8.4). Nothing is enqueued
/// unconfigured.
fn note_operator_label(
    conn: &Connection,
    exec: Option<&crate::llm::Exec>,
    scope: &str,
    scope_id: &str,
    label: &str,
    now_s: i64,
) -> Result<(), ReviewError> {
    if label != "malicious" {
        return Ok(());
    }
    let Some(exec) = exec else {
        return Ok(());
    };
    crate::llm::maybe_enqueue_draft(
        conn,
        scope,
        scope_id,
        "review",
        now_s,
        exec.daily_calls,
        exec.daily_tokens,
    )?;
    Ok(())
}

/// Run the interactive loop. Returns the number of labels written.
/// Thresholds come from the loaded model manifest, empty when none is
/// configured (every surface then compares against 0.5).
pub fn run_review(
    db: &Path,
    top: usize,
    thresholds: &std::collections::HashMap<String, f64>,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<usize, ReviewError> {
    let conn = open_db(db)?;
    let rows = review_rows(&conn, top, thresholds)?;
    if rows.is_empty() {
        writeln!(output, "review: nothing to review")?;
        return Ok(0);
    }
    // Opening the review asks for proposals; the queue guard dedups,
    // caps and budgets, and nothing is enqueued unconfigured.
    let exec = crate::llm::Exec::from_config(&crate::config::Config::from_env());
    if let Some(exec) = &exec {
        let now = crate::store::now_s();
        for row in &rows {
            crate::llm::enqueue_label(
                &conn,
                &row.scope,
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
            "{}. {} {} score={:.4} {} thr={:.2} why={} rules={} held={} top={}",
            n + 1,
            row.scope_id,
            row.scope,
            row.score,
            row.surface.as_deref().unwrap_or("none"),
            row.threshold,
            row.why.as_str(),
            if row.rule_hits.is_empty() {
                "-".to_string()
            } else {
                row.rule_hits.join(",")
            },
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
                "  llm proposes {} ({:.2}) [{}] cites {}: {}",
                p.label,
                p.confidence,
                if p.signals.is_empty() {
                    "-".to_string()
                } else {
                    p.signals.join(",")
                },
                if p.cited_turns.is_empty() {
                    "-".to_string()
                } else {
                    p.cited_turns
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
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
                    note_operator_label(
                        &conn,
                        exec.as_ref(),
                        &row.scope,
                        &row.scope_id,
                        &label,
                        now_s,
                    )?;
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
                    note_operator_label(
                        &conn,
                        exec.as_ref(),
                        &row.scope,
                        &row.scope_id,
                        label,
                        now_s,
                    )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn why_phrases_match_the_handoff_and_prompt() {
        assert_eq!(
            WhyInQueue::RuleBelowThreshold.phrase(),
            "rule fired below threshold"
        );
        assert_eq!(
            WhyInQueue::ObserveBelowThreshold.phrase(),
            "watched rule fired, score low"
        );
        assert_eq!(
            WhyInQueue::AboveThresholdNoRule.phrase(),
            "score high, no rule fired"
        );
        assert_eq!(WhyInQueue::Uncertain.phrase(), "score uncertain");
        assert_eq!(
            WhyInQueue::UnlabelledProposal.phrase(),
            "proposal unconfirmed"
        );
        assert_eq!(WhyInQueue::Score.phrase(), "scored low, nothing fired");
    }

    #[test]
    fn disagree_is_tier_one() {
        for w in [
            WhyInQueue::RuleBelowThreshold,
            WhyInQueue::ObserveBelowThreshold,
            WhyInQueue::AboveThresholdNoRule,
        ] {
            assert!(w.disagree(), "{w:?}");
        }
        for w in [
            WhyInQueue::Uncertain,
            WhyInQueue::UnlabelledProposal,
            WhyInQueue::Score,
        ] {
            assert!(!w.disagree(), "{w:?}");
        }
    }

    #[test]
    fn decided_list_agrees_on_equal_labels_including_unknown() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE labels (id INTEGER PRIMARY KEY, scope TEXT, scope_id TEXT, \
             label TEXT, source TEXT, created_at INTEGER); \
             INSERT INTO labels (scope, scope_id, label, source, created_at) VALUES \
             ('actor', 'a1', 'malicious', 'llm_proposed', 100), \
             ('actor', 'a1', 'malicious', 'operator', 200), \
             ('actor', 'a2', 'unknown', 'llm_proposed', 100), \
             ('actor', 'a2', 'unknown', 'operator', 210), \
             ('actor', 'a3', 'malicious', 'llm_proposed', 100), \
             ('actor', 'a3', 'benign', 'operator', 220), \
             ('actor', 'a4', 'benign', 'operator', 230), \
             ('actor', 'a5', 'malicious', 'operator', 10);",
        )
        .unwrap();
        let rows = decided_list(&conn, 100).unwrap();
        assert_eq!(rows.len(), 4);
        // Newest first: a4 has no proposal, a3 disagrees, a2 and a1 agree.
        assert_eq!(rows[0].scope_id, "a4");
        assert_eq!(rows[0].proposal, None);
        assert!(!rows[0].agreed);
        assert_eq!(rows[1].scope_id, "a3");
        assert_eq!(rows[1].proposal.as_deref(), Some("malicious"));
        assert!(!rows[1].agreed);
        assert_eq!(rows[2].scope_id, "a2");
        assert!(rows[2].agreed);
        assert_eq!(rows[3].scope_id, "a1");
        assert!(rows[3].agreed);
    }
}
