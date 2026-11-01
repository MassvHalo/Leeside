//! Step F: the shadow report (docs/windside.md section 6).
//!
//! `leesided report shadow --since <unix_s>` reads the store and prints,
//! in order: the false-positive rate on score rows whose actor holds a
//! verified credential, per surface (the headline); agreement between
//! score-above-threshold and block decisions per actor; the disagreements
//! ranked by score; the per-surface score distribution; and the scored
//! vs skipped (cold-start floor) row counts. The model directory comes
//! from `WINDSIDE_MODEL` and supplies the per-surface thresholds.

use crate::rules::features;
use rusqlite::{params, Connection};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("database `{0}` does not exist")]
    MissingDb(String),
    #[error("windside: {0}")]
    Windside(String),
}

/// One disagreement between the score and the rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Disagreement {
    pub actor_id: String,
    pub surface: Option<String>,
    pub score: f64,
    /// `true` when the score was above threshold but no block decided.
    pub above_without_block: bool,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SurfaceFp {
    pub above: usize,
    pub rows: usize,
    pub threshold: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShadowReport {
    pub since_us: i64,
    pub model_version: Option<String>,
    /// Verified-credential FP rate per surface, over score rows.
    pub fp_by_surface: BTreeMap<String, SurfaceFp>,
    /// Score rows on a surface with no threshold in the manifest.
    pub rows_without_threshold: usize,
    /// Per-actor agreement: (agree, total).
    pub agreement: (usize, usize),
    pub above_without_block: usize,
    pub below_with_block: usize,
    pub disagreements: Vec<Disagreement>,
    pub disagreements_total: usize,
    /// Per-surface decile counts over score rows.
    pub distribution: BTreeMap<String, [usize; 10]>,
    pub feature_rows: usize,
    pub scored: usize,
    pub skipped: usize,
}

/// How many disagreements print; the report says how many more exist.
pub const DISAGREEMENTS_SHOWN: usize = 20;

pub fn shadow(
    db: &Path,
    model_dir: Option<&Path>,
    since_s: i64,
) -> Result<ShadowReport, ReportError> {
    if !db.is_file() {
        return Err(ReportError::MissingDb(db.display().to_string()));
    }
    let since_us = since_s * 1_000_000;
    let manifest = model_dir
        .map(crate::windside::load_manifest)
        .transpose()
        .map_err(|e| ReportError::Windside(e.to_string()))?;
    let mut conn = Connection::open(db)?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    crate::store::migrate(&mut conn)?;
    shadow_on(&conn, manifest.as_ref(), since_us, since_s)
}

fn shadow_on(
    conn: &Connection,
    manifest: Option<&crate::windside::Manifest>,
    since_us: i64,
    since_s: i64,
) -> Result<ShadowReport, ReportError> {
    let scores: Vec<(String, Option<String>, f64)> = conn
        .prepare("SELECT actor_id, surface, score FROM scores WHERE ts_us >= ?1")?
        .query_map(params![since_us], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();
    let verified: HashSet<String> = conn
        .prepare(
            "SELECT DISTINCT actor_id FROM turns \
             WHERE credential_status = 'verified' AND actor_id IS NOT NULL AND ts_us >= ?1",
        )?
        .query_map(params![since_us], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    let blocked: HashMap<String, String> = conn
        .prepare(
            "SELECT key, rule FROM decisions \
             WHERE scope = 'actor' AND action = 'block' AND created_at >= ?1",
        )?
        .query_map(params![since_s], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let threshold = |surface: Option<&str>| {
        manifest
            .as_ref()
            .and_then(|m| surface.and_then(|s| m.thresholds.get(s).copied()))
    };

    let mut fp_by_surface: BTreeMap<String, SurfaceFp> = BTreeMap::new();
    let mut rows_without_threshold = 0usize;
    let mut distribution: BTreeMap<String, [usize; 10]> = BTreeMap::new();
    // Actor's max score and surface in the window, for the agreement.
    let mut actor_max: HashMap<&str, (f64, Option<&str>)> = HashMap::new();
    for (actor, surface, score) in &scores {
        let bucket = surface.clone().unwrap_or_else(|| "none".to_string());
        let decile = (score.clamp(0.0, 1.0) * 10.0) as usize;
        distribution.entry(bucket.clone()).or_insert([0; 10])[decile.min(9)] += 1;
        match threshold(surface.as_deref()) {
            None => rows_without_threshold += 1,
            Some(t) => {
                if verified.contains(actor) {
                    let fp = fp_by_surface.entry(bucket).or_insert(SurfaceFp {
                        threshold: Some(t),
                        ..Default::default()
                    });
                    fp.rows += 1;
                    if *score >= t {
                        fp.above += 1;
                    }
                }
            }
        }
        actor_max
            .entry(actor)
            .and_modify(|(m, _)| *m = m.max(*score))
            .or_insert((*score, surface.as_deref()));
    }

    let mut agree = 0usize;
    let mut total = 0usize;
    let mut above_without_block = 0usize;
    let mut below_with_block = 0usize;
    let mut disagreements = Vec::new();
    for (actor, (max, surface)) in &actor_max {
        let Some(t) = threshold(*surface) else {
            continue;
        };
        total += 1;
        let above = *max >= t;
        match (above, blocked.get(*actor)) {
            (true, None) => {
                above_without_block += 1;
                disagreements.push(Disagreement {
                    actor_id: (*actor).to_string(),
                    surface: surface.map(str::to_string),
                    score: *max,
                    above_without_block: true,
                    rule: None,
                });
            }
            (false, Some(rule)) => {
                below_with_block += 1;
                disagreements.push(Disagreement {
                    actor_id: (*actor).to_string(),
                    surface: surface.map(str::to_string),
                    score: *max,
                    above_without_block: false,
                    rule: Some(rule.clone()),
                });
            }
            _ => agree += 1,
        }
    }
    disagreements.sort_by(|a, b| {
        b.above_without_block
            .cmp(&a.above_without_block)
            .then_with(|| {
                if a.above_without_block {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }
            })
    });
    let disagreements_total = disagreements.len();
    disagreements.truncate(DISAGREEMENTS_SHOWN);

    let held_idx = features::NAMES.iter().position(|n| *n == "turns_held");
    let mut feature_rows = 0usize;
    let mut skipped = 0usize;
    if let Some(idx) = held_idx {
        let mut stmt = conn.prepare(
            "SELECT vector FROM feature_vectors \
             WHERE scope = 'actor' AND ts_us >= ?1 AND version = ?2",
        )?;
        let rows = stmt.query_map(params![since_us, features::VERSION], |r| {
            r.get::<_, String>(0)
        })?;
        for row in rows.filter_map(|r| r.ok()) {
            feature_rows += 1;
            let held: Option<f32> = serde_json::from_str::<Vec<f32>>(&row)
                .ok()
                .and_then(|v| v.get(idx).copied());
            if held.is_none_or(|h| h < crate::windside::TURNS_HELD_FLOOR) {
                skipped += 1;
            }
        }
    }

    Ok(ShadowReport {
        since_us,
        model_version: manifest.as_ref().map(|m| m.model_version.clone()),
        fp_by_surface,
        rows_without_threshold,
        agreement: (agree, total),
        above_without_block,
        below_with_block,
        disagreements,
        disagreements_total,
        distribution,
        feature_rows,
        scored: scores.len(),
        skipped,
    })
}

impl std::fmt::Display for ShadowReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "shadow since {}: model {}",
            self.since_us,
            self.model_version.as_deref().unwrap_or("none")
        )?;
        writeln!(f, "verified-credential FP rate per surface (score rows):")?;
        if self.fp_by_surface.is_empty() {
            writeln!(f, "  none")?;
        }
        for (surface, m) in &self.fp_by_surface {
            let rate = if m.rows > 0 {
                m.above as f64 / m.rows as f64
            } else {
                0.0
            };
            writeln!(
                f,
                "  {surface}: {}/{} = {rate:.4} (t={})",
                m.above,
                m.rows,
                m.threshold.map_or("?".to_string(), |t| t.to_string())
            )?;
        }
        if self.rows_without_threshold > 0 {
            writeln!(
                f,
                "  ({} rows on a surface with no threshold)",
                self.rows_without_threshold
            )?;
        }
        let (agree, total) = self.agreement;
        writeln!(
            f,
            "agreement with block decisions: {agree}/{total} actors; \
             above-threshold without block: {}; below-threshold with block: {}",
            self.above_without_block, self.below_with_block
        )?;
        writeln!(f, "disagreements ranked by score:")?;
        for d in &self.disagreements {
            if d.above_without_block {
                writeln!(
                    f,
                    "  {} {} score={:.4} above threshold, no block",
                    d.actor_id,
                    d.surface.as_deref().unwrap_or("none"),
                    d.score
                )?;
            } else {
                writeln!(
                    f,
                    "  {} {} score={:.4} below threshold, blocked by {}",
                    d.actor_id,
                    d.surface.as_deref().unwrap_or("none"),
                    d.score,
                    d.rule.as_deref().unwrap_or("?")
                )?;
            }
        }
        if self.disagreements_total > self.disagreements.len() {
            writeln!(
                f,
                "  (and {} more)",
                self.disagreements_total - self.disagreements.len()
            )?;
        }
        writeln!(f, "score distribution per surface (deciles):")?;
        for (surface, deciles) in &self.distribution {
            writeln!(
                f,
                "  {surface}: {}",
                deciles
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )?;
        }
        writeln!(
            f,
            "rows: {} actor feature rows, {} scored, {} skipped (turns_held < {})",
            self.feature_rows,
            self.scored,
            self.skipped,
            crate::windside::TURNS_HELD_FLOOR
        )
    }
}
