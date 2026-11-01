//! Step D: training export (docs/windside.md section 2).
//!
//! `leesided export --since <unix_s> --run-id <id> --out <csv>` writes one
//! CSV row per labeled feature window: the v2 feature names in order, then
//! the split keys (`scope`, `scope_id`, `surface`, `kind`, `run_id`,
//! `ts_us`, `ingest_seq`), then the chosen label with its source and
//! confidence. The run id comes from the caller (the store holds no run);
//! the ingest sequence comes from the row's turn and is the split order.
//! The chosen label is the window's
//! highest-confidence one (windside section 5); windows with no label are
//! not training rows and are excluded, as are rows from an older vector
//! version. `clock_anomalies` stays out: it is provenance, not a feature.
//! A manifest with the feature names, counts and time range lands next to
//! the CSV; train.py builds the feature matrix from the manifest's names
//! and never from the key columns.

use crate::rules::features::{self, NAMES};
use rusqlite::{params, Connection};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportStats {
    pub rows: usize,
    pub actor: usize,
    pub cluster: usize,
    pub kinds: BTreeMap<String, usize>,
    pub sources: BTreeMap<String, usize>,
    pub ts_min: Option<i64>,
    pub ts_max: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database `{0}` does not exist")]
    MissingDb(String),
    #[error("row ({0} {1} @{2}) holds {3} values, not {4}")]
    Shape(String, String, i64, usize, usize),
}

pub fn export(
    db: &Path,
    since_s: i64,
    run_id: &str,
    out_csv: &Path,
) -> Result<ExportStats, ExportError> {
    if !db.is_file() {
        return Err(ExportError::MissingDb(db.display().to_string()));
    }
    let mut conn = Connection::open(db)?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    crate::store::migrate(&mut conn)?;
    let mut stmt = conn.prepare(
        "SELECT fv.scope, fv.key, fv.surface, fv.ts_us, fv.vector, \
                l.kind, l.label, l.source, l.confidence, t.ingest_seq \
         FROM feature_vectors fv \
         JOIN labels l ON l.scope = fv.scope AND l.scope_id = fv.key AND l.window_end_ts = fv.ts_us \
         JOIN turns t ON fv.turn_id = coalesce(t.turn_id, t.peer_key || ':' || t.ts_us) \
         WHERE fv.version = ?1 AND fv.ts_us >= ?2 \
           AND l.rowid = (SELECT l2.rowid FROM labels l2 \
                          WHERE l2.scope = fv.scope AND l2.scope_id = fv.key AND l2.window_end_ts = fv.ts_us \
                          ORDER BY l2.confidence DESC, l2.source ASC, l2.created_at DESC, l2.rowid DESC LIMIT 1) \
         ORDER BY fv.ts_us ASC, fv.scope ASC, fv.key ASC",
    )?;
    let rows = stmt.query_map(params![features::VERSION, since_s * 1_000_000], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, f64>(8)?,
            r.get::<_, Option<i64>>(9)?,
        ))
    })?;
    let mut csv = String::new();
    csv.push_str(&NAMES.join(","));
    csv.push_str(",scope,scope_id,surface,kind,run_id,ts_us,ingest_seq,label,source,confidence\n");
    let mut stats = ExportStats {
        rows: 0,
        actor: 0,
        cluster: 0,
        kinds: BTreeMap::new(),
        sources: BTreeMap::new(),
        ts_min: None,
        ts_max: None,
    };
    for row in rows {
        let (scope, key, surface, ts_us, vector, kind, label, source, confidence, ingest_seq) =
            row?;
        let values: Vec<f32> = serde_json::from_str(&vector)?;
        if values.len() != NAMES.len() {
            return Err(ExportError::Shape(
                scope,
                key,
                ts_us,
                values.len(),
                NAMES.len(),
            ));
        }
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                csv.push(',');
            }
            csv.push_str(&v.to_string());
        }
        let seq = ingest_seq.map(|s| s.to_string()).unwrap_or_default();
        for cell in [
            scope.as_str(),
            key.as_str(),
            surface.as_deref().unwrap_or(""),
            kind.as_deref().unwrap_or(""),
            run_id,
            &ts_us.to_string(),
            seq.as_str(),
            label.as_str(),
            source.as_str(),
            &confidence.to_string(),
        ] {
            csv.push(',');
            csv.push_str(cell);
        }
        csv.push('\n');
        stats.rows += 1;
        match scope.as_str() {
            "actor" => stats.actor += 1,
            _ => stats.cluster += 1,
        }
        *stats
            .kinds
            .entry(kind.unwrap_or_else(|| "null".into()))
            .or_default() += 1;
        *stats.sources.entry(source).or_default() += 1;
        stats.ts_min = Some(stats.ts_min.map_or(ts_us, |m: i64| m.min(ts_us)));
        stats.ts_max = Some(stats.ts_max.map_or(ts_us, |m: i64| m.max(ts_us)));
    }
    std::fs::write(out_csv, &csv)?;
    let mut kinds_nested = serde_json::Map::new();
    for (kind, n) in &stats.kinds {
        kinds_nested.insert(
            kind.clone(),
            serde_json::json!({"total": n, "runs": {run_id: n}}),
        );
    }
    let manifest = serde_json::json!({
        "features_version": features::VERSION,
        "feature_names": NAMES.to_vec(),
        "rows": stats.rows,
        "counts_per_scope": {"actor": stats.actor, "cluster": stats.cluster},
        "counts_per_kind": kinds_nested,
        "label_counts_by_source": stats.sources,
        "ts_min": stats.ts_min,
        "ts_max": stats.ts_max,
        "exported_at": crate::store::now_s(),
    });
    std::fs::write(
        manifest_path(out_csv),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(stats)
}

fn manifest_path(out_csv: &Path) -> std::path::PathBuf {
    let mut name = out_csv.as_os_str().to_owned();
    name.push(".manifest.json");
    std::path::PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &Path) {
        let mut conn = Connection::open(path).unwrap();
        crate::store::migrate(&mut conn).unwrap();
        // Window A (actor): two labels, the higher confidence wins.
        // Window B (cluster): one label. Window C: no label, excluded.
        // Window D: an older vector version, excluded.
        for (scope, key, turn_id, ts_us, seq, version) in [
            ("actor", "a1", "tA", 1_000_000i64, 10i64, 2u32),
            ("cluster", "c1", "tB", 2_000_000, 20, 2),
            ("cluster", "c2", "tC", 3_000_000, 30, 2),
            ("cluster", "c3", "tD", 4_000_000, 40, 1),
        ] {
            let vector = format!(
                "[{}]",
                (0..NAMES.len())
                    .map(|i| (i as f32).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            conn.execute(
                "INSERT INTO turns (session_key, ts_us, ts, peer_key, principal, verb, route, status, \
                 latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, ua_hash, dropped_since_last, \
                 turn_id, ingest_seq) \
                 VALUES (?1, ?2, ?3, 'p', 'anon', 'GET', 'home', 200, \
                 1.0, 0, 0, '[]', 'html', '[]', 'u', 0, ?4, ?5)",
                params![format!("s{turn_id}"), ts_us, ts_us as f64 / 1e6, turn_id, seq],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO feature_vectors (scope, key, turn_id, ts_us, version, vector, surface, clock_anomalies) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'web', 1)",
                params![scope, key, turn_id, ts_us, version, vector],
            )
            .unwrap();
        }
        for (scope_id, source, conf, kind, label) in [
            ("a1", "rule_decision", 0.5, None, "malicious"),
            ("a1", "tool_run", 0.95, Some("attack-demo"), "malicious"),
            (
                "c1",
                "synthetic_benign",
                0.95,
                Some("benign-demo"),
                "benign",
            ),
            ("c3", "tool_run", 0.95, Some("attack-demo"), "malicious"),
        ] {
            let (scope, ts) = if scope_id == "a1" {
                ("actor", 1_000_000i64)
            } else {
                (
                    "cluster",
                    if scope_id == "c1" {
                        2_000_000
                    } else {
                        4_000_000
                    },
                )
            };
            conn.execute(
                "INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at) \
                 VALUES (?1, ?2, 'web', ?3, ?4, ?5, ?6, ?7, 'r', 0)",
                params![scope, scope_id, ts, label, source, conf, kind],
            )
            .unwrap();
        }
    }

    #[test]
    fn export_round_trips_labeled_current_windows_only() {
        let dir = std::env::temp_dir().join(format!("leeside-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gen.sqlite");
        let out = dir.join("dataset.csv");
        fixture(&db);

        let stats = export(&db, 0, "attack-demo-1", &out).unwrap();
        assert_eq!(stats.rows, 2);
        assert_eq!((stats.actor, stats.cluster), (1, 1));
        let text = std::fs::read_to_string(&out).unwrap();
        let mut lines = text.lines();
        let header: Vec<&str> = lines.next().unwrap().split(',').collect();
        assert_eq!(&header[..NAMES.len()], &NAMES);
        assert_eq!(
            &header[NAMES.len()..],
            &[
                "scope",
                "scope_id",
                "surface",
                "kind",
                "run_id",
                "ts_us",
                "ingest_seq",
                "label",
                "source",
                "confidence"
            ]
        );
        let rows: Vec<Vec<&str>> = lines.map(|l| l.split(',').collect()).collect();
        assert_eq!(rows.len(), 2);
        // Window A carries the higher-confidence label, not the 0.5 one.
        assert_eq!(rows[0][NAMES.len()], "actor");
        assert_eq!(rows[0][NAMES.len() + 3], "attack-demo");
        assert_eq!(rows[0][NAMES.len() + 4], "attack-demo-1");
        assert_eq!(rows[0][NAMES.len() + 6], "10");
        assert_eq!(rows[0][NAMES.len() + 7], "malicious");
        assert_eq!(rows[0][NAMES.len() + 8], "tool_run");
        assert_eq!(rows[0][NAMES.len() + 9], "0.95");
        // The feature block is the vector, in name order; no provenance.
        assert_eq!(rows[0][0], "0");
        assert_eq!(rows[0][NAMES.len() - 1], (NAMES.len() - 1).to_string());
        assert_eq!(rows[1][NAMES.len()], "cluster");
        assert_eq!(rows[1][NAMES.len() + 3], "benign-demo");
        assert_eq!(rows[1][NAMES.len() + 6], "20");
        // The manifest agrees with the CSV.
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("dataset.csv.manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["features_version"], 2);
        assert_eq!(manifest["rows"], 2);
        assert_eq!(
            manifest["counts_per_scope"],
            serde_json::json!({"actor": 1, "cluster": 1})
        );
        assert_eq!(
            manifest["counts_per_kind"],
            serde_json::json!({
                "attack-demo": {"total": 1, "runs": {"attack-demo-1": 1}},
                "benign-demo": {"total": 1, "runs": {"attack-demo-1": 1}}
            })
        );
        assert_eq!(
            manifest["feature_names"].as_array().unwrap().len(),
            NAMES.len()
        );
        // --since filters by window stamp.
        let out2 = dir.join("recent.csv");
        let stats = export(&db, 2, "attack-demo-1", &out2).unwrap();
        assert_eq!(stats.rows, 1);
        let text = std::fs::read_to_string(&out2).unwrap();
        assert_eq!(text.lines().count(), 2);
    }
}
