//! Step C: generator label import (docs/windside.md section 3).
//!
//! `leesided label-import <manifest>` labels every feature window in the
//! run's store after the warmup watermark: run membership, not a
//! wall-clock interval, so a backward clock step cannot exclude a turn.
//! The generator records `warmup_last_turn_id` once its two warmup turns
//! have landed; the store is fresh per run, so everything ingested after
//! it is run traffic. `attack-*` kinds label malicious with source
//! `tool_run`, `benign-*` kinds benign with `synthetic_benign`, both at
//! 0.95; the run kind lands in `labels.kind` for per-kind sampling and
//! eval. Reruns are safe (`INSERT OR IGNORE`).

use crate::store::{now_s, StoreError};
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Manifest {
    pub run_id: String,
    pub kind: String,
    pub warmup_last_turn_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportStats {
    pub actor: usize,
    pub cluster: usize,
}

impl ImportStats {
    pub fn total(self) -> usize {
        self.actor + self.cluster
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("manifest: missing or mistyped field `{0}`")]
    Field(&'static str),
    #[error("manifest: kind `{0}` is neither attack-* nor benign-*")]
    Kind(String),
    #[error("database `{0}` does not exist; label-import targets a run database")]
    MissingDb(String),
    #[error("warmup watermark turn `{0}` is not in the store; refusing to guess membership")]
    Watermark(String),
}

pub fn read_manifest(path: &Path) -> Result<Manifest, ImportError> {
    let text = std::fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let str_field = |name: &'static str| {
        v.get(name)
            .and_then(serde_json::Value::as_str)
            .map(String::from)
            .ok_or(ImportError::Field(name))
    };
    Ok(Manifest {
        run_id: str_field("run_id")?,
        kind: str_field("kind")?,
        warmup_last_turn_id: str_field("warmup_last_turn_id")?,
    })
}

/// Label the run's windows; returns the rows inserted per scope. The
/// hash key is unused since membership replaced the address join; it
/// stays on the signature so the CLI does not change.
pub fn import(
    db: &Path,
    manifest_path: &Path,
    _hash_key: &str,
) -> Result<ImportStats, ImportError> {
    let m = read_manifest(manifest_path)?;
    if !db.is_file() {
        return Err(ImportError::MissingDb(db.display().to_string()));
    }
    let (label, source, confidence) = if m.kind.starts_with("attack-") {
        ("malicious", "tool_run", 0.95)
    } else if m.kind.starts_with("benign-") {
        ("benign", "synthetic_benign", 0.95)
    } else {
        return Err(ImportError::Kind(m.kind.clone()));
    };
    let mut conn = Connection::open(db)?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    crate::store::migrate(&mut conn)?;
    let watermark: Option<i64> = conn
        .query_row(
            "SELECT rowid FROM turns WHERE turn_id = ?1",
            params![m.warmup_last_turn_id],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    let Some(mark) = watermark else {
        return Err(ImportError::Watermark(m.warmup_last_turn_id.clone()));
    };
    // Run stores are append-only, so rowid is the ingest order: every
    // turn after the watermark is run traffic, whatever its stamp says.
    let created_at = now_s();
    let mut stats = ImportStats {
        actor: 0,
        cluster: 0,
    };
    for scope in ["actor", "cluster"] {
        let n = conn.execute(
            "INSERT OR IGNORE INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at) \
             SELECT fv.scope, fv.key, fv.surface, fv.ts_us, ?1, ?2, ?3, ?4, ?5, ?6 \
             FROM feature_vectors fv \
             JOIN turns t ON fv.turn_id = coalesce(t.turn_id, t.peer_key || ':' || t.ts_us) \
             WHERE fv.scope = ?7 AND t.rowid > ?8",
            params![
                label,
                source,
                confidence,
                m.kind,
                m.run_id,
                created_at,
                scope,
                mark
            ],
        )?;
        match scope {
            "actor" => stats.actor = n,
            _ => stats.cluster = n,
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hasher;

    /// Two warmup turns, then 60 run turns in ingest order: run turn 7
    /// is stamped 700 ms below the manifest interval (a backward step)
    /// and run turn 40 comes from another address. Membership labels
    /// all 60; only confirmed actors have rows, so the fixture writes
    /// rows directly.
    fn fixture(path: &Path) {
        let mut conn = Connection::open(path).unwrap();
        crate::store::migrate(&mut conn).unwrap();
        let ip = Hasher::new("k").hex16("ip", "127.0.0.1");
        let other = Hasher::new("k").hex16("ip", "203.0.113.7");
        let start_ms = 1_793_471_600_000i64;
        let mut n = 0i64;
        let mut turn = |ts_ms: i64, hash: &str, actor: Option<&str>| {
            let ts_us = ts_ms * 1000 + (n % 1000);
            let cluster = format!("cc{n:014x}");
            conn.execute(
                "INSERT INTO turns (session_key, ts_us, ts, peer_key, principal, verb, route, status, \
                 latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, ua_hash, dropped_since_last, \
                 ip_hash, ts_ms, turn_id, actor_id, cluster_key) \
                 VALUES (?1, ?2, ?3, 'p', 'anon', 'GET', 'home', 200, \
                 1.0, 0, 0, '[]', 'html', '[]', 'u', 0, ?4, ?5, ?6, ?7, ?8)",
                params![
                    format!("s{n:015x}"),
                    ts_us,
                    ts_us as f64 / 1e6,
                    hash,
                    ts_ms,
                    format!("t{n:031x}"),
                    actor,
                    cluster.clone()
                ],
            )
            .unwrap();
            let turn_id = format!("t{n:031x}");
            conn.execute(
                "INSERT INTO feature_vectors (scope, key, turn_id, ts_us, version, vector) VALUES ('cluster', ?1, ?2, ?3, 2, '[]')",
                params![cluster, turn_id, ts_us],
            )
            .unwrap();
            if let Some(a) = actor {
                conn.execute(
                    "INSERT INTO feature_vectors (scope, key, turn_id, ts_us, version, vector) VALUES ('actor', ?1, ?2, ?3, 2, '[]')",
                    params![a, turn_id, ts_us],
                )
                .unwrap();
            }
            n += 1;
        };
        turn(start_ms - 2_000, &ip, None);
        turn(start_ms - 1_000, &ip, None);
        for i in 0..60i64 {
            let ts_ms = if i == 7 {
                start_ms - 700
            } else {
                start_ms + i * 100
            };
            let hash = if i == 40 { &other } else { &ip };
            let actor = if i < 30 {
                Some("aaaa1111bbbb2222")
            } else {
                None
            };
            turn(ts_ms, hash, actor);
        }
    }

    fn manifest(path: &Path, kind: &str) {
        let start_ms = 1_793_471_600_000i64;
        std::fs::write(
            path,
            serde_json::json!({
                "run_id": "attack-demo-1",
                "kind": kind,
                "start_ms": start_ms,
                "end_ms": start_ms + 60_000,
                "source_address": "127.0.0.1",
                "warmup_last_turn_id": format!("t{:031x}", 1),
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn import_labels_run_membership_after_the_watermark() {
        let dir = std::env::temp_dir().join(format!("leeside-labels-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gen.sqlite");
        let mf = dir.join("manifest.json");
        fixture(&db);
        manifest(&mf, "attack-demo");

        let stats = import(&db, &mf, "k").unwrap();
        // All 60 run turns: the backward-stepped one, the other-address
        // one, and the 58 ordinary ones. The 2 warmups stay unlabeled.
        // Actor rows exist for the first 30 run turns.
        assert_eq!(
            stats,
            ImportStats {
                actor: 30,
                cluster: 60
            }
        );
        let conn = Connection::open(&db).unwrap();
        let (label, source, conf, kind, note): (String, String, f64, String, String) = conn
            .query_row(
                "SELECT label, source, confidence, kind, note FROM labels LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(label, "malicious");
        assert_eq!(source, "tool_run");
        assert_eq!(conf, 0.95);
        assert_eq!(kind, "attack-demo");
        assert_eq!(note, "attack-demo-1");
        // Reruns insert nothing.
        assert_eq!(import(&db, &mf, "k").unwrap().total(), 0);
        // A benign kind labels benign.
        manifest(&mf, "benign-demo");
        let conn = Connection::open(&db).unwrap();
        conn.execute("DELETE FROM labels", []).unwrap();
        drop(conn);
        assert_eq!(import(&db, &mf, "k").unwrap().total(), 90);
        let conn = Connection::open(&db).unwrap();
        let label: String = conn
            .query_row("SELECT DISTINCT label FROM labels", [], |r| r.get(0))
            .unwrap();
        assert_eq!(label, "benign");
        let source: String = conn
            .query_row("SELECT DISTINCT source FROM labels", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source, "synthetic_benign");
        // Unknown kinds refuse.
        manifest(&mf, "weird-demo");
        assert!(matches!(import(&db, &mf, "k"), Err(ImportError::Kind(_))));
    }

    #[test]
    fn test_eligible_excludes_weak_sources() {
        let dir = std::env::temp_dir().join(format!("leeside-labels-v-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gen.sqlite");
        fixture(&db);
        let conn = Connection::open(&db).unwrap();
        for (i, source) in [
            "operator",
            "tool_run",
            "synthetic_benign",
            "honeytoken",
            "verified_business",
            "llm_proposed",
            "rule_decision",
        ]
        .iter()
        .enumerate()
        {
            conn.execute(
                "INSERT INTO labels (scope, scope_id, window_end_ts, label, source, confidence, created_at) \
                 VALUES ('cluster', 'c', ?1, 'benign', ?2, 1.0, 0)",
                params![i as i64, source],
            )
            .unwrap();
        }
        let n: i64 = conn
            .query_row("SELECT count(*) FROM labels_test_eligible", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 4);
        let bad: i64 = conn
            .query_row(
                "SELECT count(*) FROM labels_test_eligible WHERE source IN ('verified_business','llm_proposed','rule_decision')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bad, 0);
    }
}
