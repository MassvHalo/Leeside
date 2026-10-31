//! SQLite behind one writer thread. Everything that writes sends a
//! `StoreOp` over a bounded channel; a full channel drops and counts rather
//! than blocking the check path. A second connection serves reads.

mod writer;

use crate::rules::compile::State;
use crate::rules::decisions::Decision;
use crate::rules::model::{Mode, Rule, ValidationError};
use crate::rules::windows::Closed;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::oneshot;

pub const CHANNEL_CAPACITY: usize = 10_000;

/// The check columns of a turn row: `rules_matched`, `verdict`, `ruleset_hash`.
pub type TurnVerdict = (Option<String>, Option<String>, Option<Vec<u8>>);

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../../migrations/0001_init.sql")),
    (2, include_str!("../../migrations/0002_v2.sql")),
];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid rule")]
    Invalid(Vec<ValidationError>),
    #[error("rule not found")]
    NotFound,
    #[error("store closed")]
    Closed,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// One ingested event, as columns.
#[derive(Debug, Clone)]
pub struct TurnRow {
    pub session_key: String,
    pub ts_us: i64,
    pub ts: f64,
    pub peer_key: String,
    pub principal: String,
    pub verb: String,
    pub route: String,
    pub status: u16,
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
    // v2, all null on a v1 event
    pub surface: Option<String>,
    pub is_asset: Option<bool>,
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
}

/// What the check answered, to be joined onto the turn row once it lands.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    /// The join key is `(peer_key, ts_us)`, not the session: Laravel
    /// regenerates the session id on login, so the probe and the event of
    /// a login turn carry different session keys. The peer key is stable
    /// within a request.
    pub peer_key: String,
    pub ts_us: i64,
    pub rules_matched: String,
    pub verdict: String,
    pub ruleset_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatRow {
    pub rule: Arc<str>,
    pub version: u32,
    pub hour: i64,
    pub mode: Mode,
    pub matched: u64,
    pub would_act: u64,
    pub acted: u64,
}

#[derive(Debug, Clone)]
pub struct FeatureRow {
    pub session_key: String,
    pub ts_us: i64,
    pub version: u32,
    pub values: Vec<f32>,
}

pub enum StoreOp {
    Turn(TurnRow),
    ConversationClose(Closed),
    CheckRecord(CheckRecord),
    DecisionUpsert(Decision),
    DecisionDelete {
        scope: crate::rules::model::Scope,
        key: u64,
    },
    StatsFlush(Vec<StatRow>),
    Feature(FeatureRow),
    RuleWrite {
        rule: Rule,
        state: State,
        changed_by: String,
        reason: Option<String>,
        ack: oneshot::Sender<Result<u32, StoreError>>,
    },
    ModeSet(Mode),
    /// Commit everything queued before this and reply.
    Flush(oneshot::Sender<()>),
    /// Flush, reply, and end the writer loop.
    Shutdown(oneshot::Sender<()>),
}

/// A `rules` row as stored.
#[derive(Debug, Clone)]
pub struct StoredRule {
    pub id: String,
    pub version: u32,
    pub state: State,
    pub mode: String,
    pub action: String,
    pub origin_kind: String,
    pub body: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Filters for `recent_turns`; `verdict = "none"` means no check record.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct TurnQuery {
    pub peer: Option<String>,
    pub session: Option<String>,
    pub route: Option<String>,
    pub verdict: Option<String>,
    #[serde(default)]
    pub limit: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionRow {
    pub version: u32,
    pub state: State,
    pub changed_by: String,
    pub reason: Option<String>,
    pub changed_at: i64,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatView {
    pub version: u32,
    pub hour: i64,
    pub mode: Mode,
    pub matched: u64,
    pub would_act: u64,
    pub acted: u64,
}

pub struct Store {
    tx: SyncSender<StoreOp>,
    reader: Mutex<Connection>,
    dropped: AtomicU64,
    unjoined: Arc<AtomicU64>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl Store {
    /// Open (creating the file and parent directory), migrate, start the
    /// writer thread.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&mut conn)?;

        let reader = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        reader.busy_timeout(std::time::Duration::from_secs(5))?;

        let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
        let unjoined = Arc::new(AtomicU64::new(0));
        let writer_unjoined = unjoined.clone();
        let handle = std::thread::Builder::new()
            .name("leesided-writer".into())
            .spawn(move || writer::run(conn, rx, writer_unjoined))?;
        Ok(Store {
            tx,
            reader: Mutex::new(reader),
            dropped: AtomicU64::new(0),
            unjoined,
            writer: Mutex::new(Some(handle)),
        })
    }

    /// Never blocks: a full channel drops the op and counts it.
    pub fn send(&self, op: StoreOp) {
        match self.tx.try_send(op) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The one op with an ack: validated again on the writer, versioned,
    /// committed, then answered with the new version.
    pub async fn rule_write(
        &self,
        rule: Rule,
        state: State,
        changed_by: &str,
        reason: Option<String>,
    ) -> Result<u32, StoreError> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .try_send(StoreOp::RuleWrite {
                rule,
                state,
                changed_by: changed_by.to_string(),
                reason,
                ack,
            })
            .map_err(|_| StoreError::Closed)?;
        rx.await.map_err(|_| StoreError::Closed)?
    }

    pub async fn flush(&self) {
        let (ack, rx) = oneshot::channel();
        if self.tx.try_send(StoreOp::Flush(ack)).is_ok() {
            let _ = rx.await;
        }
    }

    /// Commit everything queued, stop the writer, join it. Ops sent after
    /// this are dropped and counted.
    pub async fn close(&self) {
        let handle = self.writer.lock().take();
        if let Some(handle) = handle {
            let (ack, rx) = oneshot::channel();
            if self.tx.try_send(StoreOp::Shutdown(ack)).is_ok() {
                let _ = rx.await;
            }
            let _ = tokio::task::spawn_blocking(move || handle.join()).await;
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn unjoined(&self) -> u64 {
        self.unjoined.load(Ordering::Relaxed)
    }

    pub fn with_reader<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        let conn = self.reader.lock();
        Ok(f(&conn)?)
    }

    pub fn rules_count(&self) -> Result<i64, StoreError> {
        self.with_reader(|c| c.query_row("SELECT count(*) FROM rules", [], |r| r.get(0)))
    }

    pub fn load_rules(&self, states: &[State]) -> Result<Vec<StoredRule>, StoreError> {
        let list: Vec<String> = states.iter().map(|s| format!("'{}'", s.as_str())).collect();
        let sql = format!(
            "SELECT id, version, state, mode, action, origin_kind, body, expires_at, created_at, updated_at \
             FROM rules WHERE state IN ({}) ORDER BY id",
            list.join(",")
        );
        self.with_reader(|c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map([], |r| {
                Ok(StoredRule {
                    id: r.get(0)?,
                    version: r.get(1)?,
                    state: State::parse(&r.get::<_, String>(2)?).unwrap_or(State::Retired),
                    mode: r.get(3)?,
                    action: r.get(4)?,
                    origin_kind: r.get(5)?,
                    body: r.get(6)?,
                    expires_at: r.get(7)?,
                    created_at: r.get(8)?,
                    updated_at: r.get(9)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn load_rule(&self, id: &str) -> Result<Option<StoredRule>, StoreError> {
        let all = self.load_rules(&[State::Proposed, State::Active, State::Retired])?;
        Ok(all.into_iter().find(|r| r.id == id))
    }

    pub fn rule_versions(&self, id: &str) -> Result<Vec<VersionRow>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT version, state, changed_by, reason, changed_at, body FROM rule_versions \
                 WHERE id = ?1 ORDER BY version DESC",
            )?;
            let rows = stmt.query_map(params![id], |r| {
                let body: String = r.get(5)?;
                Ok(VersionRow {
                    version: r.get(0)?,
                    state: State::parse(&r.get::<_, String>(1)?).unwrap_or(State::Retired),
                    changed_by: r.get(2)?,
                    reason: r.get(3)?,
                    changed_at: r.get(4)?,
                    body: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                })
            })?;
            rows.collect()
        })
    }

    pub fn rule_stats_since(&self, id: &str, hour_from: i64) -> Result<Vec<StatView>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT version, hour, mode, matched, would_act, acted FROM rule_stats \
                 WHERE rule = ?1 AND hour >= ?2 ORDER BY hour DESC, version DESC",
            )?;
            let rows = stmt.query_map(params![id, hour_from], |r| {
                Ok(StatView {
                    version: r.get(0)?,
                    hour: r.get(1)?,
                    mode: Mode::parse(&r.get::<_, String>(2)?).unwrap_or(Mode::Monitor),
                    matched: r.get::<_, i64>(3)? as u64,
                    would_act: r.get::<_, i64>(4)? as u64,
                    acted: r.get::<_, i64>(5)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    pub fn load_decisions(&self, now_s: i64) -> Result<Vec<Decision>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT scope, key, action, mode, rule, rule_version, created_at, expires_at \
                 FROM decisions WHERE expires_at > ?1",
            )?;
            let rows = stmt.query_map(params![now_s], |r| {
                Ok(Decision::from_row(
                    &r.get::<_, String>(0)?,
                    &r.get::<_, String>(1)?,
                    &r.get::<_, String>(2)?,
                    &r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })?;
            Ok(rows.filter_map(|r| r.ok().flatten()).collect())
        })
    }

    pub fn load_mode(&self) -> Result<Option<Mode>, StoreError> {
        self.with_reader(|c| {
            let v: Option<String> = c
                .query_row("SELECT value FROM settings WHERE key = 'mode'", [], |r| {
                    r.get(0)
                })
                .ok();
            Ok(v.and_then(|s| Mode::parse(&s)))
        })
    }

    /// For tests and the UI: the check columns of one turn row.
    pub fn turn_verdict(
        &self,
        session_key: &str,
        ts_us: i64,
    ) -> Result<Option<TurnVerdict>, StoreError> {
        self.with_reader(|c| {
            c.query_row(
                "SELECT rules_matched, verdict, ruleset_hash FROM turns WHERE session_key = ?1 AND ts_us = ?2",
                params![session_key, ts_us],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })
        })
    }

    /// Newest turns first, for the UI. Each filter is optional; `limit` is
    /// clamped by the caller.
    pub fn recent_turns(&self, q: &TurnQuery) -> Result<Vec<serde_json::Value>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT ts, session_key, peer_key, principal, verb, route, status, latency_ms, \
                 bound, exception, auth_event, validation_failed, rules_matched, verdict \
                 FROM turns \
                 WHERE (?1 IS NULL OR peer_key = ?1) AND (?2 IS NULL OR session_key = ?2) \
                 AND (?3 IS NULL OR route = ?3) \
                 AND (?4 IS NULL OR (?4 = 'none' AND verdict IS NULL) OR verdict = ?4) \
                 ORDER BY ts_us DESC LIMIT ?5",
            )?;
            let json_col = |s: Option<String>| {
                s.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .unwrap_or(serde_json::Value::Null)
            };
            let rows = stmt.query_map(
                params![q.peer, q.session, q.route, q.verdict, q.limit],
                |r| {
                    Ok(serde_json::json!({
                        "ts": r.get::<_, f64>(0)?,
                        "session_key": r.get::<_, String>(1)?,
                        "peer_key": r.get::<_, String>(2)?,
                        "principal": r.get::<_, String>(3)?,
                        "verb": r.get::<_, String>(4)?,
                        "route": r.get::<_, String>(5)?,
                        "status": r.get::<_, i64>(6)?,
                        "latency_ms": r.get::<_, f64>(7)?,
                        "bound": json_col(r.get(8)?),
                        "exception": r.get::<_, Option<String>>(9)?,
                        "auth_event": r.get::<_, Option<String>>(10)?,
                        "validation_failed": json_col(r.get(11)?),
                        "rules_matched": json_col(r.get(12)?),
                        "verdict": r.get::<_, Option<String>>(13)?,
                    }))
                },
            )?;
            rows.collect()
        })
    }

    pub fn count(&self, table: &str) -> Result<i64, StoreError> {
        let sql = format!("SELECT count(*) FROM {table}");
        self.with_reader(|c| c.query_row(&sql, [], |r| r.get(0)))
    }
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")?;
    let current: i64 = conn.query_row(
        "SELECT coalesce(max(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )?;
    for (version, sql) in MIGRATIONS {
        if *version > current {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![version],
            )?;
            tx.commit()?;
            tracing::info!(version, "migrated");
        }
    }
    Ok(())
}

pub fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Microseconds from the event's float seconds: the join key between a
/// probe and its turn.
pub fn ts_us(ts: f64) -> i64 {
    (ts * 1_000_000.0).round() as i64
}
