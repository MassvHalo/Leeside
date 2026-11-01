//! SQLite behind one writer thread. Everything that writes sends a
//! `StoreOp` over a bounded hannel; a full channel drops and counts rather
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
    (3, include_str!("../../migrations/0003_v2_extra.sql")),
    (
        4,
        include_str!("../../migrations/0004_credential_status.sql"),
    ),
    (5, include_str!("../../migrations/0005_actors.sql")),
    (
        6,
        include_str!("../../migrations/0006_cluster_and_provisional.sql"),
    ),
    (7, include_str!("../../migrations/0007_feature_vectors.sql")),
    (8, include_str!("../../migrations/0008_feature_surface.sql")),
    (9, include_str!("../../migrations/0009_labels.sql")),
    (
        10,
        include_str!("../../migrations/0010_clock_hardening.sql"),
    ),
    (11, include_str!("../../migrations/0011_scores.sql")),
    (12, include_str!("../../migrations/0012_scores_scope.sql")),
    (13, include_str!("../../migrations/0013_labels_append.sql")),
    (14, include_str!("../../migrations/0014_llm.sql")),
    (15, include_str!("../../migrations/0015_llm_reasoning.sql")),
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
    pub credential_status: Option<String>,
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
    pub turn_id: Option<String>,
    pub actor_id: Option<String>,
    pub country: Option<String>,
    pub cluster_key: Option<String>,
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
    /// Present on a v2 probe: the join is on it alone; a v1 probe joins on `(peer_key, ts_us)`.
    pub turn_id: Option<String>,
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

/// One features-v2 row: a vector over an actor or cluster window.
#[derive(Debug, Clone)]
pub struct FeatureRow {
    pub scope: &'static str,
    pub key: String,
    /// The triggering turn's id (the v1 `peer_key:ts_us` seed when the
    /// turn has none): the row's identity, unaffected by clock steps.
    pub turn_id: String,
    pub ts_us: i64,
    pub version: u32,
    pub values: Vec<f32>,
    /// The triggering turn's surface (`web`, `api`, …); None for v1 turns.
    pub surface: Option<String>,
    /// Negative inter-request intervals in the window: provenance on the
    /// row, never a feature.
    pub clock_anomalies: u32,
}

/// One `labels` row (docs/windside.md section 3): a label on one feature
/// row, written by the auto-labelers, the check join, or label-import.
#[derive(Debug, Clone)]
pub struct LabelRow {
    pub scope: &'static str,
    pub scope_id: String,
    pub surface: Option<String>,
    pub window_end_ts: i64,
    pub label: &'static str,
    pub source: &'static str,
    pub confidence: f64,
    pub kind: Option<String>,
    pub note: Option<String>,
    pub created_at: i64,
}

// `Turn` carries the whole row by value: one hop through the channel per
// event, where a box would be an allocation per event for no gain.
#[allow(clippy::large_enum_variant)]
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
    ActorUpsert(ActorRow),
    BindingUpsert(BindingRow),
    BindingDelete {
        kind: String,
        value: String,
    },
    MergeInsert(MergeRow),
    /// An unconfirmed actor whose last binding expired.
    ActorDelete(String),
    /// The tap's fingerprints for a turn whose event came first (docs/tap.md);
    /// fills only null columns, adds the mismatch flag when asked.
    TurnFingerprint {
        turn_id: String,
        ja4: Option<String>,
        ja4t: Option<String>,
        mismatch: bool,
    },
    Label(LabelRow),
    /// A point-1 label job (docs/llm.md): lands only when no open job
    /// for the subject exists, no proposal went out in the last hour,
    /// and the daily budgets hold (`llm::ENQUEUE_LABEL_SQL`).
    LlmEnqueue {
        scope: String,
        subject_id: String,
        enqueued_by: String,
        now_s: i64,
        daily_calls: u32,
        daily_tokens: u32,
    },
    /// A honeytoken hit: the actor's windows label malicious until `until_us`.
    HoneytokenHit {
        actor_id: String,
        hit_ts_us: i64,
        until_us: i64,
    },
    /// One scored actor feature row (windside §6).
    Score(ScoreRow),
    /// The actor's latest score, for rule matching.
    ActorScore {
        id: String,
        score: f64,
        ts_us: i64,
        top3: String,
    },
    /// Commit everything queued before this and reply.
    Flush(oneshot::Sender<()>),
    /// Flush, reply, and end the writer loop.
    Shutdown(oneshot::Sender<()>),
}

/// An `actors` row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActorRow {
    pub id: String,
    pub opened_us: i64,
    pub last_us: i64,
    pub merged_into: Option<String>,
    pub turns: u32,
    pub confirmed: bool,
}

impl ActorRow {
    pub fn from_actor(a: &crate::actors::Actor) -> ActorRow {
        ActorRow {
            id: format!("{:016x}", a.id),
            opened_us: a.opened_us,
            last_us: a.last_us,
            merged_into: a.merged_into.map(|m| format!("{m:016x}")),
            turns: a.turns,
            confirmed: a.confirmed,
        }
    }
}

/// An `actor_bindings` row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BindingRow {
    pub kind: String,
    pub value: String,
    pub actor_id: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub expires_at: i64,
    pub returned: bool,
}

impl BindingRow {
    pub fn new(ident: crate::actors::Ident, b: crate::actors::Binding) -> BindingRow {
        BindingRow {
            kind: ident.kind.as_str().to_string(),
            value: format!("{:016x}", ident.value),
            actor_id: format!("{:016x}", b.actor),
            first_seen: b.first_seen_us,
            last_seen: b.last_seen_us,
            expires_at: b.expires_us,
            returned: b.returned,
        }
    }
}

/// A `scores` row: one feature row's Windside score, actor or cluster.
/// Keyed (scope, scope_id, turn_id) like `feature_vectors`; ts_us is a
/// plain column.
#[derive(Debug, Clone)]
pub struct ScoreRow {
    pub scope: String,
    pub scope_id: String,
    pub turn_id: String,
    pub surface: Option<String>,
    pub ts_us: i64,
    pub score: f64,
    pub model_version: String,
    pub top3: String,
}

/// An `actor_merges` row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MergeRow {
    pub merged_id: String,
    pub into_id: String,
    pub at_us: i64,
    pub via_kind: String,
}

/// What a turn row gives back for the window rebuild at start.
#[derive(Debug, Clone)]
pub struct ReplayRow {
    pub session_key: String,
    pub peer_key: String,
    pub principal: String,
    pub credential_hash: Option<String>,
    pub credential_status: Option<String>,
    pub actor_id: Option<String>,
    pub ts_us: i64,
    pub route: String,
    pub verb: String,
    pub status: u16,
    pub validation_failed: Option<String>,
    pub exception: Option<String>,
    pub auth_event: Option<String>,
    pub req_shape: String,
    pub bound: String,
    pub bytes_out: i64,
    pub latency_ms: f64,
    pub ua_hash: String,
    pub cluster_key: Option<String>,
    pub surface: Option<String>,
    pub tag_status: Option<String>,
    pub net_hash: Option<String>,
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
                 bound, exception, auth_event, validation_failed, rules_matched, verdict, actor_id, turn_id \
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
                        "actor_id": r.get::<_, Option<String>>(14)?,
                        "turn_id": r.get::<_, Option<String>>(15)?,
                    }))
                },
            )?;
            rows.collect()
        })
    }

    pub fn load_actors(&self) -> Result<Vec<crate::actors::Actor>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT id, opened_us, last_us, merged_into, turns, confirmed FROM actors",
            )?;
            let rows = stmt.query_map([], |r| {
                let id: String = r.get(0)?;
                let merged: Option<String> = r.get(3)?;
                Ok((
                    id,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    merged,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)? != 0,
                ))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(id, opened, last, merged, turns, confirmed)| {
                    Some(crate::actors::actor_row(
                        crate::rules::windows::key16(&id)?,
                        opened,
                        last,
                        merged.as_deref().and_then(crate::rules::windows::key16),
                        turns as u32,
                        confirmed,
                    ))
                })
                .collect())
        })
    }

    pub fn load_bindings(
        &self,
        now_us: i64,
    ) -> Result<Vec<(crate::actors::Ident, crate::actors::Binding)>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT kind, value, actor_id, first_seen, last_seen, expires_at, returned \
                 FROM actor_bindings WHERE expires_at > ?1",
            )?;
            let rows = stmt.query_map(params![now_us], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)? != 0,
                ))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(kind, value, actor, first, last, expires, returned)| {
                    Some((
                        crate::actors::Ident::new(
                            crate::actors::Kind::parse(&kind)?,
                            crate::rules::windows::key16(&value)?,
                        ),
                        crate::actors::Binding {
                            actor: crate::rules::windows::key16(&actor)?,
                            first_seen_us: first,
                            last_seen_us: last,
                            expires_us: expires,
                            returned,
                        },
                    ))
                })
                .collect())
        })
    }

    /// The highest applied migration, for `/health`.
    pub fn migration_version(&self) -> Result<i64, StoreError> {
        self.with_reader(|c| {
            c.query_row(
                "SELECT coalesce(max(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
        })
    }

    /// Latest score per actor, for the in-memory lookup at start.
    /// Unparseable ids are skipped, never fatal.
    pub fn load_scores(&self) -> Result<Vec<(u64, crate::actors::ActorScore)>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT id, score, score_ts, score_top3 FROM actors WHERE score IS NOT NULL",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, f64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(id, score, ts, top3)| {
                    Some((
                        crate::rules::windows::key16(&id)?,
                        crate::actors::ActorScore {
                            score: score as f32,
                            ts_us: ts,
                            top3,
                        },
                    ))
                })
                .collect())
        })
    }

    /// Turns since `since_us`, oldest first, for the window rebuild.
    pub fn turns_since(&self, since_us: i64) -> Result<Vec<ReplayRow>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT session_key, peer_key, principal, credential_hash, credential_status, actor_id, ts_us, \
                 route, verb, status, validation_failed, exception, auth_event, req_shape, bound, bytes_out, \
                 latency_ms, ua_hash, cluster_key, surface, tag_status, net_hash FROM turns WHERE ts_us >= ?1 ORDER BY ingest_seq ASC",
            )?;
            let rows = stmt.query_map(params![since_us], |r| {
                Ok(ReplayRow {
                    session_key: r.get(0)?,
                    peer_key: r.get(1)?,
                    principal: r.get(2)?,
                    credential_hash: r.get(3)?,
                    credential_status: r.get(4)?,
                    actor_id: r.get(5)?,
                    ts_us: r.get(6)?,
                    route: r.get(7)?,
                    verb: r.get(8)?,
                    status: r.get::<_, i64>(9)? as u16,
                    validation_failed: r.get(10)?,
                    exception: r.get(11)?,
                    auth_event: r.get(12)?,
                    req_shape: r.get(13)?,
                    bound: r.get(14)?,
                    bytes_out: r.get(15)?,
                    latency_ms: r.get(16)?,
                    ua_hash: r.get(17)?,
                    cluster_key: r.get(18)?,
                    surface: r.get(19)?,
                    tag_status: r.get(20)?,
                    net_hash: r.get(21)?,
                })
            })?;
            rows.collect()
        })
    }

    /// One actor for the API: its row, the ids merged into it, its live
    /// bindings (hashes only) and its most recent turns.
    pub fn actor_detail(
        &self,
        id: &str,
        now_us: i64,
    ) -> Result<Option<serde_json::Value>, StoreError> {
        self.with_reader(|c| {
            let row = c
                .query_row(
                    "SELECT id, opened_us, last_us, merged_into, turns FROM actors WHERE id = ?1",
                    params![id],
                    |r| {
                        Ok(serde_json::json!({
                            "id": r.get::<_, String>(0)?, "opened_us": r.get::<_, i64>(1)?, "last_us": r.get::<_, i64>(2)?,
                            "merged_into": r.get::<_, Option<String>>(3)?, "turns": r.get::<_, i64>(4)?,
                        }))
                    },
                )
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(serde_json::Value::Null),
                    e => Err(e),
                })?;
            if row.is_null() {
                return Ok(None);
            }
            let mut merged = c.prepare("SELECT merged_id, at_us, via_kind FROM actor_merges WHERE into_id = ?1 ORDER BY at_us")?;
            let merged: Vec<serde_json::Value> = merged
                .query_map(params![id], |r| {
                    Ok(serde_json::json!({ "merged_id": r.get::<_, String>(0)?, "at_us": r.get::<_, i64>(1)?, "via": r.get::<_, String>(2)? }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            let mut bindings = c.prepare(
                "SELECT kind, value, first_seen, last_seen, expires_at FROM actor_bindings WHERE actor_id = ?1 AND expires_at > ?2 ORDER BY kind, last_seen DESC",
            )?;
            let bindings: Vec<serde_json::Value> = bindings
                .query_map(params![id, now_us], |r| {
                    Ok(serde_json::json!({ "kind": r.get::<_, String>(0)?, "value": r.get::<_, String>(1)?, "first_seen": r.get::<_, i64>(2)?,
                        "last_seen": r.get::<_, i64>(3)?, "expires_at": r.get::<_, i64>(4)? }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            let mut ids: Vec<String> = merged.iter().filter_map(|m| m["merged_id"].as_str().map(String::from)).collect();
            ids.push(id.to_string());
            let marks = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT ts, turn_id, route, verb, status, surface, verdict, actor_id FROM turns WHERE actor_id IN ({marks}) ORDER BY ts_us DESC LIMIT 50"
            );
            let mut recent = c.prepare(&sql)?;
            let recent: Vec<serde_json::Value> = recent
                .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
                    Ok(serde_json::json!({ "ts": r.get::<_, f64>(0)?, "turn_id": r.get::<_, Option<String>>(1)?, "route": r.get::<_, String>(2)?,
                        "verb": r.get::<_, String>(3)?, "status": r.get::<_, i64>(4)?, "surface": r.get::<_, Option<String>>(5)?,
                        "verdict": r.get::<_, Option<String>>(6)?, "actor_id": r.get::<_, Option<String>>(7)? }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(Some(serde_json::json!({ "actor": row, "merged": merged, "bindings": bindings, "recent_turns": recent })))
        })
    }

    pub fn count(&self, table: &str) -> Result<i64, StoreError> {
        let sql = format!("SELECT count(*) FROM {table}");
        self.with_reader(|c| c.query_row(&sql, [], |r| r.get(0)))
    }

    /// The live honeytoken hit for an actor, if any: `(hit_ts_us, until_us)`.
    /// The engine's auto-labeler reads this through a write-through cache.
    pub fn honeytoken_hit(&self, actor_id: &str) -> Result<Option<(i64, i64)>, StoreError> {
        self.with_reader(|c| {
            c.query_row(
                "SELECT hit_ts_us, until_us FROM honeytoken_hits WHERE actor_id = ?1",
                params![actor_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })
        })
    }
}

pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A database left at schema 1 with a live decision comes through the
    /// 0002 rebuild of `decisions` with the row intact.
    #[test]
    fn decisions_survive_the_0002_rebuild() {
        let dir = std::env::temp_dir().join(format!("leesided-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL)")
                .unwrap();
            conn.execute_batch(MIGRATIONS[0].1).unwrap();
            conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .unwrap();
            conn.execute(
                "INSERT INTO decisions (scope, key, action, mode, rule, rule_version, created_at, expires_at) \
                 VALUES ('session', 'a1b2c3d4e5f60718', 'block', 'enforce', 'r', 1, 0, 4102444800)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let version: i64 = store
            .with_reader(|c| {
                c.query_row("SELECT max(version) FROM schema_version", [], |r| r.get(0))
            })
            .unwrap();
        assert_eq!(version, MIGRATIONS.last().unwrap().0);
        let decisions = store.load_decisions(now_s()).unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].key, 0xa1b2c3d4e5f60718);
        assert_eq!(decisions[0].scope, crate::rules::model::Scope::Session);
        // The rebuilt table takes the new scope.
        store
            .with_reader(|c| {
                c.execute_batch("")?;
                Ok(())
            })
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Scores key on (scope, scope_id, turn_id) with ts_us a plain column
    /// (0012): two scores for one scope in the same microsecond coexist,
    /// and the same turn twice is refused.
    #[tokio::test]
    async fn scores_key_includes_turn_id() {
        let dir = std::env::temp_dir().join(format!("leesided-scores-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("scores.sqlite");
        let store = Store::open(&path).unwrap();
        for turn in ["t1", "t2"] {
            store.send(StoreOp::Score(ScoreRow {
                scope: "actor".to_string(),
                scope_id: "aa".to_string(),
                turn_id: turn.to_string(),
                surface: Some("web".to_string()),
                ts_us: 1_700_000_000_000_000,
                score: 0.5,
                model_version: "0.1.0".to_string(),
                top3: "[]".to_string(),
            }));
        }
        store.flush().await;
        let n: i64 = store
            .with_reader(|c| c.query_row("SELECT count(*) FROM scores", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(n, 2);
        // The same turn twice violates the key. The writer logs and drops
        // a failing op, so this goes through SQL directly.
        let dup = store.with_reader(|c| {
            c.execute(
                "INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3) \
                 VALUES ('actor', 'aa', 't1', 'web', 1700000000000000, 0.5, '0.1.0', '[]')",
                [],
            )
        });
        assert!(dup.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
