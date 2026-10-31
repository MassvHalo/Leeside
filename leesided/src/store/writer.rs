//! The writer thread: drains the channel into one transaction every 50 ms
//! or every 256 ops, whichever comes first. `RuleWrite` is validated again
//! here and acked after commit.

use super::{now_s, CheckRecord, StatRow, StoreError, StoreOp, TurnRow};
use crate::rules::compile::State;
use crate::rules::decisions::Decision;
use crate::rules::model::Rule;
use crate::rules::windows::Closed;
use rusqlite::{params, Connection, Transaction};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const BATCH_OPS: usize = 256;
const BATCH_WAIT: Duration = Duration::from_millis(50);
/// A check record whose turn has not landed in this long is dropped.
const PENDING_TTL: Duration = Duration::from_secs(60);

/// A `RuleWrite` reply, held until its transaction has committed.
type Ack = (
    oneshot::Sender<Result<u32, StoreError>>,
    Result<u32, StoreError>,
);

pub(super) fn run(mut conn: Connection, rx: Receiver<StoreOp>, unjoined: Arc<AtomicU64>) {
    let mut pending: HashMap<(String, i64), (CheckRecord, Instant)> = HashMap::new();
    let mut batch: Vec<StoreOp> = Vec::with_capacity(BATCH_OPS);
    let mut shutdown = false;
    while !shutdown {
        batch.clear();
        match rx.recv_timeout(BATCH_WAIT) {
            Ok(op) => batch.push(op),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let deadline = Instant::now() + BATCH_WAIT;
        while batch.len() < BATCH_OPS {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok(op) => {
                    let terminal = matches!(op, StoreOp::Shutdown(_));
                    batch.push(op);
                    if terminal {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    shutdown = true;
                    break;
                }
            }
        }
        if batch.is_empty() {
            expire_pending(&mut pending, &unjoined);
            continue;
        }
        let mut acks: Vec<Ack> = Vec::new();
        let mut flushes: Vec<oneshot::Sender<()>> = Vec::new();
        let result = (|| -> Result<(), StoreError> {
            let tx = conn.transaction()?;
            for op in batch.drain(..) {
                match op {
                    StoreOp::Turn(row) => {
                        insert_turn(&tx, &row)?;
                        if let Some((rec, _)) = pending.remove(&(row.peer_key.clone(), row.ts_us)) {
                            apply_check(&tx, &rec)?;
                        }
                    }
                    StoreOp::ConversationClose(c) => insert_close(&tx, &c)?,
                    StoreOp::CheckRecord(rec) => {
                        if !apply_check(&tx, &rec)? {
                            pending
                                .insert((rec.peer_key.clone(), rec.ts_us), (rec, Instant::now()));
                        }
                    }
                    StoreOp::DecisionUpsert(d) => upsert_decision(&tx, &d)?,
                    StoreOp::DecisionDelete { scope, key } => {
                        tx.execute(
                            "DELETE FROM decisions WHERE scope = ?1 AND key = ?2",
                            params![scope.as_str(), format!("{key:016x}")],
                        )?;
                    }
                    StoreOp::StatsFlush(rows) => {
                        for r in &rows {
                            upsert_stat(&tx, r)?;
                        }
                    }
                    StoreOp::Feature(f) => {
                        tx.execute(
                            "INSERT OR REPLACE INTO features (session_key, ts_us, version, vector) VALUES (?1, ?2, ?3, ?4)",
                            params![f.session_key, f.ts_us, f.version, serde_json::to_string(&f.values)?],
                        )?;
                    }
                    StoreOp::RuleWrite {
                        rule,
                        state,
                        changed_by,
                        reason,
                        ack,
                    } => {
                        let r = write_rule(&tx, &rule, state, &changed_by, reason.as_deref());
                        acks.push((ack, r));
                    }
                    StoreOp::ModeSet(mode) => {
                        tx.execute(
                            "INSERT INTO settings (key, value) VALUES ('mode', ?1) \
                             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                            params![mode.as_str()],
                        )?;
                    }
                    StoreOp::Flush(ack) => flushes.push(ack),
                    StoreOp::Shutdown(ack) => {
                        flushes.push(ack);
                        shutdown = true;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })();
        if let Err(e) = &result {
            tracing::error!(error = %e, "writer batch failed; batch dropped");
        }
        for (ack, r) in acks {
            let r = match (&result, r) {
                (Err(_), _) => Err(StoreError::Closed),
                (Ok(()), r) => r,
            };
            let _ = ack.send(r);
        }
        for f in flushes {
            let _ = f.send(());
        }
        expire_pending(&mut pending, &unjoined);
    }
    tracing::info!("writer stopped");
}

fn expire_pending(
    pending: &mut HashMap<(String, i64), (CheckRecord, Instant)>,
    unjoined: &AtomicU64,
) {
    let before = pending.len();
    pending.retain(|_, (_, at)| at.elapsed() < PENDING_TTL);
    let dropped = before - pending.len();
    if dropped > 0 {
        unjoined.fetch_add(dropped as u64, Ordering::Relaxed);
    }
}

fn insert_turn(tx: &Transaction, r: &TurnRow) -> Result<(), StoreError> {
    tx.execute(
        "INSERT OR REPLACE INTO turns (session_key, ts_us, ts, peer_key, principal, verb, route, status, \
         latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, validation_failed, exception, \
         auth_event, gate, ua_hash, dropped_since_last, surface, is_asset, credential_kind, \
         credential_hash, credential_status, tag_id, tag_status, ip_hash, net_hash, asn, ip_trust, ua_class, shape_hash, \
         shape, flags, ja4, ja4t, h2_fp, remote_port, ts_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, \
         ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40)",
        params![
            r.session_key,
            r.ts_us,
            r.ts,
            r.peer_key,
            r.principal,
            r.verb,
            r.route,
            r.status,
            r.latency_ms,
            r.bytes_in,
            r.bytes_out,
            r.req_shape,
            r.resp_shape,
            r.bound,
            r.validation_failed,
            r.exception,
            r.auth_event,
            r.gate,
            r.ua_hash,
            r.dropped_since_last,
            r.surface,
            r.is_asset,
            r.credential_kind,
            r.credential_hash,
            r.credential_status,
            r.tag_id,
            r.tag_status,
            r.ip_hash,
            r.net_hash,
            r.asn,
            r.ip_trust,
            r.ua_class,
            r.shape_hash,
            r.shape,
            r.flags,
            r.ja4,
            r.ja4t,
            r.h2_fp,
            r.remote_port,
            r.ts_ms,
        ],
    )?;
    Ok(())
}

/// True when the turn row existed and was updated.
fn apply_check(tx: &Transaction, rec: &CheckRecord) -> Result<bool, StoreError> {
    let n = tx.execute(
        "UPDATE turns SET rules_matched = ?1, verdict = ?2, ruleset_hash = ?3 \
         WHERE peer_key = ?4 AND ts_us = ?5",
        params![
            rec.rules_matched,
            rec.verdict,
            rec.ruleset_hash.as_slice(),
            rec.peer_key,
            rec.ts_us
        ],
    )?;
    Ok(n > 0)
}

fn insert_close(tx: &Transaction, c: &Closed) -> Result<(), StoreError> {
    tx.execute(
        "INSERT OR REPLACE INTO conversations (session_key, peer_key, principal, opened_ts, closed_ts, \
         turns, errors_4xx, errors_5xx, routes, flags) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            format!("{:016x}", c.session_key),
            format!("{:016x}", c.peer_key),
            c.principal.map_or_else(|| "anon".to_string(), |p| format!("{p:016x}")),
            c.opened_ms as f64 / 1000.0,
            c.last_ms as f64 / 1000.0,
            c.turns,
            c.errors_4xx,
            c.errors_5xx,
            c.routes,
            c.flags,
        ],
    )?;
    Ok(())
}

fn upsert_decision(tx: &Transaction, d: &Decision) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO decisions (scope, key, action, mode, rule, rule_version, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT(scope, key) DO UPDATE SET action = excluded.action, mode = excluded.mode, \
         rule = excluded.rule, rule_version = excluded.rule_version, created_at = excluded.created_at, \
         expires_at = excluded.expires_at",
        params![
            d.scope.as_str(),
            format!("{:016x}", d.key),
            d.action.as_str(),
            d.mode.as_str(),
            &*d.rule,
            d.rule_version,
            d.created_at,
            d.expires_at,
        ],
    )?;
    Ok(())
}

fn upsert_stat(tx: &Transaction, r: &StatRow) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO rule_stats (rule, version, hour, mode, matched, would_act, acted) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT(rule, version, hour, mode) DO UPDATE SET matched = matched + excluded.matched, \
         would_act = would_act + excluded.would_act, acted = acted + excluded.acted",
        params![&*r.rule, r.version, r.hour, r.mode.as_str(), r.matched as i64, r.would_act as i64, r.acted as i64],
    )?;
    Ok(())
}

/// Validate, bump the version, append to `rule_versions`, upsert `rules`.
fn write_rule(
    tx: &Transaction,
    rule: &Rule,
    state: State,
    changed_by: &str,
    reason: Option<&str>,
) -> Result<u32, StoreError> {
    let now = now_s();
    let errors = rule.validate(now);
    if !errors.is_empty() {
        return Err(StoreError::Invalid(errors));
    }
    let body = serde_json::to_string(rule)?;
    let prev: Option<(u32, i64)> = tx
        .query_row(
            "SELECT version, created_at FROM rules WHERE id = ?1",
            params![rule.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let version = prev.map_or(1, |(v, _)| v + 1);
    let created_at = prev.map_or(now, |(_, c)| c);
    tx.execute(
        "INSERT INTO rule_versions (id, version, state, body, changed_by, reason, changed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            rule.id,
            version,
            state.as_str(),
            body,
            changed_by,
            reason,
            now
        ],
    )?;
    tx.execute(
        "INSERT INTO rules (id, version, state, mode, action, origin_kind, body, expires_at, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(id) DO UPDATE SET version = excluded.version, state = excluded.state, \
         mode = excluded.mode, action = excluded.action, origin_kind = excluded.origin_kind, \
         body = excluded.body, expires_at = excluded.expires_at, updated_at = excluded.updated_at",
        params![
            rule.id,
            version,
            state.as_str(),
            rule.mode.as_str(),
            rule.action.as_str(),
            origin_kind(rule),
            body,
            rule.expires_at,
            created_at,
            now,
        ],
    )?;
    Ok(version)
}

fn origin_kind(rule: &Rule) -> &'static str {
    use crate::rules::model::OriginKind;
    match rule.origin.kind {
        OriginKind::Install => "install",
        OriginKind::Operator => "operator",
        OriginKind::Spark => "spark",
    }
}
