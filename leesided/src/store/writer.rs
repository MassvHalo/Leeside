//! The writer thread: drains the channel into one transaction every 50 ms
//! or every 256 ops, whichever comes first. `RuleWrite` is validated again
//! here and acked after commit.

use super::{now_s, CheckRecord, LabelRow, StatRow, StoreError, StoreOp, TurnRow};
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
    // The writer is the only turn inserter, so its counter is the ingest
    // sequence; replays order by it, not by the wall clock.
    let mut next_seq: i64 = conn
        .query_row("SELECT coalesce(max(ingest_seq), 0) FROM turns", [], |r| {
            r.get(0)
        })
        .unwrap_or(0)
        + 1;
    let mut pending: HashMap<String, (CheckRecord, Instant)> = HashMap::new();
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
                        insert_turn(&tx, &row, next_seq)?;
                        next_seq = next_seq.saturating_add(1);
                        if let Some((rec, _)) = pending.remove(&pending_key_for_turn(&row)) {
                            apply_check(&tx, &rec)?;
                        }
                    }
                    StoreOp::ConversationClose(c) => insert_close(&tx, &c)?,
                    StoreOp::CheckRecord(rec) => {
                        if !apply_check(&tx, &rec)? {
                            pending.insert(pending_key(&rec), (rec, Instant::now()));
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
                            "INSERT OR REPLACE INTO feature_vectors (scope, key, turn_id, ts_us, version, vector, surface, clock_anomalies) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![
                                f.scope,
                                f.key,
                                f.turn_id,
                                f.ts_us,
                                f.version,
                                serde_json::to_string(&f.values)?,
                                f.surface,
                                f.clock_anomalies
                            ],
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
                    StoreOp::ActorUpsert(a) => {
                        tx.execute(
                            "INSERT INTO actors (id, opened_us, last_us, merged_into, turns, confirmed) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                             ON CONFLICT(id) DO UPDATE SET last_us = excluded.last_us, merged_into = excluded.merged_into, turns = excluded.turns, confirmed = excluded.confirmed",
                            params![a.id, a.opened_us, a.last_us, a.merged_into, a.turns, a.confirmed as i64],
                        )?;
                    }
                    StoreOp::BindingUpsert(b) => {
                        tx.execute(
                            "INSERT INTO actor_bindings (kind, value, actor_id, first_seen, last_seen, expires_at, returned) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                             ON CONFLICT(kind, value) DO UPDATE SET actor_id = excluded.actor_id, first_seen = excluded.first_seen, \
                             last_seen = excluded.last_seen, expires_at = excluded.expires_at, returned = excluded.returned",
                            params![b.kind, b.value, b.actor_id, b.first_seen, b.last_seen, b.expires_at, b.returned as i64],
                        )?;
                    }
                    StoreOp::BindingDelete { kind, value } => {
                        tx.execute(
                            "DELETE FROM actor_bindings WHERE kind = ?1 AND value = ?2",
                            params![kind, value],
                        )?;
                    }
                    StoreOp::TurnFingerprint {
                        turn_id,
                        ja4,
                        ja4t,
                        mismatch,
                    } => {
                        tx.execute(
                            "UPDATE turns SET ja4 = coalesce(ja4, ?2), ja4t = coalesce(ja4t, ?3), \
                             flags = CASE WHEN ?4 AND coalesce(flags, '[]') NOT LIKE '%ua_vs_ja4_mismatch%' \
                             THEN json_insert(coalesce(flags, '[]'), '$[#]', 'ua_vs_ja4_mismatch') ELSE flags END \
                             WHERE turn_id = ?1",
                            params![turn_id, ja4, ja4t, mismatch],
                        )?;
                    }
                    StoreOp::ActorDelete(id) => {
                        tx.execute(
                            "DELETE FROM actors WHERE id = ?1 AND merged_into IS NULL",
                            params![id],
                        )?;
                    }
                    StoreOp::MergeInsert(m) => {
                        tx.execute(
                            "INSERT OR REPLACE INTO actor_merges (merged_id, into_id, at_us, via_kind) VALUES (?1, ?2, ?3, ?4)",
                            params![m.merged_id, m.into_id, m.at_us, m.via_kind],
                        )?;
                    }
                    StoreOp::Label(l) => {
                        tx.execute(
                            "INSERT OR IGNORE INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                            params![
                                l.scope,
                                l.scope_id,
                                l.surface,
                                l.window_end_ts,
                                l.label,
                                l.source,
                                l.confidence,
                                l.kind,
                                l.note,
                                l.created_at
                            ],
                        )?;
                    }
                    StoreOp::HoneytokenHit {
                        actor_id,
                        hit_ts_us,
                        until_us,
                    } => {
                        tx.execute(
                            "INSERT INTO honeytoken_hits (actor_id, hit_ts_us, until_us) VALUES (?1, ?2, ?3) \
                             ON CONFLICT(actor_id) DO UPDATE SET hit_ts_us = excluded.hit_ts_us, until_us = excluded.until_us",
                            params![actor_id, hit_ts_us, until_us],
                        )?;
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

/// A v2 record waits under its turn id; a v1 record under `(peer_key, ts_us)`.
fn pending_key(rec: &CheckRecord) -> String {
    match &rec.turn_id {
        Some(t) => format!("t:{t}"),
        None => format!("p:{}:{}", rec.peer_key, rec.ts_us),
    }
}

fn pending_key_for_turn(row: &TurnRow) -> String {
    match &row.turn_id {
        Some(t) => format!("t:{t}"),
        None => format!("p:{}:{}", row.peer_key, row.ts_us),
    }
}

fn expire_pending(pending: &mut HashMap<String, (CheckRecord, Instant)>, unjoined: &AtomicU64) {
    let before = pending.len();
    pending.retain(|_, (_, at)| at.elapsed() < PENDING_TTL);
    let dropped = before - pending.len();
    if dropped > 0 {
        unjoined.fetch_add(dropped as u64, Ordering::Relaxed);
    }
}

fn insert_turn(tx: &Transaction, r: &TurnRow, ingest_seq: i64) -> Result<(), StoreError> {
    tx.execute(
        "INSERT OR REPLACE INTO turns (session_key, ts_us, ts, peer_key, principal, verb, route, status, \
         latency_ms, bytes_in, bytes_out, req_shape, resp_shape, bound, validation_failed, exception, \
         auth_event, gate, ua_hash, dropped_since_last, surface, is_asset, credential_kind, \
         credential_hash, credential_status, tag_id, tag_status, ip_hash, net_hash, asn, ip_trust, ua_class, shape_hash, \
         shape, flags, ja4, ja4t, h2_fp, remote_port, ts_ms, turn_id, actor_id, country, cluster_key, ingest_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, \
         ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45)",
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
            r.turn_id,
            r.actor_id,
            r.country,
            r.cluster_key,
            ingest_seq,
        ],
    )?;
    Ok(())
}

/// True when the turn row existed and was updated. A v2 record joins on
/// the package-minted turn id; a v1 record on `(peer_key, ts_us)`.
fn apply_check(tx: &Transaction, rec: &CheckRecord) -> Result<bool, StoreError> {
    let n = match &rec.turn_id {
        Some(t) => tx.execute(
            "UPDATE turns SET rules_matched = ?1, verdict = ?2, ruleset_hash = ?3 WHERE turn_id = ?4",
            params![rec.rules_matched, rec.verdict, rec.ruleset_hash.as_slice(), t],
        )?,
        None => tx.execute(
            "UPDATE turns SET rules_matched = ?1, verdict = ?2, ruleset_hash = ?3 \
             WHERE peer_key = ?4 AND ts_us = ?5",
            params![rec.rules_matched, rec.verdict, rec.ruleset_hash.as_slice(), rec.peer_key, rec.ts_us],
        )?,
    };
    if n > 0 {
        maybe_rule_decision(tx, rec)?;
    }
    Ok(n > 0)
}

/// The `rule_decision` auto-labeler (docs/windside.md section 3): an
/// install-set block is a weak malicious claim on the turn's window at
/// 0.5, on the finest window available (the actor row when the turn has
/// one, else the cluster row). Only blocks label: rate limits and
/// challenges fire on benign bursts too, and watch/log decide nothing.
/// Proposed rules are not decisions. These rows never enter a test set
/// (the `labels_test_eligible` view excludes them).
fn maybe_rule_decision(tx: &Transaction, rec: &CheckRecord) -> Result<(), StoreError> {
    let rule = match blocking_rule(&rec.rules_matched) {
        Some(r) => r,
        None => return Ok(()),
    };
    let turn: Option<TurnWindows> = match &rec.turn_id {
        Some(t) => tx
            .query_row(
                "SELECT actor_id, cluster_key, ts_us FROM turns WHERE turn_id = ?1",
                params![t],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(no_row)?,
        None => tx
            .query_row(
                "SELECT actor_id, cluster_key, ts_us FROM turns WHERE peer_key = ?1 AND ts_us = ?2",
                params![rec.peer_key, rec.ts_us],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(no_row)?,
    };
    let Some((actor_id, cluster_key, ts_us)) = turn else {
        return Ok(());
    };
    // One label on the finest window that exists for this turn.
    for (scope, key) in [("actor", actor_id), ("cluster", cluster_key)] {
        if let Some(scope_id) = key {
            let label = LabelRow {
                scope,
                scope_id,
                // Ignored: the surface comes from the feature row.
                surface: None,
                window_end_ts: ts_us,
                label: "malicious",
                source: "rule_decision",
                confidence: 0.5,
                kind: None,
                note: Some(rule.clone()),
                created_at: now_s(),
            };
            if insert_label_for_row(tx, &label)? > 0 {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Insert a label only when its feature row exists; the surface comes from
/// the row. Returns the rows inserted.
fn insert_label_for_row(tx: &Transaction, label: &LabelRow) -> Result<usize, StoreError> {
    Ok(tx.execute(
        "INSERT OR IGNORE INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at) \
         SELECT ?1, ?2, fv.surface, fv.ts_us, ?3, ?4, ?5, ?6, ?7, ?8 FROM feature_vectors fv \
         WHERE fv.scope = ?1 AND fv.key = ?2 AND fv.ts_us = ?9",
        params![
            label.scope,
            label.scope_id,
            label.label,
            label.source,
            label.confidence,
            label.kind,
            label.note,
            label.created_at,
            label.window_end_ts
        ],
    )?)
}

/// The first block hit's rule id, if any. Sticky replays carry no
/// `proposed` flag and count: the install is still blocking this actor.
/// Only an explicit `proposed: true` disqualifies.
fn blocking_rule(rules_matched: &str) -> Option<String> {
    let hits: Vec<serde_json::Value> = serde_json::from_str(rules_matched).ok()?;
    hits.iter().find_map(|h| {
        if h.get("action")?.as_str()? == "block"
            && h.get("proposed").and_then(|p| p.as_bool()) != Some(true)
        {
            h.get("rule")?.as_str().map(String::from)
        } else {
            None
        }
    })
}

/// A turn's window ids: `(actor_id, cluster_key, ts_us)`.
type TurnWindows = (Option<String>, Option<String>, i64);

fn no_row(e: rusqlite::Error) -> Result<Option<TurnWindows>, rusqlite::Error> {
    match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e),
    }
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
