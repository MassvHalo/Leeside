//! The shared state behind both sockets and the API, plus the two sync
//! entry points: `check()` for a probe line and `ingest()` for an event
//! datagram. The servers are thin loops around these.

use crate::config::Config;
use crate::rules::compile::State;
use crate::rules::decisions::{Decision, Decisions};
use crate::rules::eval::{eval, Probe, Verdict};
use crate::rules::features;
use crate::rules::model::{Action, Mode, Scope, Verb};
use crate::rules::service::RulesService;
use crate::rules::stats::{hour_of, Stats};
use crate::rules::symbols::Symbols;
use crate::rules::windows::{id8, key16, principal_key, EventKeys, TurnSummary, Windows};
use crate::store::{self, CheckRecord, FeatureRow, Store, StoreError, StoreOp, TurnRow};
use serde::Deserialize;
use serde_json::value::RawValue;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Default)]
pub struct Counters {
    pub checks: AtomicU64,
    pub bad_probe: AtomicU64,
    pub sticky: AtomicU64,
    pub events: AtomicU64,
    pub bad_event: AtomicU64,
}

pub struct Engine {
    pub cfg: Config,
    pub symbols: Arc<Symbols>,
    pub windows: Windows,
    pub rules: RulesService,
    pub decisions: Decisions,
    pub stats: Stats,
    pub store: Arc<Store>,
    mode: AtomicU8,
    pub counters: Counters,
    pub started: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported schema version {0}")]
    Version(u8),
    #[error("bad field: {0}")]
    Field(&'static str),
}

#[derive(Debug, thiserror::Error)]
#[error("enforce is pinned off by config")]
pub struct ModePinned;

#[derive(Deserialize)]
struct ProbeWire<'a> {
    v: u8,
    ts: f64,
    #[serde(borrow)]
    verb: Cow<'a, str>,
    #[serde(borrow)]
    route: Cow<'a, str>,
    #[serde(borrow)]
    session_key: Cow<'a, str>,
    #[serde(borrow)]
    peer_key: Cow<'a, str>,
    #[serde(borrow)]
    principal: Cow<'a, str>,
}

#[derive(Deserialize)]
struct EventWire<'a> {
    v: u8,
    ts: f64,
    session_key: String,
    peer_key: String,
    principal: String,
    verb: String,
    route: String,
    status: u16,
    latency_ms: f64,
    bytes_in: i64,
    bytes_out: i64,
    req_shape: String,
    resp_shape: String,
    #[serde(borrow)]
    bound: &'a RawValue,
    validation_failed: Option<Vec<String>>,
    exception: Option<String>,
    auth_event: Option<String>,
    #[serde(borrow)]
    gate: Option<&'a RawValue>,
    ua_hash: String,
    dropped_since_last: i64,
}

#[derive(Deserialize)]
struct BoundWire {
    model: Option<String>,
    param: Option<String>,
    id_hash: String,
}

impl Engine {
    /// Open the store, import the install set on first start, load
    /// decisions, mode and rules.
    pub async fn open(cfg: Config) -> Result<Arc<Engine>, StoreError> {
        let store = Arc::new(Store::open(&cfg.db)?);
        let symbols = Arc::new(Symbols::default());
        let rules = RulesService::new(symbols.clone(), store.clone());
        rules.import_install(&cfg.rules_dir).await?;
        rules.load()?;
        let decisions = Decisions::default();
        decisions.load(store.load_decisions(store::now_s())?);
        let mut mode = store.load_mode()?.unwrap_or(Mode::Monitor);
        if !cfg.enforce && mode == Mode::Enforce {
            mode = Mode::Monitor;
        }
        tracing::info!(
            mode = mode.as_str(),
            decisions = decisions.len(),
            "engine open"
        );
        Ok(Arc::new(Engine {
            cfg,
            symbols,
            windows: Windows::default(),
            rules,
            decisions,
            stats: Stats::default(),
            store,
            mode: AtomicU8::new(mode as u8),
            counters: Counters::default(),
            started: Instant::now(),
        }))
    }

    #[inline]
    pub fn mode(&self) -> Mode {
        match self.mode.load(Ordering::Relaxed) {
            2 => Mode::Enforce,
            1 => Mode::Shadow,
            _ => Mode::Monitor,
        }
    }

    pub fn set_mode(&self, mode: Mode) -> Result<(), ModePinned> {
        if mode == Mode::Enforce && !self.cfg.enforce {
            return Err(ModePinned);
        }
        self.mode.store(mode as u8, Ordering::Relaxed);
        self.store.send(StoreOp::ModeSet(mode));
        tracing::info!(mode = mode.as_str(), "global mode set");
        Ok(())
    }

    /// One probe line in, one verdict line out. Never fails: anything
    /// unparseable answers `allow`.
    pub fn check(&self, line: &[u8]) -> Vec<u8> {
        self.counters.checks.fetch_add(1, Ordering::Relaxed);
        let now_s = store::now_s();
        let global = self.mode();
        let rs = self.rules.current();

        let probe: ProbeWire = match serde_json::from_slice(line) {
            Ok(p) => p,
            Err(_) => return self.bad_probe(&rs, global),
        };
        let (verb, session, peer, principal) = match (
            Verb::parse(&probe.verb),
            key16(&probe.session_key),
            key16(&probe.peer_key),
            principal_key(&probe.principal),
        ) {
            (Some(v), Some(s), Some(p), Ok(pr)) if probe.v == 1 => (v, s, p, pr),
            _ => return self.bad_probe(&rs, global),
        };
        let ts_us = store::ts_us(probe.ts);
        let ts_ms = (probe.ts * 1000.0) as u64;
        let hour = hour_of(now_s);

        // Sticky first: session, then peer, then principal.
        let keys: SmallVec<[(Scope, u64); 3]> = [
            Some((Scope::Session, session)),
            Some((Scope::Peer, peer)),
            principal.map(|p| (Scope::Principal, p)),
        ]
        .into_iter()
        .flatten()
        .collect();
        for (scope, key) in keys {
            if let Some(d) = self.decisions.get(scope, key, now_s) {
                self.counters.sticky.fetch_add(1, Ordering::Relaxed);
                let mode = global.min(d.mode);
                let retry_after =
                    (d.action == Action::RateLimit).then(|| (d.expires_at - now_s).max(1) as u32);
                let verdict = Verdict {
                    action: d.action.into(),
                    mode,
                    rule: Some(d.rule.clone()),
                    retry_after,
                    generation: rs.generation,
                    hash: rs.hash_hex.clone(),
                };
                self.stats.bump(
                    &d.rule,
                    d.rule_version,
                    hour,
                    mode,
                    true,
                    mode == Mode::Enforce,
                );
                self.store.send(StoreOp::CheckRecord(CheckRecord {
                    peer_key: probe.peer_key.into_owned(),
                    ts_us,
                    rules_matched: format!(
                        r#"[{{"rule":"{}","version":{},"action":"{}","mode":"{}","sticky":true}}]"#,
                        d.rule,
                        d.rule_version,
                        d.action.as_str(),
                        mode.as_str()
                    ),
                    verdict: verdict.action.as_str().to_string(),
                    ruleset_hash: rs.hash,
                }));
                return line_of(&verdict);
            }
        }

        let p = Probe {
            verb,
            route: &probe.route,
            session_key: session,
            peer_key: peer,
            principal,
            ts_ms,
        };
        let out = eval(&rs, &self.symbols, &self.windows, &p, global, now_s);

        if let Some(i) = out.winner {
            let h = out.hits[i];
            let c = &rs.rules[h.ix as usize];
            let meta = &rs.meta[h.ix as usize];
            let sticky = match h.action {
                Action::Block => Some((Scope::Session, session, now_s + c.block_ttl_s as i64)),
                Action::RateLimit => h
                    .sticky
                    .map(|(s, k)| (s, k, now_s + c.retry_after_s as i64)),
                _ => None,
            };
            if let Some((scope, key, expires_at)) = sticky {
                let d = Decision {
                    scope,
                    key,
                    action: h.action,
                    mode: h.mode,
                    rule: meta.id.clone(),
                    rule_version: meta.version,
                    created_at: now_s,
                    expires_at,
                };
                self.decisions.insert(d.clone());
                self.store.send(StoreOp::DecisionUpsert(d));
            }
        }

        let mut matched = String::with_capacity(16 + out.hits.len() * 72);
        matched.push('[');
        for (n, h) in out.hits.iter().enumerate() {
            let meta = &rs.meta[h.ix as usize];
            let would_act = h.action >= Action::RateLimit;
            let acted = would_act && h.mode == Mode::Enforce && !h.proposed;
            self.stats
                .bump(&meta.id, meta.version, hour, h.mode, would_act, acted);
            if n > 0 {
                matched.push(',');
            }
            matched.push_str(&format!(
                r#"{{"rule":"{}","version":{},"action":"{}","mode":"{}","proposed":{}}}"#,
                meta.id,
                meta.version,
                h.action.as_str(),
                h.mode.as_str(),
                h.proposed
            ));
        }
        matched.push(']');
        self.store.send(StoreOp::CheckRecord(CheckRecord {
            peer_key: probe.peer_key.into_owned(),
            ts_us,
            rules_matched: matched,
            verdict: out.verdict.action.as_str().to_string(),
            ruleset_hash: rs.hash,
        }));
        line_of(&out.verdict)
    }

    fn bad_probe(&self, rs: &crate::rules::compile::RuleSet, global: Mode) -> Vec<u8> {
        self.counters.bad_probe.fetch_add(1, Ordering::Relaxed);
        line_of(&Verdict::allow(rs, global))
    }

    /// One event datagram: validate, feed the windows, write the turn and
    /// its feature row. Rejected events are counted, never logged in full.
    pub fn ingest(&self, data: &[u8]) -> Result<(), IngestError> {
        let ev: EventWire = serde_json::from_slice(data)?;
        if ev.v != 1 {
            return Err(IngestError::Version(ev.v));
        }
        let session = key16(&ev.session_key).ok_or(IngestError::Field("session_key"))?;
        let peer = key16(&ev.peer_key).ok_or(IngestError::Field("peer_key"))?;
        let principal =
            principal_key(&ev.principal).map_err(|_| IngestError::Field("principal"))?;
        let verb = Verb::parse(&ev.verb).ok_or(IngestError::Field("verb"))?;
        if ev.status > 599 {
            return Err(IngestError::Field("status"));
        }
        if !ev.ts.is_finite() || ev.ts <= 0.0 {
            return Err(IngestError::Field("ts"));
        }
        let bound: Vec<BoundWire> = serde_json::from_str(ev.bound.get())?;
        let syms = &self.symbols;
        let summary = TurnSummary {
            ts_ms: (ev.ts * 1000.0) as u64,
            route: syms.intern(&ev.route),
            verb,
            status: ev.status,
            validation_fields: ev
                .validation_failed
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|f| syms.intern(f))
                .collect(),
            exception: ev.exception.as_deref().map(|x| syms.intern(x)),
            auth_event: ev.auth_event.as_deref().map(|x| syms.intern(x)),
            req_shape: syms.intern(&ev.req_shape),
            bound: bound
                .iter()
                .filter_map(|b| {
                    let name = b.model.as_deref().or(b.param.as_deref())?;
                    Some((syms.intern(name), id8(&b.id_hash)?))
                })
                .collect(),
            bytes_out: ev.bytes_out,
            latency_ms: ev.latency_ms as f32,
            ua_hash: id8(&ev.ua_hash).unwrap_or(0),
        };
        let keys = EventKeys {
            session,
            peer,
            principal,
        };
        let ts_ms = summary.ts_ms;
        self.windows.record(&keys, summary);
        let ts_us = store::ts_us(ev.ts);

        if let Some(s) = self.windows.session(session) {
            let p = self.windows.peer(peer);
            let values = features::extract(&s, p.as_deref(), ts_ms, principal.is_none(), syms);
            drop(p);
            drop(s);
            self.store.send(StoreOp::Feature(FeatureRow {
                session_key: ev.session_key.clone(),
                ts_us,
                version: features::VERSION,
                values: values.to_vec(),
            }));
        }

        self.store.send(StoreOp::Turn(TurnRow {
            session_key: ev.session_key,
            ts_us,
            ts: ev.ts,
            peer_key: ev.peer_key,
            principal: ev.principal,
            verb: ev.verb,
            route: ev.route,
            status: ev.status,
            latency_ms: ev.latency_ms,
            bytes_in: ev.bytes_in,
            bytes_out: ev.bytes_out,
            req_shape: ev.req_shape,
            resp_shape: ev.resp_shape,
            bound: ev.bound.get().to_string(),
            validation_failed: ev
                .validation_failed
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            exception: ev.exception,
            auth_event: ev.auth_event,
            gate: ev.gate.map(|g| g.get().to_string()),
            ua_hash: ev.ua_hash,
            dropped_since_last: ev.dropped_since_last,
        }));
        self.counters.events.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// The 60 s sweep: expired decisions, idle windows, expired rules.
    pub async fn sweep(&self) {
        let now_s = store::now_s();
        let now_ms = now_s as u64 * 1000;
        for (scope, key) in self.decisions.sweep(now_s) {
            self.store.send(StoreOp::DecisionDelete { scope, key });
        }
        for closed in self.windows.sweep(now_ms) {
            self.store.send(StoreOp::ConversationClose(closed));
        }
        if let Err(e) = self.rules.expire(now_s).await {
            tracing::error!(error = %e, "rule expiry sweep failed");
        }
    }

    pub fn flush_stats(&self) {
        let rows = self.stats.drain();
        if !rows.is_empty() {
            self.store.send(StoreOp::StatsFlush(rows));
        }
    }

    pub fn health(&self) -> serde_json::Value {
        let rs = self.rules.current();
        let (sessions, peers, principals) = self.windows.counts();
        serde_json::json!({
            "ok": true,
            "uptime_s": self.started.elapsed().as_secs(),
            "mode": self.mode().as_str(),
            "enforce_allowed": self.cfg.enforce,
            "rules": { "loaded": rs.len(), "generation": rs.generation, "hash": &*rs.hash_hex,
                       "invalid": self.rules.invalid().len() },
            "windows": { "sessions": sessions, "peers": peers, "principals": principals,
                         "dropped_for_cap": self.windows.dropped_for_cap() },
            "decisions": self.decisions.len(),
            "symbols": { "count": self.symbols.len(), "overflowed": self.symbols.overflowed() },
            "check": { "total": self.counters.checks.load(Ordering::Relaxed),
                       "bad_probe": self.counters.bad_probe.load(Ordering::Relaxed),
                       "sticky": self.counters.sticky.load(Ordering::Relaxed),
                       "unjoined": self.store.unjoined() },
            "ingest": { "total": self.counters.events.load(Ordering::Relaxed),
                        "bad_event": self.counters.bad_event.load(Ordering::Relaxed) },
            "store": { "dropped": self.store.dropped() },
        })
    }

    /// Flush what is in memory and stop the writer.
    pub async fn shutdown(&self) {
        self.flush_stats();
        self.store.flush().await;
        self.store.close().await;
    }

    /// For tests and the API: write a rule and reload.
    pub async fn write_rule(
        &self,
        rule: crate::rules::model::Rule,
        state: State,
        changed_by: &str,
        reason: Option<String>,
    ) -> Result<u32, StoreError> {
        self.rules.write(rule, state, changed_by, reason).await
    }
}

fn line_of(v: &Verdict) -> Vec<u8> {
    let mut out = serde_json::to_vec(v)
        .unwrap_or_else(|_| b"{\"action\":\"allow\",\"mode\":\"monitor\"}".to_vec());
    out.push(b'\n');
    out
}

/// Everything `serve` started, so a test can find the API and stop it all.
pub struct Running {
    pub api_addr: std::net::SocketAddr,
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    pub fn abort(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Bind both sockets and the API, start the sweeps.
pub async fn serve(engine: Arc<Engine>) -> std::io::Result<Running> {
    let cfg = &engine.cfg;
    std::fs::create_dir_all(&cfg.socket_dir)?;
    let check = crate::check::bind(&cfg.check_sock(), cfg.socket_mode, cfg.socket_gid)?;
    let events = crate::ingest::bind(&cfg.events_sock(), cfg.socket_mode, cfg.socket_gid)?;
    let api = tokio::net::TcpListener::bind(cfg.api).await?;
    let api_addr = api.local_addr()?;
    tracing::info!(check = %cfg.check_sock().display(), events = %cfg.events_sock().display(), api = %api_addr, "listening");

    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(crate::check::serve(engine.clone(), check)));
    tasks.push(tokio::spawn(crate::ingest::serve(engine.clone(), events)));
    tasks.push(tokio::spawn(crate::api::serve(engine.clone(), api)));
    let e = engine.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            e.sweep().await;
        }
    }));
    let e = engine.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        tick.tick().await;
        loop {
            tick.tick().await;
            e.flush_stats();
        }
    }));
    Ok(Running { api_addr, tasks })
}
