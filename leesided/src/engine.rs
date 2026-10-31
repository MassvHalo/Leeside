//! The shared state behind both sockets and the API, plus the two sync
//! entry points: `check()` for a probe line and `ingest()` for an event
//! datagram. The servers are thin loops around these.

use crate::actors::{Ident, Kind, Resolver};
use crate::config::Config;
use crate::enrich::Enricher;
use crate::rules::compile::State;
use crate::rules::decisions::{Decision, Decisions};
use crate::rules::eval::{eval, Probe, Verdict};
use crate::rules::features;
use crate::rules::model::{Action, CredentialStatus, Mode, Scope, Surface, Verb};
use crate::rules::service::RulesService;
use crate::rules::stats::{hour_of, Stats};
use crate::rules::symbols::Symbols;
use crate::rules::windows::{id8, is_hex, key16, principal_key, EventKeys, TurnSummary, Windows};
use crate::store::{self, CheckRecord, FeatureRow, Store, StoreError, StoreOp, TurnRow};
use crate::tap::classes::{is_browser_ua, Class, Ja4Classes};
use crate::tap::conns::{Connections, Hit, Pending};
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
    /// The package's `LEESIDE_HASH_KEY`, for `ip_hash` and `net_hash`;
    /// `None` leaves those columns null.
    pub hasher: Option<crate::hash::Hasher>,
    /// Actor resolution (docs/actors.md): bindings, merges, deterministic ids.
    pub resolver: Resolver,
    /// GeoLite2 lookups for `asn` and `country`; empty when the files are absent.
    pub enrich: Enricher,
    /// The tap's connections and the turns waiting on them (docs/tap.md).
    pub conns: Connections,
    /// JA4 to client class, for `ua_vs_ja4_mismatch`.
    pub ja4_classes: Ja4Classes,
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
    // v2
    #[serde(borrow, default)]
    surface: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    credential_hash: Option<Cow<'a, str>>,
    /// `verified` or `unverified` at probe time; only a verified credential
    /// is an identity that stands in for the peer.
    #[serde(borrow, default)]
    credential_status: Option<Cow<'a, str>>,
    /// Package-minted per request; joins the probe to its event.
    #[serde(borrow, default)]
    turn_id: Option<Cow<'a, str>>,
    /// Present when and only when the tag was valid.
    #[serde(borrow, default)]
    tag_id: Option<Cow<'a, str>>,
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
    // v2: every field optional so a v1 event still parses.
    #[serde(default)]
    surface: Option<String>,
    #[serde(default)]
    is_asset: Option<bool>,
    #[serde(default)]
    credential_kind: Option<String>,
    #[serde(default)]
    credential_hash: Option<String>,
    /// `verified`, `rejected`, `unverified`, or absent without a credential.
    #[serde(default)]
    credential_status: Option<String>,
    #[serde(default)]
    tag_id: Option<String>,
    #[serde(default)]
    tag_status: Option<String>,
    /// Hashed on ingest, never stored.
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    ip_trust: Option<String>,
    #[serde(default)]
    ua_class: Option<String>,
    #[serde(default)]
    shape_hash: Option<String>,
    #[serde(borrow, default)]
    shape: Option<&'a RawValue>,
    #[serde(borrow, default)]
    flags: Option<&'a RawValue>,
    #[serde(default)]
    ja4: Option<String>,
    #[serde(default)]
    ja4t: Option<String>,
    #[serde(default)]
    h2_fp: Option<String>,
    /// Client source port, for telling apart users behind one NAT address.
    #[serde(default)]
    remote_port: Option<u32>,
    /// Request time in whole milliseconds, as the package stamps it.
    #[serde(default)]
    ts_ms: Option<i64>,
    /// Package-minted per request; joins the event to its probe and seeds the actor id.
    #[serde(default)]
    turn_id: Option<String>,
}

/// Schema versions this build ingests. v2 is a superset of v1.
const SCHEMA_VERSIONS: [u8; 2] = [1, 2];

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
        let hasher = cfg.hash_key.as_deref().map(crate::hash::Hasher::new);
        if hasher.is_none() {
            tracing::warn!("LEESIDED_HASH_KEY unset: ip_hash and net_hash stay null");
        }
        // Actor ids only need to be deterministic per install, so without a
        // shared key a fixed one still gives the same id for the same turn.
        let resolver = Resolver::new(crate::hash::Hasher::new(
            cfg.hash_key.as_deref().unwrap_or("leeside-actors"),
        ));
        let now_us = store::now_s() * 1_000_000;
        resolver.load(store.load_actors()?, store.load_bindings(now_us)?);
        let enrich = Enricher::open(cfg.geoip_asn.as_deref(), cfg.geoip_country.as_deref());
        let ja4_classes = Ja4Classes::load(cfg.ja4_classes.as_deref());
        let (actors, strong, weak) = resolver.len();
        tracing::info!(
            mode = mode.as_str(),
            decisions = decisions.len(),
            ip_hashing = hasher.is_some(),
            actors,
            bindings = strong + weak,
            geoip = !enrich.is_empty(),
            "engine open"
        );
        let engine = Arc::new(Engine {
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
            hasher,
            resolver,
            enrich,
            conns: Connections::default(),
            ja4_classes,
        });
        let replayed = engine.replay_windows(now_us - 24 * 3_600 * 1_000_000)?;
        if replayed > 0 {
            tracing::info!(turns = replayed, "windows rebuilt from the last 24 h");
        }
        Ok(engine)
    }

    /// Refill the in-memory windows from stored turns, read-only: they
    /// already carry their actor id, so this neither resolves nor writes.
    fn replay_windows(&self, since_us: i64) -> Result<usize, StoreError> {
        let rows = self.store.turns_since(since_us)?;
        let syms = &self.symbols;
        let mut n = 0;
        for r in &rows {
            let (Some(session), Some(peer)) = (key16(&r.session_key), key16(&r.peer_key)) else {
                continue;
            };
            let principal = principal_key(&r.principal).ok().flatten();
            let credential = r.credential_hash.as_deref().and_then(key16);
            let actor = r.actor_id.as_deref().and_then(key16);
            let bound: Vec<BoundWire> = serde_json::from_str(&r.bound).unwrap_or_default();
            let validation: Vec<String> = r
                .validation_failed
                .as_deref()
                .and_then(|v| serde_json::from_str(v).ok())
                .unwrap_or_default();
            let summary = TurnSummary {
                ts_ms: (r.ts_us / 1000) as u64,
                route: syms.intern(&r.route),
                verb: Verb::parse(&r.verb).unwrap_or(Verb::Get),
                status: r.status,
                validation_fields: validation.iter().map(|f| syms.intern(f)).collect(),
                exception: r.exception.as_deref().map(|x| syms.intern(x)),
                auth_event: r.auth_event.as_deref().map(|x| syms.intern(x)),
                req_shape: syms.intern(&r.req_shape),
                bound: bound
                    .iter()
                    .filter_map(|b| {
                        let name = b.model.as_deref().or(b.param.as_deref())?;
                        Some((syms.intern(name), id8(&b.id_hash)?))
                    })
                    .collect(),
                bytes_out: r.bytes_out,
                latency_ms: r.latency_ms as f32,
                ua_hash: ua_code(&r.ua_hash),
                credential,
                credential_status: r
                    .credential_status
                    .as_deref()
                    .and_then(CredentialStatus::parse)
                    .map_or(0, |s| s.code()),
                surface: surface_code(r.surface.as_deref().and_then(Surface::parse)),
                tag_status: tag_code(r.tag_status.as_deref()),
                net: r.net_hash.as_deref().and_then(key16),
            };
            self.windows.record(
                &EventKeys {
                    session,
                    peer,
                    principal,
                    credential,
                    actor,
                    cluster: r.cluster_key.as_deref().and_then(key16),
                },
                summary,
            );
            n += 1;
        }
        Ok(n)
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
            (Some(v), Some(s), Some(p), Ok(pr)) if SCHEMA_VERSIONS.contains(&probe.v) => {
                (v, s, p, pr)
            }
            _ => return self.bad_probe(&rs, global),
        };
        // v1 has no surface and is always the web group; a v2 probe names it.
        let surface = match probe.surface.as_deref() {
            None => Surface::Web,
            Some(s) => match Surface::parse(s) {
                Some(s) => s,
                None => return self.bad_probe(&rs, global),
            },
        };
        let credential = match probe.credential_hash.as_deref() {
            None | Some("") => None,
            Some(h) => match key16(h) {
                Some(k) => Some(k),
                None => return self.bad_probe(&rs, global),
            },
        };
        let credential_verified =
            credential.is_some() && probe.credential_status.as_deref() == Some("verified");
        let tag = match probe.tag_id.as_deref() {
            None | Some("") => None,
            Some(t) => match key16(t) {
                Some(k) => Some(k),
                None => return self.bad_probe(&rs, global),
            },
        };
        let turn_id = probe
            .turn_id
            .as_deref()
            .filter(|t| is_hex(t, 32))
            .map(str::to_string);
        let ts_us = store::ts_us(probe.ts);
        let ts_ms = (probe.ts * 1000.0) as u64;
        let hour = hour_of(now_s);

        // The actor, by the highest-precedence identifier present with a live
        // binding: verified credential or principal, then session, then tag.
        let mut idents: SmallVec<[Ident; 4]> = SmallVec::new();
        if credential_verified {
            idents.push(Ident::new(
                Kind::Credential,
                credential.expect("verified implies present"),
            ));
        }
        if let Some(p) = principal {
            idents.push(Ident::new(Kind::Principal, p));
        }
        if session != peer {
            idents.push(Ident::new(Kind::Session, session));
        }
        if let Some(t) = tag {
            idents.push(Ident::new(Kind::Tag, t));
        }
        let actor = self.resolver.lookup_any(&idents, ts_us as i64);

        // Sticky first: actor, session, then peer (skipped when a verified
        // credential is presented: the credential is the identity there),
        // then principal, then credential.
        let keys: SmallVec<[(Scope, u64); 5]> = [
            actor.map(|a| (Scope::Actor, a)),
            Some((Scope::Session, session)),
            (!credential_verified).then_some((Scope::Peer, peer)),
            principal.map(|p| (Scope::Principal, p)),
            credential.map(|c| (Scope::Credential, c)),
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
                    turn_id,
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
            surface,
            credential,
            credential_verified,
            actor,
        };
        let out = eval(&rs, &self.symbols, &self.windows, &p, global, now_s);

        if let Some(i) = out.winner {
            let h = out.hits[i];
            let c = &rs.rules[h.ix as usize];
            let meta = &rs.meta[h.ix as usize];
            let sticky = match h.action {
                // A block sticks to the actor when the rule reasons per actor
                // and one is known, so it holds across every identifier bound
                // to it; otherwise to the session as before.
                Action::Block => match (c.sticky_scope, actor) {
                    (Scope::Actor, Some(a)) => {
                        Some((Scope::Actor, a, now_s + c.block_ttl_s as i64))
                    }
                    _ => Some((Scope::Session, session, now_s + c.block_ttl_s as i64)),
                },
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
            turn_id,
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
        if !SCHEMA_VERSIONS.contains(&ev.v) {
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
        // v2 identifiers: validated where they key a window, else carried.
        let surface = match ev.surface.as_deref() {
            None => None,
            Some(s) => Some(Surface::parse(s).ok_or(IngestError::Field("surface"))?),
        };
        let credential = match ev.credential_hash.as_deref() {
            None | Some("") => None,
            Some(h) => Some(key16(h).ok_or(IngestError::Field("credential_hash"))?),
        };
        if let Some(t) = ev.tag_id.as_deref() {
            if !t.is_empty() && key16(t).is_none() {
                return Err(IngestError::Field("tag_id"));
            }
        }
        // The address is hashed here and dropped; without a shared key the
        // columns stay null rather than carrying an unkeyed hash.
        let (ip_hash, net_hash) = match (&self.hasher, ev.ip.as_deref()) {
            (Some(h), Some(ip)) if !ip.is_empty() => {
                let net = crate::hash::net_prefix(ip);
                (Some(h.hex16("ip", ip)), net.map(|n| h.hex16("net", &n)))
            }
            _ => (None, None),
        };
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
            ua_hash: ua_code(&ev.ua_hash),
            credential,
            credential_status: ev
                .credential_status
                .as_deref()
                .and_then(CredentialStatus::parse)
                .map_or(0, |s| s.code()),
            surface: surface_code(surface),
            tag_status: tag_code(ev.tag_status.as_deref()),
            net: net_hash.as_deref().and_then(key16),
        };
        let ts_us = store::ts_us(ev.ts);
        let turn_id = match ev.turn_id.as_deref() {
            None | Some("") => None,
            Some(t) if is_hex(t, 32) => Some(t.to_string()),
            Some(_) => return Err(IngestError::Field("turn_id")),
        };
        // ASN and country from the address before it is dropped; null without the files.
        let enriched = ev
            .ip
            .as_deref()
            .filter(|ip| !ip.is_empty())
            .map(|ip| self.enrich.lookup(ip))
            .unwrap_or_default();

        // Actor resolution (docs/actors.md): what counts as an identifier.
        let credential_verified =
            credential.is_some() && ev.credential_status.as_deref() == Some("verified");
        let tag = match ev.tag_status.as_deref() {
            Some("valid") | Some("issued") => ev.tag_id.as_deref().and_then(key16),
            _ => None,
        };
        let net = net_hash.as_deref().and_then(key16);

        // The tap's fingerprints for this connection (docs/tap.md). The
        // event's own values, set by a trusted proxy, win when present; a
        // turn the tap has not reported yet waits for its datagram.
        let conn_key = match (ev.ip.as_deref(), ev.remote_port) {
            (Some(ip), Some(port)) if !ip.is_empty() && port <= 65_535 => {
                Some(self.conn_key(ip, port as u16))
            }
            _ => None,
        };
        let hit = conn_key.map_or_else(Hit::default, |k| self.conns.lookup(k, summary.ts_ms));
        let ja4 = ev
            .ja4
            .clone()
            .filter(|j| !j.is_empty())
            .or_else(|| hit.ja4.as_deref().map(str::to_string));
        let ja4t = ev
            .ja4t
            .clone()
            .filter(|j| !j.is_empty())
            .or_else(|| hit.ja4t.as_deref().map(str::to_string));
        let browser_ua = is_browser_ua(ev.ua_class.as_deref());
        let mismatch = browser_ua
            && ja4
                .as_deref()
                .is_some_and(|j| self.ja4_classes.classify(j) == Class::Library);
        if let (Some(k), Some(t)) = (conn_key, turn_id.as_deref()) {
            let need_ja4 = ja4.is_none() && hit.tls != Some(false);
            let need_ja4t = ja4t.is_none();
            if need_ja4 || need_ja4t {
                self.conns.defer(
                    k,
                    Pending {
                        turn_id: t.to_string(),
                        ts_ms: summary.ts_ms,
                        since: wall_ms(),
                        browser_ua,
                        need_ja4,
                        need_ja4t,
                    },
                );
            }
        }
        let mut idents: SmallVec<[Ident; 8]> = SmallVec::new();
        let mut shape_ident: Option<Ident> = None;
        if let Some(p) = principal {
            idents.push(Ident::new(Kind::Principal, p));
        }
        if credential_verified {
            idents.push(Ident::new(
                Kind::Credential,
                credential.expect("verified implies present"),
            ));
        }
        if session != peer {
            idents.push(Ident::new(Kind::Session, session));
        }
        if let Some(t) = tag {
            idents.push(Ident::new(Kind::Tag, t));
        }
        if let Some(n) = net {
            idents.push(Ident::new(Kind::Net, n));
            if let Some(ja4) = ja4.as_deref() {
                idents.push(Ident::pair(
                    Kind::Ja4Asn,
                    self.resolver.key("ja4", ja4),
                    enriched.asn.map_or(0, u64::from),
                ));
            }
            if let Some(shape) = ev.shape_hash.as_deref().and_then(key16) {
                shape_ident = Some(Ident::pair(Kind::ShapeNet, shape, n));
                idents.push(Ident::pair(Kind::ShapeNet, shape, n));
            }
            if let Some(ua) = key16(&ev.ua_hash) {
                idents.push(Ident::pair(Kind::UaNet, ua, n));
            }
        }
        // A v1 event has no turn id; the join key stands in as the seed.
        let seed = turn_id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", ev.peer_key, ts_us));
        let resolution = self.resolver.resolve(&seed, ts_us, &idents);
        for a in &resolution.actors_touched {
            self.store
                .send(StoreOp::ActorUpsert(store::ActorRow::from_actor(a)));
        }
        for (ident, b) in &resolution.bindings {
            self.store
                .send(StoreOp::BindingUpsert(store::BindingRow::new(*ident, *b)));
        }
        for m in &resolution.merges {
            self.store.send(StoreOp::MergeInsert(store::MergeRow {
                merged_id: format!("{:016x}", m.merged),
                into_id: format!("{:016x}", m.into),
                at_us: ts_us,
                via_kind: m.via.as_str().to_string(),
            }));
        }
        let actor = resolution.actor;
        // Cookie-less traffic has no actor; the cluster is its window.
        let cluster = match (net_hash.as_deref(), ev.shape_hash.as_deref()) {
            (Some(n), Some(s)) if key16(s).is_some() => Some(self.resolver.cluster_key(n, s)),
            _ => None,
        };

        let keys = EventKeys {
            session,
            peer,
            principal,
            credential,
            actor,
            cluster,
        };
        let ts_ms = summary.ts_ms;
        self.windows.record(&keys, summary);

        // Feature rows (features.rs v2): one per confirmed actor window, one
        // per cluster window. A provisional actor holds one turn and is noise.
        let net_ident = net.map(|n| Ident::new(Kind::Net, n));
        let context = |around: u64| features::Context {
            cluster_actors_net: net_ident
                .map_or(0, |i| self.resolver.cluster_size(i, around, ts_us)),
            shape_cluster_size: shape_ident
                .map_or(0, |i| self.resolver.cluster_size(i, around, ts_us)),
        };
        if let Some(a) = actor.filter(|a| self.resolver.actor(*a).is_some_and(|x| x.confirmed)) {
            if let Some(w) = self.windows.actor(a) {
                let p = self.windows.peer(peer);
                let values = features::extract(
                    &w,
                    p.as_deref(),
                    ts_ms,
                    principal.is_none(),
                    syms,
                    context(a),
                );
                drop(p);
                drop(w);
                self.store.send(StoreOp::Feature(FeatureRow {
                    scope: "actor",
                    key: format!("{a:016x}"),
                    ts_us,
                    version: features::VERSION,
                    values: values.to_vec(),
                }));
            }
        }
        if let Some(c) = cluster {
            if let Some(w) = self.windows.cluster(c) {
                let p = self.windows.peer(peer);
                let values = features::extract(
                    &w,
                    p.as_deref(),
                    ts_ms,
                    principal.is_none(),
                    syms,
                    context(actor.unwrap_or(0)),
                );
                drop(p);
                drop(w);
                self.store.send(StoreOp::Feature(FeatureRow {
                    scope: "cluster",
                    key: format!("{c:016x}"),
                    ts_us,
                    version: features::VERSION,
                    values: values.to_vec(),
                }));
            }
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
            surface: surface.map(|s| s.as_str().to_string()),
            is_asset: ev.is_asset,
            credential_kind: ev.credential_kind,
            credential_hash: ev.credential_hash.filter(|h| !h.is_empty()),
            credential_status: ev.credential_status,
            tag_id: ev.tag_id.filter(|t| !t.is_empty()),
            tag_status: ev.tag_status,
            ip_hash,
            net_hash,
            asn: enriched.asn.map(i64::from),
            country: enriched.country,
            turn_id,
            actor_id: actor.map(|a| format!("{a:016x}")),
            cluster_key: cluster.map(|c| format!("{c:016x}")),
            ip_trust: ev.ip_trust,
            ua_class: ev.ua_class,
            shape_hash: ev.shape_hash,
            shape: ev.shape.map(|s| s.get().to_string()),
            flags: flags_with(ev.flags, mismatch),
            ja4,
            ja4t,
            h2_fp: ev.h2_fp,
            remote_port: ev.remote_port.map(|p| p as i64),
            ts_ms: ev.ts_ms,
        }));
        self.counters.events.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// One datagram from the tap (docs/tap.md). The address is hashed into
    /// the connection key here and dropped; a turn that was waiting on this
    /// connection gets its columns filled.
    pub fn fingerprint(&self, data: &[u8]) -> Result<(), IngestError> {
        let msg: crate::tap::FpMessage = serde_json::from_slice(data)?;
        if msg.v != crate::tap::WIRE_VERSION {
            return Err(IngestError::Version(msg.v));
        }
        if msg.ip.parse::<std::net::IpAddr>().is_err() {
            return Err(IngestError::Field("ip"));
        }
        let key = self.conn_key(&msg.ip, msg.port);
        for fill in self.conns.observe(key, &msg) {
            let mismatch = fill.browser_ua
                && fill
                    .ja4
                    .as_deref()
                    .is_some_and(|j| self.ja4_classes.classify(j) == Class::Library);
            self.store.send(StoreOp::TurnFingerprint {
                turn_id: fill.turn_id,
                ja4: fill.ja4.map(|s| s.to_string()),
                ja4t: fill.ja4t.map(|s| s.to_string()),
                mismatch,
            });
        }
        Ok(())
    }

    /// A keyed hash of `ip:port`, so the connection map holds no address.
    fn conn_key(&self, ip: &str, port: u16) -> u64 {
        self.resolver.key("conn", &format!("{ip}:{port}"))
    }

    /// The 60 s sweep: expired decisions, idle windows, expired rules.
    pub async fn sweep(&self) {
        let now_s = store::now_s();
        let now_ms = now_s as u64 * 1000;
        self.conns.sweep(now_ms);
        for (scope, key) in self.decisions.sweep(now_s) {
            self.store.send(StoreOp::DecisionDelete { scope, key });
        }
        for closed in self.windows.sweep(now_ms) {
            self.store.send(StoreOp::ConversationClose(closed));
        }
        let swept = self.resolver.sweep(now_s * 1_000_000);
        for ident in swept.bindings {
            self.store.send(StoreOp::BindingDelete {
                kind: ident.kind.as_str().to_string(),
                value: format!("{:016x}", ident.value),
            });
        }
        for id in swept.actors {
            self.store.send(StoreOp::ActorDelete(format!("{id:016x}")));
            self.windows.drop_actor(id);
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
        let (sessions, peers, principals, credentials, actor_windows, clusters) =
            self.windows.counts();
        let (actors, strong, weak) = self.resolver.len();
        serde_json::json!({
            "actors": { "count": actors, "strong_bindings": strong, "weak_values": weak,
                        "merges": self.resolver.merges_done.load(Ordering::Relaxed),
                        "windows": actor_windows },
            "geoip": !self.enrich.is_empty(),
            "tap": self.conns.stats(),
            "ja4_classes": self.ja4_classes.len(),
            "ok": true,
            "uptime_s": self.started.elapsed().as_secs(),
            "mode": self.mode().as_str(),
            "enforce_allowed": self.cfg.enforce,
            "rules": { "loaded": rs.len(), "generation": rs.generation, "hash": &*rs.hash_hex,
                       "invalid": self.rules.invalid().len() },
            "windows": { "sessions": sessions, "peers": peers, "principals": principals,
                         "credentials": credentials, "clusters": clusters,
                         "dropped_for_cap": self.windows.dropped_for_cap() },
            "schema_versions": SCHEMA_VERSIONS,
            "features_version": features::VERSION,
            "ip_hashing": self.hasher.is_some(),
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

/// Host clock in milliseconds, for the deferred-fill deadline.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The package's flags array with `ua_vs_ja4_mismatch` appended when the
/// turn earned it; an unparsable array is kept as sent.
fn flags_with(flags: Option<&RawValue>, mismatch: bool) -> Option<String> {
    let raw = flags.map(|f| f.get().to_string());
    if !mismatch {
        return raw;
    }
    let mut list: Vec<String> = raw
        .as_deref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default();
    if !list.iter().any(|f| f == "ua_vs_ja4_mismatch") {
        list.push("ua_vs_ja4_mismatch".to_string());
    }
    serde_json::to_string(&list).ok().or(raw)
}

/// The user-agent hash as a window key: 8 hex (v1) or 16 hex (v2), the same
/// recipe at ingest and at replay so a rebuilt window matches a live one.
fn ua_code(hex: &str) -> u32 {
    id8(hex)
        .or_else(|| key16(hex).map(|k| k as u32))
        .unwrap_or(0)
}

/// `features::SURFACE_*` for a turn summary.
fn surface_code(s: Option<Surface>) -> u8 {
    match s {
        Some(Surface::Web) => features::SURFACE_WEB,
        Some(Surface::Api) => features::SURFACE_API,
        Some(Surface::Webhook) => features::SURFACE_WEBHOOK,
        Some(Surface::Honeypot) => features::SURFACE_HONEYPOT,
        None => 0,
    }
}

/// `features::TAG_*` for a turn summary.
fn tag_code(s: Option<&str>) -> u8 {
    match s {
        Some("absent") => features::TAG_ABSENT,
        Some("issued") => features::TAG_ISSUED,
        Some("valid") => features::TAG_VALID,
        Some("malformed") => features::TAG_MALFORMED,
        Some("bad_mac") => features::TAG_BAD_MAC,
        _ => 0,
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
    let fp = crate::ingest::bind(&cfg.fp_sock(), cfg.socket_mode, cfg.socket_gid)?;
    let api = tokio::net::TcpListener::bind(cfg.api).await?;
    let api_addr = api.local_addr()?;
    tracing::info!(check = %cfg.check_sock().display(), events = %cfg.events_sock().display(), api = %api_addr, "listening");

    let mut tasks = vec![
        tokio::spawn(crate::check::serve(engine.clone(), check)),
        tokio::spawn(crate::ingest::serve(engine.clone(), events)),
        tokio::spawn(crate::ingest::serve_fp(engine.clone(), fp)),
        tokio::spawn(crate::api::serve(engine.clone(), api)),
    ];
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
