//! Per-session, per-peer and per-principal windows of the last 64 turns:
//! exactly what a rule can ask about, nothing more. Ingest writes, eval
//! reads, the sweep closes.

use super::model::Verb;
use super::symbols::Sym;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

pub const WINDOW_TURNS: usize = 64;
pub const SESSION_IDLE_MS: u64 = 30 * 60 * 1000;
pub const SESSION_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
pub const PEER_IDLE_MS: u64 = 60 * 60 * 1000;
/// When a map is at its cap, this shorter idle is used to make room first.
pub const CAP_IDLE_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_CAP: usize = 200_000;
pub const FLAG_WATCH: u8 = 1;

/// One turn as a rule sees it. Built by ingest from the event, never from
/// raw values: every string is already a symbol, every id already a hash.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnSummary {
    pub ts_ms: u64,
    pub route: Sym,
    pub verb: Verb,
    pub status: u16,
    /// Empty = did not fail validation.
    pub validation_fields: SmallVec<[Sym; 4]>,
    pub exception: Option<Sym>,
    pub auth_event: Option<Sym>,
    pub req_shape: Sym,
    /// (model, id_hash parsed from the 8 hex).
    pub bound: SmallVec<[(Sym, u32); 2]>,
    /// -1 for a streamed response.
    pub bytes_out: i64,
    pub latency_ms: f32,
    /// The 8-hex hashed user agent, for hijack features.
    pub ua_hash: u32,
    /// The presented `credential_hash`, when any.
    pub credential: Option<u64>,
    /// `CredentialStatus::code()`; 0 without a credential.
    pub credential_status: u8,
    /// `features::SURFACE_*`; 0 for a v1 event.
    pub surface: u8,
    /// `features::TAG_*`; 0 when the tag middleware did not run.
    pub tag_status: u8,
    /// `net_hash` as a key, for `credential_moved`.
    pub net: Option<u64>,
}

/// A ring of the newest `WINDOW_TURNS` turns plus the running totals the
/// close summary needs. The buffer grows lazily, so a three-turn session
/// costs a few hundred bytes, not a full ring.
#[derive(Debug)]
pub struct Window {
    turns: VecDeque<TurnSummary>,
    pub opened_ms: u64,
    pub last_ms: u64,
    pub flags: u8,
    pub peer_key: u64,
    /// Last non-anon principal seen.
    pub principal: Option<u64>,
    pub total: u32,
    pub errors_4xx: u32,
    pub errors_5xx: u32,
}

impl Window {
    fn new(now_ms: u64, peer_key: u64, principal: Option<u64>) -> Self {
        Window {
            turns: VecDeque::with_capacity(8),
            opened_ms: now_ms,
            last_ms: now_ms,
            flags: 0,
            peer_key,
            principal,
            total: 0,
            errors_4xx: 0,
            errors_5xx: 0,
        }
    }

    fn push(&mut self, t: TurnSummary, principal: Option<u64>) {
        if self.turns.len() == WINDOW_TURNS {
            self.turns.pop_front();
        }
        self.last_ms = self.last_ms.max(t.ts_ms);
        self.total = self.total.saturating_add(1);
        match t.status {
            400..=499 => self.errors_4xx = self.errors_4xx.saturating_add(1),
            500..=599 => self.errors_5xx = self.errors_5xx.saturating_add(1),
            _ => {}
        }
        if principal.is_some() {
            self.principal = principal;
        }
        self.turns.push_back(t);
    }

    /// Newest first. The scan order every condition uses.
    #[inline]
    pub fn newest(&self) -> impl Iterator<Item = &TurnSummary> + '_ {
        self.turns.iter().rev()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.turns.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.turns.is_empty()
    }

    /// Negative inter-request intervals between consecutive turns in
    /// ingest order: how many times the wall clock stepped backward
    /// inside this window. Provenance for the row, never a feature.
    pub fn clock_anomalies(&self) -> u32 {
        self.turns
            .iter()
            .zip(self.turns.iter().skip(1))
            .filter(|(prev, next)| next.ts_ms < prev.ts_ms)
            .count() as u32
    }

    fn distinct_routes(&self) -> u32 {
        let mut seen: SmallVec<[Sym; 16]> = SmallVec::new();
        for t in &self.turns {
            if !seen.contains(&t.route) {
                seen.push(t.route);
            }
        }
        seen.len() as u32
    }
}

/// The three hashes of an event, already parsed from hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventKeys {
    pub session: u64,
    pub peer: u64,
    /// `None` for `anon`.
    pub principal: Option<u64>,
    /// `credential_hash` on `api`/`webhook` turns; `None` otherwise (v1 events always).
    pub credential: Option<u64>,
    /// The resolved actor (docs/actors.md); `None` for a turn with no strong identifier.
    pub actor: Option<u64>,
    /// `cluster_key = hash(net_hash || shape_hash)`: the window cookie-less traffic still has.
    pub cluster: Option<u64>,
}

/// The conversation-close summary, emitted by the sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    pub session_key: u64,
    pub peer_key: u64,
    pub principal: Option<u64>,
    pub opened_ms: u64,
    pub last_ms: u64,
    pub turns: u32,
    pub errors_4xx: u32,
    pub errors_5xx: u32,
    pub routes: u32,
    pub flags: u8,
}

pub struct Windows {
    sessions: DashMap<u64, Window>,
    peers: DashMap<u64, Window>,
    principals: DashMap<u64, Window>,
    credentials: DashMap<u64, Window>,
    actors: DashMap<u64, Window>,
    clusters: DashMap<u64, Window>,
    cap: usize,
    /// Turns not indexed because the map was full even after making room.
    dropped_for_cap: AtomicU64,
}

impl Default for Windows {
    fn default() -> Self {
        Self::with_cap(DEFAULT_CAP)
    }
}

impl Windows {
    pub fn with_cap(cap: usize) -> Self {
        Windows {
            sessions: DashMap::new(),
            peers: DashMap::new(),
            principals: DashMap::new(),
            credentials: DashMap::new(),
            actors: DashMap::new(),
            clusters: DashMap::new(),
            cap,
            dropped_for_cap: AtomicU64::new(0),
        }
    }

    /// Record one turn in every window its keys name.
    pub fn record(&self, keys: &EventKeys, t: TurnSummary) {
        let now_ms = t.ts_ms;
        self.push_into(&self.peers, keys.peer, keys, &t, now_ms);
        if let Some(p) = keys.principal {
            self.push_into(&self.principals, p, keys, &t, now_ms);
        }
        if let Some(c) = keys.credential {
            self.push_into(&self.credentials, c, keys, &t, now_ms);
        }
        if let Some(a) = keys.actor {
            self.push_into(&self.actors, a, keys, &t, now_ms);
        }
        if let Some(c) = keys.cluster {
            self.push_into(&self.clusters, c, keys, &t, now_ms);
        }
        self.push_into(&self.sessions, keys.session, keys, &t, now_ms);
    }

    fn push_into(
        &self,
        map: &DashMap<u64, Window>,
        key: u64,
        keys: &EventKeys,
        t: &TurnSummary,
        now_ms: u64,
    ) {
        if let Some(mut w) = map.get_mut(&key) {
            w.push(t.clone(), keys.principal);
            return;
        }
        if map.len() >= self.cap {
            map.retain(|_, w| now_ms.saturating_sub(w.last_ms) <= CAP_IDLE_MS);
            if map.len() >= self.cap {
                self.dropped_for_cap.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        map.entry(key)
            .or_insert_with(|| Window::new(now_ms, keys.peer, keys.principal))
            .push(t.clone(), keys.principal);
    }

    #[inline]
    pub fn session(&self, key: u64) -> Option<Ref<'_, u64, Window>> {
        self.sessions.get(&key)
    }

    #[inline]
    pub fn peer(&self, key: u64) -> Option<Ref<'_, u64, Window>> {
        self.peers.get(&key)
    }

    #[inline]
    pub fn principal(&self, key: u64) -> Option<Ref<'_, u64, Window>> {
        self.principals.get(&key)
    }

    #[inline]
    pub fn credential(&self, key: u64) -> Option<Ref<'_, u64, Window>> {
        self.credentials.get(&key)
    }

    #[inline]
    pub fn actor(&self, key: u64) -> Option<Ref<'_, u64, Window>> {
        self.actors.get(&key)
    }

    #[inline]
    pub fn cluster(&self, key: u64) -> Option<Ref<'_, u64, Window>> {
        self.clusters.get(&key)
    }

    /// An unconfirmed actor swept by the resolver takes its window with it.
    pub fn drop_actor(&self, key: u64) {
        self.actors.remove(&key);
    }

    pub fn set_flag(&self, session: u64, flag: u8) {
        if let Some(mut w) = self.sessions.get_mut(&session) {
            w.flags |= flag;
        }
    }

    /// Evict idle windows; sessions idle 30 min or older than 24 h close
    /// with a summary, peers and principals idle 60 min just go.
    pub fn sweep(&self, now_ms: u64) -> Vec<Closed> {
        let stale: Vec<u64> = self
            .sessions
            .iter()
            .filter(|e| {
                let w = e.value();
                now_ms.saturating_sub(w.last_ms) > SESSION_IDLE_MS
                    || now_ms.saturating_sub(w.opened_ms) > SESSION_MAX_AGE_MS
            })
            .map(|e| *e.key())
            .collect();
        let mut closed = Vec::with_capacity(stale.len());
        for key in stale {
            if let Some((_, w)) = self.sessions.remove(&key) {
                closed.push(Closed {
                    session_key: key,
                    peer_key: w.peer_key,
                    principal: w.principal,
                    opened_ms: w.opened_ms,
                    last_ms: w.last_ms,
                    turns: w.total,
                    errors_4xx: w.errors_4xx,
                    errors_5xx: w.errors_5xx,
                    routes: w.distinct_routes(),
                    flags: w.flags,
                });
            }
        }
        self.peers
            .retain(|_, w| now_ms.saturating_sub(w.last_ms) <= PEER_IDLE_MS);
        self.principals
            .retain(|_, w| now_ms.saturating_sub(w.last_ms) <= PEER_IDLE_MS);
        self.credentials
            .retain(|_, w| now_ms.saturating_sub(w.last_ms) <= PEER_IDLE_MS);
        self.actors
            .retain(|_, w| now_ms.saturating_sub(w.last_ms) <= PEER_IDLE_MS);
        self.clusters
            .retain(|_, w| now_ms.saturating_sub(w.last_ms) <= PEER_IDLE_MS);
        closed
    }

    /// (sessions, peers, principals, credentials, actors, clusters)
    pub fn counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        (
            self.sessions.len(),
            self.peers.len(),
            self.principals.len(),
            self.credentials.len(),
            self.actors.len(),
            self.clusters.len(),
        )
    }

    pub fn dropped_for_cap(&self) -> u64 {
        self.dropped_for_cap.load(Ordering::Relaxed)
    }
}

/// Exactly `len` lowercase or uppercase hex digits.
pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A 16-hex hash as the u64 the maps key on.
pub fn key16(hex: &str) -> Option<u64> {
    if hex.len() != 16 {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// A principal that is neither `anon` nor 16 hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadKey;

/// `anon` is `None`; anything else must be 16 hex.
pub fn principal_key(s: &str) -> Result<Option<u64>, BadKey> {
    if s == "anon" {
        Ok(None)
    } else {
        key16(s).map(Some).ok_or(BadKey)
    }
}

/// An 8-hex id hash as the u32 `bound` carries.
pub fn id8(hex: &str) -> Option<u32> {
    if hex.len() != 8 {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
pub(crate) fn turn(ts_ms: u64, route: Sym, status: u16) -> TurnSummary {
    TurnSummary {
        ts_ms,
        route,
        verb: Verb::Get,
        status,
        validation_fields: SmallVec::new(),
        exception: None,
        auth_event: None,
        req_shape: Sym(0),
        bound: SmallVec::new(),
        bytes_out: 0,
        latency_ms: 0.0,
        ua_hash: 0,
        credential: None,
        credential_status: 0,
        surface: 0,
        tag_status: 0,
        net: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: EventKeys = EventKeys {
        session: 1,
        peer: 2,
        principal: None,
        credential: None,
        actor: None,
        cluster: None,
    };

    #[test]
    fn keys_parse() {
        assert_eq!(key16("b8c8989a1e739961"), Some(0xb8c8989a1e739961));
        assert_eq!(key16("b8c8989a1e73996"), None);
        assert_eq!(key16("zzzzzzzzzzzzzzzz"), None);
        assert_eq!(principal_key("anon"), Ok(None));
        assert_eq!(
            principal_key("0f1e2d3c4b5a6978"),
            Ok(Some(0x0f1e2d3c4b5a6978))
        );
        assert_eq!(principal_key("nope"), Err(BadKey));
        assert_eq!(id8("7f3a9c21"), Some(0x7f3a9c21));
        assert_eq!(id8("7f3a9c2"), None);
    }

    #[test]
    fn ring_holds_the_newest_64_and_counts_everything() {
        let w = Windows::default();
        for i in 0..70u64 {
            let status = if i % 10 == 0 { 404 } else { 200 };
            w.record(&KEYS, turn(1000 + i, Sym(i as u32 % 3), status));
        }
        let s = w.session(1).unwrap();
        assert_eq!(s.len(), WINDOW_TURNS);
        assert_eq!(s.newest().next().unwrap().ts_ms, 1069);
        assert_eq!(s.newest().last().unwrap().ts_ms, 1006);
        assert_eq!(s.total, 70);
        assert_eq!(s.errors_4xx, 7);
        assert_eq!(s.opened_ms, 1000);
        assert_eq!(s.last_ms, 1069);
        assert_eq!(w.counts(), (1, 1, 0, 0, 0, 0));
    }

    #[test]
    fn principal_window_only_when_authenticated() {
        let w = Windows::default();
        w.record(&KEYS, turn(1, Sym(0), 200));
        w.record(
            &EventKeys {
                principal: Some(9),
                ..KEYS
            },
            turn(2, Sym(0), 200),
        );
        assert_eq!(w.counts(), (1, 1, 1, 0, 0, 0));
        assert_eq!(w.session(1).unwrap().principal, Some(9));
        assert!(w.principal(9).is_some());
    }

    #[test]
    fn sweep_closes_idle_sessions_with_a_summary() {
        let w = Windows::default();
        w.record(&KEYS, turn(1_000, Sym(0), 200));
        w.record(&KEYS, turn(2_000, Sym(1), 500));
        w.record(&EventKeys { session: 7, ..KEYS }, turn(2_000, Sym(0), 200));
        w.set_flag(1, FLAG_WATCH);
        let closed = w.sweep(2_000 + SESSION_IDLE_MS);
        assert!(closed.is_empty());
        let mut closed = w.sweep(2_001 + SESSION_IDLE_MS);
        closed.sort_by_key(|c| c.session_key);
        assert_eq!(
            closed,
            vec![
                Closed {
                    session_key: 1,
                    peer_key: 2,
                    principal: None,
                    opened_ms: 1_000,
                    last_ms: 2_000,
                    turns: 2,
                    errors_4xx: 0,
                    errors_5xx: 1,
                    routes: 2,
                    flags: FLAG_WATCH,
                },
                Closed {
                    session_key: 7,
                    peer_key: 2,
                    principal: None,
                    opened_ms: 2_000,
                    last_ms: 2_000,
                    turns: 1,
                    errors_4xx: 0,
                    errors_5xx: 0,
                    routes: 1,
                    flags: 0,
                },
            ]
        );
        assert_eq!(w.counts(), (0, 1, 0, 0, 0, 0));
        w.sweep(2_001 + PEER_IDLE_MS);
        assert_eq!(w.counts(), (0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn sweep_closes_sessions_older_than_a_day_even_when_active() {
        let w = Windows::default();
        w.record(&KEYS, turn(0, Sym(0), 200));
        w.record(&KEYS, turn(SESSION_MAX_AGE_MS, Sym(0), 200));
        assert_eq!(w.sweep(SESSION_MAX_AGE_MS + 1).len(), 1);
    }

    #[test]
    fn cap_makes_room_from_idle_then_drops() {
        let w = Windows::with_cap(2);
        w.record(&EventKeys { session: 1, ..KEYS }, turn(0, Sym(0), 200));
        w.record(&EventKeys { session: 2, ..KEYS }, turn(0, Sym(0), 200));
        w.record(&EventKeys { session: 3, ..KEYS }, turn(1, Sym(0), 200));
        assert_eq!(w.counts().0, 2);
        assert_eq!(w.dropped_for_cap(), 1);
        w.record(
            &EventKeys { session: 3, ..KEYS },
            turn(CAP_IDLE_MS + 2, Sym(0), 200),
        );
        assert_eq!(w.counts().0, 1);
        assert!(w.session(3).is_some());
    }
}
