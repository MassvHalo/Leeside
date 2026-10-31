//! leesided's side of the tap: the connection map that joins the tap's
//! fingerprints to turns, and the short list of turns still waiting for
//! theirs (the event beat the tap's datagram).
//!
//! Key: a keyed hash of `ip:port`, so the map holds no address. A turn joins
//! the connection whose `[syn_ts - slack, close_ts + grace]` holds its
//! `ts_ms`; that is what makes port reuse behind a NAT harmless. Entries
//! live until FIN or RST plus 30 s, or 5 min idle, under a size cap with
//! oldest-first eviction. A deferred turn waits 60 s, then its columns stay
//! null and `missed` counts it.

use super::FpMessage;
use parking_lot::Mutex;
use serde::Serialize;
use smallvec::SmallVec;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub const GRACE_MS: u64 = 30_000;
pub const IDLE_MS: u64 = 5 * 60_000;
pub const DEFER_MS: u64 = 60_000;
/// The host clock stamps both sides, but the SYN is seen by the tap and the
/// request by PHP; a second of slack covers scheduling.
pub const SLACK_MS: u64 = 1_000;
pub const CAP: usize = 65_536;

#[derive(Debug, Clone)]
struct Conn {
    syn_ts: u64,
    close_ts: Option<u64>,
    last: u64,
    tls: Option<bool>,
    ja4: Option<Arc<str>>,
    ja4t: Option<Arc<str>>,
}

impl Conn {
    fn holds(&self, ts_ms: u64) -> bool {
        ts_ms + SLACK_MS >= self.syn_ts
            && self
                .close_ts
                .is_none_or(|c| ts_ms <= c.saturating_add(GRACE_MS))
    }
}

/// A turn whose event arrived before its fingerprints.
#[derive(Debug, Clone)]
pub struct Pending {
    pub turn_id: String,
    pub ts_ms: u64,
    pub since: u64,
    pub browser_ua: bool,
    pub need_ja4: bool,
    pub need_ja4t: bool,
}

/// What the ingest found for a turn, or what a late datagram supplies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hit {
    pub found: bool,
    pub tls: Option<bool>,
    pub ja4: Option<Arc<str>>,
    pub ja4t: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct Fill {
    pub turn_id: String,
    pub browser_ua: bool,
    pub ja4: Option<Arc<str>>,
    pub ja4t: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct TapStats {
    /// Datagrams accepted from the tap.
    pub messages: u64,
    pub bad_message: u64,
    /// Turns that found their fingerprints at ingest.
    pub matched: u64,
    /// Turns that waited; of those, filled later or given up.
    pub deferred: u64,
    pub filled_late: u64,
    pub missed: u64,
    /// Turns with a remote port and no connection at all at ingest.
    pub unknown: u64,
    pub connections: usize,
    pub pending: usize,
}

#[derive(Default)]
struct Inner {
    map: HashMap<u64, SmallVec<[Conn; 2]>>,
    order: VecDeque<u64>,
    pending: HashMap<u64, Vec<Pending>>,
    stats: TapStats,
}

#[derive(Default)]
pub struct Connections {
    inner: Mutex<Inner>,
}

impl Connections {
    /// Record a tap datagram. Returns the deferred turns it completes.
    pub fn observe(&self, key: u64, msg: &FpMessage) -> Vec<Fill> {
        let mut g = self.inner.lock();
        g.stats.messages += 1;
        let inner = &mut *g;
        let conns = inner.map.entry(key).or_default();
        let existing = conns
            .iter_mut()
            .filter(|c| c.holds(msg.ts_ms) || c.close_ts.is_none())
            .max_by_key(|c| c.syn_ts);
        let conn = match existing {
            Some(c) => c,
            None => {
                conns.push(Conn {
                    syn_ts: msg.ts_ms,
                    close_ts: None,
                    last: msg.ts_ms,
                    tls: None,
                    ja4: None,
                    ja4t: None,
                });
                inner.order.push_back(key);
                conns.last_mut().expect("just pushed")
            }
        };
        conn.last = conn.last.max(msg.ts_ms);
        if msg.tls.is_some() {
            conn.tls = msg.tls;
        }
        if let Some(t) = msg.ja4t.as_deref().filter(|s| !s.is_empty()) {
            conn.ja4t = Some(Arc::from(t));
        }
        if let Some(j) = msg.ja4.as_deref().filter(|s| !s.is_empty()) {
            conn.ja4 = Some(Arc::from(j));
        }
        if msg.close {
            conn.close_ts = Some(msg.ts_ms.max(conn.close_ts.unwrap_or(0)));
        }
        let conn = conn.clone();

        // Late fills for turns that were waiting on this connection.
        let mut fills = Vec::new();
        if let Some(waiting) = g.pending.get_mut(&key) {
            waiting.retain_mut(|p| {
                if !conn.holds(p.ts_ms) {
                    return true;
                }
                if conn.tls == Some(false) {
                    p.need_ja4 = false;
                }
                let give_ja4 = p.need_ja4 && conn.ja4.is_some();
                let give_ja4t = p.need_ja4t && conn.ja4t.is_some();
                if give_ja4 || give_ja4t {
                    fills.push(Fill {
                        turn_id: p.turn_id.clone(),
                        browser_ua: p.browser_ua,
                        ja4: if give_ja4 { conn.ja4.clone() } else { None },
                        ja4t: if give_ja4t { conn.ja4t.clone() } else { None },
                    });
                    p.need_ja4 &= !give_ja4;
                    p.need_ja4t &= !give_ja4t;
                }
                p.need_ja4 || p.need_ja4t
            });
            if waiting.is_empty() {
                g.pending.remove(&key);
            }
        }
        g.stats.filled_late += fills.len() as u64;

        // The cap: drop the oldest connection, by insertion order.
        while g.map.len() > CAP {
            let Some(old) = g.order.pop_front() else {
                break;
            };
            if let Some(v) = g.map.get_mut(&old) {
                if !v.is_empty() {
                    v.remove(0);
                }
                if v.is_empty() {
                    g.map.remove(&old);
                }
            }
        }
        g.stats.connections = g.map.values().map(|v| v.len()).sum();
        g.stats.pending = g.pending.values().map(|v| v.len()).sum();
        fills
    }

    pub fn bad_message(&self) {
        self.inner.lock().stats.bad_message += 1;
    }

    /// The fingerprints for a turn at `ts_ms`, when a connection holds it.
    pub fn lookup(&self, key: u64, ts_ms: u64) -> Hit {
        let mut g = self.inner.lock();
        let found = g
            .map
            .get(&key)
            .and_then(|v| v.iter().filter(|c| c.holds(ts_ms)).max_by_key(|c| c.syn_ts))
            .cloned();
        match found {
            Some(c) => {
                if c.ja4.is_some() || c.ja4t.is_some() {
                    g.stats.matched += 1;
                }
                Hit {
                    found: true,
                    tls: c.tls,
                    ja4: c.ja4,
                    ja4t: c.ja4t,
                }
            }
            None => {
                g.stats.unknown += 1;
                Hit::default()
            }
        }
    }

    /// Wait up to `DEFER_MS` for the tap's datagram on this connection.
    pub fn defer(&self, key: u64, p: Pending) {
        let mut g = self.inner.lock();
        g.stats.deferred += 1;
        g.pending.entry(key).or_default().push(p);
        g.stats.pending = g.pending.values().map(|v| v.len()).sum();
    }

    /// Expire closed-plus-grace and idle connections and overdue waits.
    pub fn sweep(&self, now_ms: u64) {
        let mut g = self.inner.lock();
        g.map.retain(|_, v| {
            v.retain(|c| {
                c.close_ts.is_none_or(|t| now_ms <= t + GRACE_MS) && now_ms <= c.last + IDLE_MS
            });
            !v.is_empty()
        });
        let mut missed = 0u64;
        g.pending.retain(|_, v| {
            let before = v.len();
            v.retain(|p| now_ms <= p.since + DEFER_MS);
            missed += (before - v.len()) as u64;
            !v.is_empty()
        });
        g.stats.missed += missed;
        g.stats.connections = g.map.values().map(|v| v.len()).sum();
        g.stats.pending = g.pending.values().map(|v| v.len()).sum();
        while g.order.len() > g.map.len() * 2 + 16 {
            let Some(k) = g.order.pop_front() else { break };
            if g.map.contains_key(&k) {
                g.order.push_back(k);
                break;
            }
        }
    }

    pub fn stats(&self) -> TapStats {
        self.inner.lock().stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(ts_ms: u64) -> FpMessage {
        FpMessage {
            v: 1,
            ts_ms,
            ip: "203.0.113.7".into(),
            port: 51234,
            ja4t: None,
            tls: None,
            ja4: None,
            close: false,
        }
    }

    #[test]
    fn syn_then_hello_then_turn() {
        let c = Connections::default();
        let mut m = msg(10_000);
        m.ja4t = Some("65535_2-4-8-1-3_1460_7".into());
        m.tls = Some(true);
        assert!(c.observe(7, &m).is_empty());
        let mut m = msg(10_050);
        m.ja4 = Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into());
        c.observe(7, &m);
        let hit = c.lookup(7, 10_200);
        assert!(hit.found && hit.ja4.is_some() && hit.ja4t.is_some());
        assert!(!c.lookup(8, 10_200).found);
        // Before the SYN by more than the slack: not this connection.
        assert!(!c.lookup(7, 10_000 - SLACK_MS - 1).found);
        let s = c.stats();
        assert_eq!((s.matched, s.unknown, s.connections), (1, 2, 1));
    }

    #[test]
    fn port_reuse_picks_the_connection_by_time() {
        let c = Connections::default();
        let mut a = msg(1_000);
        a.ja4 = Some("A".into());
        c.observe(7, &a);
        let mut close = msg(5_000);
        close.close = true;
        c.observe(7, &close);
        // The same (ip, port) again a minute later: a new connection.
        let mut b = msg(65_000);
        b.ja4t = Some("B".into());
        c.observe(7, &b);
        assert_eq!(c.lookup(7, 2_000).ja4.as_deref(), Some("A"));
        assert_eq!(c.lookup(7, 5_000 + GRACE_MS).ja4.as_deref(), Some("A"));
        let late = c.lookup(7, 66_000);
        assert_eq!(late.ja4t.as_deref(), Some("B"));
        assert!(late.ja4.is_none());
        // Past close plus grace, and nothing new yet: unknown.
        assert!(!c.lookup(7, 40_000).found);
    }

    #[test]
    fn deferred_turn_is_filled_by_a_late_datagram_or_missed() {
        let c = Connections::default();
        c.defer(
            7,
            Pending {
                turn_id: "t1".into(),
                ts_ms: 1_200,
                since: 1_200,
                browser_ua: true,
                need_ja4: true,
                need_ja4t: true,
            },
        );
        let mut m = msg(1_000);
        m.ja4t = Some("T".into());
        m.tls = Some(true);
        let fills = c.observe(7, &m);
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].ja4t.as_deref(), Some("T"));
        assert!(fills[0].ja4.is_none());
        let mut m = msg(1_050);
        m.ja4 = Some("J".into());
        let fills = c.observe(7, &m);
        assert_eq!(fills[0].ja4.as_deref(), Some("J"));
        assert!(fills[0].browser_ua);
        assert_eq!(c.stats().pending, 0);
        // A plain-HTTP connection never gets a JA4, so the wait ends on the SYN.
        c.defer(
            9,
            Pending {
                turn_id: "t2".into(),
                ts_ms: 2_000,
                since: 2_000,
                browser_ua: false,
                need_ja4: true,
                need_ja4t: true,
            },
        );
        let mut m = msg(1_990);
        m.ja4t = Some("T".into());
        m.tls = Some(false);
        assert_eq!(c.observe(9, &m).len(), 1);
        assert_eq!(c.stats().pending, 0);
        // Nothing ever comes for this one.
        c.defer(
            11,
            Pending {
                turn_id: "t3".into(),
                ts_ms: 3_000,
                since: 3_000,
                browser_ua: false,
                need_ja4: true,
                need_ja4t: false,
            },
        );
        c.sweep(3_000 + DEFER_MS - 1);
        assert_eq!(c.stats().missed, 0);
        c.sweep(3_000 + DEFER_MS + 1);
        assert_eq!((c.stats().missed, c.stats().pending), (1, 0));
    }

    #[test]
    fn sweep_drops_closed_and_idle() {
        let c = Connections::default();
        c.observe(1, &msg(0));
        let mut close = msg(100);
        close.close = true;
        c.observe(1, &close);
        c.observe(2, &msg(0));
        c.sweep(100 + GRACE_MS + 1);
        assert_eq!(c.stats().connections, 1);
        c.sweep(IDLE_MS + 1);
        assert_eq!(c.stats().connections, 0);
    }
}
