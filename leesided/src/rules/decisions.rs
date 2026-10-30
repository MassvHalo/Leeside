//! Sticky verdicts: a `block` on a session, a `rate_limit` on a scope key.
//! The mirror answers the check path; the store is the write-behind copy
//! that survives a restart.

use super::model::{Action, Mode, Scope};
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Decision {
    pub scope: Scope,
    #[serde(serialize_with = "hex16")]
    pub key: u64,
    pub action: Action,
    /// The effective mode when decided; the answer is `min(global, this)`.
    pub mode: Mode,
    pub rule: Arc<str>,
    pub rule_version: u32,
    pub created_at: i64,
    pub expires_at: i64,
}

fn hex16<S: serde::Serializer>(key: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{key:016x}"))
}

impl Decision {
    /// From the stored columns; `None` when a column is unreadable.
    #[allow(clippy::too_many_arguments)]
    pub fn from_row(
        scope: &str,
        key: &str,
        action: &str,
        mode: &str,
        rule: String,
        rule_version: u32,
        created_at: i64,
        expires_at: i64,
    ) -> Option<Decision> {
        let scope = match scope {
            "session" => Scope::Session,
            "peer" => Scope::Peer,
            "principal" => Scope::Principal,
            _ => return None,
        };
        let action = match action {
            "rate_limit" => Action::RateLimit,
            "block" => Action::Block,
            _ => return None,
        };
        Some(Decision {
            scope,
            key: super::windows::key16(key)?,
            action,
            mode: Mode::parse(mode)?,
            rule: Arc::from(rule),
            rule_version,
            created_at,
            expires_at,
        })
    }
}

#[derive(Default)]
pub struct Decisions {
    map: DashMap<(Scope, u64), Decision>,
}

impl Decisions {
    pub fn load(&self, decisions: impl IntoIterator<Item = Decision>) {
        for d in decisions {
            self.map.insert((d.scope, d.key), d);
        }
    }

    /// A live decision for the key, or `None`; expired entries read as absent
    /// until the sweep removes them.
    #[inline]
    pub fn get(&self, scope: Scope, key: u64, now_s: i64) -> Option<Decision> {
        self.map
            .get(&(scope, key))
            .filter(|d| d.expires_at > now_s)
            .map(|d| d.clone())
    }

    pub fn insert(&self, d: Decision) {
        self.map.insert((d.scope, d.key), d);
    }

    /// Every live decision, soonest to expire first.
    pub fn live(&self, now_s: i64) -> Vec<Decision> {
        let mut out: Vec<Decision> = self
            .map
            .iter()
            .filter(|e| e.value().expires_at > now_s)
            .map(|e| e.value().clone())
            .collect();
        out.sort_by_key(|d| d.expires_at);
        out
    }

    pub fn remove(&self, scope: Scope, key: u64) -> bool {
        self.map.remove(&(scope, key)).is_some()
    }

    /// Drop expired entries; returns their keys so the store can be told.
    pub fn sweep(&self, now_s: i64) -> Vec<(Scope, u64)> {
        let gone: Vec<(Scope, u64)> = self
            .map
            .iter()
            .filter(|e| e.value().expires_at <= now_s)
            .map(|e| *e.key())
            .collect();
        for k in &gone {
            self.map.remove(k);
        }
        gone
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(scope: Scope, key: u64, expires_at: i64) -> Decision {
        Decision {
            scope,
            key,
            action: Action::Block,
            mode: Mode::Enforce,
            rule: Arc::from("r"),
            rule_version: 1,
            created_at: 0,
            expires_at,
        }
    }

    #[test]
    fn get_respects_expiry_and_sweep_removes() {
        let m = Decisions::default();
        m.insert(d(Scope::Session, 1, 100));
        m.insert(d(Scope::Peer, 1, 50));
        assert!(m.get(Scope::Session, 1, 99).is_some());
        assert!(m.get(Scope::Session, 1, 100).is_none());
        assert!(m.get(Scope::Peer, 1, 49).is_some());
        assert!(m.get(Scope::Principal, 1, 0).is_none());
        let mut gone = m.sweep(60);
        gone.sort_by_key(|(s, k)| (*s as u8, *k));
        assert_eq!(gone, vec![(Scope::Peer, 1)]);
        assert_eq!(m.len(), 1);
        assert!(m.remove(Scope::Session, 1));
        assert!(m.is_empty());
    }

    #[test]
    fn row_round_trip() {
        let d = Decision::from_row(
            "peer",
            "0f1e2d3c4b5a6978",
            "rate_limit",
            "shadow",
            "otp".into(),
            3,
            1,
            2,
        )
        .unwrap();
        assert_eq!(d.key, 0x0f1e2d3c4b5a6978);
        assert_eq!(d.action, Action::RateLimit);
        assert_eq!(d.mode, Mode::Shadow);
        assert!(Decision::from_row(
            "nope",
            "0f1e2d3c4b5a6978",
            "block",
            "enforce",
            "r".into(),
            1,
            0,
            0
        )
        .is_none());
        assert!(
            Decision::from_row("peer", "short", "block", "enforce", "r".into(), 1, 0, 0).is_none()
        );
        assert!(Decision::from_row(
            "peer",
            "0f1e2d3c4b5a6978",
            "log",
            "enforce",
            "r".into(),
            1,
            0,
            0
        )
        .is_none());
        assert_eq!(serde_json::to_value(&d).unwrap()["key"], "0f1e2d3c4b5a6978");
    }
}
