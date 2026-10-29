//! Hourly counters per rule version and effective mode, bumped on the check
//! path and drained to the writer every 10 s.

use super::model::Mode;
use crate::store::StatRow;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Default)]
pub struct Stats {
    map: DashMap<(Arc<str>, u32, i64, Mode), [u64; 3]>,
}

impl Stats {
    #[inline]
    pub fn bump(
        &self,
        rule: &Arc<str>,
        version: u32,
        hour: i64,
        mode: Mode,
        would_act: bool,
        acted: bool,
    ) {
        let mut e = self
            .map
            .entry((rule.clone(), version, hour, mode))
            .or_insert([0; 3]);
        e[0] += 1;
        e[1] += would_act as u64;
        e[2] += acted as u64;
    }

    /// Take everything counted so far.
    pub fn drain(&self) -> Vec<StatRow> {
        let keys: Vec<_> = self.map.iter().map(|e| e.key().clone()).collect();
        let mut rows = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some((k, c)) = self.map.remove(&k) {
                rows.push(StatRow {
                    rule: k.0,
                    version: k.1,
                    hour: k.2,
                    mode: k.3,
                    matched: c[0],
                    would_act: c[1],
                    acted: c[2],
                });
            }
        }
        rows
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

pub fn hour_of(now_s: i64) -> i64 {
    now_s.div_euclid(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_and_drain() {
        let s = Stats::default();
        let r: Arc<str> = Arc::from("otp");
        s.bump(&r, 1, 10, Mode::Shadow, true, false);
        s.bump(&r, 1, 10, Mode::Shadow, false, false);
        s.bump(&r, 1, 10, Mode::Enforce, true, true);
        let mut rows = s.drain();
        rows.sort_by_key(|r| r.mode);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (
                rows[0].mode,
                rows[0].matched,
                rows[0].would_act,
                rows[0].acted
            ),
            (Mode::Shadow, 2, 1, 0)
        );
        assert_eq!(
            (
                rows[1].mode,
                rows[1].matched,
                rows[1].would_act,
                rows[1].acted
            ),
            (Mode::Enforce, 1, 1, 1)
        );
        assert!(s.is_empty());
        assert_eq!(hour_of(7200), 2);
    }
}
