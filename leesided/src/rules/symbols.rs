//! Append-only string interner. Route templates, exception basenames, auth
//! event names, `req_shape` strings and model names become a `Sym(u32)` once,
//! on ingest or on compile; the check path only ever calls `get()`.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sym(pub u32);

impl Sym {
    /// Where every string beyond the cap lands. Shapes are the only field
    /// that could grow without bound; two overflowed shapes compare equal,
    /// which is the accepted loss.
    pub const OVERFLOW: Sym = Sym(u32::MAX);
}

pub const DEFAULT_CAP: usize = 1_000_000;

pub struct Symbols {
    map: DashMap<Box<str>, Sym>,
    names: RwLock<Vec<Arc<str>>>,
    overflow: AtomicU64,
    cap: usize,
}

impl Default for Symbols {
    fn default() -> Self {
        Self::with_cap(DEFAULT_CAP)
    }
}

impl Symbols {
    pub fn with_cap(cap: usize) -> Self {
        Symbols {
            map: DashMap::new(),
            names: RwLock::new(Vec::new()),
            overflow: AtomicU64::new(0),
            cap,
        }
    }

    /// Intern `s`, allocating only when it is new.
    pub fn intern(&self, s: &str) -> Sym {
        if let Some(sym) = self.map.get(s) {
            return *sym;
        }
        // The entry holds the shard lock, so two threads interning the same
        // new string serialise here and the second sees the first's insert.
        *self.map.entry(Box::from(s)).or_insert_with(|| {
            let mut names = self.names.write();
            if names.len() >= self.cap {
                self.overflow.fetch_add(1, Ordering::Relaxed);
                return Sym::OVERFLOW;
            }
            let sym = Sym(names.len() as u32);
            names.push(Arc::from(s));
            sym
        })
    }

    /// The check path: no allocation, `None` for a string never seen.
    #[inline]
    pub fn get(&self, s: &str) -> Option<Sym> {
        self.map.get(s).map(|r| *r)
    }

    pub fn name(&self, sym: Sym) -> Option<Arc<str>> {
        self.names.read().get(sym.0 as usize).cloned()
    }

    pub fn len(&self) -> usize {
        self.names.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn overflowed(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_is_idempotent_and_get_never_allocates_new() {
        let s = Symbols::default();
        let a = s.intern("home");
        let b = s.intern("home");
        assert_eq!(a, b);
        assert_eq!(s.get("home"), Some(a));
        assert_eq!(s.get("missing"), None);
        assert_eq!(s.len(), 1);
        assert_eq!(&*s.name(a).unwrap(), "home");
        let c = s.intern("venues.show");
        assert_ne!(a, c);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn cap_overflows_to_sentinel_and_counts() {
        let s = Symbols::with_cap(2);
        s.intern("a");
        s.intern("b");
        assert_eq!(s.intern("c"), Sym::OVERFLOW);
        assert_eq!(s.intern("d"), Sym::OVERFLOW);
        assert_eq!(s.overflowed(), 2);
        assert_eq!(s.get("c"), Some(Sym::OVERFLOW));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn concurrent_interning_agrees() {
        let s = Arc::new(Symbols::default());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || {
                    (0..1000)
                        .map(|i| s.intern(&format!("r{}", i % 50)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let results: Vec<Vec<Sym>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for r in &results[1..] {
            assert_eq!(r, &results[0]);
        }
        assert_eq!(s.len(), 50);
    }
}
