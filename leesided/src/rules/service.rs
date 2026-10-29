//! `RulesService`: the live `RuleSet` behind an `ArcSwap`, reloaded from
//! SQLite after every write. Reload is a function call, never a file watch.

use super::compile::{RuleMeta, RuleSet, State};
use super::model::{Mode, Rule, ValidationError};
use super::symbols::Symbols;
use crate::store::{Store, StoreError, StoredRule};
use arc_swap::{ArcSwap, Guard};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A stored body that failed to parse or validate at load. Listed, never
/// dropped.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InvalidRule {
    pub id: String,
    pub version: u32,
    pub state: State,
    pub errors: Vec<ValidationError>,
}

pub struct RulesService {
    set: ArcSwap<RuleSet>,
    symbols: Arc<Symbols>,
    store: Arc<Store>,
    generation: AtomicU64,
    /// The bodies behind the compiled set, for the sweep and the API.
    loaded: Mutex<Vec<(Rule, RuleMeta)>>,
    invalid: Mutex<Vec<InvalidRule>>,
}

impl RulesService {
    pub fn new(symbols: Arc<Symbols>, store: Arc<Store>) -> RulesService {
        RulesService {
            set: ArcSwap::from_pointee(RuleSet::empty(0)),
            symbols,
            store,
            generation: AtomicU64::new(0),
            loaded: Mutex::new(Vec::new()),
            invalid: Mutex::new(Vec::new()),
        }
    }

    /// One `load()` per probe; in-flight evaluations finish on the old set.
    #[inline]
    pub fn current(&self) -> Guard<Arc<RuleSet>> {
        self.set.load()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Read `active` and `proposed` rows, validate and compile every body,
    /// swap the set. A body that fails is logged and listed.
    pub fn load(&self) -> Result<(), StoreError> {
        let rows = self.store.load_rules(&[State::Active, State::Proposed])?;
        let mut entries: Vec<(Rule, RuleMeta)> = Vec::with_capacity(rows.len());
        let mut invalid = Vec::new();
        for row in rows {
            match parse_stored(&row) {
                Ok((rule, meta)) => entries.push((rule, meta)),
                Err(errors) => {
                    tracing::error!(id = %row.id, version = row.version, ?errors, "rule failed to load");
                    invalid.push(InvalidRule {
                        id: row.id,
                        version: row.version,
                        state: row.state,
                        errors,
                    });
                }
            }
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let set = RuleSet::compile(entries.clone(), &self.symbols, generation);
        tracing::info!(generation, rules = set.len(), hash = %set.hash_hex, "rules loaded");
        self.set.store(Arc::new(set));
        *self.loaded.lock() = entries;
        *self.invalid.lock() = invalid;
        Ok(())
    }

    /// Write through the store (validated, versioned, acked), then reload.
    pub async fn write(
        &self,
        rule: Rule,
        state: State,
        changed_by: &str,
        reason: Option<String>,
    ) -> Result<u32, StoreError> {
        let version = self
            .store
            .rule_write(rule, state, changed_by, reason)
            .await?;
        self.load()?;
        Ok(version)
    }

    pub fn invalid(&self) -> Vec<InvalidRule> {
        self.invalid.lock().clone()
    }

    pub fn loaded(&self) -> Vec<(Rule, RuleMeta)> {
        self.loaded.lock().clone()
    }

    /// Rules past `expires_at` that still claim more than shadow: the sweep
    /// writes them down to shadow with `changed_by: system`, so the drop is
    /// in the version history.
    pub async fn expire(&self, now_s: i64) -> Result<usize, StoreError> {
        let due: Vec<(Rule, RuleMeta)> = self
            .loaded()
            .into_iter()
            .filter(|(r, _)| r.expires_at.is_some_and(|e| e <= now_s) && r.mode > Mode::Shadow)
            .collect();
        let n = due.len();
        for (mut rule, meta) in due {
            rule.mode = Mode::Shadow;
            rule.expires_at = None;
            let id = rule.id.clone();
            if let Err(e) = self
                .store
                .rule_write(rule, meta.state, "system", Some("expired".into()))
                .await
            {
                tracing::error!(id = %id, error = %e, "expiry write failed");
            }
        }
        if n > 0 {
            self.load()?;
        }
        Ok(n)
    }

    /// Import `*.json` from the install directory as active shadow rules.
    /// Runs only when the `rules` table is empty.
    pub async fn import_install(&self, dir: &std::path::Path) -> Result<usize, StoreError> {
        if self.store.rules_count()? > 0 {
            return Ok(0);
        }
        let mut paths: Vec<_> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect(),
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "no install rules directory");
                return Ok(0);
            }
        };
        paths.sort();
        let mut n = 0;
        for path in paths {
            let text = std::fs::read_to_string(&path)?;
            let mut rule: Rule = match serde_json::from_str(&text) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(path = %path.display(), error = %e, "install rule skipped");
                    continue;
                }
            };
            // The install set is git-tracked and may say enforce; it goes
            // live as shadow and is promoted by an operator.
            rule.mode = rule.mode.min(Mode::Shadow);
            match self
                .store
                .rule_write(rule, State::Active, "install", Some("install set".into()))
                .await
            {
                Ok(_) => n += 1,
                Err(e) => {
                    tracing::error!(path = %path.display(), error = %e, "install rule rejected")
                }
            }
        }
        if n > 0 {
            tracing::info!(count = n, "install rules imported");
        }
        Ok(n)
    }
}

fn parse_stored(row: &StoredRule) -> Result<(Rule, RuleMeta), Vec<ValidationError>> {
    let rule: Rule = serde_json::from_str(&row.body).map_err(|e| {
        vec![ValidationError {
            path: String::new(),
            message: e.to_string(),
        }]
    })?;
    // `expires_at` in the past is fine at load: the rule evaluates as shadow
    // until the sweep writes it down.
    let errors = rule.validate(i64::MIN);
    if !errors.is_empty() {
        return Err(errors);
    }
    let meta = RuleMeta {
        id: Arc::from(rule.id.as_str()),
        version: row.version,
        note: rule.note.clone(),
        origin: rule.origin.clone(),
        state: row.state,
    };
    Ok((rule, meta))
}
