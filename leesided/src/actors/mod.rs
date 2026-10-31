//! Actor resolution (docs/actors.md): from the identifiers a turn carries
//! to one `actor_id`, under the partition rule. Pure in-memory logic; the
//! store writes the rows the `Resolution` lists. Runs at ingest, never on
//! the request path; the check path only reads `lookup()`.

use crate::hash::Hasher;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::atomic::{AtomicU64, Ordering};

/// How long a binding links after its last turn.
pub const TTL_YEAR_US: i64 = 365 * 86_400 * 1_000_000;
pub const TTL_WEEK_US: i64 = 7 * 86_400 * 1_000_000;
pub const TTL_6H_US: i64 = 6 * 3_600 * 1_000_000;
/// Actors a weak value remembers, newest kept.
pub const WEAK_FANOUT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Principal,
    Credential,
    Session,
    Tag,
    Net,
    Ja4Asn,
    ShapeNet,
    UaNet,
}

impl Kind {
    pub const STRONG: [Kind; 4] = [Kind::Principal, Kind::Credential, Kind::Session, Kind::Tag];
    pub const WEAK: [Kind; 4] = [Kind::Net, Kind::Ja4Asn, Kind::ShapeNet, Kind::UaNet];

    /// Lower is higher precedence. Principal and credential share a level:
    /// one is the web identity, the other the machine identity.
    pub fn level(self) -> u8 {
        match self {
            Kind::Principal | Kind::Credential => 1,
            Kind::Session => 2,
            Kind::Tag => 3,
            _ => 4,
        }
    }

    pub fn is_strong(self) -> bool {
        self.level() < 4
    }

    pub fn ttl_us(self) -> i64 {
        match self {
            Kind::Principal | Kind::Credential | Kind::Tag => TTL_YEAR_US,
            Kind::Session => TTL_WEEK_US,
            _ => TTL_6H_US,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Principal => "principal",
            Kind::Credential => "credential",
            Kind::Session => "session",
            Kind::Tag => "tag",
            Kind::Net => "net",
            Kind::Ja4Asn => "ja4_asn",
            Kind::ShapeNet => "shape_net",
            Kind::UaNet => "ua_net",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "principal" => Kind::Principal,
            "credential" => Kind::Credential,
            "session" => Kind::Session,
            "tag" => Kind::Tag,
            "net" => Kind::Net,
            "ja4_asn" => Kind::Ja4Asn,
            "shape_net" => Kind::ShapeNet,
            "ua_net" => Kind::UaNet,
            _ => return None,
        })
    }
}

/// One identifier value as the resolver keys it: a 16-hex hash parsed to
/// u64, or for the paired weak kinds a mix of both halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ident {
    pub kind: Kind,
    pub value: u64,
}

impl Ident {
    pub fn new(kind: Kind, value: u64) -> Ident {
        Ident { kind, value }
    }

    /// A pair such as `ja4 + asn` or `shape + net`, folded into one key.
    pub fn pair(kind: Kind, a: u64, b: u64) -> Ident {
        Ident {
            kind,
            value: a.rotate_left(17) ^ b.wrapping_mul(0x9E37_79B9_7F4A_7C15),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub actor: u64,
    pub first_seen_us: i64,
    pub last_seen_us: i64,
    pub expires_us: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub id: u64,
    pub opened_us: i64,
    pub last_us: i64,
    pub merged_into: Option<u64>,
    pub turns: u32,
    /// Strong identifiers currently bound here, for the contradiction test.
    strong: SmallVec<[Ident; 6]>,
}

/// A merge the store must record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Merge {
    pub merged: u64,
    pub into: u64,
    pub via: Kind,
}

/// What one turn did to the actor state; the store writes exactly this.
#[derive(Debug, Default)]
pub struct Resolution {
    pub actor: u64,
    pub opened: bool,
    pub merges: Vec<Merge>,
    pub bindings: Vec<(Ident, Binding)>,
    pub actors_touched: Vec<Actor>,
}

pub struct Resolver {
    hasher: Hasher,
    strong: DashMap<Ident, Binding>,
    /// Weak values map to the actors recently seen with them, newest first.
    weak: DashMap<Ident, SmallVec<[(u64, i64); WEAK_FANOUT]>>,
    actors: DashMap<u64, Actor>,
    pub merges_done: AtomicU64,
}

impl Resolver {
    pub fn new(hasher: Hasher) -> Resolver {
        Resolver {
            hasher,
            strong: DashMap::new(),
            weak: DashMap::new(),
            actors: DashMap::new(),
            merges_done: AtomicU64::new(0),
        }
    }

    /// A keyed 64-bit hash of a string identifier such as `ja4`, so weak pair
    /// keys are stable across restarts (a process-seeded hasher would not be).
    pub fn key(&self, namespace: &str, value: &str) -> u64 {
        u64::from_str_radix(&self.hasher.hex16(namespace, value), 16).unwrap_or(0)
    }

    /// Deterministic and unique: seeded by the first turn's package-minted id.
    pub fn actor_id_for(&self, turn_id: &str) -> u64 {
        let hex = self.hasher.hex16("actor", turn_id);
        u64::from_str_radix(&hex, 16).unwrap_or(0)
    }

    /// Follow `merged_into` to the root.
    pub fn canonical(&self, mut id: u64) -> u64 {
        for _ in 0..64 {
            match self.actors.get(&id).and_then(|a| a.merged_into) {
                Some(next) => id = next,
                None => return id,
            }
        }
        id
    }

    /// The check path: the canonical actor a live strong binding names.
    #[inline]
    pub fn lookup(&self, ident: Ident, now_us: i64) -> Option<u64> {
        self.strong
            .get(&ident)
            .filter(|b| b.expires_us > now_us)
            .map(|b| self.canonical(b.actor))
    }

    /// The highest-precedence identifier present that is bound, as the
    /// probe resolves it.
    pub fn lookup_any(&self, idents: &[Ident], now_us: i64) -> Option<u64> {
        let mut sorted: SmallVec<[Ident; 6]> = idents
            .iter()
            .copied()
            .filter(|i| i.kind.is_strong())
            .collect();
        sorted.sort_by_key(|i| i.kind.level());
        sorted.iter().find_map(|i| self.lookup(*i, now_us))
    }

    pub fn actor(&self, id: u64) -> Option<Actor> {
        self.actors.get(&id).map(|a| a.clone())
    }

    pub fn len(&self) -> (usize, usize, usize) {
        (self.actors.len(), self.strong.len(), self.weak.len())
    }

    /// Actors other than `actor` seen with this weak value inside its TTL.
    pub fn cluster_size(&self, ident: Ident, actor: u64, now_us: i64) -> u32 {
        self.weak.get(&ident).map_or(0, |list| {
            let mut seen: SmallVec<[u64; WEAK_FANOUT]> = SmallVec::new();
            for (a, last) in list.iter() {
                if now_us - *last > ident.kind.ttl_us() {
                    continue;
                }
                let c = self.canonical(*a);
                if c != actor && !seen.contains(&c) {
                    seen.push(c);
                }
            }
            seen.len() as u32
        })
    }

    /// Restore from the store at start.
    pub fn load(
        &self,
        actors: impl IntoIterator<Item = Actor>,
        bindings: impl IntoIterator<Item = (Ident, Binding)>,
    ) {
        for a in actors {
            self.actors.insert(a.id, a);
        }
        for (ident, b) in bindings {
            if ident.kind.is_strong() {
                if let Some(mut a) = self.actors.get_mut(&b.actor) {
                    if !a.strong.contains(&ident) {
                        a.strong.push(ident);
                    }
                }
                self.strong.insert(ident, b);
            } else {
                self.weak
                    .entry(ident)
                    .or_default()
                    .push((b.actor, b.last_seen_us));
            }
        }
    }

    /// Drop expired bindings; returns them so the store can be told.
    pub fn sweep(&self, now_us: i64) -> Vec<Ident> {
        let gone: Vec<Ident> = self
            .strong
            .iter()
            .filter(|e| e.value().expires_us <= now_us)
            .map(|e| *e.key())
            .collect();
        for ident in &gone {
            if let Some((_, b)) = self.strong.remove(ident) {
                if let Some(mut a) = self.actors.get_mut(&b.actor) {
                    a.strong.retain(|i| i != ident);
                }
            }
        }
        self.weak.retain(|ident, list| {
            list.retain(|(_, last)| now_us - *last <= ident.kind.ttl_us());
            !list.is_empty()
        });
        gone
    }

    /// One turn. `idents` are everything the turn carries that counts
    /// (docs/actors.md, "counts when"); `turn_id` seeds a new actor.
    pub fn resolve(&self, turn_id: &str, ts_us: i64, idents: &[Ident]) -> Resolution {
        let mut out = Resolution::default();
        let mut strong: SmallVec<[Ident; 6]> = idents
            .iter()
            .copied()
            .filter(|i| i.kind.is_strong())
            .collect();
        strong.sort_by_key(|i| i.kind.level());

        // Rule 1: the highest level with a live binding names the actor, but
        // an actor reached through a lower identifier is adoptable only if the
        // turn's own higher identifiers do not contradict it: Q logging in on
        // P's browser must not become P because the tag says so.
        let mut actor = strong.iter().find_map(|i| {
            self.lookup(*i, ts_us)
                .filter(|a| !self.turn_contradicts(*a, &strong, i.kind.level(), ts_us))
        });
        if actor.is_none() {
            let id = self.actor_id_for(turn_id);
            self.actors.entry(id).or_insert_with(|| Actor {
                id,
                opened_us: ts_us,
                last_us: ts_us,
                merged_into: None,
                turns: 0,
                strong: SmallVec::new(),
            });
            out.opened = true;
            actor = Some(id);
        }
        let mut actor = actor.expect("set above");

        // Rule 3: another live binding on this turn names a different actor.
        // Merge when no higher level contradicts; otherwise rule 2 re-points.
        for ident in strong.iter() {
            let Some(other) = self.lookup(*ident, ts_us) else {
                continue;
            };
            if other == actor {
                continue;
            }
            if self.turn_contradicts(other, &strong, ident.kind.level(), ts_us)
                || self.contradicts(actor, other, ident.kind.level(), ts_us)
            {
                continue;
            }
            let (canonical, merged) = self.merge(actor, other, ident.kind, ts_us, &mut out);
            actor = canonical;
            let _ = merged;
        }

        // Rule 2: every identifier present binds to the actor from now on.
        for ident in idents {
            if ident.kind.is_strong() {
                self.bind_strong(*ident, actor, ts_us, &mut out);
            } else {
                let mut list = self.weak.entry(*ident).or_default();
                list.retain(|(a, _)| self.canonical(*a) != actor);
                if list.len() == WEAK_FANOUT {
                    list.pop();
                }
                list.insert(0, (actor, ts_us));
                out.bindings.push((
                    *ident,
                    Binding {
                        actor,
                        first_seen_us: ts_us,
                        last_seen_us: ts_us,
                        expires_us: ts_us + ident.kind.ttl_us(),
                    },
                ));
            }
        }

        if let Some(mut a) = self.actors.get_mut(&actor) {
            a.last_us = a.last_us.max(ts_us);
            a.turns = a.turns.saturating_add(1);
            out.actors_touched.push(a.clone());
        }
        out.actor = actor;
        out
    }

    /// Does the turn carry an identifier at a level above `link_level` that
    /// the actor holds a different value for? Then the actor is someone else.
    fn turn_contradicts(&self, actor: u64, idents: &[Ident], link_level: u8, now_us: i64) -> bool {
        let Some(a) = self.actors.get(&actor) else {
            return false;
        };
        // Only the identity level partitions: a session or tag is a browser, not a
        // person, and a browser legitimately has many sessions (one per login).
        for level in 1..link_level.min(2) {
            let turn: SmallVec<[Ident; 4]> = idents
                .iter()
                .copied()
                .filter(|i| i.kind.level() == level)
                .collect();
            if turn.is_empty() {
                continue;
            }
            let held: SmallVec<[Ident; 4]> = a
                .strong
                .iter()
                .copied()
                .filter(|i| {
                    i.kind.level() == level
                        && self.strong.get(i).is_some_and(|b| {
                            b.expires_us > now_us && self.canonical(b.actor) == actor
                        })
                })
                .collect();
            if !held.is_empty() && !turn.iter().any(|i| held.contains(i)) {
                return true;
            }
        }
        false
    }

    /// Do `a` and `b` both hold a live strong binding at a level above
    /// `link_level` that differs? Then they are different people sharing a
    /// lower identifier, and must not merge.
    fn contradicts(&self, a: u64, b: u64, link_level: u8, now_us: i64) -> bool {
        let live = |actor: u64| -> SmallVec<[Ident; 6]> {
            self.actors.get(&actor).map_or(SmallVec::new(), |x| {
                x.strong
                    .iter()
                    .copied()
                    .filter(|i| {
                        i.kind.level() < link_level
                            && self.strong.get(i).is_some_and(|b| {
                                b.expires_us > now_us && self.canonical(b.actor) == actor
                            })
                    })
                    .collect()
            })
        };
        let ia = live(a);
        let ib = live(b);
        for level in 1..link_level.min(2) {
            let la: SmallVec<[Ident; 4]> = ia
                .iter()
                .copied()
                .filter(|i| i.kind.level() == level)
                .collect();
            let lb: SmallVec<[Ident; 4]> = ib
                .iter()
                .copied()
                .filter(|i| i.kind.level() == level)
                .collect();
            if !la.is_empty() && !lb.is_empty() && !la.iter().any(|i| lb.contains(i)) {
                return true;
            }
        }
        false
    }

    /// The older actor stays canonical; the other points at it.
    fn merge(&self, a: u64, b: u64, via: Kind, ts_us: i64, out: &mut Resolution) -> (u64, u64) {
        let (opened_a, opened_b) = (
            self.actors.get(&a).map_or(i64::MAX, |x| x.opened_us),
            self.actors.get(&b).map_or(i64::MAX, |x| x.opened_us),
        );
        let (canonical, merged) = if (opened_b, b) < (opened_a, a) {
            (b, a)
        } else {
            (a, b)
        };
        let moved: SmallVec<[Ident; 6]> = self
            .actors
            .get_mut(&merged)
            .map(|mut m| {
                m.merged_into = Some(canonical);
                m.last_us = m.last_us.max(ts_us);
                std::mem::take(&mut m.strong)
            })
            .unwrap_or_default();
        if let Some(mut c) = self.actors.get_mut(&canonical) {
            for i in moved {
                if !c.strong.contains(&i) {
                    c.strong.push(i);
                }
            }
            c.last_us = c.last_us.max(ts_us);
            out.actors_touched.push(c.clone());
        }
        if let Some(m) = self.actors.get(&merged) {
            out.actors_touched.push(m.clone());
        }
        out.merges.push(Merge {
            merged,
            into: canonical,
            via,
        });
        self.merges_done.fetch_add(1, Ordering::Relaxed);
        (canonical, merged)
    }

    fn bind_strong(&self, ident: Ident, actor: u64, ts_us: i64, out: &mut Resolution) {
        let previous = self.strong.get(&ident).map(|b| *b);
        if let Some(p) = previous {
            if p.actor != actor {
                if let Some(mut old) = self.actors.get_mut(&p.actor) {
                    old.strong.retain(|i| *i != ident);
                }
            }
        }
        let binding = Binding {
            actor,
            first_seen_us: previous
                .filter(|p| p.actor == actor)
                .map_or(ts_us, |p| p.first_seen_us),
            last_seen_us: ts_us,
            expires_us: ts_us + ident.kind.ttl_us(),
        };
        self.strong.insert(ident, binding);
        if let Some(mut a) = self.actors.get_mut(&actor) {
            if !a.strong.contains(&ident) {
                a.strong.push(ident);
            }
        }
        out.bindings.push((ident, binding));
    }
}

/// A row as stored, for load.
pub fn actor_row(
    id: u64,
    opened_us: i64,
    last_us: i64,
    merged_into: Option<u64>,
    turns: u32,
) -> Actor {
    Actor {
        id,
        opened_us,
        last_us,
        merged_into,
        turns,
        strong: SmallVec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000;

    fn r() -> Resolver {
        Resolver::new(Hasher::new("k"))
    }

    fn id(kind: Kind, v: u64) -> Ident {
        Ident::new(kind, v)
    }

    /// Resolve a turn with a fresh, unique turn id.
    fn turn(res: &Resolver, n: u64, ts_us: i64, idents: &[Ident]) -> u64 {
        res.resolve(&format!("{n:016x}"), ts_us, idents).actor
    }

    #[test]
    fn levels_ttls_and_ids() {
        assert!(
            Kind::Principal.level() < Kind::Session.level()
                && Kind::Session.level() < Kind::Tag.level()
        );
        assert_eq!(Kind::Credential.level(), Kind::Principal.level());
        assert_eq!(Kind::Credential.ttl_us(), TTL_YEAR_US);
        assert!(Kind::Net.ttl_us() < Kind::Session.ttl_us());
        assert!(!Kind::Net.is_strong());
        let a = r();
        assert_eq!(
            a.actor_id_for("0123456789abcdef"),
            a.actor_id_for("0123456789abcdef")
        );
        assert_ne!(
            a.actor_id_for("0123456789abcdef"),
            a.actor_id_for("0123456789abcdee")
        );
        assert_ne!(
            Ident::pair(Kind::Ja4Asn, 1, 2),
            Ident::pair(Kind::Ja4Asn, 2, 1)
        );
    }

    #[test]
    fn anonymous_browsing_then_login_then_second_device() {
        let res = r();
        let (t, s1, s2, s3, p) = (
            id(Kind::Tag, 10),
            id(Kind::Session, 1),
            id(Kind::Session, 2),
            id(Kind::Session, 3),
            id(Kind::Principal, 100),
        );
        let a = turn(&res, 1, S, &[t, s1]);
        assert_eq!(turn(&res, 2, 2 * S, &[t, s1]), a);
        // S1 expires; S2 arrives with the live tag.
        let later = 2 * S + TTL_WEEK_US + S;
        assert_eq!(
            turn(&res, 3, later, &[t, s2]),
            a,
            "the tag carries the actor across session expiry"
        );
        // Login: P unbound, T and S2 point at A, A has no principal.
        assert_eq!(turn(&res, 4, later + S, &[p, s2, t]), a);
        // Second device: P is live, S3 is new.
        assert_eq!(turn(&res, 5, later + 2 * S, &[p, s3]), a);
        assert_eq!(res.lookup(s3, later + 3 * S), Some(a));
        assert_eq!(res.merges_done.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn logout_then_login_as_someone_else_does_not_merge() {
        let res = r();
        let (t, s4, p, q) = (
            id(Kind::Tag, 10),
            id(Kind::Session, 4),
            id(Kind::Principal, 100),
            id(Kind::Principal, 200),
        );
        let a = turn(&res, 1, S, &[p, id(Kind::Session, 1), t]);
        // Q logs in on the same browser: new session, same tag, A holds P.
        let c = turn(&res, 2, 2 * S, &[q, s4, t]);
        assert_ne!(c, a);
        assert_eq!(
            res.lookup(t, 3 * S),
            Some(c),
            "the tag re-points to Q's actor"
        );
        assert_eq!(
            res.lookup(p, 3 * S),
            Some(a),
            "P keeps its actor and history"
        );
        assert_eq!(res.merges_done.load(Ordering::Relaxed), 0);
        // Q keeps browsing: tag and session agree on C.
        assert_eq!(turn(&res, 3, 4 * S, &[q, s4, t]), c);
    }

    #[test]
    fn login_on_existing_session_merges_guest_into_user() {
        let res = r();
        let (t, s1, s2, p) = (
            id(Kind::Tag, 10),
            id(Kind::Session, 1),
            id(Kind::Session, 2),
            id(Kind::Principal, 100),
        );
        let g = turn(&res, 1, S, &[t, s1]);
        // Laravel regenerates the session on login: P unbound, S2 unbound, T bound to G.
        let a = turn(&res, 2, 2 * S, &[p, s2, t]);
        assert_eq!(
            a, g,
            "the guest actor is the user's actor: pre-login browsing belongs to the user"
        );
        assert_eq!(res.lookup(p, 3 * S), Some(g));
        assert_eq!(res.lookup(s2, 3 * S), Some(g));
    }

    #[test]
    fn two_anonymous_actors_merge_with_the_older_canonical() {
        let res = r();
        let (t, s5) = (id(Kind::Tag, 10), id(Kind::Session, 5));
        let a = turn(&res, 1, S, &[t]);
        let b = turn(&res, 2, 2 * S, &[s5]);
        assert_ne!(a, b);
        let who = turn(&res, 3, 3 * S, &[t, s5]);
        assert_eq!(who, a, "older id stays canonical");
        assert_eq!(res.canonical(b), a);
        assert_eq!(res.actor(b).unwrap().merged_into, Some(a));
        assert_eq!(res.merges_done.load(Ordering::Relaxed), 1);
        assert_eq!(
            res.lookup(s5, 4 * S),
            Some(a),
            "lookups resolve through the merge"
        );
    }

    #[test]
    fn two_credentials_under_one_net_are_two_actors_and_unverified_binds_nothing() {
        let res = r();
        let net = id(Kind::Net, 7);
        let a = turn(&res, 1, S, &[id(Kind::Credential, 1), net]);
        let b = turn(&res, 2, 2 * S, &[id(Kind::Credential, 2), net]);
        assert_ne!(a, b);
        assert_eq!(res.merges_done.load(Ordering::Relaxed), 0);
        assert_eq!(
            res.cluster_size(net, a, 3 * S),
            1,
            "one other actor on the network"
        );
        assert_eq!(res.cluster_size(net, b, 3 * S), 1);
        assert_eq!(
            res.cluster_size(net, a, 3 * S + TTL_6H_US + S),
            0,
            "weak bindings expire"
        );
        // A turn with only weak identifiers opens an actor of its own and binds no strong value.
        let c = turn(&res, 3, 4 * S, &[net]);
        assert_ne!(c, a);
        assert_eq!(res.len().1, 2, "two strong bindings: the two credentials");
    }

    #[test]
    fn expired_session_does_not_link() {
        let res = r();
        let s = id(Kind::Session, 1);
        let a = turn(&res, 1, S, &[s]);
        assert_eq!(res.lookup(s, S + TTL_WEEK_US - 1), Some(a));
        assert_eq!(res.lookup(s, S + TTL_WEEK_US), None);
        let b = turn(&res, 2, S + TTL_WEEK_US + S, &[s]);
        assert_ne!(b, a, "the value binds afresh");
        let gone = res.sweep(S + TTL_WEEK_US + 2 * S + TTL_WEEK_US);
        assert_eq!(gone, vec![s]);
    }

    #[test]
    fn determinism_same_turns_same_actors_after_reload() {
        let script: Vec<(u64, i64, Vec<Ident>)> = vec![
            (1, S, vec![id(Kind::Tag, 1), id(Kind::Session, 1)]),
            (2, 2 * S, vec![id(Kind::Session, 2)]),
            (3, 3 * S, vec![id(Kind::Tag, 1), id(Kind::Session, 2)]),
            (
                4,
                4 * S,
                vec![
                    id(Kind::Principal, 9),
                    id(Kind::Session, 3),
                    id(Kind::Tag, 1),
                ],
            ),
            (
                5,
                5 * S,
                vec![
                    id(Kind::Principal, 8),
                    id(Kind::Session, 4),
                    id(Kind::Tag, 1),
                ],
            ),
        ];
        let run = |res: &Resolver| {
            script
                .iter()
                .map(|(n, ts, ids)| turn(res, *n, *ts, ids))
                .collect::<Vec<_>>()
        };
        let fresh = run(&r());
        // The same script through a resolver that was reloaded after turn 3.
        let first = r();
        for (n, ts, ids) in &script[..3] {
            turn(&first, *n, *ts, ids);
        }
        let reloaded = r();
        let actors: Vec<Actor> = first
            .actors
            .iter()
            .map(|e| e.value().clone())
            .map(|a| actor_row(a.id, a.opened_us, a.last_us, a.merged_into, a.turns))
            .collect();
        let bindings: Vec<(Ident, Binding)> = first
            .strong
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();
        reloaded.load(actors, bindings);
        let mut resumed: Vec<u64> = fresh[..3].to_vec();
        for (n, ts, ids) in &script[3..] {
            resumed.push(turn(&reloaded, *n, *ts, ids));
        }
        assert_eq!(resumed, fresh);
    }
}
