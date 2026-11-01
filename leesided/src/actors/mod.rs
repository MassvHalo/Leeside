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
/// A browser-side identifier seen once is provisional until it returns.
pub const TTL_PROVISIONAL_US: i64 = 24 * 3_600 * 1_000_000;
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

    /// Browser-side identifiers are provisional until they come back: a
    /// client that ignores cookies mints a fresh one per request and must
    /// leave nothing behind.
    pub fn is_provisional(self) -> bool {
        matches!(self, Kind::Session | Kind::Tag)
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
    /// Seen on a later turn than the one that created it. Provisional kinds
    /// get their full TTL only once returned.
    pub returned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub id: u64,
    pub opened_us: i64,
    pub last_us: i64,
    pub merged_into: Option<u64>,
    pub turns: u32,
    /// Something durable vouched for this actor: a principal or credential
    /// bound, or a provisional identifier that came back. Unconfirmed actors
    /// are swept with their last binding.
    pub confirmed: bool,
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
    /// `None` when the turn carried no strong identifier: a peer or shape
    /// cluster is never an actor, so such turns have no actor at all.
    pub actor: Option<u64>,
    pub opened: bool,
    pub merges: Vec<Merge>,
    pub bindings: Vec<(Ident, Binding)>,
    pub actors_touched: Vec<Actor>,
}

/// What a sweep removed.
#[derive(Debug, Default)]
pub struct Swept {
    pub bindings: Vec<Ident>,
    /// Unconfirmed actors whose last binding expired: a scanner that never
    /// returned a cookie leaves nothing behind.
    pub actors: Vec<u64>,
}

/// An actor's latest Windside score (docs/windside.md section 6).
#[derive(Debug, Clone)]
pub struct ActorScore {
    pub score: f32,
    pub ts_us: i64,
    pub top3: String,
}

pub struct Resolver {
    hasher: Hasher,
    strong: DashMap<Ident, Binding>,
    /// Weak values map to the actors recently seen with them, newest first.
    weak: DashMap<Ident, SmallVec<[(u64, i64); WEAK_FANOUT]>>,
    actors: DashMap<u64, Actor>,
    /// Latest score per canonical actor id; written through to the store.
    scores: DashMap<u64, ActorScore>,
    pub merges_done: AtomicU64,
}

impl Resolver {
    pub fn new(hasher: Hasher) -> Resolver {
        Resolver {
            hasher,
            strong: DashMap::new(),
            weak: DashMap::new(),
            actors: DashMap::new(),
            scores: DashMap::new(),
            merges_done: AtomicU64::new(0),
        }
    }

    /// A keyed 64-bit hash of a string identifier such as `ja4`, so weak pair
    /// keys are stable across restarts (a process-seeded hasher would not be).
    pub fn key(&self, namespace: &str, value: &str) -> u64 {
        u64::from_str_radix(&self.hasher.hex16(namespace, value), 16).unwrap_or(0)
    }

    /// `cluster_key`: hash of `net_hash || shape_hash`, its own namespace.
    pub fn cluster_key(&self, net_hash: &str, shape_hash: &str) -> u64 {
        self.key("cluster", &format!("{net_hash}{shape_hash}"))
    }

    /// Deterministic and unique: seeded by the first turn's package-minted id.
    pub fn actor_id_for(&self, turn_id: &str) -> u64 {
        u64::from_str_radix(&self.hasher.hex16("actor", turn_id), 16).unwrap_or(0)
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

    /// The actor's latest score, if any row cleared the floor yet.
    pub fn score(&self, id: u64) -> Option<f32> {
        self.scores.get(&id).map(|s| s.score)
    }

    pub fn set_score(&self, id: u64, score: ActorScore) {
        self.scores.insert(id, score);
    }

    /// Restore latest scores from the store at start.
    pub fn load_scores(&self, scores: impl IntoIterator<Item = (u64, ActorScore)>) {
        for (id, s) in scores {
            self.scores.insert(id, s);
        }
    }

    /// (actors, strong bindings, weak values)
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

    /// Drop expired bindings, then unconfirmed actors left with none.
    pub fn sweep(&self, now_us: i64) -> Swept {
        let mut out = Swept {
            bindings: self
                .strong
                .iter()
                .filter(|e| e.value().expires_us <= now_us)
                .map(|e| *e.key())
                .collect(),
            actors: Vec::new(),
        };
        let mut candidates: SmallVec<[u64; 32]> = SmallVec::new();
        for ident in &out.bindings {
            if let Some((_, b)) = self.strong.remove(ident) {
                if let Some(mut a) = self.actors.get_mut(&b.actor) {
                    a.strong.retain(|i| i != ident);
                    if !a.confirmed && a.strong.is_empty() && !candidates.contains(&b.actor) {
                        candidates.push(b.actor);
                    }
                }
            }
        }
        for id in candidates {
            let gone = self
                .actors
                .get(&id)
                .is_some_and(|a| !a.confirmed && a.strong.is_empty() && a.merged_into.is_none());
            if gone {
                self.actors.remove(&id);
                out.actors.push(id);
            }
        }
        self.weak.retain(|ident, list| {
            list.retain(|(_, last)| now_us - *last <= ident.kind.ttl_us());
            !list.is_empty()
        });
        out
    }

    /// One turn. `idents` are everything the turn carries that counts
    /// (docs/actors.md, "counts when"); `turn_id` seeds a new actor. A turn
    /// with no strong identifier resolves to no actor.
    pub fn resolve(&self, turn_id: &str, ts_us: i64, idents: &[Ident]) -> Resolution {
        let mut out = Resolution::default();
        let mut strong: SmallVec<[Ident; 6]> = idents
            .iter()
            .copied()
            .filter(|i| i.kind.is_strong())
            .collect();
        if strong.is_empty() {
            return out;
        }
        strong.sort_by_key(|i| i.kind.level());
        let turn_identity = identity_of(&strong);

        // Rule 1: the highest level with a live binding names the actor, but
        // an actor reached through a lower identifier is adoptable only if the
        // turn's own identity identifiers do not contradict it: Q logging in
        // on P's browser must not become P because the tag says so.
        let mut actor = strong.iter().find_map(|i| {
            self.lookup(*i, ts_us)
                .filter(|a| !identity_conflict(&self.live_identity(*a, ts_us), &turn_identity))
        });
        if actor.is_none() {
            let id = self.actor_id_for(turn_id);
            self.actors.entry(id).or_insert_with(|| Actor {
                id,
                opened_us: ts_us,
                last_us: ts_us,
                merged_into: None,
                turns: 0,
                confirmed: false,
                strong: SmallVec::new(),
            });
            out.opened = true;
            actor = Some(id);
        }
        let mut actor = actor.expect("set above");

        // Rule 3: another live binding on this turn names a different actor.
        // Merge unless an identity contradicts; otherwise rule 2 re-points.
        for ident in strong.iter() {
            let Some(other) = self.lookup(*ident, ts_us) else {
                continue;
            };
            if other == actor {
                continue;
            }
            let other_identity = self.live_identity(other, ts_us);
            if identity_conflict(&other_identity, &turn_identity)
                || identity_conflict(&self.live_identity(actor, ts_us), &other_identity)
            {
                continue;
            }
            actor = self.merge(actor, other, ident.kind, ts_us, &mut out);
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
                        returned: false,
                    },
                ));
            }
        }

        if let Some(mut a) = self.actors.get_mut(&actor) {
            a.last_us = a.last_us.max(ts_us);
            a.turns = a.turns.saturating_add(1);
            out.actors_touched.push(a.clone());
        }
        out.actor = Some(actor);
        out
    }

    /// The actor's live identity-level bindings.
    fn live_identity(&self, actor: u64, now_us: i64) -> SmallVec<[Ident; 4]> {
        self.actors.get(&actor).map_or(SmallVec::new(), |a| {
            a.strong
                .iter()
                .copied()
                .filter(|i| {
                    i.kind.level() == 1
                        && self.strong.get(i).is_some_and(|b| {
                            b.expires_us > now_us && self.canonical(b.actor) == actor
                        })
                })
                .collect()
        })
    }

    /// The older actor stays canonical; the other points at it.
    fn merge(&self, a: u64, b: u64, via: Kind, ts_us: i64, out: &mut Resolution) -> u64 {
        let (opened_a, opened_b) = (
            self.actors.get(&a).map_or(i64::MAX, |x| x.opened_us),
            self.actors.get(&b).map_or(i64::MAX, |x| x.opened_us),
        );
        let (canonical, merged) = if (opened_b, b) < (opened_a, a) {
            (b, a)
        } else {
            (a, b)
        };
        let (moved, confirmed) = self
            .actors
            .get_mut(&merged)
            .map(|mut m| {
                m.merged_into = Some(canonical);
                m.last_us = m.last_us.max(ts_us);
                (std::mem::take(&mut m.strong), m.confirmed)
            })
            .unwrap_or_default();
        if let Some(mut c) = self.actors.get_mut(&canonical) {
            for i in moved {
                if !c.strong.contains(&i) {
                    c.strong.push(i);
                }
            }
            c.confirmed |= confirmed;
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
        canonical
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
        // Returned: the same value bound to the same actor on an earlier turn.
        let same_actor = previous.filter(|p| self.canonical(p.actor) == self.canonical(actor));
        let returned = same_actor.is_some_and(|p| p.returned || p.first_seen_us < ts_us);
        let first_seen = same_actor.map_or(ts_us, |p| p.first_seen_us);
        let expires_us = if ident.kind.is_provisional() && !returned {
            first_seen + TTL_PROVISIONAL_US
        } else {
            ts_us + ident.kind.ttl_us()
        };
        let binding = Binding {
            actor,
            first_seen_us: first_seen,
            last_seen_us: ts_us,
            expires_us,
            returned,
        };
        self.strong.insert(ident, binding);
        if let Some(mut a) = self.actors.get_mut(&actor) {
            if !a.strong.contains(&ident) {
                a.strong.push(ident);
            }
            if returned || !ident.kind.is_provisional() {
                a.confirmed = true;
            }
        }
        out.bindings.push((ident, binding));
    }
}

fn identity_of(strong: &[Ident]) -> SmallVec<[Ident; 4]> {
    strong
        .iter()
        .copied()
        .filter(|i| i.kind.level() == 1)
        .collect()
}

/// The identity-level rule, per kind: two principals are the same person
/// only if equal, and a shared principal settles it whatever the credentials
/// (one user, two API tokens). Without a principal on both sides, two
/// credentials are the same actor only if one is shared (two tokens under
/// one NAT are two actors). Sessions and tags never partition: a browser is
/// not a person and has many sessions.
fn identity_conflict(a: &[Ident], b: &[Ident]) -> bool {
    let principals = |s: &[Ident]| -> SmallVec<[u64; 2]> {
        s.iter()
            .filter(|i| i.kind == Kind::Principal)
            .map(|i| i.value)
            .collect()
    };
    let credentials = |s: &[Ident]| -> SmallVec<[u64; 4]> {
        s.iter()
            .filter(|i| i.kind == Kind::Credential)
            .map(|i| i.value)
            .collect()
    };
    let (pa, pb) = (principals(a), principals(b));
    if !pa.is_empty() && !pb.is_empty() {
        return !pa.iter().any(|p| pb.contains(p));
    }
    let (ca, cb) = (credentials(a), credentials(b));
    !ca.is_empty() && !cb.is_empty() && !ca.iter().any(|c| cb.contains(c))
}

/// A row as stored, for load.
pub fn actor_row(
    id: u64,
    opened_us: i64,
    last_us: i64,
    merged_into: Option<u64>,
    turns: u32,
    confirmed: bool,
) -> Actor {
    Actor {
        id,
        opened_us,
        last_us,
        merged_into,
        turns,
        confirmed,
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

    /// Resolve a turn with a fresh, unique turn id; panics on a turn with no actor.
    fn turn(res: &Resolver, n: u64, ts_us: i64, idents: &[Ident]) -> u64 {
        res.resolve(&format!("{n:032x}"), ts_us, idents)
            .actor
            .expect("strong identifier present")
    }

    #[test]
    fn levels_ttls_and_ids() {
        assert!(Kind::Principal.level() < Kind::Session.level());
        assert!(Kind::Session.level() < Kind::Tag.level());
        assert_eq!(Kind::Credential.level(), Kind::Principal.level());
        assert_eq!(Kind::Credential.ttl_us(), TTL_YEAR_US);
        assert!(Kind::Net.ttl_us() < Kind::Session.ttl_us());
        assert!(!Kind::Net.is_strong());
        assert!(Kind::Session.is_provisional() && Kind::Tag.is_provisional());
        assert!(!Kind::Principal.is_provisional() && !Kind::Credential.is_provisional());
        let a = r();
        let t = "0123456789abcdef0123456789abcdef";
        assert_eq!(a.actor_id_for(t), a.actor_id_for(t));
        assert_ne!(
            a.actor_id_for(t),
            a.actor_id_for("0123456789abcdef0123456789abcdee")
        );
        assert_ne!(
            Ident::pair(Kind::Ja4Asn, 1, 2),
            Ident::pair(Kind::Ja4Asn, 2, 1)
        );
        assert_ne!(a.cluster_key("aa", "bb"), a.cluster_key("bb", "aa"));
    }

    #[test]
    fn a_turn_with_no_strong_identifier_has_no_actor() {
        let res = r();
        let out = res.resolve(
            &"1".repeat(32),
            S,
            &[id(Kind::Net, 7), Ident::pair(Kind::ShapeNet, 1, 7)],
        );
        assert_eq!(out.actor, None);
        assert!(out.bindings.is_empty() && !out.opened);
        assert_eq!(
            res.len(),
            (0, 0, 0),
            "a peer or shape cluster is never an actor"
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
        assert_eq!(a, g, "pre-login browsing belongs to the user");
        assert_eq!(res.lookup(p, 3 * S), Some(g));
        assert_eq!(res.lookup(s2, 3 * S), Some(g));
        assert!(res.actor(g).unwrap().confirmed);
    }

    #[test]
    fn one_principal_two_credentials_is_one_actor_two_credentials_alone_are_two() {
        let res = r();
        let (p, c1, c2, net) = (
            id(Kind::Principal, 1),
            id(Kind::Credential, 11),
            id(Kind::Credential, 12),
            id(Kind::Net, 7),
        );
        let a = turn(&res, 1, S, &[p, c1, net]);
        assert_eq!(
            turn(&res, 2, 2 * S, &[p, c2, net]),
            a,
            "one user, two API tokens"
        );
        assert_eq!(res.lookup(c2, 3 * S), Some(a));
        assert_eq!(res.merges_done.load(Ordering::Relaxed), 0);

        let res = r();
        let (c3, c4) = (id(Kind::Credential, 13), id(Kind::Credential, 14));
        let x = turn(&res, 3, S, &[c3, net]);
        let y = turn(&res, 4, 2 * S, &[c4, net]);
        assert_ne!(x, y, "two tokens under one NAT are two actors");
        assert_eq!(res.merges_done.load(Ordering::Relaxed), 0);
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
    fn expired_session_does_not_link_and_a_returned_one_lasts_a_week() {
        let res = r();
        let s = id(Kind::Session, 1);
        let a = turn(&res, 1, S, &[s]);
        // Seen once: provisional, a day.
        assert_eq!(res.lookup(s, S + TTL_PROVISIONAL_US - 1), Some(a));
        assert_eq!(res.lookup(s, S + TTL_PROVISIONAL_US), None);
        // Returned within the day: the full week from the return.
        let s2 = id(Kind::Session, 2);
        let b = turn(&res, 2, S, &[s2]);
        assert_eq!(turn(&res, 3, 2 * S, &[s2]), b);
        assert_eq!(res.lookup(s2, 2 * S + TTL_WEEK_US - 1), Some(b));
        assert_eq!(res.lookup(s2, 2 * S + TTL_WEEK_US), None);
        assert!(res.actor(b).unwrap().confirmed);
        assert!(!res.actor(a).unwrap().confirmed);
    }

    #[test]
    fn cookie_less_scanner_leaves_nothing_behind() {
        let res = r();
        let net = id(Kind::Net, 7);
        // 100 turns, each with the fresh session Laravel mints for a client that returns no cookie.
        for i in 0..100u64 {
            turn(&res, i, S + i as i64, &[id(Kind::Session, 1000 + i), net]);
        }
        assert_eq!(res.len().0, 100, "provisional actors while the day runs");
        let swept = res.sweep(S + TTL_PROVISIONAL_US + 200);
        assert_eq!(swept.bindings.len(), 100);
        assert_eq!(swept.actors.len(), 100);
        assert_eq!(
            res.len(),
            (0, 0, 0),
            "zero actors, zero strong bindings, weak values aged out"
        );
    }

    #[test]
    fn a_browser_that_returns_its_tag_is_one_durable_actor() {
        let res = r();
        let (t, s1) = (id(Kind::Tag, 10), id(Kind::Session, 1));
        let a = turn(&res, 1, S, &[t, s1]); // the tag was issued on this turn
        assert_eq!(turn(&res, 2, 2 * S, &[t, s1]), a); // and came back valid
        let swept = res.sweep(S + TTL_PROVISIONAL_US + S);
        assert!(swept.actors.is_empty());
        assert_eq!(res.len().0, 1);
        assert!(res.actor(a).unwrap().confirmed);
        assert_eq!(
            res.lookup(t, 2 * S + TTL_YEAR_US - 1),
            Some(a),
            "the tag now lasts its year"
        );
    }

    #[test]
    fn two_cookie_less_browsers_behind_one_nat_become_two_actors_never_one() {
        let res = r();
        let net = id(Kind::Net, 7);
        let shape = Ident::pair(Kind::ShapeNet, 42, 7);
        let (ta, sa, tb, sb) = (
            id(Kind::Tag, 1),
            id(Kind::Session, 1),
            id(Kind::Tag, 2),
            id(Kind::Session, 2),
        );
        let a = turn(&res, 1, S, &[ta, sa, net, shape]);
        let b = turn(&res, 2, 2 * S, &[tb, sb, net, shape]);
        assert_ne!(a, b);
        assert_eq!(turn(&res, 3, 3 * S, &[ta, sa, net, shape]), a);
        assert_eq!(turn(&res, 4, 4 * S, &[tb, sb, net, shape]), b);
        assert_eq!(
            res.merges_done.load(Ordering::Relaxed),
            0,
            "weak keys never merge"
        );
        assert_eq!(
            res.cluster_size(shape, a, 5 * S),
            1,
            "but they share a cluster"
        );
        res.sweep(5 * S + TTL_PROVISIONAL_US);
        assert_eq!(res.len().0, 2);
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
        // The same script through a resolver reloaded after turn 3.
        let first = r();
        for (n, ts, ids) in &script[..3] {
            turn(&first, *n, *ts, ids);
        }
        let reloaded = r();
        let actors: Vec<Actor> = first
            .actors
            .iter()
            .map(|e| e.value().clone())
            .map(|a| {
                actor_row(
                    a.id,
                    a.opened_us,
                    a.last_us,
                    a.merged_into,
                    a.turns,
                    a.confirmed,
                )
            })
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
