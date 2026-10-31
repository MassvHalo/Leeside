//! The Windside feature extractor, v2. One fixed-order `f32` vector per
//! window, computed from the windows alone: symbols, hashes, statuses,
//! timestamps. leesided is the single source of truth for these; the lab
//! trains on the rows ingest writes and never re-implements them.
//!
//! Two rules hold for every name here: rule outcomes are never features
//! (what the gate answered cannot be learned back), and raw identifiers are
//! never features (counts of distinct hashes are). `names_pass_the_denylist`
//! holds the list to both.
//!
//! Rows are emitted per **confirmed actor** window and per **cluster**
//! window; a provisional actor holds one turn and is noise. The repo's v1
//! (30 names, per session) was the pre-Windside vector.

use super::symbols::Symbols;
use super::windows::{TurnSummary, Window};

pub const VERSION: u32 = 2;

/// The order the values are written in. A model file whose names differ
/// from this list fails the load.
pub const NAMES: [&str; 38] = [
    // v1: volume and pace
    "turns_total",
    "turns_held",
    "age_s",
    "idle_s",
    "turns_last_60s",
    "turns_last_600s",
    "gap_mean_ms",
    "gap_cv",
    // v1: errors and outcomes
    "ratio_4xx",
    "ratio_5xx",
    "ratio_404",
    "ratio_422",
    "count_not_found_exc",
    // v1: auth
    "login_failed_total",
    "login_ok_total",
    // v1: breadth
    "distinct_routes",
    "distinct_routes_ratio",
    "distinct_bound_ids",
    "unrouted_ratio",
    "distinct_req_shapes",
    // v1: payload
    "bytes_out_mean",
    "bytes_out_max",
    "latency_mean_ms",
    "latency_max_ms",
    // v1: navigation
    "verb_post_ratio",
    "repeat_route_ratio",
    "ua_changes",
    // v1: cross-key
    "peer_turns_600s",
    "peer_ratio_4xx",
    "is_anon",
    // v2: cluster and identity signals (docs/actors.md)
    "cluster_actors_net",
    "shape_cluster_size",
    "tag_dropped",
    "credential_moved",
    // v2: surface indicators, the newest turn's surface
    "surface_web",
    "surface_api",
    "surface_webhook",
    "surface_honeypot",
];

pub const N: usize = NAMES.len();

/// Surface codes on a turn summary.
pub const SURFACE_WEB: u8 = 1;
pub const SURFACE_API: u8 = 2;
pub const SURFACE_WEBHOOK: u8 = 3;
pub const SURFACE_HONEYPOT: u8 = 4;

/// Tag status codes on a turn summary.
pub const TAG_ABSENT: u8 = 1;
pub const TAG_ISSUED: u8 = 2;
pub const TAG_VALID: u8 = 3;
pub const TAG_MALFORMED: u8 = 4;
pub const TAG_BAD_MAC: u8 = 5;

/// What the extractor cannot see from one window: the resolver's weak
/// clusters around it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context {
    /// Other actors seen on this window's current network inside the TTL.
    pub cluster_actors_net: u32,
    /// Other actors sharing this window's shape on this network.
    pub shape_cluster_size: u32,
}

/// Extract over a window (actor or cluster), with the peer window when held.
pub fn extract(
    window: &Window,
    peer: Option<&Window>,
    now_ms: u64,
    is_anon: bool,
    syms: &Symbols,
    ctx: Context,
) -> [f32; N] {
    let mut f = [0f32; N];
    let held = window.len();
    let heldf = held.max(1) as f32;
    f[0] = window.total as f32;
    f[1] = held as f32;
    f[2] = now_ms.saturating_sub(window.opened_ms) as f32 / 1000.0;
    f[3] = now_ms.saturating_sub(window.last_ms) as f32 / 1000.0;

    let login_failed = syms.get("login_failed");
    let login_ok = syms.get("login");
    let not_found = syms.get("ModelNotFoundException");
    let unrouted = syms.get("_unrouted");

    let mut last_60 = 0u32;
    let mut last_600 = 0u32;
    let mut gaps: Vec<f32> = Vec::with_capacity(held);
    let mut prev_ts: Option<u64> = None;
    let (mut c4, mut c5, mut c404, mut c422, mut nf, mut lf, mut lo, mut unr, mut post, mut repeat) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    let mut routes: Vec<u32> = Vec::with_capacity(16);
    let mut shapes: Vec<u32> = Vec::with_capacity(8);
    let mut ids: Vec<u64> = Vec::with_capacity(16);
    let mut uas: Vec<u32> = Vec::with_capacity(2);
    let (mut bytes_sum, mut bytes_max) = (0f64, 0i64);
    let (mut lat_sum, mut lat_max) = (0f32, 0f32);
    let mut prev_route = None;
    // v2
    let mut saw_issued = false;
    let mut tag_dropped = false;
    let mut cred_nets: Vec<(u64, u64)> = Vec::with_capacity(4);
    let mut credential_moved = false;

    // Oldest to newest, so gaps, repeats and "issued then absent" read in time order.
    let turns: Vec<&TurnSummary> = window.newest().collect();
    for t in turns.iter().rev() {
        let age = now_ms.saturating_sub(t.ts_ms);
        if age <= 60_000 {
            last_60 += 1;
        }
        if age <= 600_000 {
            last_600 += 1;
        }
        if let Some(p) = prev_ts {
            gaps.push(t.ts_ms.saturating_sub(p) as f32);
        }
        prev_ts = Some(t.ts_ms);
        match t.status {
            404 => {
                c4 += 1;
                c404 += 1
            }
            422 => {
                c4 += 1;
                c422 += 1
            }
            400..=499 => c4 += 1,
            500..=599 => c5 += 1,
            _ => {}
        }
        if t.exception.is_some() && t.exception == not_found {
            nf += 1;
        }
        if t.auth_event.is_some() {
            if t.auth_event == login_failed {
                lf += 1;
            } else if t.auth_event == login_ok {
                lo += 1;
            }
        }
        if unrouted == Some(t.route) {
            unr += 1;
        }
        if t.verb == super::model::Verb::Post {
            post += 1;
        }
        if prev_route == Some(t.route) {
            repeat += 1;
        }
        prev_route = Some(t.route);
        push_if_absent(&mut routes, t.route.0);
        push_if_absent(&mut shapes, t.req_shape.0);
        for (m, id) in &t.bound {
            push_if_absent64(&mut ids, ((m.0 as u64) << 32) | *id as u64);
        }
        push_if_absent(&mut uas, t.ua_hash);
        if t.bytes_out >= 0 {
            bytes_sum += t.bytes_out as f64;
            bytes_max = bytes_max.max(t.bytes_out);
        }
        lat_sum += t.latency_ms;
        lat_max = lat_max.max(t.latency_ms);
        // tag_dropped: a tag was issued here, and a later turn here carried none.
        match t.tag_status {
            TAG_ISSUED => saw_issued = true,
            TAG_ABSENT if saw_issued => tag_dropped = true,
            _ => {}
        }
        // credential_moved: one credential seen from two networks inside the window.
        if let (Some(c), Some(n)) = (t.credential, t.net) {
            if cred_nets.iter().any(|(cc, nn)| *cc == c && *nn != n) {
                credential_moved = true;
            } else if !cred_nets.contains(&(c, n)) {
                cred_nets.push((c, n));
            }
        }
    }

    f[4] = last_60 as f32;
    f[5] = last_600 as f32;
    if !gaps.is_empty() {
        let mean = gaps.iter().sum::<f32>() / gaps.len() as f32;
        let var = gaps.iter().map(|g| (g - mean) * (g - mean)).sum::<f32>() / gaps.len() as f32;
        f[6] = mean;
        f[7] = if mean > 0.0 { var.sqrt() / mean } else { 0.0 };
    }
    f[8] = c4 as f32 / heldf;
    f[9] = c5 as f32 / heldf;
    f[10] = c404 as f32 / heldf;
    f[11] = c422 as f32 / heldf;
    f[12] = nf as f32;
    f[13] = lf as f32;
    f[14] = lo as f32;
    f[15] = routes.len() as f32;
    f[16] = routes.len() as f32 / heldf;
    f[17] = ids.len() as f32;
    f[18] = unr as f32 / heldf;
    f[19] = shapes.len() as f32;
    f[20] = (bytes_sum / heldf as f64) as f32;
    f[21] = bytes_max as f32;
    f[22] = lat_sum / heldf;
    f[23] = lat_max;
    f[24] = post as f32 / heldf;
    f[25] = repeat as f32 / heldf;
    f[26] = uas.len().saturating_sub(1) as f32;
    if let Some(p) = peer {
        let mut n = 0u32;
        let mut p4 = 0u32;
        for t in p.newest() {
            if now_ms.saturating_sub(t.ts_ms) > 600_000 {
                break;
            }
            n += 1;
            if (400..500).contains(&t.status) {
                p4 += 1;
            }
        }
        f[27] = n as f32;
        f[28] = if n > 0 { p4 as f32 / n as f32 } else { 0.0 };
    }
    f[29] = is_anon as u8 as f32;
    f[30] = ctx.cluster_actors_net as f32;
    f[31] = ctx.shape_cluster_size as f32;
    f[32] = tag_dropped as u8 as f32;
    f[33] = credential_moved as u8 as f32;
    if let Some(newest) = turns.first() {
        match newest.surface {
            SURFACE_WEB => f[34] = 1.0,
            SURFACE_API => f[35] = 1.0,
            SURFACE_WEBHOOK => f[36] = 1.0,
            SURFACE_HONEYPOT => f[37] = 1.0,
            _ => {}
        }
    }
    f
}

fn push_if_absent(v: &mut Vec<u32>, x: u32) {
    if !v.contains(&x) {
        v.push(x);
    }
}

fn push_if_absent64(v: &mut Vec<u64>, x: u64) {
    if !v.contains(&x) {
        v.push(x);
    }
}

/// Name tokens that would make a feature a rule outcome or a raw identifier.
/// A name is split on `_` and no token may be one of these; counts of
/// distinct values ("distinct_bound_ids", "cluster_actors_net") are fine.
pub const DENYLIST: [&str; 20] = [
    "rule",
    "rules",
    "verdict",
    "gate",
    "applied",
    "block",
    "allow",
    "action",
    "mode",
    "sticky",
    "decision",
    "hash",
    "key",
    "id",
    "ip",
    "principal",
    "ja4",
    "asn",
    "country",
    "actor",
];

#[cfg(test)]
mod tests {
    use super::super::windows::{turn, EventKeys, Windows};
    use super::*;

    #[test]
    fn names_are_unique_and_match_the_vector() {
        let mut names = NAMES.to_vec();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), N);
        assert_eq!(VERSION, 2);
    }

    #[test]
    fn names_pass_the_denylist() {
        for name in NAMES {
            for token in name.split('_') {
                assert!(
                    !DENYLIST.contains(&token),
                    "{name}: token {token} names a rule outcome or an identifier"
                );
            }
        }
    }

    #[test]
    fn counts_what_the_window_holds() {
        let syms = Symbols::default();
        let w = Windows::default();
        let keys = EventKeys {
            session: 1,
            peer: 2,
            principal: None,
            credential: None,
            actor: None,
            cluster: None,
        };
        let login = syms.intern("portal.login");
        let home = syms.intern("home");
        let failed = syms.intern("login_failed");
        let mut t = turn(1_000, home, 200);
        t.bytes_out = 1000;
        t.latency_ms = 10.0;
        t.tag_status = TAG_ISSUED;
        t.surface = SURFACE_WEB;
        w.record(&keys, t);
        for i in 0..3u64 {
            let mut t = turn(2_000 + i * 1000, login, 401);
            t.verb = super::super::model::Verb::Post;
            t.auth_event = Some(failed);
            t.bytes_out = 100;
            t.latency_ms = 30.0;
            t.ua_hash = i as u32 % 2;
            t.tag_status = TAG_ABSENT;
            t.surface = SURFACE_API;
            w.record(&keys, t);
        }
        let s = w.session(1).unwrap();
        let p = w.peer(2).unwrap();
        let f = extract(
            &s,
            Some(&p),
            5_000,
            true,
            &syms,
            Context {
                cluster_actors_net: 3,
                shape_cluster_size: 2,
            },
        );
        let at = |name: &str| f[NAMES.iter().position(|n| *n == name).unwrap()];
        assert_eq!(at("turns_total"), 4.0);
        assert_eq!(at("turns_held"), 4.0);
        assert_eq!(at("age_s"), 4.0);
        assert_eq!(at("idle_s"), 1.0);
        assert_eq!(at("turns_last_60s"), 4.0);
        assert_eq!(at("gap_mean_ms"), 1000.0);
        assert_eq!(at("gap_cv"), 0.0);
        assert_eq!(at("ratio_4xx"), 0.75);
        assert_eq!(at("login_failed_total"), 3.0);
        assert_eq!(at("distinct_routes"), 2.0);
        assert_eq!(at("repeat_route_ratio"), 0.5);
        assert_eq!(at("verb_post_ratio"), 0.75);
        assert_eq!(at("bytes_out_max"), 1000.0);
        assert_eq!(at("bytes_out_mean"), 325.0);
        assert_eq!(at("latency_max_ms"), 30.0);
        assert_eq!(at("ua_changes"), 1.0);
        assert_eq!(at("peer_turns_600s"), 4.0);
        assert_eq!(at("peer_ratio_4xx"), 0.75);
        assert_eq!(at("is_anon"), 1.0);
        assert_eq!(at("cluster_actors_net"), 3.0);
        assert_eq!(at("shape_cluster_size"), 2.0);
        assert_eq!(
            at("tag_dropped"),
            1.0,
            "issued on the first turn, absent on the later ones"
        );
        assert_eq!(at("credential_moved"), 0.0);
        assert_eq!(
            (at("surface_web"), at("surface_api")),
            (0.0, 1.0),
            "the newest turn is api"
        );
    }

    #[test]
    fn credential_moved_needs_two_networks_for_one_credential() {
        let syms = Symbols::default();
        let w = Windows::default();
        let keys = EventKeys {
            session: 1,
            peer: 2,
            principal: None,
            credential: Some(9),
            actor: None,
            cluster: None,
        };
        let route = syms.intern("api.ping");
        for (i, net) in [7u64, 7, 8].iter().enumerate() {
            let mut t = turn(1_000 + i as u64 * 1000, route, 200);
            t.credential = Some(9);
            t.net = Some(*net);
            w.record(&keys, t);
        }
        let s = w.session(1).unwrap();
        let f = extract(&s, None, 5_000, false, &syms, Context::default());
        assert_eq!(
            f[NAMES.iter().position(|n| *n == "credential_moved").unwrap()],
            1.0
        );
        // The same networks under two credentials move nothing.
        let w2 = Windows::default();
        for (i, (c, net)) in [(1u64, 7u64), (2, 8)].iter().enumerate() {
            let mut t = turn(1_000 + i as u64 * 1000, route, 200);
            t.credential = Some(*c);
            t.net = Some(*net);
            w2.record(&keys, t);
        }
        let f = extract(
            &w2.session(1).unwrap(),
            None,
            5_000,
            false,
            &syms,
            Context::default(),
        );
        assert_eq!(
            f[NAMES.iter().position(|n| *n == "credential_moved").unwrap()],
            0.0
        );
    }
}
