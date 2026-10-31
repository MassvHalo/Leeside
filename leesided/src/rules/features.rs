//! The Windside feature extractor, v1. One fixed-order `f32` vector per
//! turn, computed from the windows alone: symbols, hashes, statuses,
//! timestamps. leesided is the single source of truth for these; the lab
//! trains on the rows ingest writes and never re-implements them.

use super::symbols::Symbols;
use super::windows::Window;

pub const VERSION: u32 = 1;

/// The order the values are written in. A model file whose names differ
/// from this list fails the load.
pub const NAMES: [&str; 30] = [
    "turns_total",
    "turns_held",
    "age_s",
    "idle_s",
    "turns_last_60s",
    "turns_last_600s",
    "gap_mean_ms",
    "gap_cv",
    "ratio_4xx",
    "ratio_5xx",
    "ratio_404",
    "ratio_422",
    "count_not_found_exc",
    "login_failed_total",
    "login_ok_total",
    "distinct_routes",
    "distinct_routes_ratio",
    "distinct_bound_ids",
    "unrouted_ratio",
    "distinct_req_shapes",
    "bytes_out_mean",
    "bytes_out_max",
    "latency_mean_ms",
    "latency_max_ms",
    "verb_post_ratio",
    "repeat_route_ratio",
    "ua_changes",
    "peer_turns_600s",
    "peer_ratio_4xx",
    "is_anon",
];

pub const N: usize = NAMES.len();

/// Extract over the session window (and the peer window when held).
pub fn extract(
    session: &Window,
    peer: Option<&Window>,
    now_ms: u64,
    is_anon: bool,
    syms: &Symbols,
) -> [f32; N] {
    let mut f = [0f32; N];
    let held = session.len();
    let heldf = held.max(1) as f32;
    f[0] = session.total as f32;
    f[1] = held as f32;
    f[2] = now_ms.saturating_sub(session.opened_ms) as f32 / 1000.0;
    f[3] = now_ms.saturating_sub(session.last_ms) as f32 / 1000.0;

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

    // Oldest to newest, so gaps and repeats read in time order.
    let turns: Vec<_> = session.newest().collect();
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
        w.record(&keys, t);
        for i in 0..3u64 {
            let mut t = turn(2_000 + i * 1000, login, 401);
            t.verb = super::super::model::Verb::Post;
            t.auth_event = Some(failed);
            t.bytes_out = 100;
            t.latency_ms = 30.0;
            t.ua_hash = i as u32 % 2;
            w.record(&keys, t);
        }
        let s = w.session(1).unwrap();
        let p = w.peer(2).unwrap();
        let f = extract(&s, Some(&p), 5_000, true, &syms);
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
    }
}
