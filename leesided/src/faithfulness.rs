//! Faithfulness checks (docs/llm-evals.md section 3): every signal a
//! label proposal claims is verified against its own cited turns
//! before anything is written. The caller drops the failed signals
//! and keeps the label only when a surviving signal sits on the
//! label's side; every failure is logged.
//!
//! The label envelope carries the brief's window names (`iri_cv`,
//! `asset_ratio`) as aliases beside the raw v2 features; flag shares
//! and rejected credentials have no window source, so those checks
//! compute over the signal's cited turns (`flags`, distinct `cred`
//! prefixes). Checks are pure over the envelope, so the worker and
//! `llm eval` run the same code.

use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Curated scanner-probe paths, embedded: full path or any segment
/// matches. exclusions (robots.txt and friends) are documented with
/// the list.
const SCANNER_PATHS_JSON: &str = include_str!("../data/scanner-paths.json");

/// The brief's table, in order. `rejected_actions` joins the live
/// signal enum with the outcomes round; its check already exists and
/// fails closed until turns carry `app_outcome`.
pub const SIGNALS: [&str; 12] = [
    "scanner_paths",
    "high_404_rate",
    "machine_cadence",
    "no_assets",
    "ua_inconsistent",
    "credential_stuffing",
    "webhook_forgery",
    "honeytoken_hit",
    "rejected_actions",
    "normal_browsing",
    "verified_partner",
    "insufficient_data",
];

pub fn scanner_paths() -> HashSet<String> {
    let v: Value = serde_json::from_str(SCANNER_PATHS_JSON).unwrap_or(Value::Null);
    v.get("paths")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub struct Aux<'a> {
    pub honeytoken_routes: &'a HashSet<String>,
    pub scanner_paths: &'a HashSet<String>,
}

/// One claimed signal with its own cited turn indices.
#[derive(Debug, Clone, PartialEq)]
pub struct CitedSignal {
    pub name: String,
    pub turns: Vec<usize>,
}

/// The label side a signal argues for: the nine malicious signals,
/// the two benign ones, and nothing for `insufficient_data` (it
/// argues for `unknown`, which has no side).
pub fn side(signal: &str) -> Option<&'static str> {
    match signal {
        "scanner_paths"
        | "high_404_rate"
        | "machine_cadence"
        | "no_assets"
        | "ua_inconsistent"
        | "credential_stuffing"
        | "webhook_forgery"
        | "honeytoken_hit"
        | "rejected_actions" => Some("malicious"),
        "normal_browsing" | "verified_partner" => Some("benign"),
        _ => None,
    }
}

fn turns(envelope: &Value) -> Vec<&Value> {
    envelope
        .get("turns")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn window(envelope: &Value) -> Option<&serde_json::Map<String, Value>> {
    envelope.get("window")?.as_object()
}

fn window_num(window: Option<&serde_json::Map<String, Value>>, name: &str) -> Option<f64> {
    window?.get(name)?.as_f64()
}

fn str_field<'a>(t: &'a Value, name: &str) -> Option<&'a str> {
    t.get(name)?.as_str()
}

fn status(t: &Value) -> Option<i64> {
    t.get("status")?.as_i64()
}

fn flags(t: &Value) -> Vec<&str> {
    t.get("flags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Share of `ts` with the predicate true; empty is 0.
fn share(ts: &[&Value], f: impl Fn(&Value) -> bool) -> f64 {
    if ts.is_empty() {
        return 0.0;
    }
    ts.iter().filter(|t| f(t)).count() as f64 / ts.len() as f64
}

fn is_404(t: &Value) -> bool {
    status(t) == Some(404)
}

fn is_asset(t: &Value) -> bool {
    t.get("is_asset").and_then(Value::as_i64) == Some(1)
}

/// A page view: a 2xx on the web surface that is not an asset.
fn is_html_turn(t: &Value) -> bool {
    matches!(status(t), Some(s) if (200..300).contains(&s))
        && str_field(t, "surface") == Some("web")
        && !is_asset(t)
}

fn in_wordlist(path: &str, list: &HashSet<String>) -> bool {
    if list.contains(path) {
        return true;
    }
    path.split('/')
        .any(|seg| !seg.is_empty() && list.contains(seg))
}

fn distinct_paths<'a>(ts: &[&'a Value]) -> HashSet<&'a str> {
    ts.iter().filter_map(|t| str_field(t, "path")).collect()
}

/// Max over flags of the share of turns carrying it; no turns is 0.
fn max_flag_rate(ts: &[&Value]) -> f64 {
    let mut rates: HashMap<&str, usize> = HashMap::new();
    for t in ts {
        for f in flags(t) {
            *rates.entry(f).or_insert(0) += 1;
        }
    }
    rates
        .values()
        .map(|n| *n as f64 / ts.len().max(1) as f64)
        .fold(0.0, f64::max)
}

fn distinct_rejected_creds<'a>(ts: &[&'a Value]) -> HashSet<&'a str> {
    ts.iter()
        .filter(|t| str_field(t, "credential_status") == Some("rejected"))
        .filter_map(|t| str_field(t, "cred"))
        .collect()
}

/// Check every claimed signal against its own cited turns and
/// return the failed signal names in claim order; empty means all
/// passed. An out-of-range citation fails the signal under check:
/// citing turns that are not there is unfaithful. `machine_cadence`
/// and `insufficient_data` read the window only, so they may cite
/// nothing; every other signal with no cited turns carries no
/// evidence and fails.
pub fn check_proposal(envelope: &Value, signals: &[CitedSignal], aux: &Aux) -> Vec<String> {
    let all = turns(envelope);
    let win = window(envelope);
    let mut failed = Vec::new();
    for signal in signals {
        let mut cited_turns = Vec::with_capacity(signal.turns.len());
        let mut bad_cite = false;
        for i in &signal.turns {
            match all.get(*i) {
                Some(t) => cited_turns.push(*t),
                None => {
                    bad_cite = true;
                    break;
                }
            }
        }
        let ok = !bad_cite
            && match signal.name.as_str() {
                "scanner_paths" => {
                    (distinct_paths(&cited_turns).len() >= 3 && share(&cited_turns, is_404) > 0.5)
                        || cited_turns.iter().any(|t| {
                            str_field(t, "path").is_some_and(|p| in_wordlist(p, aux.scanner_paths))
                        })
                }
                "high_404_rate" => share(&cited_turns, is_404) > 0.5,
                "machine_cadence" => {
                    window_num(win, "iri_cv").is_some_and(|v| v < 0.2)
                        || window_num(win, "turns_last_60s").is_some_and(|v| v >= 30.0)
                }
                "no_assets" => {
                    window_num(win, "asset_ratio").is_some_and(|v| v < 0.05)
                        && cited_turns.iter().any(|t| is_html_turn(t))
                }
                "ua_inconsistent" => cited_turns.iter().any(|t| {
                    (str_field(t, "ua_class") == Some("browser")
                        && flags(t).contains(&"ua_chromium_no_ch"))
                        || str_field(t, "ja4_class") == Some("library")
                }),
                "credential_stuffing" => distinct_rejected_creds(&cited_turns).len() >= 5,
                "webhook_forgery" => {
                    !cited_turns.is_empty()
                        && cited_turns.iter().all(|t| {
                            str_field(t, "surface") == Some("webhook")
                                && str_field(t, "credential_status") == Some("rejected")
                        })
                }
                "honeytoken_hit" => cited_turns.iter().any(|t| {
                    str_field(t, "path").is_some_and(|p| aux.honeytoken_routes.contains(p))
                }),
                "rejected_actions" => {
                    !cited_turns.is_empty()
                        && cited_turns.iter().all(|t| {
                            str_field(t, "app_outcome")
                                .is_some_and(|o| o.rsplit(':').next() == Some("rejected"))
                        })
                }
                "normal_browsing" => {
                    !cited_turns.is_empty()
                        && max_flag_rate(&cited_turns) <= 0.2
                        && window_num(win, "asset_ratio").is_some_and(|v| v > 0.1)
                }
                "verified_partner" => {
                    cited_turns
                        .iter()
                        .any(|t| str_field(t, "credential_status") == Some("verified"))
                        && !cited_turns
                            .iter()
                            .any(|t| str_field(t, "credential_status") == Some("rejected"))
                }
                "insufficient_data" => window_num(win, "turns_held").is_some_and(|v| v < 10.0),
                _ => false,
            };
        if !ok {
            failed.push(signal.name.clone());
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(turns: Vec<Value>, window: Value, signal: &str, cited: &[usize]) -> Vec<String> {
        let honey = HashSet::from(["admin.backup".to_string()]);
        let wordlist = scanner_paths();
        let aux = Aux {
            honeytoken_routes: &honey,
            scanner_paths: &wordlist,
        };
        check_proposal(
            &envelope(turns, window),
            &[CitedSignal {
                name: signal.to_string(),
                turns: cited.to_vec(),
            }],
            &aux,
        )
    }

    fn check_all(turns: Vec<Value>, window: Value, signals: &[(&str, &[usize])]) -> Vec<String> {
        let honey = HashSet::from(["admin.backup".to_string()]);
        let wordlist = scanner_paths();
        let aux = Aux {
            honeytoken_routes: &honey,
            scanner_paths: &wordlist,
        };
        let signals: Vec<CitedSignal> = signals
            .iter()
            .map(|(name, cited)| CitedSignal {
                name: name.to_string(),
                turns: cited.to_vec(),
            })
            .collect();
        check_proposal(&envelope(turns, window), &signals, &aux)
    }

    fn turn(path: &str, status: i64) -> Value {
        json!({
            "method": "GET", "path": path, "status": status,
            "ua_class": "browser", "flags": [],
            "credential_status": null, "tag_status": "absent",
            "ja4_class": "unknown", "surface": "web",
            "is_asset": 0, "cred": null,
        })
    }

    fn envelope(turns: Vec<Value>, window: Value) -> Value {
        json!({"task": "propose_label", "subject": {}, "window": window, "turns": turns})
    }

    #[test]
    fn scanner_paths_needs_three_distinct_404s_or_a_wordlist_hit() {
        let scan = vec![
            turn("/a", 404),
            turn("/b", 404),
            turn("/c", 404),
            turn("/", 200),
        ];
        assert!(check(scan, json!({}), "scanner_paths", &[0, 1, 2]).is_empty());
        let two = vec![turn("/a", 404), turn("/b", 404)];
        assert!(!check(two, json!({}), "scanner_paths", &[0, 1]).is_empty());
        let wordlisted = vec![turn("/wp-login.php", 200)];
        assert!(check(wordlisted, json!({}), "scanner_paths", &[0]).is_empty());
        let clean = vec![turn("/", 200)];
        assert!(!check(clean, json!({}), "scanner_paths", &[0]).is_empty());
    }

    #[test]
    fn high_404_rate_is_a_strict_majority() {
        let ts = vec![turn("/a", 404), turn("/b", 404), turn("/", 200)];
        assert!(check(ts, json!({}), "high_404_rate", &[0, 1, 2]).is_empty());
        let ts = vec![turn("/a", 404), turn("/", 200)];
        assert!(!check(ts, json!({}), "high_404_rate", &[0, 1]).is_empty());
    }

    #[test]
    fn machine_cadence_passes_on_steady_cadence_or_burst() {
        let ts = vec![turn("/", 200)];
        assert!(check(ts.clone(), json!({"iri_cv": 0.02}), "machine_cadence", &[0]).is_empty());
        assert!(check(ts.clone(), json!({"iri_cv": 0.19}), "machine_cadence", &[0]).is_empty());
        assert!(!check(ts.clone(), json!({"iri_cv": 0.2}), "machine_cadence", &[0]).is_empty());
        let burst = json!({"iri_cv": 0.9, "turns_last_60s": 40.0});
        assert!(check(ts.clone(), burst, "machine_cadence", &[0]).is_empty());
        let edge = json!({"iri_cv": 0.9, "turns_last_60s": 30.0});
        assert!(check(ts.clone(), edge, "machine_cadence", &[0]).is_empty());
        let thin = json!({"iri_cv": 0.9, "turns_last_60s": 29.0});
        assert!(!check(ts.clone(), thin, "machine_cadence", &[0]).is_empty());
        assert!(!check(ts.clone(), json!({}), "machine_cadence", &[0]).is_empty());
        // A window signal may cite nothing.
        assert!(check(ts, json!({"iri_cv": 0.02}), "machine_cadence", &[]).is_empty());
    }

    #[test]
    fn no_assets_needs_an_html_turn_and_almost_no_assets() {
        let win = json!({"asset_ratio": 0.0});
        let bot = vec![turn("/", 200)];
        assert!(check(bot.clone(), win.clone(), "no_assets", &[0]).is_empty());
        assert!(!check(bot, win.clone(), "no_assets", &[]).is_empty());
        let mut asset = turn("/", 200);
        asset["is_asset"] = json!(1);
        assert!(!check(vec![asset], json!({"asset_ratio": 1.0}), "no_assets", &[0]).is_empty());
        let mut t = turn("api.ping", 200);
        t["surface"] = json!("api");
        assert!(!check(vec![t], win, "no_assets", &[0]).is_empty());
    }

    #[test]
    fn ua_inconsistent_matches_flag_or_library_ja4() {
        let mut t = turn("/", 200);
        t["flags"] = json!(["ua_chromium_no_ch"]);
        assert!(check(vec![t], json!({}), "ua_inconsistent", &[0]).is_empty());
        let mut t = turn("/", 200);
        t["ua_class"] = json!("library");
        t["ja4_class"] = json!("library");
        assert!(check(vec![t], json!({}), "ua_inconsistent", &[0]).is_empty());
        assert!(!check(vec![turn("/", 200)], json!({}), "ua_inconsistent", &[0]).is_empty());
    }

    #[test]
    fn credential_stuffing_counts_rejected_creds_on_its_own_turns() {
        let mut ts = Vec::new();
        for i in 0..5 {
            let mut t = turn("portal.login", 401);
            t["credential_status"] = json!("rejected");
            t["cred"] = json!(format!("ab12cd{i:02}"));
            ts.push(t);
        }
        assert!(check(
            ts.clone(),
            json!({}),
            "credential_stuffing",
            &[0, 1, 2, 3, 4]
        )
        .is_empty());
        // Five rejected turns exist, but the signal cites one: the
        // check sees the cited turns, not the envelope.
        assert!(!check(ts.clone(), json!({}), "credential_stuffing", &[0]).is_empty());
        ts.truncate(4);
        assert!(!check(ts, json!({}), "credential_stuffing", &[0, 1, 2, 3]).is_empty());
    }

    #[test]
    fn webhook_forgery_needs_all_cited_rejected_webhooks() {
        let mut t = turn("webhooks.demo", 401);
        t["surface"] = json!("webhook");
        t["credential_status"] = json!("rejected");
        assert!(check(
            vec![t.clone(), t.clone()],
            json!({}),
            "webhook_forgery",
            &[0, 1]
        )
        .is_empty());
        assert!(!check(
            vec![t, turn("/", 200)],
            json!({}),
            "webhook_forgery",
            &[0, 1]
        )
        .is_empty());
    }

    #[test]
    fn honeytoken_hit_matches_a_cited_route() {
        assert!(check(
            vec![turn("admin.backup", 200)],
            json!({}),
            "honeytoken_hit",
            &[0]
        )
        .is_empty());
        assert!(!check(vec![turn("home", 200)], json!({}), "honeytoken_hit", &[0]).is_empty());
    }

    #[test]
    fn rejected_actions_fails_closed_without_outcomes() {
        // No app_outcome on the turns yet (the outcomes round adds
        // it): the signal cannot be faithful.
        assert!(!check(
            vec![turn("portal.login", 200)],
            json!({}),
            "rejected_actions",
            &[0]
        )
        .is_empty());
        let mut t = turn("portal.login", 200);
        t["app_outcome"] = json!("promo_code:rejected");
        assert!(check(vec![t], json!({}), "rejected_actions", &[0]).is_empty());
    }

    #[test]
    fn normal_browsing_needs_cited_assets_and_quiet_flags() {
        let mut ts = Vec::new();
        for _ in 0..8 {
            let mut t = turn("/", 200);
            t["is_asset"] = json!(1);
            ts.push(t);
        }
        ts.push(turn("/venues", 200));
        ts.push(turn("/venues/1", 200));
        let win = json!({"asset_ratio": 0.8});
        assert!(check(ts, win.clone(), "normal_browsing", &[8, 9]).is_empty());
        assert!(!check(
            vec![turn("/venues", 200)],
            win.clone(),
            "normal_browsing",
            &[]
        )
        .is_empty());
        let mut flagged = turn("/", 200);
        flagged["flags"] = json!(["library_ua_on_web"]);
        let ts = vec![flagged.clone(), flagged];
        assert!(!check(ts, win, "normal_browsing", &[0]).is_empty());
    }

    #[test]
    fn verified_partner_reads_its_own_turns() {
        let mut t = turn("api.ping", 200);
        t["surface"] = json!("api");
        t["credential_status"] = json!("verified");
        assert!(check(vec![t.clone()], json!({}), "verified_partner", &[0]).is_empty());
        // A rejected turn elsewhere in the envelope is fine; a
        // rejected turn in the cited set fails the signal.
        let mut r = turn("api.ping", 401);
        r["credential_status"] = json!("rejected");
        assert!(check(
            vec![t.clone(), r.clone()],
            json!({}),
            "verified_partner",
            &[0]
        )
        .is_empty());
        assert!(!check(vec![t, r], json!({}), "verified_partner", &[0, 1]).is_empty());
    }

    #[test]
    fn insufficient_data_reads_turns_held() {
        assert!(check(vec![], json!({"turns_held": 4.0}), "insufficient_data", &[]).is_empty());
        assert!(!check(
            vec![],
            json!({"turns_held": 64.0}),
            "insufficient_data",
            &[]
        )
        .is_empty());
    }

    #[test]
    fn unknown_signals_and_bad_citations_fail() {
        assert!(!check(vec![turn("/", 200)], json!({}), "no_such_signal", &[0]).is_empty());
        assert!(!check(vec![turn("/", 200)], json!({}), "high_404_rate", &[7]).is_empty());
        assert!(!check(vec![], json!({}), "high_404_rate", &[]).is_empty());
    }

    #[test]
    fn check_proposal_lists_every_failure_in_claim_order() {
        let ts = vec![turn("/a", 404), turn("/b", 404), turn("/", 200)];
        let win = json!({"iri_cv": 0.02});
        let failed = check_all(
            ts.clone(),
            win.clone(),
            &[
                ("scanner_paths", &[0, 1, 2][..]),
                ("high_404_rate", &[1, 2][..]),
                ("machine_cadence", &[][..]),
            ],
        );
        assert_eq!(failed, vec!["high_404_rate".to_string()]);
        let failed = check_all(
            ts,
            win,
            &[("high_404_rate", &[1, 2][..]), ("no_such_signal", &[0][..])],
        );
        assert_eq!(
            failed,
            vec!["high_404_rate".to_string(), "no_such_signal".to_string()]
        );
    }

    #[test]
    fn sides_split_malicious_benign_and_sideless() {
        for s in [
            "scanner_paths",
            "high_404_rate",
            "machine_cadence",
            "no_assets",
            "ua_inconsistent",
            "credential_stuffing",
            "webhook_forgery",
            "honeytoken_hit",
            "rejected_actions",
        ] {
            assert_eq!(side(s), Some("malicious"), "{s}");
        }
        for s in ["normal_browsing", "verified_partner"] {
            assert_eq!(side(s), Some("benign"), "{s}");
        }
        assert_eq!(side("insufficient_data"), None);
        assert_eq!(side("no_such_signal"), None);
    }
}
