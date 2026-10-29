//! Session B integration: both sockets, the store, decisions across a
//! restart, reload under load, proposed rules, and the UDS round trip.

use leesided::config::Config;
use leesided::engine::{serve, Engine, Running};
use leesided::rules::compile::State;
use leesided::rules::model::{Mode, Rule};
use leesided::store::ts_us;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixDatagram, UnixStream};

static NEXT: AtomicU32 = AtomicU32::new(0);
/// The load test and the latency test must not share the two cores.
static HEAVY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Harness {
    dir: PathBuf,
    engine: Arc<Engine>,
    running: Running,
}

impl Harness {
    async fn start() -> Harness {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("leesided-it-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Harness::open(dir).await
    }

    async fn open(dir: PathBuf) -> Harness {
        let cfg = Config {
            socket_dir: dir.clone(),
            db: dir.join("leesided.sqlite"),
            api: "127.0.0.1:0".parse().unwrap(),
            enforce: true,
            rules_dir: PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/install")),
            socket_mode: 0o600,
            socket_gid: None,
        };
        let engine = Engine::open(cfg).await.expect("engine open");
        let running = serve(engine.clone()).await.expect("serve");
        Harness {
            dir,
            engine,
            running,
        }
    }

    async fn restart(self) -> Harness {
        let dir = self.dir.clone();
        self.running.abort();
        self.engine.shutdown().await;
        drop(self);
        Harness::open(dir).await
    }

    async fn probe(&self, line: &str) -> Value {
        let mut s = UnixStream::connect(self.dir.join("check.sock"))
            .await
            .expect("connect check.sock");
        s.write_all(line.as_bytes()).await.unwrap();
        s.write_all(b"\n").await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        serde_json::from_slice(&out)
            .unwrap_or_else(|e| panic!("bad verdict {e}: {}", String::from_utf8_lossy(&out)))
    }

    async fn event(&self, line: &str) {
        let sock = UnixDatagram::unbound().unwrap();
        sock.send_to(line.as_bytes(), self.dir.join("events.sock"))
            .await
            .expect("send event");
    }

    async fn http(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let mut s = TcpStream::connect(self.running.api_addr).await.unwrap();
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: leesided\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw);
        let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body).unwrap_or(Value::String(body.to_string()))
        };
        (status, value)
    }

    async fn wait_for(&self, what: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

const SESSION: &str = "a1b2c3d4e5f60718";
const PEER: &str = "0f1e2d3c4b5a6978";

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn probe_json(ts: f64, verb: &str, route: &str, session: &str) -> String {
    json!({"v":1,"ts":ts,"verb":verb,"route":route,"session_key":session,"peer_key":PEER,"principal":"anon"}).to_string()
}

fn login_failed_event(ts: f64, session: &str) -> String {
    json!({"v":1,"ts":ts,"session_key":session,"peer_key":PEER,"principal":"anon","verb":"POST",
        "route":"portal.login","status":401,"latency_ms":12.5,"bytes_in":40,"bytes_out":30,
        "req_shape":"{otp:str:6,phone:str:10}","resp_shape":"{ok:bool}","bound":[],
        "validation_failed":null,"exception":null,"auth_event":"login_failed",
        "gate":{"action":"allow","mode":"monitor","rule":null,"applied":false},
        "ua_hash":"9c8b7a6f","dropped_since_last":0})
    .to_string()
}

fn rule_json(id: &str, mode: &str, action: &str, route: &str) -> Value {
    let mut v = json!({"id": id, "note": "test", "mode": mode, "action": action,
        "match": {"route": [route], "verb": ["GET", "POST"], "principal": "any"},
        "origin": {"kind": "operator"}});
    if action == "rate_limit" {
        v["retry_after_s"] = 5.into();
    }
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contract_probe_and_event_from_the_brief() {
    let h = Harness::start().await;
    let (st, health) = h.http("GET", "/health", None).await;
    assert_eq!(st, 200);
    assert_eq!(health["rules"]["loaded"], 3, "install set imported");
    assert_eq!(health["mode"], "monitor");

    let probe = r#"{"v":1,"ts":1761600000.123,"verb":"POST","route":"portal.login","session_key":"a1b2c3d4e5f60718","peer_key":"0f1e2d3c4b5a6978","principal":"anon"}"#;
    let v = h.probe(probe).await;
    assert_eq!(v["action"], "allow");
    assert_eq!(v["mode"], "monitor");
    assert!(v.get("rule").is_none());
    assert_eq!(v["generation"], 1);
    assert_eq!(v["hash"].as_str().unwrap().len(), 64);

    let event = r#"{"v":1,"ts":1761600000.123,"session_key":"a1b2c3d4e5f60718","peer_key":"0f1e2d3c4b5a6978","principal":"anon","verb":"POST","route":"portal.login","status":422,"bytes_in":410,"bytes_out":1204,"latency_ms":38.2,"req_shape":"{otp:str:6,phone:str:10}","resp_shape":"{errors:{otp:[str:23*1]},message:str:23}","bound":[],"validation_failed":["otp"],"exception":"ValidationException","auth_event":null,"gate":null,"ua_hash":"9c8b7a6f","dropped_since_last":0}"#;
    h.event(event).await;
    h.wait_for("window", || {
        h.engine.windows.session(0xa1b2c3d4e5f60718).is_some()
    })
    .await;
    {
        let w = h.engine.windows.session(0xa1b2c3d4e5f60718).unwrap();
        let t = w.newest().next().unwrap();
        assert_eq!(t.status, 422);
        assert_eq!(t.route, h.engine.symbols.get("portal.login").unwrap());
        assert_eq!(t.validation_fields.len(), 1);
        assert_eq!(t.exception, h.engine.symbols.get("ValidationException"));
        assert_eq!(t.bytes_out, 1204);
        assert_eq!(t.ua_hash, 0x9c8b7a6f);
    }
    h.engine.store.flush().await;
    let key = ts_us(1761600000.123);
    h.wait_for("turn row with verdict", || {
        matches!(h.engine.store.turn_verdict(SESSION, key), Ok(Some((Some(_), Some(ref v), Some(_)))) if v == "allow")
    })
    .await;
    let (matched, _, hash) = h.engine.store.turn_verdict(SESSION, key).unwrap().unwrap();
    assert_eq!(matched.unwrap(), "[]");
    assert_eq!(hash.unwrap().len(), 32);
    assert_eq!(h.engine.store.count("features").unwrap(), 1);
    assert_eq!(h.engine.store.unjoined(), 0);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otp_burst_rate_limits_sticks_and_survives_restart() {
    let h = Harness::start().await;
    let (st, _) = h
        .http("PUT", "/mode", Some(&json!({"mode": "enforce"})))
        .await;
    assert_eq!(st, 200);
    let (st, shown) = h.http("GET", "/rules/portal-otp-burst", None).await;
    assert_eq!(st, 200);
    assert_eq!(
        shown["rule"]["mode"], "shadow",
        "install set lands as shadow"
    );
    let mut rule = shown["rule"].clone();
    rule["mode"] = "enforce".into();
    let (st, upd) = h.http("PUT", "/rules/portal-otp-burst", Some(&rule)).await;
    assert_eq!(st, 200, "{upd}");
    assert_eq!(upd["version"], 2);

    let session = "cb56f9bedebf3ec6";
    let now = now_f64();
    for i in 0..4 {
        h.event(&login_failed_event(now - 30.0 + i as f64, session))
            .await;
    }
    h.wait_for("4 turns", || {
        h.engine
            .windows
            .session(0xcb56f9bedebf3ec6)
            .is_some_and(|w| w.len() == 4)
    })
    .await;
    let v = h
        .probe(&probe_json(now, "POST", "portal.login", session))
        .await;
    assert_eq!(v["action"], "allow", "four failures is under the burst");
    h.event(&login_failed_event(now - 1.0, session)).await;
    h.wait_for("5 turns", || {
        h.engine
            .windows
            .session(0xcb56f9bedebf3ec6)
            .is_some_and(|w| w.len() == 5)
    })
    .await;

    let v = h
        .probe(&probe_json(now, "POST", "portal.login", session))
        .await;
    assert_eq!(v["action"], "rate_limit", "{v}");
    assert_eq!(v["mode"], "enforce");
    assert_eq!(v["rule"], "portal-otp-burst");
    assert_eq!(v["retry_after"], 30);
    assert_eq!(h.engine.decisions.len(), 1);

    let v = h
        .probe(&probe_json(now + 1.0, "GET", "home", session))
        .await;
    assert_eq!(
        v["action"], "rate_limit",
        "sticky on every route for the session"
    );
    assert!(v["retry_after"].as_u64().unwrap() <= 30);
    assert_eq!(h.engine.counters.sticky.load(Ordering::Relaxed), 1);

    h.engine.flush_stats();
    h.engine.store.flush().await;
    let (_, shown) = h.http("GET", "/rules/portal-otp-burst", None).await;
    let stats = shown["stats_24h"].as_array().unwrap();
    assert!(!stats.is_empty());
    assert!(
        stats
            .iter()
            .any(|s| s["mode"] == "enforce" && s["acted"].as_u64().unwrap() >= 1),
        "{stats:?}"
    );

    let hash_before = h.http("GET", "/health", None).await.1["rules"]["hash"].clone();
    let h = h.restart().await;
    assert_eq!(
        h.engine.decisions.len(),
        1,
        "decision reloaded from the store"
    );
    assert_eq!(h.engine.mode(), Mode::Enforce, "mode persisted");
    assert_eq!(
        h.http("GET", "/health", None).await.1["rules"]["hash"],
        hash_before,
        "same set, same hash"
    );
    let v = h
        .probe(&probe_json(now_f64(), "GET", "home", session))
        .await;
    assert_eq!(
        v["action"], "rate_limit",
        "still enforced after a restart with empty windows"
    );
    assert_eq!(v["generation"], 1, "generation restarts per process");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposed_rule_counts_but_never_wins_until_accepted() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let proposed: Rule =
        serde_json::from_value(rule_json("spark-home-block", "enforce", "block", "home")).unwrap();
    h.engine
        .write_rule(
            proposed,
            State::Proposed,
            "spark",
            Some("incident 7".into()),
        )
        .await
        .unwrap();
    let (st, list) = h.http("GET", "/rules?state=proposed", None).await;
    assert_eq!(st, 200);
    assert_eq!(list["rules"][0]["id"], "spark-home-block");

    for i in 0..5 {
        let v = h
            .probe(&probe_json(now_f64() + i as f64, "GET", "home", SESSION))
            .await;
        assert_eq!(v["action"], "allow", "proposed never wins");
    }
    h.engine.flush_stats();
    h.engine.store.flush().await;
    let (_, shown) = h.http("GET", "/rules/spark-home-block", None).await;
    let stats = shown["stats_24h"].as_array().unwrap();
    assert_eq!(
        stats
            .iter()
            .map(|s| s["matched"].as_u64().unwrap())
            .sum::<u64>(),
        5
    );
    assert_eq!(
        stats
            .iter()
            .map(|s| s["acted"].as_u64().unwrap())
            .sum::<u64>(),
        0
    );

    let (st, acc) = h
        .http("POST", "/rules/spark-home-block/accept", Some(&json!({})))
        .await;
    assert_eq!(st, 200, "{acc}");
    let v = h
        .probe(&probe_json(now_f64(), "GET", "home", SESSION))
        .await;
    assert_eq!(
        (v["action"].as_str(), v["mode"].as_str()),
        (Some("block"), Some("shadow")),
        "accepted as shadow by default"
    );
    assert_eq!(
        h.engine.decisions.len(),
        1,
        "a shadow block still sticks, at shadow"
    );
    let v = h
        .probe(&probe_json(now_f64(), "GET", "venues.show", SESSION))
        .await;
    assert_eq!(
        (v["action"].as_str(), v["mode"].as_str()),
        (Some("block"), Some("shadow"))
    );

    let (st, _) = h.http("POST", "/rules/spark-home-block/retire", None).await;
    assert_eq!(st, 200);
    assert_eq!(h.http("GET", "/health", None).await.1["rules"]["loaded"], 3);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_validate_schema_export_and_pinned_mode() {
    let h = Harness::start().await;
    let (st, v) = h
        .http("POST", "/rules/validate", Some(&json!({"id": "x"})))
        .await;
    assert_eq!(st, 200);
    assert_eq!(v["ok"], false);
    let (_, v) = h
        .http(
            "POST",
            "/rules/validate",
            Some(&rule_json("fine-rule", "shadow", "watch", "home")),
        )
        .await;
    assert_eq!(v["ok"], true);
    let (st, schema) = h.http("GET", "/rules/schema", None).await;
    assert_eq!(st, 200);
    assert_eq!(schema["title"], "Rule");
    let (_, export) = h.http("GET", "/rules/export", None).await;
    assert_eq!(export.as_array().unwrap().len(), 3);
    let (st, created) = h
        .http(
            "POST",
            "/rules",
            Some(&rule_json("fine-rule", "shadow", "watch", "home")),
        )
        .await;
    assert_eq!(st, 201, "{created}");
    let (st, _) = h
        .http(
            "POST",
            "/rules",
            Some(&rule_json("fine-rule", "shadow", "watch", "home")),
        )
        .await;
    assert_eq!(st, 409);
    let (st, bad) = h
        .http(
            "POST",
            "/rules",
            Some(&rule_json("ab", "shadow", "watch", "home")),
        )
        .await;
    assert_eq!(st, 422, "{bad}");
    let (_, export) = h.http("GET", "/rules/export", None).await;
    assert_eq!(export.as_array().unwrap().len(), 4);
    let (st, _) = h.http("GET", "/rules/nope", None).await;
    assert_eq!(st, 404);
    h.running.abort();
    h.engine.shutdown().await;

    let dir = std::env::temp_dir().join(format!("leesided-it-pinned-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config {
        socket_dir: dir.clone(),
        db: dir.join("db.sqlite"),
        api: "127.0.0.1:0".parse().unwrap(),
        enforce: false,
        rules_dir: dir.clone(),
        socket_mode: 0o600,
        socket_gid: None,
    };
    let engine = Engine::open(cfg).await.unwrap();
    let running = serve(engine.clone()).await.unwrap();
    let h = Harness {
        dir,
        engine,
        running,
    };
    let (st, _) = h
        .http("PUT", "/mode", Some(&json!({"mode": "enforce"})))
        .await;
    assert_eq!(st, 409);
    let (st, _) = h
        .http("PUT", "/mode", Some(&json!({"mode": "shadow"})))
        .await;
    assert_eq!(st, 200);
    assert_eq!(h.http("GET", "/mode", None).await.1["mode"], "shadow");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_input_is_counted_and_answered_allow() {
    let h = Harness::start().await;
    let v = h.probe("this is not json").await;
    assert_eq!(v["action"], "allow");
    let v = h.probe(r#"{"v":1,"ts":1.0,"verb":"GET","route":"home","session_key":"short","peer_key":"0f1e2d3c4b5a6978","principal":"anon"}"#).await;
    assert_eq!(v["action"], "allow");
    assert_eq!(h.engine.counters.bad_probe.load(Ordering::Relaxed), 2);
    h.event("{\"v\":2}").await;
    h.event(&login_failed_event(now_f64(), "nothex")).await;
    h.wait_for("bad events", || {
        h.engine.counters.bad_event.load(Ordering::Relaxed) == 2
    })
    .await;
    assert_eq!(h.engine.counters.events.load(Ordering::Relaxed), 0);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_under_load_keeps_generation_monotonic() {
    let _heavy = HEAVY.lock().await;
    let h = Harness::start().await;
    let engine = h.engine.clone();
    let workers: Vec<_> = (0..4)
        .map(|w| {
            let engine = engine.clone();
            std::thread::spawn(move || {
                let mut last = 0u64;
                for i in 0..10_000u64 {
                    let line = probe_json(
                        1_761_600_000.0 + i as f64,
                        "GET",
                        if i % 2 == 0 { "home" } else { "venues.show" },
                        SESSION,
                    );
                    let out = engine.check(line.as_bytes());
                    let v: Value = serde_json::from_slice(&out).unwrap();
                    let g = v["generation"].as_u64().unwrap();
                    assert!(
                        g >= last,
                        "worker {w}: generation went backwards {last} -> {g}"
                    );
                    last = g;
                }
                last
            })
        })
        .collect();
    for _ in 0..100 {
        engine.rules.load().unwrap();
    }
    for w in workers {
        assert!(w.join().unwrap() >= 1);
    }
    assert_eq!(engine.rules.generation(), 101);
    assert_eq!(engine.counters.checks.load(Ordering::Relaxed), 40_000);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uds_round_trip_p99_under_one_millisecond() {
    let _heavy = HEAVY.lock().await;
    let h = Harness::start().await;
    for i in 0..200 {
        h.probe(&probe_json(now_f64(), "GET", "home", SESSION))
            .await;
        let _ = i;
    }
    let mut samples = Vec::with_capacity(2000);
    for i in 0..2000u64 {
        let line = probe_json(
            now_f64(),
            if i % 3 == 0 { "POST" } else { "GET" },
            if i % 2 == 0 { "home" } else { "portal.login" },
            SESSION,
        );
        let t0 = Instant::now();
        let v = h.probe(&line).await;
        samples.push(t0.elapsed());
        assert_eq!(v["action"], "allow");
    }
    samples.sort();
    let at = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    println!(
        "uds round trip: p50 {:?} p90 {:?} p99 {:?} max {:?}",
        at(0.5),
        at(0.9),
        at(0.99),
        samples[samples.len() - 1]
    );
    // The budget is for the release build on a quiet host; a debug build only reports.
    if !cfg!(debug_assertions) {
        assert!(at(0.99) < Duration::from_millis(1), "p99 {:?}", at(0.99));
    }
    h.running.abort();
    h.engine.shutdown().await;
}
