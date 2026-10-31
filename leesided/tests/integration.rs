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
        Harness::open_with(dir, None).await
    }

    async fn open_with(dir: PathBuf, api_token: Option<&str>) -> Harness {
        let cfg = Config {
            socket_dir: dir.clone(),
            db: dir.join("leesided.sqlite"),
            api: "127.0.0.1:0".parse().unwrap(),
            enforce: true,
            rules_dir: PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/install")),
            socket_mode: 0o600,
            socket_gid: None,
            api_token: api_token.map(String::from),
            hash_key: Some("test-key".into()),
            geoip_asn: None,
            geoip_country: None,
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
        self.http_as(None, method, path, body).await
    }

    async fn http_as(
        &self,
        token: Option<&str>,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut s = TcpStream::connect(self.running.api_addr).await.unwrap();
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: leesided\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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
async fn block_sticks_for_block_min() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let mut v = rule_json("home-block", "enforce", "block", "home");
    v["block_min"] = 10.into();
    let rule: Rule = serde_json::from_value(v).unwrap();
    h.engine
        .write_rule(rule, State::Active, "operator", None)
        .await
        .unwrap();

    let now = now_f64();
    let v = h.probe(&probe_json(now, "GET", "home", SESSION)).await;
    assert_eq!(v["action"], "block");
    assert_eq!(h.engine.decisions.len(), 1);
    let now_s = now as i64;
    assert!(
        h.engine.decisions.sweep(now_s + 590).is_empty(),
        "still live at 9m50s"
    );
    assert_eq!(
        h.engine.decisions.sweep(now_s + 610).len(),
        1,
        "gone by 10m10s"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bearer_token_guards_everything_but_health() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let h = Harness::open_with(dir, Some("s3cret-token")).await;

    assert_eq!(h.http("GET", "/health", None).await.0, 200);
    for path in ["/rules", "/mode", "/decisions", "/turns"] {
        assert_eq!(
            h.http("GET", path, None).await.0,
            401,
            "{path} without a token"
        );
        assert_eq!(
            h.http_as(Some("s3cret-tokeN"), "GET", path, None).await.0,
            401,
            "{path} with a wrong token"
        );
        assert_eq!(
            h.http_as(Some("s3cret-token"), "GET", path, None).await.0,
            200,
            "{path} with the token"
        );
    }
    let (st, _) = h
        .http("PUT", "/mode", Some(&json!({"mode": "enforce"})))
        .await;
    assert_eq!(st, 401);
    assert_eq!(
        h.engine.mode(),
        Mode::Monitor,
        "an unauthorised write changes nothing"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decisions_list_and_unblock_and_turns() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let mut v = rule_json("home-block", "enforce", "block", "home");
    v["block_min"] = 10.into();
    let rule: Rule = serde_json::from_value(v).unwrap();
    h.engine
        .write_rule(rule, State::Active, "operator", None)
        .await
        .unwrap();
    let ts = now_f64();
    assert_eq!(
        h.probe(&probe_json(ts, "GET", "home", SESSION)).await["action"],
        "block"
    );

    let (st, body) = h.http("GET", "/decisions", None).await;
    assert_eq!(st, 200);
    let list = body["decisions"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["scope"], "session");
    assert_eq!(list[0]["key"], SESSION);
    assert_eq!(list[0]["rule"], "home-block");

    assert_eq!(h.http("DELETE", "/decisions/session/zz", None).await.0, 400);
    let gone = format!("/decisions/session/{SESSION}");
    assert_eq!(h.http("DELETE", &gone, None).await.0, 204);
    assert_eq!(h.http("DELETE", &gone, None).await.0, 404);
    assert!(h.engine.decisions.is_empty());

    h.event(&login_failed_event(ts, SESSION)).await;
    h.wait_for("turn stored", || {
        h.engine.store.count("turns").unwrap_or(0) == 1
    })
    .await;
    let (st, body) = h
        .http("GET", &format!("/turns?peer={PEER}&limit=5"), None)
        .await;
    assert_eq!(st, 200);
    let turns = body["turns"].as_array().unwrap();
    assert_eq!(turns.len(), 1);
    assert_eq!(turns[0]["route"], "portal.login");
    assert_eq!(turns[0]["auth_event"], "login_failed");
    let (_, body) = h.http("GET", "/turns?peer=0000000000000000", None).await;
    assert!(body["turns"].as_array().unwrap().is_empty());
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
        api_token: None,
        hash_key: None,
        geoip_asn: None,
        geoip_country: None,
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

fn v2_event(
    ts: f64,
    session: &str,
    route: &str,
    surface: &str,
    credential: Option<&str>,
) -> String {
    json!({"v":2,"ts":ts,"session_key":session,"peer_key":PEER,"principal":"anon","verb":"POST",
        "route":route,"status":200,"latency_ms":3.1,"bytes_in":12,"bytes_out":16,
        "req_shape":"{}","resp_shape":"{ok:bool}","bound":[],
        "validation_failed":null,"exception":null,"auth_event":null,
        "gate":{"action":"allow","mode":"monitor","rule":null,"applied":false},
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,
        "surface":surface,"is_asset":false,
        "credential_kind": credential.map(|_| "bearer"),"credential_hash":credential,
        "credential_status": credential.map(|_| "verified"),
        "tag_id":"0123456789abcdef","tag_status":"valid",
        "ip":"203.0.113.7","ip_trust":"direct","ua_class":"library",
        "shape_hash":"aaaaaaaaaaaaaaaa",
        "shape":{"method":"POST","http_version":"HTTP/1.1","has_cookie":false,"has_referer":false,
                 "header_count":5,"accept_language":"0000","header_names_hash":"bbbbbbbbbbbbbbbb",
                 "cookie_names_hash":"cccccccccccccccc","order_reliable":true},
        "flags":["library_ua_on_web"],"ja4":null,"ja4t":null,"h2_fp":null})
    .to_string()
}

fn v2_probe(
    ts: f64,
    route: &str,
    session: &str,
    surface: &str,
    credential: Option<&str>,
) -> String {
    json!({"v":2,"ts":ts,"verb":"POST","route":route,"surface":surface,"session_key":session,
        "peer_key":PEER,"principal":"anon","credential_hash":credential,
        "credential_status":credential.map(|_| "verified")})
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_events_are_stored_with_hashed_ip_and_v1_still_accepted() {
    let h = Harness::start().await;
    let now = now_f64();
    h.event(&v2_event(
        now,
        SESSION,
        "api.ping",
        "api",
        Some("feedfacefeedface"),
    ))
    .await;
    h.event(&login_failed_event(now + 1.0, SESSION)).await;
    h.wait_for("two turns", || {
        h.engine
            .windows
            .session(0xa1b2c3d4e5f60718)
            .is_some_and(|w| w.len() == 2)
    })
    .await;
    assert_eq!(h.engine.counters.bad_event.load(Ordering::Relaxed), 0);
    assert_eq!(
        h.engine.windows.counts().3,
        1,
        "a credential window was opened"
    );
    h.engine.store.flush().await;
    let row = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT surface, credential_kind, credential_hash, tag_id, ip_hash, net_hash, ua_class, flags, ja4 \
                 FROM turns WHERE session_key = ?1 AND ts_us = ?2",
                rusqlite::params![SESSION, ts_us(now)],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, Option<String>>(8)?,
                    ))
                },
            )
        })
        .unwrap();
    assert_eq!(row.0.as_deref(), Some("api"));
    assert_eq!(row.1.as_deref(), Some("bearer"));
    assert_eq!(row.2.as_deref(), Some("feedfacefeedface"));
    assert_eq!(row.3.as_deref(), Some("0123456789abcdef"));
    let hasher = leesided::hash::Hasher::new("test-key");
    assert_eq!(row.4, Some(hasher.hex16("ip", "203.0.113.7")));
    assert_eq!(row.5, Some(hasher.hex16("net", "203.0.113.0/24")));
    assert_eq!(row.6.as_deref(), Some("library"));
    assert_eq!(row.7.as_deref(), Some(r#"["library_ua_on_web"]"#));
    assert_eq!(row.8, None);
    let raw_ip: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM turns WHERE ip_hash = '203.0.113.7' OR net_hash LIKE '203.%'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(raw_ip, 0, "the address is never stored");
    let v1: Option<String> = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT surface FROM turns WHERE ts_us = ?1",
                rusqlite::params![ts_us(now + 1.0)],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(v1, None, "a v1 event leaves the v2 columns null");
    h.event(r#"{"v":3,"ts":1.0}"#).await;
    h.wait_for("v3 rejected", || {
        h.engine.counters.bad_event.load(Ordering::Relaxed) == 1
    })
    .await;
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn surface_match_and_credential_scope_with_no_peer_rate_on_api() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    // Three failed pings per credential within a minute, api only.
    let per_cred: Rule = serde_json::from_value(json!({
        "id": "api-cred-burst", "note": "t", "mode": "enforce", "action": "rate_limit", "retry_after_s": 7,
        "match": {"route": ["api.ping"], "verb": ["POST"], "principal": "any", "surface": ["api"]},
        "when": {"scope": "credential", "window_s": 60, "count": {}, "gte": 3},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    // A peer-scope rule that would fire on anything: must stay silent on api.
    let per_peer: Rule = serde_json::from_value(json!({
        "id": "peer-anything", "note": "t", "mode": "enforce", "action": "block",
        "match": {"route": ["*"], "verb": ["POST"], "principal": "any"},
        "when": {"scope": "peer", "count": {}, "gte": 1},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(per_cred, State::Active, "operator", None)
        .await
        .unwrap();
    h.engine
        .write_rule(per_peer, State::Active, "operator", None)
        .await
        .unwrap();

    let now = now_f64();
    let cred = "feedfacefeedface";
    for i in 0..3 {
        h.event(&v2_event(
            now - 10.0 + i as f64,
            SESSION,
            "api.ping",
            "api",
            Some(cred),
        ))
        .await;
    }
    h.wait_for("3 cred turns", || {
        h.engine
            .windows
            .credential(0xfeedfacefeedface)
            .is_some_and(|w| w.len() == 3)
    })
    .await;

    // Same peer, api surface: the peer rule reads an empty window, the credential rule fires.
    let v = h
        .probe(&v2_probe(now, "api.ping", SESSION, "api", Some(cred)))
        .await;
    assert_eq!(v["action"], "rate_limit", "{v}");
    assert_eq!(v["rule"], "api-cred-burst");
    assert_eq!(v["retry_after"], 7);
    // A different credential from the same peer is untouched.
    let v = h
        .probe(&v2_probe(
            now,
            "api.ping",
            "cb56f9bedebf3ec6",
            "api",
            Some("0123456789abcdef"),
        ))
        .await;
    assert_eq!(v["action"], "allow", "{v}");
    // The same credential on a web probe is still rate limited: the decision
    // sticks to the credential key whatever the surface.
    let v = h
        .probe(&v2_probe(
            now,
            "api.ping",
            "cb56f9bedebf3ec6",
            "web",
            Some(cred),
        ))
        .await;
    assert_eq!(v["rule"], "api-cred-burst", "{v}");
    // Without the credential, the api rule is gated off by surface and the
    // peer window is live again.
    let v = h
        .probe(&v2_probe(now, "api.ping", "cb56f9bedebf3ec6", "web", None))
        .await;
    assert_eq!(
        v["rule"], "peer-anything",
        "on web the peer window is live and the api rule is gated off: {v}"
    );
    assert_eq!(v["action"], "block");
    // A v1 probe is web.
    let v = h
        .probe(&probe_json(now, "POST", "home", "1111111111111111"))
        .await;
    assert_eq!(v["action"], "block", "{v}");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_api_burst_trips_peer_rule_but_a_credentialed_one_does_not() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let per_peer: Rule = serde_json::from_value(json!({
        "id": "api-peer-burst", "note": "t", "mode": "enforce", "action": "block",
        "match": {"route": ["api.ping"], "verb": ["POST"], "principal": "any", "surface": ["api"]},
        "when": {"scope": "peer", "window_s": 60, "count": {}, "gte": 3},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(per_peer, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_f64();
    for i in 0..3 {
        h.event(&v2_event(
            now - 10.0 + i as f64,
            "1111111111111111",
            "api.ping",
            "api",
            None,
        ))
        .await;
    }
    h.wait_for("3 peer turns", || {
        h.engine
            .windows
            .peer(0x0f1e2d3c4b5a6978)
            .is_some_and(|w| w.len() == 3)
    })
    .await;
    // No credential: the peer window is live on api, the scanner is blocked.
    let v = h
        .probe(&v2_probe(now, "api.ping", "1111111111111111", "api", None))
        .await;
    assert_eq!(v["action"], "block", "{v}");
    assert_eq!(v["rule"], "api-peer-burst");
    // The same address with a credential: the credential is the identity,
    // the peer window reads as empty, the session's block does not apply.
    let v = h
        .probe(&v2_probe(
            now,
            "api.ping",
            "2222222222222222",
            "api",
            Some("feedfacefeedface"),
        ))
        .await;
    assert_eq!(v["action"], "allow", "{v}");
    // ... and the per-peer block that stuck to the first session is not
    // consulted for a credentialed probe either (sticky skips the peer key).
    let v = h
        .probe(&v2_probe(
            now,
            "api.ping",
            "1111111111111111",
            "api",
            Some("feedfacefeedface"),
        ))
        .await;
    assert_eq!(
        v["action"], "block",
        "the SESSION decision still applies: {v}"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

fn v2_probe_status(
    ts: f64,
    route: &str,
    session: &str,
    surface: &str,
    credential: &str,
    status: &str,
) -> String {
    json!({"v":2,"ts":ts,"verb":"POST","route":route,"surface":surface,"session_key":session,
        "peer_key":PEER,"principal":"anon","credential_hash":credential,"credential_status":status})
    .to_string()
}

fn rejected_key_event(ts: f64, session: &str, credential: &str) -> String {
    json!({"v":2,"ts":ts,"session_key":session,"peer_key":PEER,"principal":"anon","verb":"POST",
        "route":"api.ping","status":401,"latency_ms":1.0,"bytes_in":0,"bytes_out":20,
        "req_shape":"[]","resp_shape":"{message:str:12}","bound":[],
        "validation_failed":null,"exception":null,"auth_event":null,"gate":null,
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,
        "surface":"api","is_asset":false,"credential_kind":"api_key","credential_hash":credential,
        "credential_status":"rejected","ip":"203.0.113.9","ip_trust":"direct","ua_class":"library"})
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_credential_burst_is_one_peer_not_many_credentials() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let stuffing: Rule = serde_json::from_value(json!({
        "id": "api-key-stuffing", "note": "ten rejected keys from one address", "mode": "enforce", "action": "block",
        "match": {"route": ["api.ping"], "verb": ["POST"], "principal": "any", "surface": ["api"]},
        "when": {"scope": "peer", "window_s": 600,
                 "distinct": {"field": "credential", "where": {"credential_status": ["rejected"]}}, "gte": 10},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(stuffing, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_f64();
    for i in 0..10u64 {
        // Each attempt a new session (no cookie jar) and a new key.
        h.event(&rejected_key_event(
            now - 30.0 + i as f64,
            &format!("{:016x}", 0x1000 + i),
            &format!("{:016x}", 0xabc00 + i),
        ))
        .await;
    }
    h.wait_for("10 peer turns", || {
        h.engine
            .windows
            .peer(0x0f1e2d3c4b5a6978)
            .is_some_and(|w| w.len() == 10)
    })
    .await;
    {
        let w = h.engine.windows.peer(0x0f1e2d3c4b5a6978).unwrap();
        let mut creds: Vec<u64> = w.newest().filter_map(|t| t.credential).collect();
        creds.sort();
        creds.dedup();
        assert_eq!(creds.len(), 10, "ten rejected credentials on one peer");
        assert!(w.newest().all(|t| t.credential_status == 2));
    }
    // The eleventh key, unverified at probe time: the peer window is live, the rule fires.
    let v = h
        .probe(&v2_probe_status(
            now,
            "api.ping",
            "0000000000002000",
            "api",
            "0000000000abcff",
            "unverified",
        ))
        .await;
    assert_eq!(
        v["action"], "allow",
        "a 15-hex hash is a bad probe and answers allow: {v}"
    );
    let v = h
        .probe(&v2_probe_status(
            now,
            "api.ping",
            "0000000000002000",
            "api",
            "00000000000abcff",
            "unverified",
        ))
        .await;
    assert_eq!(v["action"], "block", "{v}");
    assert_eq!(v["rule"], "api-key-stuffing");
    // A verified credential from the same address is a different identity: nothing fires.
    let v = h
        .probe(&v2_probe_status(
            now,
            "api.ping",
            "0000000000002001",
            "api",
            "00000000000abd00",
            "verified",
        ))
        .await;
    assert_eq!(v["action"], "allow", "{v}");
    h.running.abort();
    h.engine.shutdown().await;
}

fn forged_webhook_event(ts: f64, session: &str, claimed: &str) -> String {
    json!({"v":2,"ts":ts,"session_key":session,"peer_key":PEER,"principal":"anon","verb":"POST",
        "route":"webhooks.demo","status":401,"latency_ms":1.0,"bytes_in":12,"bytes_out":26,
        "req_shape":"{order:int}","resp_shape":"{message:str:12}","bound":[],
        "validation_failed":null,"exception":null,"auth_event":null,
        "gate":{"action":"allow","mode":"monitor","rule":null,"applied":false},
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,
        "surface":"webhook","is_asset":false,"credential_kind":"webhook_sig","credential_hash":claimed,
        "credential_status":"rejected","ip":"203.0.113.9","ip_trust":"direct","ua_class":"library"})
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_webhook_burst_trips_a_peer_rule_and_a_signed_one_does_not() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let forgeries: Rule = serde_json::from_value(json!({
        "id": "webhook-forgeries", "note": "three rejected signatures from one address", "mode": "enforce",
        "action": "rate_limit", "retry_after_s": 60,
        "match": {"route": ["webhooks.demo"], "verb": ["POST"], "principal": "any", "surface": ["webhook"]},
        "when": {"scope": "peer", "window_s": 600, "count": {"credential_status": ["rejected"]}, "gte": 3},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(forgeries, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_f64();
    for i in 0..3u64 {
        h.event(&forged_webhook_event(
            now - 20.0 + i as f64,
            &format!("{:016x}", 0x7000 + i),
            &format!("{:016x}", 0xbad000 + i),
        ))
        .await;
    }
    h.wait_for("3 forgeries on the peer", || {
        h.engine
            .windows
            .peer(0x0f1e2d3c4b5a6978)
            .is_some_and(|w| w.len() == 3)
    })
    .await;
    // The next forgery: unverified at probe time, so the peer window is read and the rule fires.
    let v = h
        .probe(&v2_probe_status(
            now,
            "webhooks.demo",
            "0000000000007003",
            "webhook",
            "0000000000bad003",
            "unverified",
        ))
        .await;
    assert_eq!(v["action"], "rate_limit", "{v}");
    assert_eq!(v["rule"], "webhook-forgeries");
    // A correctly signed webhook from the same address is its signer's identity: nothing fires.
    let v = h
        .probe(&v2_probe_status(
            now,
            "webhooks.demo",
            "0000000000007004",
            "webhook",
            "00000000000acc01",
            "verified",
        ))
        .await;
    assert_eq!(v["action"], "allow", "{v}");
    h.running.abort();
    h.engine.shutdown().await;
}

fn tagged_event(
    ts: f64,
    turn_id: &str,
    session: &str,
    principal: &str,
    tag: &str,
    route: &str,
) -> String {
    json!({"v":2,"ts":ts,"turn_id":turn_id,"session_key":session,"peer_key":PEER,"principal":principal,"verb":"GET",
        "route":route,"status":200,"latency_ms":1.0,"bytes_in":0,"bytes_out":100,"req_shape":"[]","resp_shape":"html",
        "bound":[],"validation_failed":null,"exception":null,"auth_event":null,"gate":null,
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,"surface":"web","tag_id":tag,"tag_status":"valid",
        "ip":"203.0.113.7","ip_trust":"direct","ua_class":"chromium"})
    .to_string()
}

fn tagged_probe(ts: f64, turn_id: &str, session: &str, tag: Option<&str>, route: &str) -> String {
    json!({"v":2,"ts":ts,"turn_id":turn_id,"verb":"GET","route":route,"surface":"web","session_key":session,
        "peer_key":PEER,"principal":"anon","tag_id":tag}).to_string()
}

const TAG: &str = "7d2b9e4c1a6f0e3b";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tag_links_sessions_into_one_actor_and_an_actor_block_survives_session_change() {
    use leesided::actors::{Ident, Kind};
    use leesided::rules::model::Scope;
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let rule: Rule = serde_json::from_value(json!({
        "id": "actor-home-burst", "note": "three home loads by one actor", "mode": "enforce", "action": "block",
        "match": {"route": ["home"], "verb": ["GET"], "principal": "any", "surface": ["web"]},
        "when": {"scope": "actor", "window_s": 600, "count": {}, "gte": 3},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(rule, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_f64();
    // Two sessions, one tag: the browser cleared its session cookie but kept the tag.
    h.event(&tagged_event(
        now - 30.0,
        "0000000000000a01",
        "1111111111111111",
        "anon",
        TAG,
        "home",
    ))
    .await;
    h.event(&tagged_event(
        now - 20.0,
        "0000000000000a02",
        "1111111111111111",
        "anon",
        TAG,
        "home",
    ))
    .await;
    h.event(&tagged_event(
        now - 10.0,
        "0000000000000a03",
        "2222222222222222",
        "anon",
        TAG,
        "home",
    ))
    .await;
    let tag = Ident::new(Kind::Tag, 0x7d2b9e4c1a6f0e3b);
    h.wait_for("tag bound", || {
        h.engine.resolver.lookup(tag, (now * 1e6) as i64).is_some()
    })
    .await;
    let actor = h.engine.resolver.lookup(tag, (now * 1e6) as i64).unwrap();
    h.wait_for("actor window of 3", || {
        h.engine.windows.actor(actor).is_some_and(|w| w.len() == 3)
    })
    .await;
    assert_eq!(
        h.engine.resolver.lookup(
            Ident::new(Kind::Session, 0x1111111111111111),
            (now * 1e6) as i64
        ),
        Some(actor)
    );
    assert_eq!(
        h.engine.resolver.lookup(
            Ident::new(Kind::Session, 0x2222222222222222),
            (now * 1e6) as i64
        ),
        Some(actor)
    );
    h.engine.store.flush().await;
    let ids: Vec<Option<String>> = h
        .engine
        .store
        .with_reader(|c| {
            let mut st = c.prepare("SELECT actor_id FROM turns WHERE turn_id IN ('0000000000000a01','0000000000000a02','0000000000000a03')")?;
            let rows = st.query_map([], |r| r.get::<_, Option<String>>(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(ids.len(), 3);
    assert!(
        ids.iter()
            .all(|i| i.as_deref() == Some(&format!("{actor:016x}")[..])),
        "{ids:?}"
    );

    // A third, fresh session with the old tag: the probe finds the actor, the rule fires on its window.
    let v = h
        .probe(&tagged_probe(
            now,
            "0000000000000a04",
            "3333333333333333",
            Some(TAG),
            "home",
        ))
        .await;
    assert_eq!(v["action"], "block", "{v}");
    assert_eq!(v["rule"], "actor-home-burst");
    assert!(
        h.engine
            .decisions
            .get(Scope::Actor, actor, store_now())
            .is_some(),
        "the block stuck to the actor"
    );
    // Another fresh session, a route the rule does not match: the sticky actor decision answers.
    let v = h
        .probe(&tagged_probe(
            now,
            "0000000000000a05",
            "4444444444444444",
            Some(TAG),
            "venues.show",
        ))
        .await;
    assert_eq!(
        v["action"], "block",
        "sticky on the actor across sessions: {v}"
    );
    // Without the tag, a new session is nobody: no actor, no block.
    let v = h
        .probe(&tagged_probe(
            now,
            "0000000000000a06",
            "5555555555555555",
            None,
            "venues.show",
        ))
        .await;
    assert_eq!(v["action"], "allow", "{v}");
    // The API shows the actor with its bindings, by any merged id.
    let (st, detail) = h.http("GET", &format!("/actors/{actor:016x}"), None).await;
    assert_eq!(st, 200, "{detail}");
    let kinds: Vec<&str> = detail["detail"]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"tag") && kinds.contains(&"session"),
        "{kinds:?}"
    );
    assert_eq!(detail["detail"]["actor"]["turns"], 3);
    h.running.abort();
    h.engine.shutdown().await;
}

fn store_now() -> i64 {
    leesided::store::now_s()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actors_survive_a_restart_and_resolve_the_same_in_a_fresh_store() {
    use leesided::actors::{Ident, Kind};
    let script = |now: f64| {
        vec![
            tagged_event(
                now - 40.0,
                "0000000000000b01",
                "1111111111111111",
                "anon",
                TAG,
                "home",
            ),
            tagged_event(
                now - 30.0,
                "0000000000000b02",
                "1111111111111111",
                "anon",
                TAG,
                "venues.show",
            ),
            // Login regenerates the session: the tag carries the guest actor into the user's.
            tagged_event(
                now - 20.0,
                "0000000000000b03",
                "2222222222222222",
                "0f0f0f0f0f0f0f0f",
                TAG,
                "portal.login",
            ),
            tagged_event(
                now - 10.0,
                "0000000000000b04",
                "2222222222222222",
                "0f0f0f0f0f0f0f0f",
                TAG,
                "home",
            ),
        ]
    };
    let now = now_f64();
    let read_ids = |h: &Harness| -> Vec<(String, String)> {
        h.engine
            .store
            .with_reader(|c| {
                let mut st = c.prepare("SELECT turn_id, actor_id FROM turns WHERE turn_id LIKE '0000000000000b%' ORDER BY turn_id")?;
                let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
                rows.collect()
            })
            .unwrap()
    };

    let h = Harness::start().await;
    for e in script(now) {
        h.event(&e).await;
    }
    let tag = Ident::new(Kind::Tag, 0x7d2b9e4c1a6f0e3b);
    let principal = Ident::new(Kind::Principal, 0x0f0f0f0f0f0f0f0f);
    h.wait_for("principal bound", || {
        h.engine
            .resolver
            .lookup(principal, (now * 1e6) as i64)
            .is_some()
    })
    .await;
    let actor = h.engine.resolver.lookup(tag, (now * 1e6) as i64).unwrap();
    assert_eq!(
        h.engine.resolver.lookup(principal, (now * 1e6) as i64),
        Some(actor),
        "guest actor became the user's"
    );
    h.engine.store.flush().await;
    let first = read_ids(&h);
    assert_eq!(first.len(), 4);
    assert!(
        first.iter().all(|(_, a)| *a == format!("{actor:016x}")),
        "{first:?}"
    );

    // Restart on the same store: bindings reload, windows rebuild from turns.
    let h = h.restart().await;
    assert_eq!(
        h.engine.resolver.lookup(tag, (now * 1e6) as i64),
        Some(actor)
    );
    assert_eq!(
        h.engine.resolver.lookup(principal, (now * 1e6) as i64),
        Some(actor)
    );
    assert!(
        h.engine.windows.actor(actor).is_some_and(|w| w.len() == 4),
        "actor window rebuilt from stored turns"
    );
    assert_eq!(
        h.http("GET", "/health", None).await.1["actors"]["count"]
            .as_u64()
            .unwrap(),
        1
    );
    // A probe for a brand-new session with the tag names the same actor.
    let probe_ids = [Ident::new(Kind::Session, 0x9999999999999999), tag];
    assert_eq!(
        h.engine.resolver.lookup_any(&probe_ids, (now * 1e6) as i64),
        Some(actor)
    );
    h.running.abort();
    h.engine.shutdown().await;

    // The same script into an empty store yields the same assignments.
    let h2 = Harness::start().await;
    for e in script(now) {
        h2.event(&e).await;
    }
    h2.wait_for("principal bound again", || {
        h2.engine
            .resolver
            .lookup(principal, (now * 1e6) as i64)
            .is_some()
    })
    .await;
    h2.engine.store.flush().await;
    assert_eq!(read_ids(&h2), first, "deterministic across stores");
    h2.running.abort();
    h2.engine.shutdown().await;
}
