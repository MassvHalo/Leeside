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

    async fn start_with_routes(honeytoken_routes: &[&str], business_routes: &[&str]) -> Harness {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("leesided-it-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Harness::open_with_routes(
            dir,
            honeytoken_routes.iter().map(|s| s.to_string()).collect(),
            business_routes.iter().map(|s| s.to_string()).collect(),
        )
        .await
    }

    async fn open(dir: PathBuf) -> Harness {
        Harness::open_with(dir, None).await
    }

    async fn open_with(dir: PathBuf, api_token: Option<&str>) -> Harness {
        Harness::open_full(dir, api_token, Vec::new(), Vec::new()).await
    }

    async fn open_with_routes(
        dir: PathBuf,
        honeytoken_routes: Vec<String>,
        business_routes: Vec<String>,
    ) -> Harness {
        Harness::open_full(dir, None, honeytoken_routes, business_routes).await
    }

    async fn open_full(
        dir: PathBuf,
        api_token: Option<&str>,
        honeytoken_routes: Vec<String>,
        business_routes: Vec<String>,
    ) -> Harness {
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
            ja4_classes: Some(PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/data/ja4-classes.json"
            ))),
            honeytoken_routes,
            business_routes,
            windside_model: None,
            windside_mode: leesided::config::WindsideMode::Off,
            ..Config::default()
        };
        let engine = Engine::open(cfg).await.expect("engine open");
        let running = serve(engine.clone()).await.expect("serve");
        Harness {
            dir,
            engine,
            running,
        }
    }

    async fn open_llm(dir: PathBuf, api_token: Option<&str>) -> Harness {
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
            ja4_classes: Some(PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/data/ja4-classes.json"
            ))),
            windside_model: None,
            windside_mode: leesided::config::WindsideMode::Off,
            llm_url: Some("http://127.0.0.1:9".to_string()),
            llm_key: Some("test".to_string()),
            llm_mode: leesided::config::LlmMode::Dry,
            ..Config::default()
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

    /// A harness with a Windside model and mode, for the shadow tests.
    async fn open_windside(
        dir: PathBuf,
        model: Option<PathBuf>,
        mode: leesided::config::WindsideMode,
    ) -> Harness {
        std::fs::create_dir_all(dir.join("rules-empty")).unwrap();
        let cfg = Config {
            socket_dir: dir.clone(),
            db: dir.join("leesided.sqlite"),
            api: "127.0.0.1:0".parse().unwrap(),
            enforce: true,
            rules_dir: dir.join("rules-empty"),
            socket_mode: 0o600,
            socket_gid: None,
            api_token: None,
            hash_key: Some("test-key".into()),
            geoip_asn: None,
            geoip_country: None,
            ja4_classes: None,
            honeytoken_routes: Vec::new(),
            business_routes: Vec::new(),
            windside_model: model,
            windside_mode: mode,
            ..Config::default()
        };
        let engine = Engine::open(cfg).await.expect("engine open");
        let running = serve(engine.clone()).await.expect("serve");
        Harness {
            dir,
            engine,
            running,
        }
    }

    /// A constant test model: every row scores sigmoid(2.0) = 0.8808.
    fn shadow_model(dir: &std::path::Path) {
        use leesided::rules::features::NAMES;
        let manifest = serde_json::json!({
            "model_version": "0.0.0-test",
            "features_version": 2,
            "feature_names": NAMES.as_slice(),
            "thresholds": {"web": {"threshold": 0.7}},
        });
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("manifest.json"), manifest.to_string()).unwrap();
        std::fs::write(
            dir.join("model.txt"),
            "tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nlabel_index=0\n\
             max_feature_idx=37\nobjective=binary sigmoid:1\ntree_sizes=100\n\n\
             Tree=0\nnum_leaves=1\nnum_cat=0\nleaf_value=2.0\nleaf_weight=10\n\
             leaf_count=10\nis_linear=0\nshrinkage=1\n",
        )
        .unwrap();
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

    /// A raw request at the inspector: (status, header block, body).
    async fn ui(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        form: Option<&str>,
    ) -> (u16, String, String) {
        let mut s = TcpStream::connect(self.running.api_addr).await.unwrap();
        let body = form.unwrap_or("");
        let ck = cookie
            .map(|c| format!("Cookie: {c}\r\n"))
            .unwrap_or_default();
        let ct = if form.is_some() {
            "Content-Type: application/x-www-form-urlencoded\r\n"
        } else {
            ""
        };
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: leesided\r\nConnection: close\r\n{ck}{ct}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        let (headers, body) = text
            .split_once("\r\n\r\n")
            .map(|(h, b)| (h.to_string(), b.to_string()))
            .unwrap_or((text.clone(), String::new()));
        (status, headers, body)
    }

    /// Log in and return the cookie value for later requests.
    async fn ui_login(&self, token: &str) -> (u16, String, String) {
        self.ui(
            "POST",
            "/ui/login",
            None,
            Some(&format!("token={token}&next=%2Fui%2Fllm")),
        )
        .await
    }
}

fn ui_header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim())
    })
}

fn ui_cookie(headers: &str) -> String {
    let set = ui_header(headers, "set-cookie").expect("a login sets a cookie");
    assert!(set.contains("HttpOnly"), "{set}");
    assert!(set.contains("SameSite=Strict"), "{set}");
    assert!(set.contains("Path=/ui"), "{set}");
    set.split(';').next().unwrap().trim().to_string()
}

fn ui_csrf(body: &str) -> String {
    let key = "name=\"csrf\" value=\"";
    let i = body.find(key).expect("a csrf token in the page");
    let rest = &body[i + key.len()..];
    rest[..rest.find('"').unwrap()].to_string()
}

fn ui_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn ui_harness(token: Option<&str>) -> Harness {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Harness::open_with(dir, token).await
}

/// A harness with the LLM configured in dry mode (dummy endpoint, never
/// sent): the writer-thread triggers enqueue against real budgets.
async fn ui_llm_harness(token: Option<&str>) -> Harness {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Harness::open_llm(dir, token).await
}

const SESSION: &str = "a1b2c3d4e5f60718";
const PEER: &str = "0f1e2d3c4b5a6978";

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Integer microseconds: the v2 wire `ts`, exact across the JSON hop.
fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
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
    // A v1 event opens a provisional actor and names no cluster: no feature row yet.
    assert_eq!(h.engine.store.count("feature_vectors").unwrap(), 0);
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
        ja4_classes: None,
        honeytoken_routes: Vec::new(),
        business_routes: Vec::new(),
        windside_model: None,
        windside_mode: leesided::config::WindsideMode::Off,
        ..Config::default()
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
async fn ts_type_is_pinned_to_the_schema_version() {
    let h = Harness::start().await;
    // A v2 line with a float ts is a bad line on both sockets.
    let mut v2p: Value =
        serde_json::from_str(&v2_probe(ts_us(now_f64()), "home", SESSION, "web", None)).unwrap();
    v2p["ts"] = json!(1761600000.123f64);
    assert_eq!(h.probe(&v2p.to_string()).await["action"], "allow");
    let mut v2e: Value =
        serde_json::from_str(&v2_event(ts_us(now_f64()), SESSION, "home", "web", None)).unwrap();
    v2e["ts"] = json!(1761600000.123f64);
    h.event(&v2e.to_string()).await;
    // A v1 line with an integer ts is a bad line too: v1 keeps float seconds.
    let mut v1p: Value =
        serde_json::from_str(&probe_json(now_f64(), "GET", "home", SESSION)).unwrap();
    v1p["ts"] = json!(1761600000123000i64);
    assert_eq!(h.probe(&v1p.to_string()).await["action"], "allow");
    let f = now_f64();
    let mut v1e: Value = serde_json::from_str(&login_failed_event(f, SESSION)).unwrap();
    v1e["ts"] = json!(ts_us(f));
    h.event(&v1e.to_string()).await;
    h.wait_for("bad ts lines", || {
        h.engine.counters.bad_event.load(Ordering::Relaxed) == 2
    })
    .await;
    assert_eq!(h.engine.counters.bad_probe.load(Ordering::Relaxed), 2);
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
    ts: i64,
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
    ts: i64,
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
        ts_us(now),
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
    // Windows update before the turn op is queued (engine::ingest), so a
    // windows wait alone can flush before the row lands. settle() waits on
    // the events counter, which increments after the op is sent.
    h.settle(2).await;
    let row = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                // Exact: the v2 `ts` is integer microseconds, so the
                // stored ts_us is the sent value bit for bit.
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
                // ±1µs: v1 keeps the float `ts`, and serde_json's parser
                // can return the 1-ulp neighbor across the hop. Without
                // the range a slip would pass vacuously via no row.
                "SELECT surface FROM turns WHERE ts_us BETWEEN ?1 - 1 AND ?1 + 1",
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

    let now = now_us();
    let cred = "feedfacefeedface";
    for i in 0..3 {
        h.event(&v2_event(
            now - 10_000_000 + (i as i64) * 1_000_000,
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
    // A v1 probe is web (v1 keeps the float `ts`).
    let v = h
        .probe(&probe_json(
            now as f64 / 1e6,
            "POST",
            "home",
            "1111111111111111",
        ))
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
    let now = now_us();
    for i in 0..3 {
        h.event(&v2_event(
            now - 10_000_000 + (i as i64) * 1_000_000,
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
    ts: i64,
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

fn rejected_key_event(ts: i64, session: &str, credential: &str) -> String {
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
    let now = now_us();
    for i in 0..10u64 {
        // Each attempt a new session (no cookie jar) and a new key.
        h.event(&rejected_key_event(
            now - 30_000_000 + (i as i64) * 1_000_000,
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

fn forged_webhook_event(ts: i64, session: &str, claimed: &str) -> String {
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
    let now = now_us();
    for i in 0..3u64 {
        h.event(&forged_webhook_event(
            now - 20_000_000 + (i as i64) * 1_000_000,
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
    ts: i64,
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

fn tagged_probe(ts: i64, turn_id: &str, session: &str, tag: Option<&str>, route: &str) -> String {
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
    let now = now_us();
    // Two sessions, one tag: the browser cleared its session cookie but kept the tag.
    h.event(&tagged_event(
        now - 30_000_000,
        "00000000000000000000000000000a01",
        "1111111111111111",
        "anon",
        TAG,
        "home",
    ))
    .await;
    h.event(&tagged_event(
        now - 20_000_000,
        "00000000000000000000000000000a02",
        "1111111111111111",
        "anon",
        TAG,
        "home",
    ))
    .await;
    h.event(&tagged_event(
        now - 10_000_000,
        "00000000000000000000000000000a03",
        "2222222222222222",
        "anon",
        TAG,
        "home",
    ))
    .await;
    let tag = Ident::new(Kind::Tag, 0x7d2b9e4c1a6f0e3b);
    h.wait_for("tag bound", || h.engine.resolver.lookup(tag, now).is_some())
        .await;
    let actor = h.engine.resolver.lookup(tag, now).unwrap();
    h.wait_for("actor window of 3", || {
        h.engine.windows.actor(actor).is_some_and(|w| w.len() == 3)
    })
    .await;
    assert_eq!(
        h.engine
            .resolver
            .lookup(Ident::new(Kind::Session, 0x1111111111111111), now),
        Some(actor)
    );
    assert_eq!(
        h.engine
            .resolver
            .lookup(Ident::new(Kind::Session, 0x2222222222222222), now),
        Some(actor)
    );
    h.engine.store.flush().await;
    let ids: Vec<Option<String>> = h
        .engine
        .store
        .with_reader(|c| {
            let mut st = c.prepare("SELECT actor_id FROM turns WHERE turn_id IN ('00000000000000000000000000000a01','00000000000000000000000000000a02','00000000000000000000000000000a03')")?;
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
            "00000000000000000000000000000a04",
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
            "00000000000000000000000000000a05",
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
            "00000000000000000000000000000a06",
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
    let script = |now: i64| {
        vec![
            tagged_event(
                now - 40_000_000,
                "00000000000000000000000000000b01",
                "1111111111111111",
                "anon",
                TAG,
                "home",
            ),
            tagged_event(
                now - 30_000_000,
                "00000000000000000000000000000b02",
                "1111111111111111",
                "anon",
                TAG,
                "venues.show",
            ),
            // Login regenerates the session: the tag carries the guest actor into the user's.
            tagged_event(
                now - 20_000_000,
                "00000000000000000000000000000b03",
                "2222222222222222",
                "0f0f0f0f0f0f0f0f",
                TAG,
                "portal.login",
            ),
            tagged_event(
                now - 10_000_000,
                "00000000000000000000000000000b04",
                "2222222222222222",
                "0f0f0f0f0f0f0f0f",
                TAG,
                "home",
            ),
        ]
    };
    let now = now_us();
    let read_ids = |h: &Harness| -> Vec<(String, String)> {
        h.engine
            .store
            .with_reader(|c| {
                let mut st = c.prepare("SELECT turn_id, actor_id FROM turns WHERE turn_id LIKE '00000000000000000000000000000b%' ORDER BY turn_id")?;
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
        h.engine.resolver.lookup(principal, now).is_some()
    })
    .await;
    let actor = h.engine.resolver.lookup(tag, now).unwrap();
    assert_eq!(
        h.engine.resolver.lookup(principal, now),
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
    assert_eq!(h.engine.resolver.lookup(tag, now), Some(actor));
    assert_eq!(h.engine.resolver.lookup(principal, now), Some(actor));
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
    assert_eq!(h.engine.resolver.lookup_any(&probe_ids, now), Some(actor));
    h.running.abort();
    h.engine.shutdown().await;

    // The same script into an empty store yields the same assignments.
    let h2 = Harness::start().await;
    for e in script(now) {
        h2.event(&e).await;
    }
    h2.wait_for("principal bound again", || {
        h2.engine.resolver.lookup(principal, now).is_some()
    })
    .await;
    h2.engine.store.flush().await;
    assert_eq!(read_ids(&h2), first, "deterministic across stores");
    h2.running.abort();
    h2.engine.shutdown().await;
}

fn tagless_event(ts: i64, turn_id: &str, session: &str) -> String {
    json!({"v":2,"ts":ts,"turn_id":turn_id,"session_key":session,"peer_key":PEER,"principal":"anon","verb":"GET",
        "route":"home","status":200,"latency_ms":1.0,"bytes_in":0,"bytes_out":100,"req_shape":"[]","resp_shape":"html",
        "bound":[],"validation_failed":null,"exception":null,"auth_event":null,"gate":null,
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,"surface":"web","tag_status":"issued","tag_id":null,
        "ip":"203.0.113.7","ip_trust":"direct","ua_class":"library","shape_hash":"aaaaaaaaaaaaaaaa"})
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_less_scanner_leaves_one_cluster_window_and_no_actors() {
    let h = Harness::start().await;
    let now = now_us();
    // Laravel mints a session per request for a client that returns no cookie;
    // the tag is issued every time and never comes back.
    for i in 0..100u64 {
        h.event(&tagless_event(
            now - 200_000_000 + (i as i64) * 1_000_000,
            &format!("{i:032x}"),
            &format!("{:016x}", 0x5000 + i),
        ))
        .await;
    }
    h.wait_for("100 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 100
    })
    .await;
    let counts = h.engine.windows.counts();
    assert_eq!(
        counts.5, 1,
        "one cluster window for the whole burst: {counts:?}"
    );
    assert_eq!(
        counts.4, 100,
        "one provisional actor per fresh session, for now"
    );
    let cluster = h.engine.resolver.cluster_key(
        &leesided::hash::Hasher::new("test-key").hex16("net", "203.0.113.0/24"),
        "aaaaaaaaaaaaaaaa",
    );
    assert!(
        h.engine
            .windows
            .cluster(cluster)
            .is_some_and(|w| w.len() == 64),
        "the cluster window holds the newest 64"
    );
    // A day later nothing came back: the sweep removes every binding and every unconfirmed actor.
    let swept = h.engine.resolver.sweep(now + 25 * 3600 * 1_000_000);
    assert_eq!(swept.actors.len(), 100);
    assert_eq!(h.engine.resolver.len().0, 0, "zero actors after the sweep");
    h.engine.store.flush().await;
    let with_actor: i64 = h
        .engine
        .store
        .with_reader(|c| c.query_row("SELECT count(actor_id) FROM turns", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(with_actor, 100, "turns keep the id they were ingested with");
    h.running.abort();
    h.engine.shutdown().await;
}

fn feature_rows(h: &Harness, scope: &str) -> Vec<(String, i64, String)> {
    h.engine
        .store
        .with_reader(|c| {
            let mut st = c.prepare(
                "SELECT key, ts_us, vector FROM feature_vectors WHERE scope = ?1 ORDER BY ts_us",
            )?;
            let rows = st.query_map(rusqlite::params![scope], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.collect()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn features_v2_rows_per_confirmed_actor_and_per_cluster() {
    use leesided::rules::features::{NAMES, VERSION};
    let h = Harness::start().await;
    let now = now_us();
    // A cookie-less scanner: 100 fresh sessions, no tag ever returned.
    for i in 0..100u64 {
        h.event(&tagless_event(
            now - 300_000_000 + (i as i64) * 1_000_000,
            &format!("{i:032x}"),
            &format!("{:016x}", 0x5000 + i),
        ))
        .await;
    }
    h.wait_for("100 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 100
    })
    .await;
    h.engine.store.flush().await;
    assert!(
        feature_rows(&h, "actor").is_empty(),
        "provisional actors emit no rows"
    );
    let clusters = feature_rows(&h, "cluster");
    assert_eq!(clusters.len(), 100, "every turn scores through its cluster");
    assert_eq!(
        clusters
            .iter()
            .map(|(k, _, _)| k.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        1,
        "one cluster"
    );
    let last: Vec<f32> = serde_json::from_str(&clusters.last().unwrap().2).unwrap();
    assert_eq!(last.len(), NAMES.len());
    let at = |v: &[f32], name: &str| v[NAMES.iter().position(|n| *n == name).unwrap()];
    assert_eq!(at(&last, "turns_held"), 64.0);
    assert_eq!(at(&last, "turns_total"), 100.0);
    assert_eq!(at(&last, "surface_web"), 1.0);
    assert!(
        at(&last, "tag_dropped") == 0.0,
        "issued every time, never returned, never absent after an issue on this cluster"
    );

    // A browser: issued, then valid. One actor row, at the confirming turn, covering both.
    let t1 = tagged_event(
        now - 20_000_000,
        &"a".repeat(32),
        "1111111111111111",
        "anon",
        TAG,
        "home",
    )
    .replace("\"tag_status\":\"valid\"", "\"tag_status\":\"issued\"");
    let t2 = tagged_event(
        now - 10_000_000,
        &"b".repeat(32),
        "1111111111111111",
        "anon",
        TAG,
        "venues.show",
    );
    h.event(&t1).await;
    h.event(&t2).await;
    h.wait_for("102 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 102
    })
    .await;
    h.engine.store.flush().await;
    let actors = feature_rows(&h, "actor");
    assert_eq!(actors.len(), 1, "{actors:?}");
    let v: Vec<f32> = serde_json::from_str(&actors[0].2).unwrap();
    assert_eq!(
        at(&v, "turns_held"),
        2.0,
        "the first window already covers the provisional turn"
    );
    assert_eq!(at(&v, "distinct_routes"), 2.0);
    assert_eq!(actors[0].1, now - 10_000_000);
    let version: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row("SELECT DISTINCT version FROM feature_vectors", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(version as u32, VERSION);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_65th_turn_evicts_the_first() {
    use leesided::rules::features::NAMES;
    let h = Harness::start().await;
    let now = now_us();
    // One cluster, 65 turns: the window holds the newest 64, the total counts all.
    for i in 0..65u64 {
        h.event(&tagless_event(
            now - 300_000_000 + (i as i64) * 1_000_000,
            &format!("{i:032x}"),
            &format!("{:016x}", 0x6000 + i),
        ))
        .await;
    }
    h.wait_for("65 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 65
    })
    .await;
    h.engine.store.flush().await;
    let clusters = feature_rows(&h, "cluster");
    assert_eq!(clusters.len(), 65, "a row per turn");
    let at = |v: &[f32], name: &str| v[NAMES.iter().position(|n| *n == name).unwrap()];
    let first: Vec<f32> = serde_json::from_str(&clusters.first().unwrap().2).unwrap();
    assert_eq!(at(&first, "turns_held"), 1.0);
    assert_eq!(at(&first, "turns_total"), 1.0);
    let last: Vec<f32> = serde_json::from_str(&clusters.last().unwrap().2).unwrap();
    assert_eq!(at(&last, "turns_held"), 64.0, "the window holds 64");
    assert_eq!(
        at(&last, "turns_total"),
        65.0,
        "the total counts the evicted one"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_s_surface_is_its_turn_s() {
    use leesided::rules::features::NAMES;
    let h = Harness::start().await;
    let now = now_us();
    // One cluster across three surfaces; the window mixes them, each row
    // carries the surface of the turn that triggered it.
    for (i, surface) in ["web", "api", "webhook"].iter().enumerate() {
        let ev = tagless_event(
            now - 10_000_000 + (i as i64) * 1_000_000,
            &format!("{i:032x}"),
            &format!("{:016x}", 0x7000 + i),
        )
        .replace(r#""surface":"web""#, &format!(r#""surface":"{surface}""#));
        h.event(&ev).await;
    }
    h.settle(3).await;
    let surfaces: Vec<Option<String>> = h
        .engine
        .store
        .with_reader(|c| {
            let mut st = c.prepare(
                "SELECT surface FROM feature_vectors WHERE scope = 'cluster' ORDER BY ts_us",
            )?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(
        surfaces,
        vec![
            Some("web".to_string()),
            Some("api".to_string()),
            Some("webhook".to_string())
        ]
    );
    let clusters = feature_rows(&h, "cluster");
    assert_eq!(clusters.len(), 3, "mixed surfaces share one window");
    let at = |v: &[f32], name: &str| v[NAMES.iter().position(|n| *n == name).unwrap()];
    let last: Vec<f32> = serde_json::from_str(&clusters.last().unwrap().2).unwrap();
    assert_eq!(
        (
            at(&last, "surface_web"),
            at(&last, "surface_api"),
            at(&last, "surface_webhook")
        ),
        (0.0, 0.0, 1.0),
        "the indicators name the newest turn's surface"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn features_v2_are_deterministic_across_a_restart_and_a_fresh_store() {
    let now = now_us();
    let script = |now: i64| {
        vec![
            tagged_event(
                now - 50_000_000,
                &"1".repeat(32),
                "1111111111111111",
                "anon",
                TAG,
                "home",
            )
            .replace("\"tag_status\":\"valid\"", "\"tag_status\":\"issued\""),
            tagged_event(
                now - 40_000_000,
                &"2".repeat(32),
                "1111111111111111",
                "anon",
                TAG,
                "venues.show",
            ),
            tagged_event(
                now - 30_000_000,
                &"3".repeat(32),
                "2222222222222222",
                "0f0f0f0f0f0f0f0f",
                TAG,
                "portal.login",
            ),
            tagged_event(
                now - 20_000_000,
                &"4".repeat(32),
                "2222222222222222",
                "0f0f0f0f0f0f0f0f",
                TAG,
                "home",
            ),
        ]
    };
    let fifth = |now: i64| {
        tagged_event(
            now - 10_000_000,
            &"5".repeat(32),
            "2222222222222222",
            "0f0f0f0f0f0f0f0f",
            TAG,
            "api.venues.index",
        )
    };

    let h = Harness::start().await;
    for e in script(now) {
        h.event(&e).await;
    }
    h.wait_for("4 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 4
    })
    .await;
    h.engine.store.flush().await;
    let before = feature_rows(&h, "actor");
    assert_eq!(
        before.len(),
        3,
        "rows from the confirming turn on: {before:?}"
    );
    // Restart: windows rebuilt from turns, bindings reloaded; one more turn.
    let h = h.restart().await;
    h.event(&fifth(now)).await;
    h.wait_for("5th event", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 1
    })
    .await;
    h.engine.store.flush().await;
    let after = feature_rows(&h, "actor");
    assert_eq!(after.len(), 4);
    h.running.abort();
    h.engine.shutdown().await;

    // The same five turns straight into a fresh store give the same five... four rows, byte for byte.
    let h2 = Harness::start().await;
    for e in script(now) {
        h2.event(&e).await;
    }
    h2.event(&fifth(now)).await;
    h2.wait_for("5 events", || {
        h2.engine.counters.events.load(Ordering::Relaxed) == 5
    })
    .await;
    h2.engine.store.flush().await;
    let fresh = feature_rows(&h2, "actor");
    assert_eq!(fresh, after, "same turns, same vectors, restart or not");
    h2.running.abort();
    h2.engine.shutdown().await;
}

// ---- the passive tap (docs/tap.md) ----

/// A v2 web turn from 203.0.113.7 with a source port, as php-fpm reports it.
fn fp_event(ts: i64, turn_id: &str, port: u16, ja4: Option<&str>, ua_class: &str) -> String {
    json!({"v":2,"ts":ts,"ts_ms":ts / 1000,"turn_id":turn_id,"session_key":"1234123412341234","peer_key":PEER,
        "principal":"anon","verb":"GET","route":"home","status":200,"latency_ms":1.0,"bytes_in":0,"bytes_out":100,
        "req_shape":"[]","resp_shape":"html","bound":[],"validation_failed":null,"exception":null,"auth_event":null,"gate":null,
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,"surface":"web","tag_status":"absent","tag_id":null,
        "ip":"203.0.113.7","remote_port":port,"ip_trust":"direct","ua_class":ua_class,"shape_hash":"aaaaaaaaaaaaaaaa",
        "flags":["library_ua_on_web"],"ja4":ja4})
    .to_string()
}

const PYTHON_JA4: &str = "t13d181000_85036bcba153_d41ae481755e";
const SOME_JA4T: &str = "65535_2-4-8-1-3_1460_7";

impl Harness {
    async fn fp(&self, msg: Value) {
        let sock = UnixDatagram::unbound().unwrap();
        sock.send_to(msg.to_string().as_bytes(), self.dir.join("fp.sock"))
            .await
            .expect("send fp");
    }

    fn turn_fp(&self, turn_id: &str) -> (Option<String>, Option<String>, Option<String>) {
        self.engine
            .store
            .with_reader(|c| {
                c.query_row(
                    "SELECT ja4, ja4t, flags FROM turns WHERE turn_id = ?1",
                    rusqlite::params![turn_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .unwrap()
    }

    async fn settle(&self, events: u64) {
        self.wait_for("events", || {
            self.engine.counters.events.load(Ordering::Relaxed) == events
        })
        .await;
        self.engine.store.flush().await;
    }
}

fn fp_msg(ts_ms: u64, port: u16) -> Value {
    json!({"v":1,"ts_ms":ts_ms,"ip":"203.0.113.7","port":port})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tap_fingerprints_join_the_turn_by_connection_and_time() {
    let h = Harness::start().await;
    let now = now_us();
    let t0 = (now / 1000) as u64;
    // SYN, then ClientHello, then the request: the usual order.
    let mut syn = fp_msg(t0 - 100, 51234);
    syn["ja4t"] = SOME_JA4T.into();
    syn["tls"] = true.into();
    h.fp(syn).await;
    let mut hello = fp_msg(t0 - 50, 51234);
    hello["ja4"] = "t13d1516h2_8daaf6152771_e5627efa2ab1".into();
    h.fp(hello).await;
    h.wait_for("2 tap messages", || h.engine.conns.stats().messages == 2)
        .await;
    h.event(&fp_event(now, &"c".repeat(32), 51234, None, "library"))
        .await;
    // Another port the tap never saw: nothing to join, the turn waits.
    h.event(&fp_event(
        now + 100_000,
        &"d".repeat(32),
        51235,
        None,
        "library",
    ))
    .await;
    h.settle(2).await;
    assert_eq!(
        (
            h.engine.store.dropped(),
            h.engine.store.count("turns").unwrap()
        ),
        (0, 2),
        "bad_event {}",
        h.engine.counters.bad_event.load(Ordering::Relaxed)
    );
    let (ja4, ja4t, flags) = h.turn_fp(&"c".repeat(32));
    assert_eq!(ja4.as_deref(), Some("t13d1516h2_8daaf6152771_e5627efa2ab1"));
    assert_eq!(ja4t.as_deref(), Some(SOME_JA4T));
    assert_eq!(
        flags.as_deref(),
        Some("[\"library_ua_on_web\"]"),
        "no mismatch for a library UA"
    );
    let (ja4, ja4t, _) = h.turn_fp(&"d".repeat(32));
    assert!(ja4.is_none() && ja4t.is_none());
    // The tap's JA4 feeds the weak ja4+asn binding at ingest (docs/tap.md).
    // Actor 0 exists nowhere, so cluster_size counts every actor recorded
    // under this fingerprint; asn is 0 without GeoIP databases.
    use leesided::actors::{Ident, Kind};
    let ja4_ident = Ident::pair(
        Kind::Ja4Asn,
        h.engine
            .resolver
            .key("ja4", "t13d1516h2_8daaf6152771_e5627efa2ab1"),
        0,
    );
    assert_eq!(h.engine.resolver.cluster_size(ja4_ident, 0, now), 1);
    let s = h.engine.conns.stats();
    assert_eq!(
        (s.matched, s.unknown, s.deferred, s.missed),
        (1, 1, 1, 0),
        "{s:?}"
    );
    // 60 s later nothing came: the wait ends and the columns stay null.
    h.engine.conns.sweep(t0 + 61_000);
    assert_eq!(h.engine.conns.stats().missed, 1);
    let (_, health) = h.http("GET", "/health", None).await;
    assert_eq!(health["tap"]["matched"], 1);
    assert!(health["ja4_classes"].as_u64().unwrap() >= 6);
    // The store never saw the address: the turn carries hashes only.
    let raw: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM turns WHERE ip_hash LIKE '%203.0.113%' OR cluster_key LIKE '%203.0%'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(raw, 0);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_event_can_beat_the_tap_datagram_and_still_be_filled() {
    let h = Harness::start().await;
    let now = now_us();
    let t0 = (now / 1000) as u64;
    // A browser UA whose TLS stack turns out to be Python's: the late fill
    // also brings the mismatch flag, through json_insert on the stored row.
    h.event(&fp_event(now, &"e".repeat(32), 51300, None, "firefox"))
        .await;
    h.settle(1).await;
    let (ja4, ja4t, flags) = h.turn_fp(&"e".repeat(32));
    assert!(ja4.is_none() && ja4t.is_none());
    assert_eq!(flags.as_deref(), Some("[\"library_ua_on_web\"]"));
    assert_eq!(h.engine.conns.stats().deferred, 1);
    let mut syn = fp_msg(t0 - 30, 51300);
    syn["ja4t"] = SOME_JA4T.into();
    syn["tls"] = true.into();
    h.fp(syn).await;
    let mut hello = fp_msg(t0 - 10, 51300);
    hello["ja4"] = PYTHON_JA4.into();
    h.fp(hello).await;
    h.wait_for("late fills", || h.engine.conns.stats().filled_late == 2)
        .await;
    h.engine.store.flush().await;
    let (ja4, ja4t, flags) = h.turn_fp(&"e".repeat(32));
    assert_eq!(ja4.as_deref(), Some(PYTHON_JA4));
    assert_eq!(ja4t.as_deref(), Some(SOME_JA4T));
    assert_eq!(
        flags.as_deref(),
        Some("[\"library_ua_on_web\",\"ua_vs_ja4_mismatch\"]")
    );
    assert_eq!(h.engine.conns.stats().pending, 0);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trusted_proxy_ja4_on_the_event_is_kept_and_a_mismatch_flags_at_ingest() {
    let h = Harness::start().await;
    let now = now_us();
    let t0 = (now / 1000) as u64;
    let mut syn = fp_msg(t0 - 100, 51400);
    syn["ja4t"] = SOME_JA4T.into();
    syn["tls"] = true.into();
    h.fp(syn).await;
    let mut hello = fp_msg(t0 - 50, 51400);
    hello["ja4"] = PYTHON_JA4.into();
    h.fp(hello).await;
    h.wait_for("tap messages", || h.engine.conns.stats().messages == 2)
        .await;
    // The proxy's value is the event's, and wins over the tap's.
    h.event(&fp_event(
        now,
        &"f".repeat(32),
        51400,
        Some("t13d0000h2_proxy_value"),
        "chromium",
    ))
    .await;
    h.settle(1).await;
    let (ja4, ja4t, flags) = h.turn_fp(&"f".repeat(32));
    assert_eq!(ja4.as_deref(), Some("t13d0000h2_proxy_value"));
    assert_eq!(ja4t.as_deref(), Some(SOME_JA4T));
    assert_eq!(
        flags.as_deref(),
        Some("[\"library_ua_on_web\"]"),
        "an unknown ja4 never flags"
    );
    // Same connection, a second request on it (keep-alive): the tap's Python
    // JA4 under a Chromium UA flags at ingest.
    h.event(&fp_event(
        now + 500_000,
        &"a1".repeat(16),
        51400,
        None,
        "chromium",
    ))
    .await;
    h.settle(2).await;
    let (ja4, _, flags) = h.turn_fp(&"a1".repeat(16));
    assert_eq!(ja4.as_deref(), Some(PYTHON_JA4));
    assert_eq!(
        flags.as_deref(),
        Some("[\"library_ua_on_web\",\"ua_vs_ja4_mismatch\"]")
    );
    // A bad message counts and changes nothing.
    h.fp(json!({"v":1,"ts_ms":t0,"ip":"not an ip","port":1}))
        .await;
    h.wait_for("bad message", || h.engine.conns.stats().bad_message == 1)
        .await;
    h.running.abort();
    h.engine.shutdown().await;
}

fn cred_event(
    ts: i64,
    turn_id: &str,
    session: &str,
    tag: &str,
    route: &str,
    status: u16,
    cred_status: &str,
) -> String {
    json!({"v":2,"ts":ts,"turn_id":turn_id,"session_key":session,"peer_key":PEER,"principal":"anon","verb":"GET",
        "route":route,"status":status,"latency_ms":1.0,"bytes_in":0,"bytes_out":100,"req_shape":"[]","resp_shape":"html",
        "bound":[],"validation_failed":null,"exception":null,"auth_event":null,"gate":null,
        "ua_hash":"9c8b7a6f9c8b7a6f","dropped_since_last":0,"surface":"web","tag_id":tag,"tag_status":"valid",
        "credential_kind":"api_key","credential_hash":"0011223344556677","credential_status":cred_status,
        "ip":"203.0.113.7","ip_trust":"direct","ua_class":"chromium"})
    .to_string()
}

fn all_labels(h: &Harness) -> Vec<(String, String, String, f64, Option<String>)> {
    h.engine
        .store
        .with_reader(|c| {
            let mut st = c.prepare(
                "SELECT scope, label, source, confidence, note FROM labels ORDER BY window_end_ts",
            )?;
            let rows = st.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honeytoken_labels_the_hit_and_the_following_hour() {
    let h = Harness::start_with_routes(&["admin.backup"], &[]).await;
    let now = now_us();
    // Provisional first sighting: no actor row, no label.
    h.event(&tagged_event(
        now,
        "00000000000000000000000000000b01",
        SESSION,
        "anon",
        TAG,
        "home",
    ))
    .await;
    // The hit confirms the actor: row plus label.
    h.event(&tagged_event(
        now + 60_000_000,
        "00000000000000000000000000000b02",
        SESSION,
        "anon",
        TAG,
        "admin.backup",
    ))
    .await;
    // Inside the hour: chained label pointing at the hit.
    h.event(&tagged_event(
        now + 1_800_000_000,
        "00000000000000000000000000000b03",
        SESSION,
        "anon",
        TAG,
        "home",
    ))
    .await;
    // Past the hour: row, no label.
    h.event(&tagged_event(
        now + 3_700_000_000,
        "00000000000000000000000000000b04",
        SESSION,
        "anon",
        TAG,
        "home",
    ))
    .await;
    h.wait_for("4 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 4
    })
    .await;
    h.engine.store.flush().await;
    let labels = all_labels(&h);
    assert_eq!(labels.len(), 2, "{labels:?}");
    assert_eq!(labels[0].0, "actor");
    assert_eq!(labels[0].1, "malicious");
    assert_eq!(labels[0].2, "honeytoken");
    assert_eq!(labels[0].3, 0.9);
    assert_eq!(labels[0].4.as_deref(), Some("admin.backup"));
    assert_eq!(labels[1].2, "honeytoken");
    assert!(
        labels[1]
            .4
            .as_deref()
            .is_some_and(|n| n.starts_with("hit:")),
        "{labels:?}"
    );
    let orphans: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM labels l LEFT JOIN feature_vectors fv \
                 ON fv.scope = l.scope AND fv.key = l.scope_id AND fv.ts_us = l.window_end_ts \
                 WHERE fv.ts_us IS NULL",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(orphans, 0, "every label sits on a real row");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_business_labels_completed_actions_only() {
    let h = Harness::start_with_routes(&[], &["portal.login"]).await;
    let now = now_us();
    // A verified credential is a strong ident: confirmed on first sight.
    h.event(&cred_event(
        now,
        "00000000000000000000000000000c01",
        SESSION,
        TAG,
        "portal.login",
        200,
        "verified",
    ))
    .await;
    // Rejected, off-list, and unverified turns: rows, no labels.
    h.event(&cred_event(
        now + 1_000_000,
        "00000000000000000000000000000c02",
        SESSION,
        TAG,
        "portal.login",
        403,
        "verified",
    ))
    .await;
    h.event(&cred_event(
        now + 2_000_000,
        "00000000000000000000000000000c03",
        SESSION,
        TAG,
        "home",
        200,
        "verified",
    ))
    .await;
    h.event(&cred_event(
        now + 3_000_000,
        "00000000000000000000000000000c04",
        SESSION,
        TAG,
        "portal.login",
        200,
        "unverified",
    ))
    .await;
    h.wait_for("4 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 4
    })
    .await;
    h.engine.store.flush().await;
    let labels = all_labels(&h);
    assert_eq!(labels.len(), 1, "{labels:?}");
    assert_eq!(labels[0].0, "actor");
    assert_eq!(labels[0].1, "benign");
    assert_eq!(labels[0].2, "verified_business");
    assert_eq!(labels[0].3, 0.8);
    assert_eq!(labels[0].4.as_deref(), Some("portal.login"));
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_decision_labels_blocks_and_nothing_else() {
    let h = Harness::start().await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let burst: Rule = serde_json::from_value(json!({
        "id": "label-burst", "note": "three home loads by one actor", "mode": "enforce", "action": "block",
        "match": {"route": ["home"], "verb": ["GET"], "principal": "any", "surface": ["web"]},
        "when": {"scope": "actor", "window_s": 600, "count": {}, "gte": 3},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(burst, State::Active, "operator", None)
        .await
        .unwrap();
    let watch: Rule = serde_json::from_value(json!({
        "id": "label-watch", "note": "about loads are watched", "mode": "enforce", "action": "watch",
        "match": {"route": ["about"], "verb": ["GET"], "principal": "any", "surface": ["web"]},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(watch, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_us();
    for (i, turn) in ["d01", "d02", "d03"].iter().enumerate() {
        h.event(&tagged_event(
            now - 30_000_000 + (i as i64) * 1_000_000,
            &format!("00000000000000000000000000000{turn}"),
            SESSION,
            "anon",
            TAG,
            "home",
        ))
        .await;
    }
    h.wait_for("3 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 3
    })
    .await;
    // The probe matches the block rule; the event joins the check to the turn.
    let v = h
        .probe(&tagged_probe(
            now,
            "00000000000000000000000000000d04",
            "3333333333333333",
            Some(TAG),
            "home",
        ))
        .await;
    assert_eq!(v["action"], "block", "{v}");
    h.event(&tagged_event(
        now,
        "00000000000000000000000000000d04",
        "3333333333333333",
        "anon",
        TAG,
        "home",
    ))
    .await;
    // A fresh actor on the watched route: watch verdict, no label.
    let v = h
        .probe(&tagged_probe(
            now,
            "00000000000000000000000000000d05",
            "4444444444444444",
            Some("aaaaaaaaaaaaaaaa"),
            "about",
        ))
        .await;
    assert_eq!(v["action"], "watch", "{v}");
    h.event(&tagged_event(
        now,
        "00000000000000000000000000000d05",
        "4444444444444444",
        "anon",
        "aaaaaaaaaaaaaaaa",
        "about",
    ))
    .await;
    h.wait_for("5 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 5
    })
    .await;
    h.engine.store.flush().await;
    let labels = all_labels(&h);
    assert_eq!(labels.len(), 1, "{labels:?}");
    assert_eq!(labels[0].0, "actor");
    assert_eq!(labels[0].1, "malicious");
    assert_eq!(labels[0].2, "rule_decision");
    assert_eq!(labels[0].3, 0.5);
    assert_eq!(labels[0].4.as_deref(), Some("label-burst"));
    let eligible: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row("SELECT count(*) FROM labels_test_eligible", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(eligible, 0, "rule_decision rows never enter a test set");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_mode_writes_scores_and_changes_no_decision() {
    use leesided::config::WindsideMode;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("windside-model");
    Harness::shadow_model(&model);
    let h = Harness::open_windside(dir, Some(model.clone()), WindsideMode::Shadow).await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let rule: Rule = serde_json::from_value(json!({
        "id": "windside-shadow-test", "note": "score above the test threshold",
        "mode": "enforce", "action": "block",
        "match": {"route": ["home"], "verb": ["GET"], "principal": "any", "surface": ["web"]},
        "when": {"scope": "actor", "score": {"gte": 0.7}},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(rule, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_us();
    // Actor one: issued, then five valid turns. The actor confirms at the
    // second turn and every later turn writes a row; rows at five and six
    // held turns clear the floor and score.
    let s1 = "1111111111111111";
    let t1 = tagged_event(now, &"a".repeat(32), s1, "anon", TAG, "home")
        .replace("\"tag_status\":\"valid\"", "\"tag_status\":\"issued\"");
    h.event(&t1).await;
    for i in 1..6i64 {
        h.event(&tagged_event(
            now + i * 1_000_000,
            &format!("{i:032x}"),
            s1,
            "anon",
            TAG,
            "home",
        ))
        .await;
    }
    // Actor two: three turns, never five held; the floor skips it.
    let s2 = "2222222222222222";
    let tag2 = "0123456789abcdef";
    let u1 = tagged_event(now, &"b".repeat(32), s2, "anon", tag2, "home")
        .replace("\"tag_status\":\"valid\"", "\"tag_status\":\"issued\"");
    h.event(&u1).await;
    for i in 1..3i64 {
        h.event(&tagged_event(
            now + i * 1_000_000,
            &format!("1{i:031x}"),
            s2,
            "anon",
            tag2,
            "home",
        ))
        .await;
    }
    h.wait_for("nine events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 9
    })
    .await;
    h.engine.store.flush().await;
    let scores: Vec<(String, String, f64, String)> = h
        .engine
        .store
        .with_reader(|c| {
            let mut stmt = c
                .prepare("SELECT scope, scope_id, score, top3 FROM scores")
                .unwrap();
            Ok(stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect::<Vec<(String, String, f64, String)>>())
        })
        .unwrap();
    let actor_scores: Vec<_> = scores.iter().filter(|(s, _, _, _)| s == "actor").collect();
    assert_eq!(actor_scores.len(), 2, "{scores:?}");
    for (_, _, p, top3) in &actor_scores {
        assert!((p - 0.8807970779778823).abs() < 1e-9, "{p}");
        assert_eq!(top3, "[]");
    }
    let actor1: String = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT DISTINCT actor_id FROM turns WHERE session_key = ?1",
                rusqlite::params![s1],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(actor_scores.iter().all(|(_, a, _, _)| a == &actor1));
    let actor_score: Option<f64> = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT score FROM actors WHERE id = ?1",
                rusqlite::params![actor1],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(actor_score.is_some_and(|s| (s - 0.8807970779778823).abs() < 1e-9));
    // The score rule is present and the actor is above it, but shadow
    // never fires: allow, and no decision sticks.
    let v = h
        .probe(&tagged_probe(
            now + 6_000_000,
            &"f".repeat(32),
            s1,
            Some(TAG),
            "home",
        ))
        .await;
    assert_eq!(v["action"], "allow", "{v}");
    assert!(h.engine.decisions.is_empty());
    // The report agrees with the store, split by scope: two actor rows
    // scored, five skipped. The tagged helper carries no ip, so no
    // cluster resolves and the cluster scope is absent.
    let report = leesided::report::shadow(&h.dir.join("leesided.sqlite"), Some(&model), 0).unwrap();
    let actor = &report.by_scope["actor"];
    assert_eq!((actor.feature_rows, actor.scored, actor.skipped), (7, 2, 5));
    assert!(!report.by_scope.contains_key("cluster"));
    assert_eq!(report.agreement, (0, 1));
    assert_eq!(report.above_without_block, 1);
    assert_eq!(report.disagreements.len(), 1);
    assert_eq!(report.disagreements[0].scope_id, actor1);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_with_wrong_features_version_refuses_to_load() {
    use leesided::config::WindsideMode;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("windside-model");
    Harness::shadow_model(&model);
    let manifest = std::fs::read_to_string(model.join("manifest.json")).unwrap();
    std::fs::write(
        model.join("manifest.json"),
        manifest.replace("\"features_version\":2", "\"features_version\":999"),
    )
    .unwrap();
    let h = Harness::open_windside(dir, Some(model), WindsideMode::Shadow).await;
    let (_, health) = h.http("GET", "/health", None).await;
    assert_eq!(health["windside"]["mode"], "shadow");
    assert!(health["windside"]["model_version"].is_null());
    let err = health["windside"]["error"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(err.contains("features_version"), "{err}");
    // The daemon still serves; nothing scores.
    let v = h
        .probe(&probe_json(now_f64(), "GET", "home", SESSION))
        .await;
    assert_eq!(v["action"], "allow");
    h.engine.store.flush().await;
    let scored: i64 = h
        .engine
        .store
        .with_reader(|c| c.query_row("SELECT count(*) FROM scores", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(scored, 0);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_scores_cluster_rows_for_cookie_less_traffic() {
    use leesided::config::WindsideMode;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("windside-model");
    Harness::shadow_model(&model);
    let h = Harness::open_windside(dir, Some(model), WindsideMode::Shadow).await;
    let now = now_us();
    // Six tagless turns with fresh sessions (a client that returns no
    // cookie): one cluster window, no confirmed actor anywhere.
    for i in 0..6u64 {
        h.event(&tagless_event(
            now + (i as i64) * 1_000_000,
            &format!("{i:032x}"),
            &format!("{:016x}", 0x5000 + i),
        ))
        .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let scores: Vec<(String, f64)> = h
        .engine
        .store
        .with_reader(|c| {
            let mut stmt = c.prepare("SELECT scope, score FROM scores").unwrap();
            Ok(stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect::<Vec<(String, f64)>>())
        })
        .unwrap();
    // Held five and six clear the floor; nothing actor-scoped exists.
    assert_eq!(scores.len(), 2, "{scores:?}");
    assert!(scores.iter().all(|(s, _)| s == "cluster"));
    for (_, p) in &scores {
        assert!((p - 0.8807970779778823).abs() < 1e-9, "{p}");
    }
    let actor_rows: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM feature_vectors WHERE scope = 'actor'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(actor_rows, 0);
    let (_, health) = h.http("GET", "/health", None).await;
    assert_eq!(health["windside"]["scored"]["cluster"], 2);
    assert_eq!(health["windside"]["skipped"]["cluster"], 4);
    assert_eq!(health["windside"]["scored"]["actor"], 0);
    assert_eq!(health["migration_version"], 19);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_labels_the_highest_scored_actor() {
    use leesided::config::WindsideMode;
    use std::io::Cursor;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("windside-model");
    Harness::shadow_model(&model);
    // Empty store first: nothing to review.
    let h0 = Harness::open_windside(dir.join("empty"), None, WindsideMode::Off).await;
    let mut out = Vec::new();
    let labeled = leesided::review::run_review(
        &dir.join("empty").join("leesided.sqlite"),
        20,
        &mut Cursor::new(""),
        &mut out,
    )
    .unwrap();
    assert_eq!(labeled, 0);
    assert!(String::from_utf8(out).unwrap().contains("no scored actors"));
    h0.running.abort();
    h0.engine.shutdown().await;

    let h = Harness::open_windside(dir, Some(model), WindsideMode::Shadow).await;
    let now = now_us();
    let t1 = tagged_event(now, &"a".repeat(32), SESSION, "anon", TAG, "home")
        .replace("\"tag_status\":\"valid\"", "\"tag_status\":\"issued\"");
    h.event(&t1).await;
    for i in 1..6i64 {
        h.event(&tagged_event(
            now + i * 1_000_000,
            &format!("{i:032x}"),
            SESSION,
            "anon",
            TAG,
            "home",
        ))
        .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let db = h.dir.join("leesided.sqlite");
    let mut out = Vec::new();
    let labeled = leesided::review::run_review(&db, 20, &mut Cursor::new("m\n"), &mut out).unwrap();
    assert_eq!(labeled, 1);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("score=0.8808"), "{text}");
    assert!(text.contains("held=6"), "{text}");
    let label: (String, String, f64, Option<String>) = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT label, source, confidence, kind FROM labels",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
        })
        .unwrap();
    assert_eq!(
        label,
        ("malicious".to_string(), "operator".to_string(), 1.0, None)
    );
    // Re-reviewing appends: both judgments stay, the latest wins.
    let mut out = Vec::new();
    let labeled = leesided::review::run_review(&db, 20, &mut Cursor::new("b\n"), &mut out).unwrap();
    assert_eq!(labeled, 1);
    let rows: Vec<(String, i64)> = h
        .engine
        .store
        .with_reader(|c| {
            c.prepare("SELECT label, created_at FROM labels ORDER BY id ASC")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap();
    assert_eq!(rows.len(), 2, "append, not upsert");
    assert_eq!(rows[0].0, "malicious");
    assert_eq!(rows[1].0, "benign");
    let latest: String = h
        .engine
        .store
        .with_reader(|c| c.query_row("SELECT label FROM labels_test_eligible", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(latest, "benign");
    // Skipping writes nothing.
    let mut out = Vec::new();
    let labeled = leesided::review::run_review(&db, 20, &mut Cursor::new("\n"), &mut out).unwrap();
    assert_eq!(labeled, 0);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test]
async fn review_confirm_writes_an_operator_label_the_export_carries() {
    use leesided::config::WindsideMode;
    use std::io::Cursor;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("windside-model");
    Harness::shadow_model(&model);
    let h = Harness::open_windside(dir, Some(model), WindsideMode::Shadow).await;
    let now = now_us();
    for i in 0..6i64 {
        h.event(&tagged_event(
            now + i * 1_000_000,
            &format!("{i:032x}"),
            SESSION,
            "anon",
            TAG,
            "home",
        ))
        .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let db = h.dir.join("leesided.sqlite");
    // A proposal for the scored actor, as the worker would write it.
    let (scope_id, window_ts): (String, i64) = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT key, ts_us FROM feature_vectors WHERE scope = 'actor' \
                 ORDER BY ts_us DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    h.engine
        .store
        .send(leesided::store::StoreOp::Label(leesided::store::LabelRow {
            scope: "actor",
            scope_id: scope_id.clone(),
            surface: Some("web".to_string()),
            window_end_ts: window_ts,
            label: "malicious",
            source: "llm_proposed",
            confidence: 0.6,
            kind: None,
            note: Some("machine cadence".to_string()),
            created_at: 0,
            signals: None,
            daily_calls: 0,
            daily_tokens: 0,
        }));
    h.engine.store.flush().await;
    let mut out = Vec::new();
    let labeled = leesided::review::run_review(&db, 20, &mut Cursor::new("c\n"), &mut out).unwrap();
    assert_eq!(labeled, 1);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("llm proposes malicious (0.60)"), "{text}");
    assert!(text.contains("confirmed proposal"), "{text}");
    let op: (String, String, f64, String) = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT label, source, confidence, note FROM labels WHERE source = 'operator'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
        })
        .unwrap();
    assert_eq!(
        op,
        (
            "malicious".to_string(),
            "operator".to_string(),
            1.0,
            "confirmed llm_proposed".to_string()
        )
    );
    // The export carries the confirmed label at 1.0, not the 0.6 proposal.
    let csv = h.dir.join("export.csv");
    let stats = leesided::export::export(&db, 0, "confirm-test", &csv).unwrap();
    assert!(stats.rows > 0);
    let text = std::fs::read_to_string(&csv).unwrap();
    assert!(
        text.lines().any(|l| l.ends_with(",malicious,operator,1")),
        "{text}"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

#[test]
fn every_subcommand_answers_help() {
    let bin = env!("CARGO_BIN_EXE_leesided");
    for args in [
        ["--help"].as_slice(),
        ["serve", "--help"].as_slice(),
        ["rules", "schema", "--help"].as_slice(),
        ["rules", "validate", "--help"].as_slice(),
        ["rules", "export", "--help"].as_slice(),
        ["tap", "--help"].as_slice(),
        ["label-import", "--help"].as_slice(),
        ["export", "--help"].as_slice(),
        ["report", "shadow", "--help"].as_slice(),
        ["review", "--help"].as_slice(),
        ["llm", "--help"].as_slice(),
        ["llm", "show", "--help"].as_slice(),
        ["llm", "send", "--help"].as_slice(),
        ["llm", "subjects", "--help"].as_slice(),
    ] {
        let out = std::process::Command::new(bin).args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.starts_with("usage:"), "{args:?}: {text}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_pages_redirect_without_a_session() {
    let h = Harness::start().await;
    for path in [
        "/ui/",
        "/ui/llm",
        "/ui/llm/1",
        "/ui/jobs",
        "/ui/turns/abc",
        "/ui/trace/abc",
        "/ui/actors",
        "/ui/actors/abc",
        "/ui/clusters",
        "/ui/clusters/abc",
        "/ui/review",
        "/ui/labels",
        "/ui/rules",
        "/ui/model",
        "/ui/features",
    ] {
        let (st, headers, _) = h.ui("GET", path, None, None).await;
        assert_eq!(st, 303, "{path}");
        let loc = ui_header(&headers, "location").unwrap();
        assert!(loc.starts_with("/ui/login?next="), "{path} -> {loc}");
    }
    for (method, path) in [
        ("POST", "/ui/jobs/1/retry"),
        ("POST", "/ui/jobs/1/cancel"),
        ("POST", "/ui/llm/1/resend"),
    ] {
        let (st, headers, _) = h.ui(method, path, None, Some("csrf=x")).await;
        assert_eq!(st, 303, "{method} {path}");
        assert!(ui_header(&headers, "location")
            .unwrap()
            .starts_with("/ui/login?next="));
    }
    // A bogus cookie is no session either.
    let (st, _, _) = h
        .ui("GET", "/ui/llm", Some("leeside_ui=deadbeef"), None)
        .await;
    assert_eq!(st, 303);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_login_round_trip() {
    let h = ui_harness(Some("op-token")).await;
    let (st, _, body) = h.ui("GET", "/ui/login", None, None).await;
    assert_eq!(st, 200);
    assert!(body.contains("Operator token"), "{body}");
    let (st, headers, body) = h.ui_login("wrong").await;
    assert_eq!(st, 401);
    assert!(body.contains("wrong token"), "{body}");
    assert!(ui_header(&headers, "set-cookie").is_none());
    let (st, headers, _) = h.ui_login("op-token").await;
    assert_eq!(st, 303);
    assert_eq!(ui_header(&headers, "location"), Some("/ui/llm"));
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/llm", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    // An open redirect through `next` is refused.
    let (st, headers, _) = h
        .ui(
            "POST",
            "/ui/login",
            None,
            Some("token=op-token&next=https%3A%2F%2Fevil"),
        )
        .await;
    assert_eq!(st, 303);
    assert_eq!(ui_header(&headers, "location"), Some("/ui/llm"));
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_empty_store_renders() {
    let h = ui_harness(Some("op-token")).await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/llm", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("No calls logged yet."), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/jobs", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("No jobs in this state."), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/llm/1", Some(&cookie), None).await;
    assert_eq!(st, 404);
    assert!(body.contains("No such call"), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/actors", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("No actors yet."), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/clusters", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("No clusters yet."), "{body}");
    let (st, _, _) = h.ui("GET", "/ui/turns/abc", Some(&cookie), None).await;
    assert_eq!(st, 404);
    let (st, _, _) = h.ui("GET", "/ui/trace/abc", Some(&cookie), None).await;
    assert_eq!(st, 404);
    let (st, _, _) = h
        .ui("GET", "/ui/jobs?status=bogus", Some(&cookie), None)
        .await;
    assert_eq!(st, 400);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_exchange_renders_verbatim() {
    use leesided::store::{LlmCallRow, StoreOp};
    let h = ui_harness(Some("op-token")).await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let system = "You label actors. <rules> & \"regs\"";
    let envelope = serde_json::json!({"subject": "actor:aa", "turns": [1, 2]});
    let request = serde_json::json!({
        "model": "m",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": envelope.to_string()},
        ],
        "max_tokens": 4000,
        "reasoning_effort": "low",
    })
    .to_string();
    let proposal = r#"{"label":"malicious","confidence":0.93,"reason":"Wordlist paths at machine cadence.","signals":["scanner_paths","machine_cadence"]}"#;
    let reasoning = "Thinking <aloud> & onward.";
    let response = serde_json::json!({
        "choices": [{"message": {"content": proposal, "reasoning_content": reasoning}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20},
    })
    .to_string();
    h.engine.store.send(StoreOp::LlmCallInsert(LlmCallRow {
        job_id: None,
        point: "label".into(),
        model: "m".into(),
        prompt_hash: "h".into(),
        json_mode: "prompt".into(),
        input_summary: r#"{"subject":"actor:aa"}"#.into(),
        request: request.clone(),
        response: Some(response),
        parsed: Some(proposal.into()),
        latency_ms: Some(900),
        prompt_tokens: Some(10),
        completion_tokens: Some(20),
        finish_reason: Some("stop".into()),
        reasoning_tokens: Some(5),
        reasoning_excerpt: Some(reasoning.into()),
        resend_of: None,
        created_at: 1_700_000_000,
    }));
    h.engine.store.flush().await;
    let (st, _, body) = h.ui("GET", "/ui/llm/1", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    // The stored bytes, pretty-printed and escaped: nothing lost.
    let pretty =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&request).unwrap()).unwrap();
    assert!(
        body.contains(&ui_escape(&pretty)),
        "pretty request verbatim"
    );
    // The envelope decoded one level, the system prompt, the full
    // reasoning, and the recomputed validation.
    let envelope_pretty = serde_json::to_string_pretty(&envelope).unwrap();
    assert!(
        body.contains(&ui_escape(&envelope_pretty)),
        "envelope decoded"
    );
    assert!(body.contains(&ui_escape(system)), "system prompt");
    assert!(body.contains(&ui_escape(reasoning)), "reasoning whole");
    assert!(body.contains("label (docs/llm.md §8.1)"), "schema named");
    assert!(
        body.contains("<span class=\"chip good\">valid</span>"),
        "valid chip"
    );
    assert!(body.contains("parsed</span>"), "outcome");
    // The produced label and the operator's later word.
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    db.execute(
        "INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at, signals) \
         VALUES ('actor', 'aa', 'web', 99, 'malicious', 'llm_proposed', 0.93, NULL, 'proposal [llm_call:1]', 1_700_000_001, '[\"scanner_paths\"]')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at, signals) \
         VALUES ('actor', 'aa', 'web', 99, 'benign', 'operator', 1.0, NULL, 'review', 1_700_000_002, NULL)",
        [],
    )
    .unwrap();
    drop(db);
    let (st, _, body) = h.ui("GET", "/ui/llm/1", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("What happened next"), "{body}");
    assert!(body.contains("rejected</span>"), "operator rejected");
    assert!(body.contains("benign</span>"), "operator chose benign");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_jobs_retry_and_cancel() {
    let h = ui_harness(Some("op-token")).await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    db.execute(
        "INSERT INTO llm_jobs (point, scope, subject_id, status, attempts, enqueued_by, created_at, updated_at, last_error) \
         VALUES ('label', 'actor', 'aa', 'failed', 3, 'review', 1_700_000_000, 1_700_000_001, 'boom')",
        [],
    )
    .unwrap();
    let failed = db.last_insert_rowid();
    db.execute(
        "INSERT INTO llm_jobs (point, scope, subject_id, status, attempts, enqueued_by, created_at, updated_at) \
         VALUES ('label', 'cluster', 'bb', 'queued', 0, 'review', 1_700_000_000, 1_700_000_000)",
        [],
    )
    .unwrap();
    let queued = db.last_insert_rowid();
    drop(db);
    let (st, _, body) = h.ui("GET", "/ui/jobs", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(
        body.contains("actor:aa") && body.contains("cluster:bb"),
        "{body}"
    );
    let csrf = ui_csrf(&body);
    let (st, headers, _) = h
        .ui(
            "POST",
            &format!("/ui/jobs/{failed}/retry"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    assert_eq!(ui_header(&headers, "location"), Some("/ui/jobs"));
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let (status, attempts): (String, i64) = db
        .query_row(
            "SELECT status, attempts FROM llm_jobs WHERE id = ?1",
            [failed],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((status.as_str(), attempts), ("queued", 0));
    drop(db);
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/jobs/{queued}/cancel"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let (status, err): (String, Option<String>) = db
        .query_row(
            "SELECT status, last_error FROM llm_jobs WHERE id = ?1",
            [queued],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(err.as_deref(), Some("cancelled by the operator"));
    drop(db);
    // A wrong csrf token is refused, and a missing job is 404.
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/jobs/{failed}/retry"),
            Some(&cookie),
            Some("csrf=wrong"),
        )
        .await;
    assert_eq!(st, 403);
    let (st, _, _) = h
        .ui(
            "POST",
            "/ui/jobs/9999/retry",
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 404);
    h.running.abort();
    h.engine.shutdown().await;
}

fn ui_field(body: &str, name: &str) -> String {
    let key = format!("name=\"{name}\" value=\"");
    let i = body
        .find(&key)
        .unwrap_or_else(|| panic!("{name} in the page"));
    let rest = &body[i + key.len()..];
    rest[..rest.find('"').unwrap()].to_string()
}

async fn ui_actor_harness() -> (Harness, String, String) {
    let h = ui_harness(Some("op-token")).await;
    let now = now_us();
    for i in 0..6i64 {
        h.event(&tagged_event(
            now + i * 1_000_000,
            &format!("{i:032x}"),
            SESSION,
            "anon",
            TAG,
            "home",
        ))
        .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let actor: String = db
        .query_row(
            "SELECT actor_id FROM turns WHERE turn_id = ?1",
            ["00000000000000000000000000000005"],
            |r| r.get(0),
        )
        .unwrap();
    let ts: i64 = db
        .query_row(
            "SELECT ts_us FROM turns WHERE turn_id = ?1",
            ["00000000000000000000000000000005"],
            |r| r.get(0),
        )
        .unwrap();
    drop(db);
    (h, actor, ts.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_trace_lists_all_seven_steps() {
    let (h, actor, _) = ui_actor_harness().await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    db.execute(
        "INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3) \
         VALUES ('actor', ?1, '00000000000000000000000000000005', 'web', 1, 0.97, '0.1.0', \
         '[{\"name\":\"turns_held\",\"path_gain\":2.4}]')",
        [&actor],
    )
    .unwrap();
    db.execute(
        "INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at, signals) \
         VALUES ('actor', ?1, 'web', 99, 'malicious', 'llm_proposed', 0.93, NULL, 'wordlist paths [llm_call:7]', 1, '[\"scanner_paths\"]')",
        [&actor],
    )
    .unwrap();
    db.execute(
        "INSERT INTO decisions (scope, key, action, mode, rule, rule_version, created_at, expires_at) \
         VALUES ('actor', ?1, 'block', 'monitor', 'operator', 0, 1, 4_000_000_000)",
        [&actor],
    )
    .unwrap();
    drop(db);
    let (st, _, body) = h
        .ui(
            "GET",
            "/ui/trace/00000000000000000000000000000005",
            Some(&cookie),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    for step in [
        "1 · Turn",
        "2 · Resolution",
        "3 · Feature rows",
        "4 · Scores",
        "5 · Proposal",
        "6 · Labels",
        "7 · Decision",
    ] {
        assert!(body.contains(step), "step {step} present");
    }
    assert!(body.contains("on this turn"), "deciding identifier marked");
    assert!(body.contains("turns_held"), "feature values named");
    assert!(body.contains("0.9700"), "score value");
    assert!(body.contains("wordlist paths"), "proposal reason");
    assert!(body.contains("/ui/llm/7"), "proposal links the exchange");
    assert!(body.contains("llm_proposed"), "labels listed");
    assert!(body.contains("operator v0"), "sticky decision shown");
    // The turn page shows the same turn's columns, tap join and rows.
    let (st, _, body) = h
        .ui(
            "GET",
            "/ui/turns/00000000000000000000000000000005",
            Some(&cookie),
            None,
        )
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("Every stored column"), "{body}");
    assert!(body.contains("Tap join"), "{body}");
    assert!(body.contains("turns_held"), "its feature row");
    let (st, _, _) = h
        .ui("GET", "/ui/turns/does-not-exist", Some(&cookie), None)
        .await;
    assert_eq!(st, 404);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_actor_pages_label_block_unblock() {
    let (h, actor, _) = ui_actor_harness().await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/actors", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains(&actor), "actor listed");
    let (st, _, body) = h
        .ui("GET", &format!("/ui/actors/{actor}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200, "{body}");
    for section in [
        "Bindings",
        "Client",
        "Cluster",
        "Activity",
        "Scores",
        "Labels",
        "Decisions",
        "Similar actors",
        "Turns",
    ] {
        assert!(body.contains(section), "{section} present");
    }
    assert!(body.contains("browser only"), "derived kind");
    let csrf = ui_csrf(&body);
    let window = ui_field(&body, "window_end_ts");
    // A bad verdict is refused; a stale window conflicts.
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/label"),
            Some(&cookie),
            Some(&format!("csrf={csrf}&label=evil&window_end_ts={window}")),
        )
        .await;
    assert_eq!(st, 400);
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/label"),
            Some(&cookie),
            Some(&format!("csrf={csrf}&label=benign&window_end_ts=1")),
        )
        .await;
    assert_eq!(st, 409);
    let (st, headers, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/label"),
            Some(&cookie),
            Some(&format!(
                "csrf={csrf}&label=malicious&note=reviewed&window_end_ts={window}"
            )),
        )
        .await;
    assert_eq!(st, 303);
    assert_eq!(
        ui_header(&headers, "location").unwrap(),
        format!("/ui/actors/{actor}")
    );
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let (label, note): (String, Option<String>) = db
        .query_row(
            "SELECT label, note FROM labels WHERE scope = 'actor' AND scope_id = ?1 AND source = 'operator'",
            [&actor],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (label.as_str(), note.as_deref()),
        ("malicious", Some("reviewed"))
    );
    drop(db);
    let (st, _, body) = h
        .ui("GET", &format!("/ui/actors/{actor}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200);
    assert!(body.contains("reviewed"), "label reflected on reload");
    // Block, then unblock.
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/block"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let rule: String = db
        .query_row(
            "SELECT rule FROM decisions WHERE scope = 'actor' AND key = ?1",
            [&actor],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rule, "operator");
    drop(db);
    let (st, _, body) = h
        .ui("GET", &format!("/ui/actors/{actor}"), Some(&cookie), None)
        .await;
    assert!(body.contains("blocked</span>"), "{body}");
    assert_eq!(st, 200);
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/unblock"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/unblock"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 404, "nothing left to lift");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_cluster_pages_and_labels() {
    let h = ui_harness(Some("op-token")).await;
    let now = now_us();
    for i in 0..6i64 {
        h.event(&v2_event(now + i * 1_000_000, SESSION, "home", "web", None))
            .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let key: String = db
        .query_row("SELECT cluster_key FROM turns LIMIT 1", [], |r| r.get(0))
        .unwrap();
    drop(db);
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/clusters", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains(&key), "cluster listed");
    let (st, _, body) = h
        .ui("GET", &format!("/ui/clusters/{key}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200, "{body}");
    for section in ["Actors", "Activity", "Scores", "Labels", "Turns"] {
        assert!(body.contains(section), "{section} present");
    }
    let csrf = ui_csrf(&body);
    let window = ui_field(&body, "window_end_ts");
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/clusters/{key}/label"),
            Some(&cookie),
            Some(&format!("csrf={csrf}&label=unknown&window_end_ts={window}")),
        )
        .await;
    assert_eq!(st, 303);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let label: String = db
        .query_row(
            "SELECT label FROM labels WHERE scope = 'cluster' AND scope_id = ?1",
            [&key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(label, "unknown");
    drop(db);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_review_decide_writes_the_operator_label() {
    let (h, actor, _) = ui_actor_harness().await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    db.execute(
        "INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3) \
         VALUES ('actor', ?1, 't', 'web', 1, 0.97, '0.1.0', '[]')",
        [&actor],
    )
    .unwrap();
    db.execute(
        "INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, confidence, kind, note, created_at, signals) \
         VALUES ('actor', ?1, 'web', 99, 'malicious', 'llm_proposed', 0.93, NULL, 'wordlist paths [llm_call:7]', 1, '[\"scanner_paths\"]')",
        [&actor],
    )
    .unwrap();
    drop(db);
    let (st, _, body) = h.ui("GET", "/ui/review", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains(&actor), "row queued");
    assert!(body.contains("0.9700"), "why carries the score");
    assert!(body.contains("wordlist paths"), "proposal reason shown");
    let csrf = ui_csrf(&body);
    let window = ui_field(&body, "window_end_ts");
    let (st, headers, _) = h
        .ui(
            "POST",
            "/ui/review/decide",
            Some(&cookie),
            Some(&format!(
                "csrf={csrf}&scope_id={actor}&window_end_ts={window}&verdict=confirm"
            )),
        )
        .await;
    assert_eq!(st, 303);
    assert_eq!(ui_header(&headers, "location"), Some("/ui/review"));
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let (label, note): (String, Option<String>) = db
        .query_row(
            "SELECT label, note FROM labels WHERE scope = 'actor' AND scope_id = ?1 AND source = 'operator'",
            [&actor],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (label.as_str(), note.as_deref()),
        ("malicious", Some("confirmed llm_proposed"))
    );
    drop(db);
    let (st, _, body) = h.ui("GET", "/ui/review", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(
        body.contains("confirmed llm_proposed"),
        "decision reflected on reload"
    );
    // A second verdict appends beside the first; a bad one is refused.
    let (st, _, _) = h
        .ui(
            "POST",
            "/ui/review/decide",
            Some(&cookie),
            Some(&format!(
                "csrf={csrf}&scope_id={actor}&window_end_ts={window}&verdict=benign"
            )),
        )
        .await;
    assert_eq!(st, 303);
    let (st, _, _) = h
        .ui(
            "POST",
            "/ui/review/decide",
            Some(&cookie),
            Some(&format!(
                "csrf={csrf}&scope_id={actor}&window_end_ts={window}&verdict=evil"
            )),
        )
        .await;
    assert_eq!(st, 400);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_step4_pages_render() {
    let h = ui_harness(Some("op-token")).await;
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    for section in [
        "Health",
        "Counts",
        "Today's LLM calls",
        "Latest turns",
        "Latest decisions",
    ] {
        assert!(body.contains(section), "{section} present");
    }
    let (st, _, body) = h.ui("GET", "/ui/review", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("Nothing scored yet"), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/labels", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("No labels under these filters."), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/rules", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("portal-otp-burst"), "install set listed");
    assert!(body.contains("No drafts"), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/model", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("No model loaded"), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/features", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("turns_held"), "{body}");
    assert!(body.contains("distinct user agents minus one"), "{body}");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_rule_disable_lifts_the_rule_from_the_probe_path() {
    let h = ui_harness(Some("op-token")).await;
    h.engine.set_mode(Mode::Enforce).unwrap();
    let rule: Rule = serde_json::from_value(json!({
        "id": "ui-toggle-burst", "note": "t", "mode": "enforce", "action": "block",
        "match": {"route": ["api.ping"], "verb": ["POST"], "principal": "any", "surface": ["api"]},
        "when": {"scope": "peer", "window_s": 60, "count": {}, "gte": 3},
        "origin": {"kind": "operator"}
    }))
    .unwrap();
    h.engine
        .write_rule(rule, State::Active, "operator", None)
        .await
        .unwrap();
    let now = now_us();
    for i in 0..3 {
        h.event(&v2_event(
            now - 10_000_000 + (i as i64) * 1_000_000,
            "1111111111111111",
            "api.ping",
            "api",
            None,
        ))
        .await;
    }
    h.wait_for("3 peer turns", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 3
    })
    .await;
    let v = h
        .probe(&v2_probe(now, "api.ping", "1111111111111111", "api", None))
        .await;
    assert_eq!(v["action"], "block", "rule trips first: {v}");
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (_, _, body) = h.ui("GET", "/ui/rules", Some(&cookie), None).await;
    let csrf = ui_csrf(&body);
    assert!(body.contains("ui-toggle-burst"), "{body}");
    // Disable: the page, the compiled set, and the probe path agree.
    let (st, _, _) = h
        .ui(
            "POST",
            "/ui/rules/ui-toggle-burst/disable",
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    let (st, _, body) = h.ui("GET", "/ui/rules", Some(&cookie), None).await;
    assert_eq!(st, 200);
    assert!(body.contains("disabled</span>"), "{body}");
    assert!(!h
        .engine
        .rules
        .loaded()
        .iter()
        .any(|(r, _)| r.id == "ui-toggle-burst"));
    for i in 0..3 {
        h.event(&v2_event(
            now + (i as i64) * 1_000_000,
            "3333333333333333",
            "api.ping",
            "api",
            None,
        ))
        .await;
    }
    h.wait_for("6 events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    let v = h
        .probe(&v2_probe(now, "api.ping", "3333333333333333", "api", None))
        .await;
    assert_eq!(v["action"], "allow", "disabled rule stays silent: {v}");
    // Every change is an audit row.
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let (enabled, by): (i64, String) = db
        .query_row(
            "SELECT enabled, by FROM rule_state_audit WHERE rule_id = 'ui-toggle-burst'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((enabled, by.as_str()), (0, "console"));
    drop(db);
    // Re-enable: the rule is back on the probe path.
    let (st, _, _) = h
        .ui(
            "POST",
            "/ui/rules/ui-toggle-burst/enable",
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    assert!(h
        .engine
        .rules
        .loaded()
        .iter()
        .any(|(r, _)| r.id == "ui-toggle-burst"));
    let v = h
        .probe(&v2_probe(now, "api.ping", "3333333333333333", "api", None))
        .await;
    assert_eq!(v["action"], "block", "re-enabled rule trips: {v}");
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let n: i64 = db
        .query_row(
            "SELECT count(*) FROM rule_state_audit WHERE rule_id = 'ui-toggle-burst'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 2);
    drop(db);
    let (st, _, _) = h
        .ui(
            "POST",
            "/ui/rules/no-such-rule/disable",
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 404);
    h.running.abort();
    h.engine.shutdown().await;
}

/// The LLM-output tables have no writer op (the drain writes them
/// directly), so the inspector tests seed through a second
/// connection; the busy timeout covers the writer's lock.
fn ui_seed(h: &Harness, sql: &str) {
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    db.execute_batch(sql).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_actor_explanation_renders_with_its_turn() {
    let (h, actor, _) = ui_actor_harness().await;
    ui_seed(
        &h,
        "INSERT INTO scores (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3, \
         explanation) VALUES ('actor', (SELECT actor_id FROM turns WHERE turn_id = \
         '00000000000000000000000000000005'), '00000000000000000000000000000005', 'web', 3000000, \
         0.91, '0.1.0', '[]', 'Wordlist paths at machine cadence, no assets fetched.')",
    );
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h
        .ui("GET", &format!("/ui/actors/{actor}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(
        body.contains("Wordlist paths at machine cadence, no assets fetched."),
        "{body}"
    );
    assert!(
        body.contains("/ui/turns/00000000000000000000000000000005"),
        "{body}"
    );
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_rules_drafts_render_verbatim() {
    let h = ui_harness(Some("op-token")).await;
    ui_seed(
        &h,
        "INSERT INTO rule_drafts (cluster_key, rule, reason, parse_ok, parse_error, call_id, \
         status, created_at) VALUES ('cc', '{\"id\":\"draft-burst\"}', 'Three scanners, one shape.', \
         1, NULL, NULL, 'pending', 1700000000)",
    );
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/rules", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("draft-burst"), "{body}");
    assert!(body.contains("Three scanners, one shape."), "{body}");
    assert!(body.contains("parses</span>"), "{body}");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_payloads_list_and_detail() {
    let h = ui_harness(Some("op-token")).await;
    ui_seed(
        &h,
        "INSERT INTO payload_patterns (pattern_hash, method, pattern, first_seen_s, last_seen_s, \
         turns) VALUES ('ph', 'GET', '/venues/{id}', 1700000000, 1700000600, 3); \
         INSERT INTO payload_classes (pattern_hash, category, confidence, call_id, created_at) \
         VALUES ('ph', 'enumeration', 0.8, NULL, 1700000600)",
    );
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h.ui("GET", "/ui/payloads", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("/venues/{id}"), "{body}");
    assert!(body.contains("enumeration"), "{body}");
    let (st, _, body) = h.ui("GET", "/ui/payloads/ph", Some(&cookie), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("enumeration"), "{body}");
    assert!(body.contains("0.80"), "{body}");
    let (st, _, _) = h.ui("GET", "/ui/payloads/nope", Some(&cookie), None).await;
    assert_eq!(st, 404);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classify_first_sight_upserts_pattern_and_job() {
    let h = ui_llm_harness(Some("op-token")).await;
    let now = now_us();
    h.event(&v2_event(now, SESSION, "venues.show", "web", None))
        .await;
    let mut v: Value = serde_json::from_str(&v2_event(
        now + 1_000_000,
        "b1b2c3d4e5f60719",
        "_unrouted",
        "web",
        None,
    ))
    .unwrap();
    v["status"] = json!(404);
    v["path"] = json!("/venues/42");
    v["sample_query"] = json!("page=2");
    v["body_slice"] = json!("{}");
    h.event(&v.to_string()).await;
    h.wait_for("two events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 2
    })
    .await;
    h.engine.store.flush().await;
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let mut patterns: Vec<(String, String, i64)> = db
        .prepare("SELECT pattern, method, turns FROM payload_patterns")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    patterns.sort();
    assert_eq!(
        patterns,
        vec![
            ("/venues/{id}".to_string(), "POST".to_string(), 1),
            ("venues.show".to_string(), "POST".to_string(), 1),
        ]
    );
    let sample: Option<String> = db
        .query_row(
            "SELECT sample_query FROM payload_patterns WHERE pattern = '/venues/{id}'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sample.as_deref(), Some("page=2"));
    let jobs: i64 = db
        .query_row(
            "SELECT count(*) FROM llm_jobs WHERE point = 'classify'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 2);
    // Nothing per turn: the samples leave no column on `turns`.
    let sql: String = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'turns'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!sql.contains("sample_query"), "{sql}");
    drop(db);
    // Second sight: the counters bump, no new job.
    h.event(&v2_event(
        now + 2_000_000,
        SESSION,
        "venues.show",
        "web",
        None,
    ))
    .await;
    h.wait_for("three events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 3
    })
    .await;
    h.engine.store.flush().await;
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let turns: i64 = db
        .query_row(
            "SELECT turns FROM payload_patterns WHERE pattern = 'venues.show'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(turns, 2);
    let jobs: i64 = db
        .query_row(
            "SELECT count(*) FROM llm_jobs WHERE point = 'classify'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 2);
    drop(db);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explain_crossing_and_swing_enqueue() {
    use leesided::store::{ScoreRow, StoreOp};
    let h = ui_llm_harness(Some("op-token")).await;
    let score = |id: &str, turn: &str, p: f64| {
        StoreOp::Score(ScoreRow {
            scope: "actor".to_string(),
            scope_id: id.to_string(),
            turn_id: turn.to_string(),
            surface: Some("web".to_string()),
            ts_us: 1_700_000_000_000_000,
            score: p,
            model_version: "0.1.0".to_string(),
            top3: "[]".to_string(),
            threshold: Some(0.5),
            daily_calls: 500,
            daily_tokens: 500_000,
        })
    };
    // First sight above the threshold crosses.
    h.engine.store.send(score("aa", "t1", 0.9));
    // Below first: nothing; then above: crossed.
    h.engine.store.send(score("bb", "t1", 0.4));
    h.engine.store.flush().await;
    h.engine.store.send(score("bb", "t2", 0.9));
    // A repeat near the last score: the cooldown holds.
    h.engine.store.send(score("aa", "t2", 0.92));
    h.engine.store.flush().await;
    let jobs: Vec<String> = h
        .engine
        .store
        .with_reader(|c| {
            let mut stmt = c
                .prepare("SELECT subject_id FROM llm_jobs WHERE point = 'explain' ORDER BY id")
                .unwrap();
            Ok(stmt
                .query_map([], |r| r.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect::<Vec<String>>())
        })
        .unwrap();
    assert_eq!(jobs, vec!["aa".to_string(), "bb".to_string()]);
    // A swing above 0.2 past the cooldown asks again.
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    db.execute(
        "UPDATE llm_jobs SET status = 'done', updated_at = updated_at - 7200 \
         WHERE point = 'explain' AND subject_id = 'aa'",
        [],
    )
    .unwrap();
    drop(db);
    h.engine.store.send(score("aa", "t3", 0.5));
    h.engine.store.flush().await;
    let n: i64 = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM llm_jobs WHERE point = 'explain' AND subject_id = 'aa'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(n, 2);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_fifth_operator_label_enqueues() {
    use leesided::store::{LabelRow, StoreOp};
    let h = ui_llm_harness(Some("op-token")).await;
    let now = leesided::store::now_s();
    for i in 0..5i64 {
        h.engine.store.send(StoreOp::Label(LabelRow {
            scope: "cluster",
            scope_id: "cc".to_string(),
            surface: Some("web".to_string()),
            window_end_ts: 3_000_000 + i,
            label: "malicious",
            source: "operator",
            confidence: 1.0,
            kind: None,
            note: None,
            created_at: now,
            signals: None,
            daily_calls: 500,
            daily_tokens: 500_000,
        }));
    }
    h.engine.store.flush().await;
    let job: (String, String, String) = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row("SELECT point, scope, subject_id FROM llm_jobs", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
        })
        .unwrap();
    assert_eq!(job.0, "draft");
    assert_eq!(job.1, "cluster");
    assert_eq!(job.2, "cc");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_actor_labels_resolve_the_cluster() {
    use leesided::store::{LabelRow, StoreOp};
    let (h, actor, _) = ui_actor_harness().await;
    ui_seed(
        &h,
        &format!("UPDATE turns SET cluster_key = 'cc9' WHERE actor_id = '{actor}'"),
    );
    let now = leesided::store::now_s();
    for i in 0..5i64 {
        h.engine.store.send(StoreOp::Label(LabelRow {
            scope: "actor",
            scope_id: actor.clone(),
            surface: Some("web".to_string()),
            window_end_ts: 3_000_000 + i,
            label: "malicious",
            source: "operator",
            confidence: 1.0,
            kind: None,
            note: None,
            created_at: now,
            signals: None,
            daily_calls: 500,
            daily_tokens: 500_000,
        }));
    }
    h.engine.store.flush().await;
    let subject: String = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT subject_id FROM llm_jobs WHERE point = 'draft'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(subject, "cc9");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_buttons_queue_one_job() {
    let h = ui_llm_harness(Some("op-token")).await;
    let now = now_us();
    for i in 0..6i64 {
        h.event(&v2_event(now + i * 1_000_000, SESSION, "home", "web", None))
            .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let (key, actor): (String, String) = db
        .query_row("SELECT cluster_key, actor_id FROM turns LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    drop(db);
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h
        .ui("GET", &format!("/ui/clusters/{key}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("Draft a rule"), "button present");
    let csrf = ui_csrf(&body);
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/clusters/{key}/draft"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    // The actor button resolves the same cluster; the guard dedups.
    let (st, _, body) = h
        .ui("GET", &format!("/ui/actors/{actor}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("Draft a rule"), "actor button present");
    let csrf = ui_csrf(&body);
    let (st, _, _) = h
        .ui(
            "POST",
            &format!("/ui/actors/{actor}/draft"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 303);
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let jobs: Vec<(String, String)> = db
        .prepare("SELECT point, subject_id FROM llm_jobs WHERE point = 'draft'")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert_eq!(jobs, vec![("draft".to_string(), key.clone())]);
    drop(db);
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_button_is_unavailable_unconfigured() {
    let h = ui_harness(Some("op-token")).await;
    let now = now_us();
    for i in 0..6i64 {
        h.event(&v2_event(now + i * 1_000_000, SESSION, "home", "web", None))
            .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    let db = rusqlite::Connection::open(h.dir.join("leesided.sqlite")).unwrap();
    let key: String = db
        .query_row("SELECT cluster_key FROM turns LIMIT 1", [], |r| r.get(0))
        .unwrap();
    drop(db);
    let (_, headers, _) = h.ui_login("op-token").await;
    let cookie = ui_cookie(&headers);
    let (st, _, body) = h
        .ui("GET", &format!("/ui/clusters/{key}"), Some(&cookie), None)
        .await;
    assert_eq!(st, 200, "{body}");
    let csrf = ui_csrf(&body);
    let (st, _, body) = h
        .ui(
            "POST",
            &format!("/ui/clusters/{key}/draft"),
            Some(&cookie),
            Some(&format!("csrf={csrf}")),
        )
        .await;
    assert_eq!(st, 503, "{body}");
    h.running.abort();
    h.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_malicious_verdict_enqueues_draft() {
    use leesided::config::WindsideMode;
    use std::io::Cursor;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("leesided-it-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("windside-model");
    Harness::shadow_model(&model);
    let h = Harness::open_windside(dir, Some(model), WindsideMode::Shadow).await;
    let now = now_us();
    for i in 0..6i64 {
        h.event(&tagged_event(
            now + i * 1_000_000,
            &format!("{i:032x}"),
            SESSION,
            "anon",
            TAG,
            "home",
        ))
        .await;
    }
    h.wait_for("six events", || {
        h.engine.counters.events.load(Ordering::Relaxed) == 6
    })
    .await;
    h.engine.store.flush().await;
    // Four operator malicious already; the review writes the fifth.
    // The env carries the LLM config only for this call: no other test
    // reads it, and a leak would only enqueue label jobs elsewhere.
    ui_seed(
        &h,
        "UPDATE turns SET cluster_key = 'cc7'; \
         INSERT INTO labels (scope, scope_id, surface, window_end_ts, label, source, \
         confidence, kind, note, created_at) \
         SELECT 'actor', actor_id, 'web', 3000000, 'malicious', 'operator', 1.0, NULL, \
         't', strftime('%s', 'now') FROM (SELECT DISTINCT actor_id FROM turns \
         WHERE actor_id IS NOT NULL) \
         CROSS JOIN (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4);",
    );
    std::env::set_var("LEESIDED_LLM_URL", "http://127.0.0.1:9");
    std::env::set_var("LEESIDED_LLM_KEY", "test");
    std::env::set_var("LEESIDED_LLM_MODE", "dry");
    let mut out = Vec::new();
    let labeled = leesided::review::run_review(
        &h.dir.join("leesided.sqlite"),
        20,
        &mut Cursor::new("m\n"),
        &mut out,
    )
    .unwrap();
    std::env::remove_var("LEESIDED_LLM_URL");
    std::env::remove_var("LEESIDED_LLM_KEY");
    std::env::remove_var("LEESIDED_LLM_MODE");
    assert_eq!(labeled, 1);
    let subject: String = h
        .engine
        .store
        .with_reader(|c| {
            c.query_row(
                "SELECT subject_id FROM llm_jobs WHERE point = 'draft'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(subject, "cc7");
    h.running.abort();
    h.engine.shutdown().await;
}
