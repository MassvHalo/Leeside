use leesided::config::Config;
use leesided::engine::{serve, Engine};
use leesided::rules::model::Rule;
use leesided::store::now_s;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    if words.iter().any(|w| *w == "--help" || *w == "-h") {
        print_help(&words);
        return;
    }
    match words.as_slice() {
        [] | ["serve"] => run_serve(),
        ["rules", "schema"] => println!("{}", leesided::rules::schema::rule_schema_json()),
        ["rules", "validate", path] => {
            let text = std::fs::read_to_string(path).expect("read rule file");
            match Rule::parse(&text, now_s()) {
                Ok(_) => println!("ok"),
                Err(errors) => {
                    for e in &errors {
                        println!("{e}");
                    }
                    std::process::exit(1);
                }
            }
        }
        ["rules", "export"] => run_export(),
        ["tap", rest @ ..] => run_tap(rest),
        ["label-import", path] => run_label_import(path),
        ["export", rest @ ..] => run_export_data(rest),
        ["report", "shadow", rest @ ..] => run_report_shadow(rest),
        ["review", rest @ ..] => run_review(rest),
        ["llm", "show", rest @ ..] => run_llm_show(rest),
        ["llm", "send", rest @ ..] => run_llm_send(rest),
        ["llm", "subjects", rest @ ..] => run_llm_subjects(rest),
        ["llm", "drain"] => run_llm_drain(),
        _ => {
            eprintln!("{FULL_USAGE}");
            std::process::exit(2);
        }
    }
}

const FULL_USAGE: &str = "usage: leesided [serve | rules schema | rules validate <file> | rules export | tap [--probe] [--iface X] [--ports 80,443] [--tls-ports 443] [--sock PATH] | label-import <manifest> | export --since <unix_s> --run-id <id> --out <csv> | report shadow --since <unix_s> | review [--top <n>] | llm show --point <point> --subject <scope>:<id> | llm send --point <point> --subject <scope>:<id> | llm subjects [--scope actor|cluster] [--top <n>] | llm drain]";

/// Every subcommand answers `--help` (or `-h`) with its usage line.
fn print_help(words: &[&str]) {
    let line = match words {
        ["serve", ..] => "usage: leesided serve (config from LEESIDED_* env; LEESIDED_DB, LEESIDED_API, LEESIDED_RULES_DIR)",
        ["rules", ..] => "usage: leesided rules schema | rules validate <file> | rules export",
        ["tap", ..] => "usage: leesided tap [--probe] [--iface X] [--ports 80,443] [--tls-ports 443] [--sock PATH]",
        ["label-import", ..] => "usage: leesided label-import <manifest>",
        ["export", ..] => "usage: leesided export --since <unix_s> --run-id <id> --out <csv>",
        ["report", ..] => "usage: leesided report shadow --since <unix_s>",
        ["review", ..] => "usage: leesided review [--top <n>]",
        ["llm", "show", ..] => "usage: leesided llm show --point label|explain|classify|draft --subject <actor|cluster|pattern>:<id>",
        ["llm", "send", ..] => "usage: leesided llm send --point label|explain|classify|draft --subject <actor|cluster|pattern>:<id>",
        ["llm", "subjects", ..] => {
            "usage: leesided llm subjects [--scope actor|cluster] [--top <n>]"
        }
        ["llm", "drain", ..] => "usage: leesided llm drain (drains the queued jobs in LEESIDED_LLM_MODE)",
        ["llm", ..] => "usage: leesided llm show --point <point> --subject <scope>:<id> | llm send --point <point> --subject <scope>:<id> | llm subjects [--scope actor|cluster] [--top <n>] | llm drain",
        _ => FULL_USAGE,
    };
    println!("{line}");
}

/// The passive fingerprint tap (docs/tap.md): its own process, needs
/// CAP_NET_RAW. Env gives the defaults, flags override.
fn run_tap(args: &[&str]) {
    use leesided::tap::capture::{self, TapConfig};
    let socket_dir = std::env::var("LEESIDED_SOCKET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Config::default().socket_dir);
    let mut cfg = TapConfig::from_env(&socket_dir);
    let mut probe = false;
    let mut it = args.iter();
    let ports =
        |v: &str| -> Vec<u16> { v.split(',').filter_map(|p| p.trim().parse().ok()).collect() };
    while let Some(a) = it.next() {
        if *a == "--probe" {
            probe = true;
            continue;
        }
        let Some(v) = it.next() else {
            eprintln!("leesided tap: {a} needs a value");
            std::process::exit(2);
        };
        match *a {
            "--iface" => cfg.iface = Some(v.to_string()),
            "--ports" => cfg.ports = ports(v),
            "--tls-ports" => cfg.tls_ports = ports(v),
            "--sock" => cfg.sock = std::path::PathBuf::from(v),
            _ => {
                eprintln!("leesided tap: bad argument {a}");
                std::process::exit(2);
            }
        }
    }
    if probe {
        match capture::probe() {
            Ok(()) => println!("ok: this process may capture"),
            Err(e) => {
                eprintln!("cannot capture: {e} (needs CAP_NET_RAW: sudo setcap cap_net_raw+ep <binary>, or root)");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Err(e) = capture::run(cfg) {
        eprintln!("leesided tap: {e}");
        std::process::exit(1);
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn run_serve() {
    runtime().block_on(async {
        let cfg = Config::from_env();
        let engine = Engine::open(cfg).await.unwrap_or_else(|e| {
            eprintln!("leesided: {e}");
            std::process::exit(1);
        });
        // Live probes the wire settings once at start-up; dry sends
        // nothing, so its settings stay unprobed until a live drain.
        if let Some(exec) = engine.llm.exec.clone() {
            if exec.mode == leesided::config::LlmMode::Live {
                let inner = engine.clone();
                let probed = tokio::task::spawn_blocking(move || {
                    leesided::llm::probe(&exec.url, &exec.key, &exec.model)
                })
                .await
                .expect("probe thread")
                .map_err(|e| e.to_string());
                match probed {
                    Ok(o) => {
                        tracing::info!(
                            json_mode = o.json_mode.as_str(),
                            effort = o.effort,
                            "llm endpoint probed"
                        );
                        *inner.llm.json_mode.write() = Some(o.json_mode);
                        *inner.llm.effort_supported.write() = Some(o.effort);
                    }
                    Err(e) => tracing::warn!("llm probe failed ({e}); the worker retries"),
                }
            }
        }
        let running = serve(engine.clone()).await.unwrap_or_else(|e| {
            eprintln!("leesided: {e}");
            std::process::exit(1);
        });
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        running.abort();
        engine.shutdown().await;
    });
}

fn run_label_import(path: &str) {
    let cfg = Config::from_env();
    let Some(key) = cfg.hash_key.as_deref() else {
        eprintln!(
            "leesided label-import: LEESIDED_HASH_KEY must be set (labels join on the hashed source address)"
        );
        std::process::exit(1);
    };
    match leesided::labels::import(&cfg.db, std::path::Path::new(path), key) {
        Ok(s) => println!(
            "labels: {} (actor {}, cluster {})",
            s.total(),
            s.actor,
            s.cluster
        ),
        Err(e) => {
            eprintln!("leesided label-import: {e}");
            std::process::exit(1);
        }
    }
}

fn run_export_data(args: &[&str]) {
    let mut since_s: i64 = 0;
    let mut run_id: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--since" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided export: --since needs a value");
                    std::process::exit(2);
                };
                since_s = v.parse().unwrap_or_else(|_| {
                    eprintln!("leesided export: --since is unix seconds, not {v}");
                    std::process::exit(2);
                });
            }
            "--run-id" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided export: --run-id needs a value");
                    std::process::exit(2);
                };
                run_id = Some(v);
            }
            "--out" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided export: --out needs a value");
                    std::process::exit(2);
                };
                out = Some(v);
            }
            _ => {
                eprintln!("leesided export: bad argument {a}");
                std::process::exit(2);
            }
        }
    }
    let (Some(out), Some(run_id)) = (out, run_id) else {
        eprintln!("leesided export: --run-id <id> and --out <csv> are required");
        std::process::exit(2);
    };
    let cfg = Config::from_env();
    match leesided::export::export(&cfg.db, since_s, run_id, std::path::Path::new(out)) {
        Ok(s) => println!(
            "export: {} rows (actor {}, cluster {}) -> {out}",
            s.rows, s.actor, s.cluster
        ),
        Err(e) => {
            eprintln!("leesided export: {e}");
            std::process::exit(1);
        }
    }
}

fn run_report_shadow(args: &[&str]) {
    let mut since_s: i64 = 0;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--since" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided report: --since needs a value");
                    std::process::exit(2);
                };
                since_s = v.parse().unwrap_or_else(|_| {
                    eprintln!("leesided report: --since is unix seconds, not {v}");
                    std::process::exit(2);
                });
            }
            _ => {
                eprintln!("leesided report: bad argument {a}");
                std::process::exit(2);
            }
        }
    }
    let cfg = Config::from_env();
    match leesided::report::shadow(&cfg.db, cfg.windside_model.as_deref(), since_s) {
        Ok(r) => println!("{r}"),
        Err(e) => {
            eprintln!("leesided report: {e}");
            std::process::exit(1);
        }
    }
}

fn run_llm_subjects(args: &[&str]) {
    let mut top: usize = 20;
    let mut scope: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--top" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided llm subjects: --top needs a value");
                    std::process::exit(2);
                };
                top = v.parse().unwrap_or_else(|_| {
                    eprintln!("leesided llm subjects: --top is a row count, not {v}");
                    std::process::exit(2);
                });
            }
            "--scope" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided llm subjects: --scope needs a value");
                    std::process::exit(2);
                };
                if *v != "actor" && *v != "cluster" {
                    eprintln!("leesided llm subjects: --scope is actor or cluster, not {v}");
                    std::process::exit(2);
                }
                scope = Some(v.to_string());
            }
            _ => {
                eprintln!("leesided llm subjects: bad argument {a}");
                std::process::exit(2);
            }
        }
    }
    let cfg = Config::from_env();
    match leesided::llm::subjects(&cfg.db, scope.as_deref(), top) {
        Ok(rows) => {
            let head = ["scope", "id", "rows", "score", "proposal"];
            println!(
                "{:<8} {:<16} {:>6} {:>8}  {}",
                head[0], head[1], head[2], head[3], head[4]
            );
            for r in rows {
                println!(
                    "{:<8} {:<16} {:>6} {:>8}  {}",
                    r.scope,
                    r.id,
                    r.rows,
                    r.score
                        .map(|s| format!("{s:.4}"))
                        .unwrap_or_else(|| "-".to_string()),
                    if r.proposal_pending { "pending" } else { "-" },
                );
            }
        }
        Err(e) => {
            eprintln!("leesided llm subjects: {e}");
            std::process::exit(1);
        }
    }
}

fn run_review(args: &[&str]) {
    let mut top: usize = 20;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--top" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided review: --top needs a value");
                    std::process::exit(2);
                };
                top = v.parse().unwrap_or_else(|_| {
                    eprintln!("leesided review: --top is a row count, not {v}");
                    std::process::exit(2);
                });
            }
            _ => {
                eprintln!("leesided review: bad argument {a}");
                std::process::exit(2);
            }
        }
    }
    let cfg = Config::from_env();
    let stdin = std::io::stdin();
    let mut input = std::io::BufReader::new(stdin.lock());
    let mut output = std::io::stdout();
    match leesided::review::run_review(&cfg.db, top, &mut input, &mut output) {
        Ok(n) => {
            println!("review: {n} labeled");
        }
        Err(e) => {
            eprintln!("leesided review: {e}");
            std::process::exit(1);
        }
    }
}

fn llm_args(args: &[&str], cmd: &str) -> (String, String) {
    let mut point: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--point" | "--subject" => {
                let Some(v) = it.next() else {
                    eprintln!("leesided llm {cmd}: {a} needs a value");
                    std::process::exit(2);
                };
                if *a == "--point" {
                    point = Some(v.to_string());
                } else {
                    subject = Some(v.to_string());
                }
            }
            _ => {
                eprintln!("leesided llm {cmd}: bad argument {a}");
                std::process::exit(2);
            }
        }
    }
    match (point, subject) {
        (Some(p), Some(s)) => (p, s),
        _ => {
            eprintln!(
                "leesided llm {cmd}: --point label|explain|classify|draft --subject <actor|cluster|pattern>:<id> required"
            );
            std::process::exit(2);
        }
    }
}

/// Drain the queued jobs the way the daemon's worker tick does, in
/// the configured mode: in dry this logs the full request for every
/// queued job and sends nothing.
fn run_llm_drain() {
    let cfg = Config::from_env();
    let Some(exec) = leesided::llm::Exec::from_config(&cfg) else {
        eprintln!(
            "leesided llm drain: LLM is not configured (LEESIDED_LLM_URL and LEESIDED_LLM_KEY)"
        );
        std::process::exit(2);
    };
    let classes = leesided::tap::classes::Ja4Classes::load(cfg.ja4_classes.as_deref());
    let thresholds = llm_thresholds(&cfg);
    let mut settled = leesided::llm::DrainMode {
        json: None,
        effort: None,
    };
    for _ in 0..25 {
        let ctx = leesided::llm::DrainCtx {
            exec: exec.clone(),
            json_mode: settled.json,
            effort_supported: settled.effort,
            classes: classes.clone(),
            thresholds: thresholds.clone(),
        };
        match leesided::llm::drain_once(&cfg.db, &ctx) {
            Ok((leesided::llm::DrainOutcome::Empty, _)) => break,
            Ok((out, mode)) => {
                settled = mode;
                match out {
                    leesided::llm::DrainOutcome::Done { job } => {
                        println!("drain: job {job} done");
                    }
                    leesided::llm::DrainOutcome::Deferred { job, why } => {
                        println!("drain: job {job} deferred ({why})");
                    }
                    leesided::llm::DrainOutcome::Failed { job, why } => {
                        println!("drain: job {job} failed ({why})");
                    }
                    leesided::llm::DrainOutcome::Empty => {}
                }
            }
            Err(e) => {
                eprintln!("leesided llm drain: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn llm_thresholds(cfg: &Config) -> std::collections::HashMap<String, f64> {
    let Some(dir) = cfg.windside_model.as_deref() else {
        return std::collections::HashMap::new();
    };
    match leesided::windside::load_manifest(dir) {
        Ok(m) => m.thresholds,
        Err(e) => {
            eprintln!("leesided llm: model unreadable ({e}); threshold stays null");
            std::collections::HashMap::new()
        }
    }
}

fn run_llm_show(args: &[&str]) {
    let cfg = Config::from_env();
    let (point, subject) = llm_args(args, "show");
    if !["label", "explain", "classify", "draft"].contains(&point.as_str()) {
        eprintln!(
            "leesided llm show: unknown point `{point}` (built: label explain classify draft)"
        );
        std::process::exit(2);
    }
    let subject = leesided::llm::parse_subject(&subject).unwrap_or_else(|e| {
        eprintln!("leesided llm show: {e}");
        std::process::exit(2);
    });
    let classes = leesided::tap::classes::Ja4Classes::load(cfg.ja4_classes.as_deref());
    match leesided::llm::show_point(
        &cfg.db,
        &cfg.llm_model,
        &classes,
        &llm_thresholds(&cfg),
        &point,
        &subject,
    ) {
        Ok(request) => println!("{}", serde_json::to_string_pretty(&request).expect("json")),
        Err(e) => {
            eprintln!("leesided llm show: {e}");
            std::process::exit(1);
        }
    }
}

fn run_llm_send(args: &[&str]) {
    let cfg = Config::from_env();
    let (point, subject) = llm_args(args, "send");
    if !["label", "explain", "classify", "draft"].contains(&point.as_str()) {
        eprintln!(
            "leesided llm send: unknown point `{point}` (built: label explain classify draft)"
        );
        std::process::exit(2);
    }
    let subject = leesided::llm::parse_subject(&subject).unwrap_or_else(|e| {
        eprintln!("leesided llm send: {e}");
        std::process::exit(2);
    });
    let (Some(url), Some(key)) = (cfg.llm_url.clone(), cfg.llm_key.clone()) else {
        eprintln!("leesided llm send: LEESIDED_LLM_URL and LEESIDED_LLM_KEY are required");
        std::process::exit(2);
    };
    let exec = leesided::llm::Exec {
        url: url.clone(),
        key: key.clone(),
        model: cfg.llm_model.clone(),
        model_overrides: leesided::llm::Exec::overrides_from_config(&cfg),
        mode: leesided::config::LlmMode::Live,
        daily_calls: cfg.llm_daily_calls,
        daily_tokens: cfg.llm_daily_tokens,
    };
    // The worker's wire settings, so the send matches live: prompt
    // mode needs no probe, but `reasoning_effort` does.
    let effort = match leesided::llm::probe(&url, &key, &exec.model) {
        Ok(o) => {
            eprintln!(
                "probe: json_mode={} effort={}",
                o.json_mode.as_str(),
                o.effort
            );
            if o.effort {
                leesided::llm::effort_for(&point).ok()
            } else {
                None
            }
        }
        Err(e) => {
            eprintln!("probe failed ({e}); sending without reasoning_effort");
            None
        }
    };
    let classes = leesided::tap::classes::Ja4Classes::load(cfg.ja4_classes.as_deref());
    match leesided::llm::send_point(
        &cfg.db,
        &exec,
        &classes,
        &llm_thresholds(&cfg),
        &point,
        &subject,
        effort,
        None,
    ) {
        Ok(out) => {
            for (i, raw) in out.raws.iter().enumerate() {
                println!("--- raw response {} ---\n{raw}", i + 1);
            }
            match out.parsed {
                Some(p) => {
                    let v: serde_json::Value = serde_json::from_str(&p).expect("parsed json");
                    println!(
                        "--- parsed ---\n{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "point": point,
                            "call_id": out.call_id,
                            "parsed": v,
                        }))
                        .expect("json")
                    );
                }
                None => println!("--- parsed ---\nnone"),
            }
        }
        Err(e) => {
            eprintln!("leesided llm send: {e}");
            std::process::exit(1);
        }
    }
}

fn run_export() {
    runtime().block_on(async {
        let cfg = Config::from_env();
        let engine = Engine::open(cfg).await.unwrap_or_else(|e| {
            eprintln!("leesided: {e}");
            std::process::exit(1);
        });
        let rules: Vec<Rule> = engine
            .rules
            .loaded()
            .into_iter()
            .filter(|(_, m)| m.state == leesided::rules::compile::State::Active)
            .map(|(r, _)| r)
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rules).expect("serialise")
        );
        engine.shutdown().await;
    });
}
