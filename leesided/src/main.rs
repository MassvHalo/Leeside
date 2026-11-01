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
        _ => {
            eprintln!(
                "usage: leesided [serve | rules schema | rules validate <file> | rules export | tap [--probe] [--iface X] [--ports 80,443] [--tls-ports 443] [--sock PATH] | label-import <manifest> | export --since <unix_s> --run-id <id> --out <csv> | report shadow --since <unix_s>]"
            );
            std::process::exit(2);
        }
    }
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
