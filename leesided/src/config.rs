//! Environment configuration, read once at start. See docs/rules.md.

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// Holds `events.sock` (datagram) and `check.sock` (stream).
    pub socket_dir: PathBuf,
    pub db: PathBuf,
    pub api: SocketAddr,
    /// `false` pins the global mode to monitor.
    pub enforce: bool,
    /// The install set, imported when the `rules` table is empty.
    pub rules_dir: PathBuf,
    /// Permission bits on both sockets; PHP-FPM must be able to connect and write.
    pub socket_mode: u32,
    /// Numeric group to chown the sockets to (www-data on the sample host), when set.
    pub socket_gid: Option<u32>,
    /// When set, every API route but `/health` needs `Authorization: Bearer <token>`.
    pub api_token: Option<String>,
    /// The package's `LEESIDE_HASH_KEY`, so `ip_hash`/`net_hash` join with its values.
    pub hash_key: Option<String>,
    /// GeoLite2-ASN.mmdb and GeoLite2-Country.mmdb for enrichment; unset or missing leaves asn and country null.
    pub geoip_asn: Option<PathBuf>,
    pub geoip_country: Option<PathBuf>,
    /// `data/ja4-classes.json`: JA4 to browser/library, for `ua_vs_ja4_mismatch` (docs/tap.md).
    pub ja4_classes: Option<PathBuf>,
    /// Route names that are honeytokens (docs/windside.md section 3): a hit
    /// labels the actor's windows malicious for the following hour.
    pub honeytoken_routes: Vec<String>,
    /// App-defined route names that count as completed business actions:
    /// with a verified credential and a sub-400 status they label the
    /// actor's window benign (`verified_business`).
    pub business_routes: Vec<String>,
    /// Model directory (`manifest.json` + `model.txt`): scored at
    /// start-up when set, refused when its `features_version` differs.
    pub windside_model: Option<PathBuf>,
    /// `off`, `shadow` or `active` (docs/windside.md section 6).
    pub windside_mode: WindsideMode,
    /// Any OpenAI-compatible Chat Completions base URL (docs/llm.md
    /// section 4); absent disables every LLM worker.
    pub llm_url: Option<String>,
    pub llm_key: Option<String>,
    pub llm_model: String,
    /// `off`, `dry` or `live` (default `off`). Dry builds the full
    /// request and logs it with a null response; live sends.
    pub llm_mode: LlmMode,
    /// Per-point daily budgets in calls and tokens.
    pub llm_daily_calls: u32,
    pub llm_daily_tokens: u32,
}

/// What the loaded model may do. Shadow writes scores and changes no
/// decision; only active lets score rules fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindsideMode {
    #[default]
    Off,
    Shadow,
    Active,
}

impl WindsideMode {
    pub fn parse(s: &str) -> Option<WindsideMode> {
        match s {
            "off" => Some(WindsideMode::Off),
            "shadow" => Some(WindsideMode::Shadow),
            "active" => Some(WindsideMode::Active),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WindsideMode::Off => "off",
            WindsideMode::Shadow => "shadow",
            WindsideMode::Active => "active",
        }
    }
}

/// What the LLM workers may do. Dry builds the full request and logs it
/// with a null response; only live sends. Default off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LlmMode {
    #[default]
    Off,
    Dry,
    Live,
}

impl LlmMode {
    pub fn parse(s: &str) -> Option<LlmMode> {
        match s {
            "off" => Some(LlmMode::Off),
            "dry" => Some(LlmMode::Dry),
            "live" => Some(LlmMode::Live),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LlmMode::Off => "off",
            LlmMode::Dry => "dry",
            LlmMode::Live => "live",
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket_dir: PathBuf::from("/run/leeside"),
            db: PathBuf::from("/var/lib/leeside/leesided.sqlite"),
            api: "127.0.0.1:7390".parse().expect("static addr"),
            enforce: true,
            rules_dir: default_rules_dir(),
            socket_mode: 0o660,
            socket_gid: None,
            api_token: None,
            hash_key: None,
            geoip_asn: None,
            geoip_country: None,
            ja4_classes: Some(default_ja4_classes()),
            honeytoken_routes: Vec::new(),
            business_routes: Vec::new(),
            windside_model: None,
            windside_mode: WindsideMode::Off,
            llm_url: None,
            llm_key: None,
            llm_model: "meta-models/muse-spark-open-1026".to_string(),
            llm_mode: LlmMode::Off,
            llm_daily_calls: 500,
            llm_daily_tokens: 500_000,
        }
    }
}

fn default_ja4_classes() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("data/ja4-classes.json");
            if beside.is_file() {
                return beside;
            }
        }
    }
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/ja4-classes.json"
    ))
}

fn default_rules_dir() -> PathBuf {
    // Next to the binary first, then the repo layout for `cargo run`.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("rules/install");
            if beside.is_dir() {
                return beside;
            }
        }
    }
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/install"))
}

impl Config {
    pub fn from_env() -> Config {
        let mut cfg = Config::default();
        if let Ok(v) = std::env::var("LEESIDED_SOCKET_DIR") {
            cfg.socket_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("LEESIDED_DB") {
            cfg.db = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("LEESIDED_API") {
            cfg.api = v
                .parse()
                .unwrap_or_else(|_| panic!("LEESIDED_API: not host:port: {v}"));
        }
        if let Ok(v) = std::env::var("LEESIDED_ENFORCE") {
            cfg.enforce = !matches!(v.as_str(), "0" | "false" | "no" | "off");
        }
        if let Ok(v) = std::env::var("LEESIDED_RULES_DIR") {
            cfg.rules_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("LEESIDED_SOCKET_MODE") {
            cfg.socket_mode = u32::from_str_radix(&v, 8)
                .unwrap_or_else(|_| panic!("LEESIDED_SOCKET_MODE: not octal: {v}"));
        }
        if let Ok(v) = std::env::var("LEESIDED_SOCKET_GID") {
            cfg.socket_gid = Some(
                v.parse()
                    .unwrap_or_else(|_| panic!("LEESIDED_SOCKET_GID: not a number: {v}")),
            );
        }
        if let Ok(v) = std::env::var("LEESIDED_API_TOKEN") {
            if !v.is_empty() {
                cfg.api_token = Some(v);
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_HASH_KEY") {
            if !v.is_empty() {
                cfg.hash_key = Some(v);
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_GEOIP_ASN") {
            if !v.is_empty() {
                cfg.geoip_asn = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_GEOIP_COUNTRY") {
            if !v.is_empty() {
                cfg.geoip_country = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_JA4_CLASSES") {
            cfg.ja4_classes = (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("LEESIDED_HONEYTOKEN_ROUTES") {
            cfg.honeytoken_routes = split_routes(&v);
        }
        if let Ok(v) = std::env::var("LEESIDED_BUSINESS_ROUTES") {
            cfg.business_routes = split_routes(&v);
        }
        if let Ok(v) = std::env::var("LEESIDED_WINDSIDE_MODEL") {
            if !v.is_empty() {
                cfg.windside_model = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_WINDSIDE_MODE") {
            cfg.windside_mode = WindsideMode::parse(&v).unwrap_or_else(|| {
                panic!("LEESIDED_WINDSIDE_MODE: off, shadow or active, not {v}")
            });
        }
        if let Ok(v) = std::env::var("LEESIDED_LLM_URL") {
            if !v.is_empty() {
                cfg.llm_url = Some(v);
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_LLM_KEY") {
            if !v.is_empty() {
                cfg.llm_key = Some(v);
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_LLM_MODEL") {
            if !v.is_empty() {
                cfg.llm_model = v;
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_LLM_MODE") {
            cfg.llm_mode = LlmMode::parse(&v)
                .unwrap_or_else(|| panic!("LEESIDED_LLM_MODE: off, dry or live, not {v}"));
        }
        if let Ok(v) = std::env::var("LEESIDED_LLM_DAILY_CALLS") {
            cfg.llm_daily_calls = v
                .parse()
                .unwrap_or_else(|_| panic!("LEESIDED_LLM_DAILY_CALLS: not a number: {v}"));
        }
        if let Ok(v) = std::env::var("LEESIDED_LLM_DAILY_TOKENS") {
            cfg.llm_daily_tokens = v
                .parse()
                .unwrap_or_else(|_| panic!("LEESIDED_LLM_DAILY_TOKENS: not a number: {v}"));
        }
        cfg
    }

    pub fn events_sock(&self) -> PathBuf {
        self.socket_dir.join("events.sock")
    }

    pub fn check_sock(&self) -> PathBuf {
        self.socket_dir.join("check.sock")
    }

    /// The tap's datagrams (docs/tap.md).
    pub fn fp_sock(&self) -> PathBuf {
        self.socket_dir.join("fp.sock")
    }
}

/// Comma-separated route names; empty entries dropped.
fn split_routes(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}
