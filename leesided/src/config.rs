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
    /// When unset, every API route but `/health` answers 503; when set, those
    /// routes need `Authorization: Bearer <token>`.
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
    /// Per-point model overrides (`LEESIDED_LLM_MODEL_<POINT>`), each
    /// falling back to `llm_model`: classify and explain can move to a
    /// non-reasoning model while label and draft keep Muse Spark.
    pub llm_model_label: Option<String>,
    pub llm_model_explain: Option<String>,
    pub llm_model_classify: Option<String>,
    pub llm_model_draft: Option<String>,
    /// `off`, `dry` or `live` (default `off`). Dry builds the full
    /// request and logs it with a null response; live sends.
    pub llm_mode: LlmMode,
    /// Per-point daily budgets in calls and tokens.
    pub llm_daily_calls: u32,
    pub llm_daily_tokens: u32,
    /// The app this daemon serves; rule enable flags are per app.
    pub app_id: String,
    /// Console mount path (`LEESIDED_CONSOLE_PATH`, default
    /// `/windside`): the routes, cookie path, redirects and page
    /// links for the console.
    pub console_path: String,
    /// Read-only console sessions (`LEESIDED_VIEWER_TOKEN`); unset
    /// disables viewer login. The operator token stays admin.
    pub viewer_token: Option<String>,
    /// The proxy whose `X-Forwarded-For` the console allowlist
    /// trusts (`LEESIDED_TRUSTED_PROXY`, one IP or CIDR); unset
    /// trusts none.
    pub trusted_proxy: Option<Cidr>,
    /// CIDRs allowed onto the console paths
    /// (`LEESIDED_CONSOLE_ALLOW`, comma-separated); empty allows all.
    pub console_allow: Vec<Cidr>,
    /// The published dashboard (`LEESIDED_CONSOLE_DIR`, default
    /// `/var/www/leeside-ui`): `index.html` plus `assets/`, served at
    /// the console root. Dev points it at `leesided/ui/dist`.
    pub console_dir: PathBuf,
}

/// An IP network: a bare `1.2.3.4` (a /32, or /128 for v6) or
/// `1.2.3.0/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: std::net::IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let s = s.trim();
        let (ip, bits) = match s.split_once('/') {
            Some((ip, b)) => {
                let bits: u8 = b.trim().parse().map_err(|_| format!("bad CIDR {s:?}"))?;
                (ip.trim(), Some(bits))
            }
            None => (s, None),
        };
        let addr: std::net::IpAddr = ip.parse().map_err(|_| format!("bad CIDR {s:?}"))?;
        let max = match addr {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        let bits = bits.unwrap_or(max);
        if bits > max {
            return Err(format!("bad CIDR {s:?}"));
        }
        Ok(Cidr { addr, bits })
    }

    pub fn matches(self, ip: std::net::IpAddr) -> bool {
        match (self.addr, ip) {
            (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.bits)
                };
                u32::from(a) & mask == u32::from(b) & mask
            }
            (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.bits)
                };
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
}

/// The app id until multi-app lands: every rule flag, decision and
/// console session is scoped to it.
pub const DEFAULT_APP: &str = "default";

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
            llm_model_label: None,
            llm_model_explain: None,
            llm_model_classify: None,
            llm_model_draft: None,
            llm_mode: LlmMode::Off,
            llm_daily_calls: 500,
            llm_daily_tokens: 500_000,
            app_id: DEFAULT_APP.to_string(),
            console_path: "/windside".to_string(),
            viewer_token: None,
            trusted_proxy: None,
            console_allow: Vec::new(),
            console_dir: PathBuf::from("/var/www/leeside-ui"),
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
        if let Ok(v) = std::env::var("LEESIDED_APP_ID") {
            if !v.is_empty() {
                cfg.app_id = v;
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
        for (var, slot) in [
            ("LEESIDED_LLM_MODEL_LABEL", &mut cfg.llm_model_label),
            ("LEESIDED_LLM_MODEL_EXPLAIN", &mut cfg.llm_model_explain),
            ("LEESIDED_LLM_MODEL_CLASSIFY", &mut cfg.llm_model_classify),
            ("LEESIDED_LLM_MODEL_DRAFT", &mut cfg.llm_model_draft),
        ] {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    *slot = Some(v);
                }
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
        if let Ok(v) = std::env::var("LEESIDED_CONSOLE_PATH") {
            cfg.console_path = parse_console_path(&v);
        }
        if let Ok(v) = std::env::var("LEESIDED_VIEWER_TOKEN") {
            if !v.is_empty() {
                cfg.viewer_token = Some(v);
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_TRUSTED_PROXY") {
            if !v.trim().is_empty() {
                cfg.trusted_proxy =
                    Some(Cidr::parse(&v).unwrap_or_else(|e| panic!("LEESIDED_TRUSTED_PROXY: {e}")));
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_CONSOLE_DIR") {
            if !v.trim().is_empty() {
                cfg.console_dir = PathBuf::from(v);
            }
        }
        if let Ok(v) = std::env::var("LEESIDED_CONSOLE_ALLOW") {
            cfg.console_allow = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| Cidr::parse(s).unwrap_or_else(|e| panic!("LEESIDED_CONSOLE_ALLOW: {e}")))
                .collect();
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

/// A console mount path: leading slash, no trailing slash.
fn parse_console_path(v: &str) -> String {
    let t = v.trim_end_matches('/');
    if t.is_empty() || !t.starts_with('/') {
        panic!("LEESIDED_CONSOLE_PATH: not a path prefix: {v}");
    }
    t.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matches_inside_and_rejects_outside() {
        let c = Cidr::parse("10.1.2.0/24").unwrap();
        assert!(c.matches(ip("10.1.2.3")));
        assert!(c.matches(ip("10.1.2.0")));
        assert!(!c.matches(ip("10.1.3.3")));
        assert!(!c.matches(ip("127.0.0.1")));
        // A bare IP is a single host.
        let host = Cidr::parse("127.0.0.1").unwrap();
        assert!(host.matches(ip("127.0.0.1")));
        assert!(!host.matches(ip("127.0.0.2")));
        // Families never mix.
        assert!(!c.matches(ip("::1")));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.matches(ip("2001:db8::1")));
        assert!(!v6.matches(ip("2001:db9::1")));
        assert!(!v6.matches(ip("10.1.2.3")));
    }

    #[test]
    fn cidr_rejects_garbage() {
        assert!(Cidr::parse("nope").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
        assert!(Cidr::parse("").is_err());
    }
}
