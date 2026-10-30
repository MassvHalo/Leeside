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
        }
    }
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
        cfg
    }

    pub fn events_sock(&self) -> PathBuf {
        self.socket_dir.join("events.sock")
    }

    pub fn check_sock(&self) -> PathBuf {
        self.socket_dir.join("check.sock")
    }
}
