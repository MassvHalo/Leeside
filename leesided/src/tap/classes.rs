//! A curated map from JA4 to a client class, for the `ua_vs_ja4_mismatch`
//! flag: a browser User-Agent whose TLS stack is a known library. Exact
//! match only; a fingerprint not in the file is `Unknown` and never flags.
//!
//! The file is `data/ja4-classes.json`, seeded from FoxIO's sample mapping
//! and extended from whatever database export the operator has
//! (`bin/ja4-classes.py` converts the CSV shape).

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Browser,
    Library,
    Unknown,
}

impl Class {
    pub fn parse(s: &str) -> Class {
        match s {
            "browser" => Class::Browser,
            "library" => Class::Library,
            _ => Class::Unknown,
        }
    }
}

#[derive(serde::Deserialize)]
struct File {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    ja4: String,
    class: String,
}

#[derive(Default, Clone)]
pub struct Ja4Classes {
    map: HashMap<String, Class>,
}

impl Ja4Classes {
    /// Missing or unreadable file: one warning, empty map.
    pub fn load(path: Option<&Path>) -> Ja4Classes {
        let Some(path) = path else {
            return Ja4Classes::default();
        };
        match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str::<File>(&s).map_err(|e| e.to_string()))
        {
            Ok(f) => {
                let map = f
                    .entries
                    .into_iter()
                    .map(|e| (e.ja4, Class::parse(&e.class)))
                    .collect::<HashMap<_, _>>();
                tracing::info!(path = %path.display(), entries = map.len(), "ja4 classes loaded");
                Ja4Classes { map }
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ja4 classes unreadable: every fingerprint is unknown");
                Ja4Classes::default()
            }
        }
    }

    pub fn classify(&self, ja4: &str) -> Class {
        self.map.get(ja4).copied().unwrap_or(Class::Unknown)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// `ua_class` values the package assigns to browsers.
pub fn is_browser_ua(ua_class: Option<&str>) -> bool {
    matches!(
        ua_class,
        Some("chromium") | Some("firefox") | Some("safari") | Some("other_browser")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_by_default_and_the_shipped_file_parses() {
        let c = Ja4Classes::default();
        assert_eq!(
            c.classify("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            Class::Unknown
        );
        let shipped = Ja4Classes::load(Some(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/data/ja4-classes.json"
        ))));
        assert!(!shipped.is_empty());
        assert_eq!(
            shipped.classify("t13d1516h2_8daaf6152771_02713d6af862"),
            Class::Browser
        );
        assert_eq!(
            shipped.classify("t13d181000_85036bcba153_d41ae481755e"),
            Class::Library
        );
        assert!(is_browser_ua(Some("firefox")) && !is_browser_ua(Some("library")));
    }
}
