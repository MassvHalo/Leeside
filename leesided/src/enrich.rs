//! Enrichment at ingest: ASN and country for the client address from the
//! GeoLite2 databases, before the address is hashed and dropped. Both are
//! optional columns; with a file missing the daemon says so once at start
//! and leaves them null. No resolution path depends on them.

use maxminddb::geoip2;
use std::net::IpAddr;
use std::path::Path;

pub struct Enricher {
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    country: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Enriched {
    pub asn: Option<u32>,
    pub country: Option<String>,
}

impl Enricher {
    /// Open whichever files are configured and present.
    pub fn open(asn: Option<&Path>, country: Option<&Path>) -> Enricher {
        let load = |what: &str, path: Option<&Path>| -> Option<maxminddb::Reader<Vec<u8>>> {
            let path = path?;
            match maxminddb::Reader::open_readfile(path) {
                Ok(r) => {
                    tracing::info!(what, path = %path.display(), "geoip database loaded");
                    Some(r)
                }
                Err(e) => {
                    tracing::warn!(what, path = %path.display(), error = %e, "geoip database unavailable; column stays null");
                    None
                }
            }
        };
        let asn = load("asn", asn);
        let country = load("country", country);
        if asn.is_none() && country.is_none() {
            tracing::warn!("no geoip databases: asn and country stay null");
        }
        Enricher { asn, country }
    }

    pub fn none() -> Enricher {
        Enricher {
            asn: None,
            country: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.asn.is_none() && self.country.is_none()
    }

    pub fn lookup(&self, ip: &str) -> Enriched {
        let Ok(addr) = ip.parse::<IpAddr>() else {
            return Enriched::default();
        };
        let asn = self
            .asn
            .as_ref()
            .and_then(|r| r.lookup::<geoip2::Asn>(addr).ok())
            .and_then(|a| a.autonomous_system_number);
        let country = self
            .country
            .as_ref()
            .and_then(|r| r.lookup::<geoip2::Country>(addr).ok())
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code)
            .map(str::to_string);
        Enriched { asn, country }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_files_mean_null_columns_not_errors() {
        let e = Enricher::open(Some(Path::new("/nonexistent/GeoLite2-ASN.mmdb")), None);
        assert!(e.is_empty());
        assert_eq!(e.lookup("203.0.113.7"), Enriched::default());
        assert_eq!(Enricher::none().lookup("not an ip"), Enriched::default());
    }

    /// Runs only where a real database is available (the deploy box), so the
    /// lookup path itself is exercised somewhere.
    #[test]
    fn real_database_when_present() {
        let Ok(path) = std::env::var("LEESIDED_GEOIP_ASN") else {
            return;
        };
        let e = Enricher::open(
            Some(Path::new(&path)),
            std::env::var("LEESIDED_GEOIP_COUNTRY")
                .ok()
                .as_deref()
                .map(Path::new),
        );
        if e.asn.is_none() {
            return;
        }
        let hit = e.lookup("8.8.8.8");
        assert!(hit.asn.is_some());
    }
}
