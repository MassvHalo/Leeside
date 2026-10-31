//! The package's hash recipe, so values leesided derives on ingest join
//! with the ones PHP sends: `HMAC-SHA256(key, namespace || "\0" || value)`
//! truncated to 16 hex. One key per install (`LEESIDE_HASH_KEY` on both
//! sides); no second salt.

use sha2::{Digest, Sha256};

const BLOCK: usize = 64;

pub struct Hasher {
    /// The key padded or hashed to one block, ready for ipad/opad.
    block: [u8; BLOCK],
}

impl Hasher {
    /// The key's raw bytes, as PHP's `hash_hmac` takes them.
    pub fn new(key: &str) -> Hasher {
        let key = key.as_bytes();
        let mut block = [0u8; BLOCK];
        if key.len() > BLOCK {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        Hasher { block }
    }

    pub fn hmac(&self, namespace: &str, value: &str) -> [u8; 32] {
        let mut inner = Sha256::new();
        inner.update(self.block.map(|b| b ^ 0x36));
        inner.update(namespace.as_bytes());
        inner.update([0u8]);
        inner.update(value.as_bytes());
        let mut outer = Sha256::new();
        outer.update(self.block.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    /// 16 hex: the first 8 bytes of the HMAC.
    pub fn hex16(&self, namespace: &str, value: &str) -> String {
        hex(&self.hmac(namespace, value)[..8])
    }
}

/// The network an address belongs to, as the string the `net` hash is
/// taken over: `a.b.c.0/24` for IPv4, `xxxx:xxxx:xxxx::/48` for IPv6.
pub fn net_prefix(ip: &str) -> Option<String> {
    match ip.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]))
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case_2() {
        // key "Jefe", data "what do ya want for nothing?"; our recipe inserts
        // namespace\0, so split the data around the NUL to hit the vector.
        let h = Hasher::new("Jefe");
        let data = "what do ya want for nothing?";
        let (ns, rest) = data.split_at(4);
        // namespace = "what", value = " do ya want for nothing?" gives
        // "what\0 do ya..." which is not the RFC data; test raw HMAC instead
        // through a namespace-free path by reproducing the padding here.
        let mut inner = Sha256::new();
        inner.update(h.block.map(|b| b ^ 0x36));
        inner.update(data.as_bytes());
        let mut outer = Sha256::new();
        outer.update(h.block.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        let mac: [u8; 32] = outer.finalize().into();
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let _ = (ns, rest);
    }

    #[test]
    fn recipe_matches_php_hash_hmac_with_nul_separator() {
        // php -r 'echo substr(hash_hmac("sha256", "ip" . "\x00" . "203.0.113.7", "k"), 0, 16);'
        let h = Hasher::new("k");
        assert_eq!(h.hex16("ip", "203.0.113.7"), "5a3bf0e6aa7dc3e5");
        assert_eq!(h.hex16("ip", "203.0.113.7").len(), 16);
        assert_ne!(h.hex16("ip", "203.0.113.7"), h.hex16("net", "203.0.113.7"));
        assert_ne!(
            Hasher::new("k").hex16("ip", "x"),
            Hasher::new("k2").hex16("ip", "x")
        );
    }

    #[test]
    fn long_keys_are_hashed_first() {
        let long = "x".repeat(100);
        let h = Hasher::new(&long);
        assert_eq!(&h.block[32..], &[0u8; 32]);
        assert_eq!(h.hex16("ip", "1.2.3.4").len(), 16);
    }

    #[test]
    fn net_prefixes() {
        assert_eq!(net_prefix("203.0.113.7").as_deref(), Some("203.0.113.0/24"));
        assert_eq!(
            net_prefix("2001:db8:abcd:12::1").as_deref(),
            Some("2001:db8:abcd::/48")
        );
        assert_eq!(net_prefix("nope"), None);
    }
}
