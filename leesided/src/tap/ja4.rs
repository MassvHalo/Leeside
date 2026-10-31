//! JA4, the TLS ClientHello fingerprint (FoxIO, BSD-3), from the bytes a
//! client sends first on a TLS connection. The rules are the spec's
//! `technical_details/JA4.md`; the worked example there is the test.
//!
//! One deliberate reading: when there is no `supported_versions` extension
//! the spec says to use "the Protocol Version" and to ignore the handshake
//! version at the top of the packet; this takes the record layer's version.
//! Every current client sends `supported_versions`, so the branch is rare.

use sha2::{Digest, Sha256};

/// A ClientHello longer than this is not one.
pub const MAX_HELLO: usize = 16 * 1024;

const SNI: u16 = 0x0000;
const ALPN: u16 = 0x0010;
const SIGALGS: u16 = 0x000d;
const SUPPORTED_VERSIONS: u16 = 0x002b;

#[derive(Debug, PartialEq, Eq)]
pub enum Parse {
    /// A complete ClientHello.
    Done(Ja4),
    /// Not enough of the stream yet; call again with more of it.
    NeedMore,
    /// Not a TLS ClientHello: plain HTTP, something else, or malformed.
    NotTls,
}

/// The parts of a ClientHello the fingerprint is made of, GREASE removed,
/// original order kept.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ja4 {
    pub version: u16,
    pub sni: bool,
    pub ciphers: Vec<u16>,
    /// Every extension type, SNI and ALPN included.
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    /// The first ALPN value, when the extension lists one.
    pub alpn: Option<Vec<u8>>,
}

/// RFC 8701: both bytes equal, low nibble 0xa.
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Parse from the start of the client's byte stream: one or more TLS
/// records whose payloads concatenate to a ClientHello handshake message.
pub fn parse(stream: &[u8]) -> Parse {
    if stream.is_empty() {
        return Parse::NeedMore;
    }
    if stream[0] != 0x16 || stream.get(1) != Some(&0x03) {
        return Parse::NotTls;
    }
    if stream.len() > MAX_HELLO {
        return Parse::NotTls;
    }
    let record_version = be16(stream, 1).unwrap_or(0);
    let mut handshake: Vec<u8> = Vec::with_capacity(stream.len());
    let mut at = 0;
    let mut need = None;
    while need.is_none_or(|n| handshake.len() < n) {
        if stream.len() < at + 5 {
            return Parse::NeedMore;
        }
        if stream[at] != 0x16 {
            return Parse::NotTls;
        }
        let len = be16(stream, at + 3).unwrap_or(0) as usize;
        if stream.len() < at + 5 + len {
            return Parse::NeedMore;
        }
        handshake.extend_from_slice(&stream[at + 5..at + 5 + len]);
        at += 5 + len;
        if need.is_none() && handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Parse::NotTls;
            }
            let body = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            need = Some(4 + body);
        }
    }
    let body = &handshake[4..need.unwrap_or(4)];
    match client_hello(body, record_version) {
        Some(j) => Parse::Done(j),
        None => Parse::NotTls,
    }
}

fn client_hello(b: &[u8], record_version: u16) -> Option<Ja4> {
    let mut at = 2 + 32; // legacy version, random
    let sid_len = *b.get(at)? as usize;
    at += 1 + sid_len;
    let cipher_len = be16(b, at)? as usize;
    at += 2;
    let ciphers_raw = b.get(at..at + cipher_len)?;
    at += cipher_len;
    let comp_len = *b.get(at)? as usize;
    at += 1 + comp_len;
    let mut j = Ja4 {
        version: record_version,
        ..Ja4::default()
    };
    for pair in ciphers_raw.as_chunks::<2>().0 {
        let c = u16::from_be_bytes([pair[0], pair[1]]);
        if !is_grease(c) {
            j.ciphers.push(c);
        }
    }
    let Some(ext_len) = be16(b, at) else {
        return Some(j); // SSL3-style hello without extensions
    };
    at += 2;
    let exts = b.get(at..at + ext_len as usize)?;
    let mut e = 0;
    let mut supported: Option<u16> = None;
    while e + 4 <= exts.len() {
        let kind = be16(exts, e)?;
        let len = be16(exts, e + 2)? as usize;
        let data = exts.get(e + 4..e + 4 + len)?;
        e += 4 + len;
        if is_grease(kind) {
            continue;
        }
        j.extensions.push(kind);
        match kind {
            SNI => j.sni = true,
            ALPN => {
                let list_len = be16(data, 0).unwrap_or(0) as usize;
                let list = data.get(2..2 + list_len).unwrap_or(&[]);
                if let Some(&n) = list.first() {
                    j.alpn = Some(list.get(1..1 + n as usize).unwrap_or(&[]).to_vec());
                }
            }
            SIGALGS => {
                let list_len = be16(data, 0).unwrap_or(0) as usize;
                for pair in data.get(2..2 + list_len).unwrap_or(&[]).as_chunks::<2>().0 {
                    let s = u16::from_be_bytes([pair[0], pair[1]]);
                    if !is_grease(s) {
                        j.signature_algorithms.push(s);
                    }
                }
            }
            SUPPORTED_VERSIONS => {
                let list_len = *data.first().unwrap_or(&0) as usize;
                for pair in data.get(1..1 + list_len).unwrap_or(&[]).as_chunks::<2>().0 {
                    let v = u16::from_be_bytes([pair[0], pair[1]]);
                    if !is_grease(v) && supported.is_none_or(|s| v > s) {
                        supported = Some(v);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(v) = supported {
        j.version = v;
    }
    Some(j)
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn sha12(s: &str) -> String {
    let d = Sha256::digest(s.as_bytes());
    crate::hash::hex(&d)[..12].to_string()
}

/// First and last ASCII alphanumeric of the first ALPN value; the first and
/// last hex characters of the value when either end is not alphanumeric;
/// `00` without ALPN.
pub fn alpn_code(alpn: Option<&[u8]>) -> String {
    let Some(v) = alpn.filter(|v| !v.is_empty()) else {
        return "00".into();
    };
    let (first, last) = (v[0], v[v.len() - 1]);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return format!("{}{}", first as char, last as char);
    }
    let h = crate::hash::hex(v);
    format!("{}{}", &h[..1], &h[h.len() - 1..])
}

impl Ja4 {
    /// `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub fn fingerprint(&self) -> String {
        let sni = if self.sni { 'd' } else { 'i' };
        let nc = self.ciphers.len().min(99);
        let ne = self.extensions.len().min(99);
        let alpn = alpn_code(self.alpn.as_deref());
        let b = if self.ciphers.is_empty() {
            "000000000000".to_string()
        } else {
            let mut sorted = self.ciphers.clone();
            sorted.sort_unstable();
            sha12(&hex_list(&sorted))
        };
        let mut exts: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(|e| *e != SNI && *e != ALPN)
            .collect();
        exts.sort_unstable();
        let c = if exts.is_empty() {
            "000000000000".to_string()
        } else {
            let mut s = hex_list(&exts);
            if !self.signature_algorithms.is_empty() {
                s.push('_');
                s.push_str(&hex_list(&self.signature_algorithms));
            }
            sha12(&s)
        };
        format!(
            "t{}{sni}{nc:02}{ne:02}{alpn}_{b}_{c}",
            version_code(self.version)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(s: &str) -> Vec<u16> {
        s.split(',')
            .map(|h| u16::from_str_radix(h, 16).unwrap())
            .collect()
    }

    /// The worked example in technical_details/JA4.md, verbatim.
    #[test]
    fn the_spec_example() {
        let j = Ja4 {
            version: 0x0304,
            sni: true,
            ciphers: list(
                "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035",
            ),
            extensions: list(
                "001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015",
            ),
            signature_algorithms: list("0403,0804,0401,0503,0805,0501,0806,0601"),
            alpn: Some(b"h2".to_vec()),
        };
        assert_eq!(j.fingerprint(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        let no_sigalgs = Ja4 {
            signature_algorithms: vec![],
            ..j.clone()
        };
        assert!(no_sigalgs.fingerprint().ends_with("_6d807ffa2a79"));
        let empty = Ja4::default();
        assert_eq!(empty.fingerprint(), "t00i000000_000000000000_000000000000");
    }

    /// The ALPN table in the spec.
    #[test]
    fn alpn_rules() {
        let cases: [(&[u8], &str); 11] = [
            (b"h2", "h2"),
            (b"http/1.1", "h1"),
            (b"h", "hh"),
            (b"", "00"),
            (&[0xab], "ab"),
            (&[0x20], "20"),
            (&[0xab, 0xcd], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xab], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xab, 0xcd], "3d"),
        ];
        for (v, want) in cases {
            assert_eq!(alpn_code(Some(v)), want, "{v:?}");
        }
        assert_eq!(alpn_code(Some(&[0x30, 0xab, 0xcd, 0x31])), "01");
        assert_eq!(alpn_code(None), "00");
    }

    #[test]
    fn grease() {
        for v in [0x0a0a, 0x1a1a, 0x8a8a, 0xfafa] {
            assert!(is_grease(v));
        }
        for v in [0x0a1a, 0x1301, 0x0000, 0xaaab] {
            assert!(!is_grease(v));
        }
    }

    const CURL: &[u8] = include_bytes!("../../tests/fixtures/clienthello-curl.bin");
    const PYTHON: &[u8] = include_bytes!("../../tests/fixtures/clienthello-python.bin");

    /// Real hellos, captured with a plain socket: curl (OpenSSL) and Python's
    /// urllib (OpenSSL through `ssl`). Both TLS 1.3, SNI absent (they were
    /// sent to 127.0.0.1), distinct.
    #[test]
    fn captured_hellos() {
        let Parse::Done(curl) = parse(CURL) else {
            panic!("curl hello did not parse")
        };
        let Parse::Done(py) = parse(PYTHON) else {
            panic!("python hello did not parse")
        };
        assert_eq!(curl.version, 0x0304);
        assert!(!curl.sni);
        assert_eq!(curl.alpn.as_deref(), Some(&b"h2"[..]));
        assert!(curl.fingerprint().starts_with("t13i"));
        // Values cross-checked against an independent Python reading of the
        // same bytes (same cipher list from OpenSSL, so the same JA4_b).
        assert_eq!(curl.fingerprint(), "t13i3012h2_1d37bd780c83_8537cf56674e");
        assert_eq!(py.fingerprint(), "t13i301100_1d37bd780c83_ecd0401ec68b");
        assert_eq!(py.alpn, None);
        // Same hello, in two TCP segments: NeedMore, then the same answer.
        assert_eq!(parse(&CURL[..700]), Parse::NeedMore);
        assert_eq!(parse(&CURL[..5]), Parse::NeedMore);
        assert_eq!(parse(CURL), Parse::Done(curl));
    }

    #[test]
    fn not_tls() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Parse::NotTls);
        assert_eq!(
            parse(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0, 0, 0]),
            Parse::NotTls
        );
        assert_eq!(parse(&[]), Parse::NeedMore);
    }
}
