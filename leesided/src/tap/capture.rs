//! The capture loop: an `AF_PACKET` socket (cooked, so loopback and
//! Ethernet look the same), inbound packets only, filtered in user space to
//! the configured ports. SYNs give JA4T; the first bytes on a TLS port are
//! buffered per half-open connection until a ClientHello parses or turns out
//! not to be one; FIN or RST closes. Each finding is one datagram to
//! leesided's `fp.sock`.
//!
//! Needs `CAP_NET_RAW`; `probe()` says whether this process has it. Linux
//! only; elsewhere `run` returns `Unsupported`.

use super::ja4::{self, Parse, MAX_HELLO};
use super::ja4t::ja4t;
use super::{FpMessage, WIRE_VERSION};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

/// Half-open connections awaiting their ClientHello, at most.
pub const HALF_OPEN_CAP: usize = 10_000;

#[derive(Debug, Clone)]
pub struct TapConfig {
    /// `None` captures on every interface.
    pub iface: Option<String>,
    /// Server ports to watch (destination port of inbound packets).
    pub ports: Vec<u16>,
    /// The subset that speaks TLS, where a ClientHello is expected.
    pub tls_ports: Vec<u16>,
    pub sock: PathBuf,
}

impl TapConfig {
    pub fn from_env(socket_dir: &std::path::Path) -> TapConfig {
        let list = |name: &str, default: &str| -> Vec<u16> {
            std::env::var(name)
                .unwrap_or_else(|_| default.to_string())
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect()
        };
        TapConfig {
            iface: std::env::var("LEESIDED_TAP_IFACE")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(default_route_iface),
            ports: list("LEESIDED_TAP_PORTS", "80,443"),
            tls_ports: list("LEESIDED_TAP_TLS_PORTS", "443"),
            sock: socket_dir.join("fp.sock"),
        }
    }
}

/// The interface of the IPv4 default route, from `/proc/net/route`.
pub fn default_route_iface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|l| {
        let mut f = l.split_whitespace();
        let iface = f.next()?;
        let dest = f.next()?;
        (dest == "00000000").then(|| iface.to_string())
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A packet to the server, parsed as far as the tap needs.
#[derive(Debug, PartialEq, Eq)]
pub struct Inbound<'a> {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub syn: bool,
    pub fin_or_rst: bool,
    /// The TCP header, for JA4T.
    pub tcp: &'a [u8],
    pub payload: &'a [u8],
}

/// Parse an IPv4 or IPv6 packet starting at the network header.
pub fn parse_packet(pkt: &[u8]) -> Option<Inbound<'_>> {
    let (src, tcp) = match pkt.first()? >> 4 {
        4 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl || pkt[9] != 6 {
                return None;
            }
            let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            let end = total.clamp(ihl, pkt.len());
            let src = IpAddr::from([pkt[12], pkt[13], pkt[14], pkt[15]]);
            (src, &pkt[ihl..end])
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != 6 {
                return None;
            }
            let len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let end = (40 + len).min(pkt.len());
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[8..24]);
            (IpAddr::from(a), &pkt[40..end])
        }
        _ => return None,
    };
    if tcp.len() < 20 {
        return None;
    }
    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    let flags = tcp[13];
    Some(Inbound {
        src,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        syn: flags & 0x02 != 0 && flags & 0x10 == 0,
        fin_or_rst: flags & 0x05 != 0,
        tcp,
        payload: &tcp[doff..],
    })
}

/// The tap's state machine, separate from the socket so it can be tested.
pub struct Tap {
    cfg: TapConfig,
    half_open: HashMap<(IpAddr, u16, u16), Vec<u8>>,
    order: VecDeque<(IpAddr, u16, u16)>,
}

impl Tap {
    pub fn new(cfg: TapConfig) -> Tap {
        Tap {
            cfg,
            half_open: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Messages to send for one inbound packet.
    pub fn packet(&mut self, pkt: &[u8], ts_ms: u64) -> Vec<FpMessage> {
        let Some(p) = parse_packet(pkt) else {
            return vec![];
        };
        if !self.cfg.ports.contains(&p.dst_port) {
            return vec![];
        }
        let tls = self.cfg.tls_ports.contains(&p.dst_port);
        let key = (p.src, p.src_port, p.dst_port);
        let base = |ts: u64| FpMessage {
            v: WIRE_VERSION,
            ts_ms: ts,
            ip: p.src.to_string(),
            port: p.src_port,
            ja4t: None,
            tls: None,
            ja4: None,
            close: false,
        };
        let mut out = Vec::new();
        if p.syn {
            let mut m = base(ts_ms);
            m.ja4t = ja4t(p.tcp);
            m.tls = Some(tls);
            out.push(m);
            if tls {
                self.half_open.remove(&key);
                self.open(key);
            }
        }
        if tls && !p.payload.is_empty() {
            if !self.half_open.contains_key(&key) {
                self.open(key);
            }
            let buf = self.half_open.get_mut(&key).expect("opened");
            if buf.len() + p.payload.len() <= MAX_HELLO {
                buf.extend_from_slice(p.payload);
            }
            match ja4::parse(buf) {
                Parse::NeedMore if buf.len() < MAX_HELLO => {}
                Parse::Done(j) => {
                    let mut m = base(ts_ms);
                    m.ja4 = Some(j.fingerprint());
                    out.push(m);
                    self.half_open.remove(&key);
                }
                _ => {
                    self.half_open.remove(&key);
                }
            }
        }
        if p.fin_or_rst {
            let mut m = base(ts_ms);
            m.close = true;
            out.push(m);
            self.half_open.remove(&key);
        }
        out
    }

    fn open(&mut self, key: (IpAddr, u16, u16)) {
        self.half_open.insert(key, Vec::new());
        self.order.push_back(key);
        while self.half_open.len() > HALF_OPEN_CAP {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            self.half_open.remove(&old);
        }
    }

    pub fn half_open(&self) -> usize {
        self.half_open.len()
    }
}

/// Can this process open a packet socket? `Ok` means the tap will run.
pub fn probe() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let fd = linux::open(None)?;
        // SAFETY: fd came from socket(2) and is closed once.
        unsafe { libc::close(fd) };
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the tap needs Linux AF_PACKET",
        ))
    }
}

/// Capture until killed.
pub fn run(cfg: TapConfig) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(cfg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the tap needs Linux AF_PACKET",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    const ETH_P_ALL: u16 = 0x0003;
    const PACKET_OUTGOING: u8 = 4;

    /// A cooked packet socket, bound to one interface when named.
    pub fn open(iface: Option<&str>) -> io::Result<i32> {
        // SAFETY: plain libc calls with checked return values; sockaddr_ll is
        // zeroed before the fields in use are set.
        unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                ETH_P_ALL.to_be() as i32,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(name) = iface {
                let c = std::ffi::CString::new(name)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "iface"))?;
                let idx = libc::if_nametoindex(c.as_ptr());
                if idx == 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(io::Error::new(e.kind(), format!("interface {name}: {e}")));
                }
                let mut sll: libc::sockaddr_ll = std::mem::zeroed();
                sll.sll_family = libc::AF_PACKET as u16;
                sll.sll_protocol = ETH_P_ALL.to_be();
                sll.sll_ifindex = idx as i32;
                let r = libc::bind(
                    fd,
                    &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as u32,
                );
                if r < 0 {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
            }
            Ok(fd)
        }
    }

    pub fn run(cfg: TapConfig) -> io::Result<()> {
        let fd = open(cfg.iface.as_deref())?;
        let out = UnixDatagram::unbound()?;
        tracing::info!(
            iface = cfg.iface.as_deref().unwrap_or("all"),
            ports = ?cfg.ports,
            tls_ports = ?cfg.tls_ports,
            sock = %cfg.sock.display(),
            "tap capturing"
        );
        let sock = cfg.sock.clone();
        let mut tap = Tap::new(cfg);
        let mut buf = vec![0u8; 65_536];
        let mut sent = 0u64;
        let mut send_errors = 0u64;
        loop {
            // SAFETY: buf and addr are valid for the lengths passed; recvfrom
            // writes at most that much.
            let (n, pkttype) = unsafe {
                let mut addr: libc::sockaddr_ll = std::mem::zeroed();
                let mut len = std::mem::size_of::<libc::sockaddr_ll>() as u32;
                let n = libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut len,
                );
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                (n as usize, addr.sll_pkttype)
            };
            if pkttype == PACKET_OUTGOING {
                continue;
            }
            for m in tap.packet(&buf[..n], now_ms()) {
                let bytes = serde_json::to_vec(&m).unwrap_or_default();
                match out.send_to(&bytes, &sock) {
                    Ok(_) => sent += 1,
                    Err(e) => {
                        send_errors += 1;
                        if send_errors.is_power_of_two() {
                            tracing::warn!(error = %e, sock = %sock.display(), send_errors, "fp.sock send failed");
                        }
                    }
                }
            }
            if sent.is_multiple_of(10_000) && sent > 0 {
                tracing::info!(sent, half_open = tap.half_open(), "tap progress");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(
        src: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        opts: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let doff = (20 + opts.len()).div_ceil(4);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[12] = (doff as u8) << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp.extend_from_slice(opts);
        tcp.resize(doff * 4, 0);
        tcp.extend_from_slice(payload);
        let total = 20 + tcp.len();
        let mut ip = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            6,
            0,
            0,
        ];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&[127, 0, 0, 1]);
        ip.extend_from_slice(&tcp);
        ip
    }

    const CURL: &[u8] = include_bytes!("../../tests/fixtures/clienthello-curl.bin");

    fn cfg() -> TapConfig {
        TapConfig {
            iface: None,
            ports: vec![80, 443],
            tls_ports: vec![443],
            sock: PathBuf::from("/nonexistent/fp.sock"),
        }
    }

    #[test]
    fn syn_hello_in_two_segments_then_fin() {
        let mut tap = Tap::new(cfg());
        let src = [203, 0, 113, 7];
        let syn = ipv4_tcp(src, 51234, 443, 0x02, &[2, 4, 5, 180, 1, 3, 3, 7], &[]);
        let m = tap.packet(&syn, 1_000);
        assert_eq!(m.len(), 1);
        assert_eq!(
            (m[0].port, m[0].tls, m[0].close),
            (51234, Some(true), false)
        );
        assert_eq!(m[0].ja4t.as_deref(), Some("65535_2-1-3_1460_7"));
        assert_eq!(m[0].ip, "203.0.113.7");
        let (a, b) = CURL.split_at(900);
        assert!(tap
            .packet(&ipv4_tcp(src, 51234, 443, 0x18, &[], a), 1_010)
            .is_empty());
        assert_eq!(tap.half_open(), 1);
        let m = tap.packet(&ipv4_tcp(src, 51234, 443, 0x18, &[], b), 1_020);
        assert_eq!(m.len(), 1);
        assert!(m[0].ja4.as_deref().unwrap().starts_with("t13i"));
        assert_eq!(tap.half_open(), 0);
        let m = tap.packet(&ipv4_tcp(src, 51234, 443, 0x11, &[], &[]), 2_000);
        assert!(m[0].close);
    }

    #[test]
    fn plain_http_port_gives_ja4t_only_and_other_ports_nothing() {
        let mut tap = Tap::new(cfg());
        let src = [203, 0, 113, 7];
        let m = tap.packet(&ipv4_tcp(src, 40000, 80, 0x02, &[2, 4, 5, 180], &[]), 1);
        assert_eq!(m[0].tls, Some(false));
        assert!(m[0].ja4t.is_some());
        let m = tap.packet(
            &ipv4_tcp(src, 40000, 80, 0x18, &[], b"GET / HTTP/1.1\r\n"),
            2,
        );
        assert!(m.is_empty());
        assert!(tap
            .packet(&ipv4_tcp(src, 40000, 8080, 0x02, &[], &[]), 3)
            .is_empty());
        // Plain HTTP on a TLS port: the buffer is dropped, nothing sent.
        let m = tap.packet(
            &ipv4_tcp(src, 40001, 443, 0x18, &[], b"GET / HTTP/1.1\r\n"),
            4,
        );
        assert!(m.is_empty() && tap.half_open() == 0);
        // A SYN-ACK is the server's, not a client SYN.
        assert!(tap
            .packet(&ipv4_tcp(src, 40002, 443, 0x12, &[], &[]), 5)
            .is_empty());
    }

    #[test]
    fn ipv6_parses() {
        let mut pkt = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt.extend_from_slice(&[0u8; 16]);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&5555u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;
        pkt.extend_from_slice(&tcp);
        let p = parse_packet(&pkt).unwrap();
        assert_eq!(p.src.to_string(), "2001:db8::1");
        assert!(p.syn && p.src_port == 5555);
    }

    #[test]
    fn default_route_is_a_name_or_none() {
        let _ = default_route_iface();
        let _ = probe(); // Ok with CAP_NET_RAW, EPERM without; either is fine here.
    }
}
