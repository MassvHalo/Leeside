//! The passive fingerprint tap (docs/tap.md): a sniffer on the host reads
//! the TCP SYN and the TLS ClientHello of every connection to the web ports
//! and tells leesided, over `fp.sock`, the JA4T and JA4 of that connection.
//! leesided joins them to turns by `(client ip, remote_port)` and the turn's
//! time, and fills the `ja4` and `ja4t` columns at ingest, or a little later
//! when the event beat the tap's datagram.
//!
//! Nothing here is on the request path. The tap is the only part of leesided
//! that needs a privilege (`CAP_NET_RAW`), so it runs as its own process,
//! `leesided tap`, in its own unit.

pub mod capture;
pub mod classes;
pub mod conns;
pub mod ja4;
pub mod ja4t;

use serde::{Deserialize, Serialize};

/// One datagram from the tap to leesided. `ip` crosses the socket raw, as
/// the event's `ip` does, and is hashed on receipt; nothing raw is written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpMessage {
    pub v: u8,
    /// When the tap saw the packet, host clock.
    pub ts_ms: u64,
    pub ip: String,
    pub port: u16,
    /// From the SYN. `tls` says whether a ClientHello is expected on this port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4t: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    /// From the ClientHello.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    /// FIN or RST from the client: the connection is over.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub close: bool,
}

pub const WIRE_VERSION: u8 = 1;
