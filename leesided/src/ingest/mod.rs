//! The ingest server: a Unix datagram socket, one event per datagram, no
//! reply. Rejected events are counted, never logged in full.

use crate::engine::Engine;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UnixDatagram;

/// A datagram larger than this is not a v1 event (shapes cap at 2 KB each).
pub const MAX_DATAGRAM: usize = 65_536;

pub fn bind(path: &Path, mode: u32, gid: Option<u32>) -> std::io::Result<UnixDatagram> {
    crate::check::prepare(path, mode, gid, |p| {
        let std_sock = std::os::unix::net::UnixDatagram::bind(p)?;
        std_sock.set_nonblocking(true)?;
        UnixDatagram::from_std(std_sock)
    })
}

/// The tap's socket: one fingerprint message per datagram, no reply.
pub async fn serve_fp(engine: Arc<Engine>, sock: UnixDatagram) {
    let mut buf = vec![0u8; 4096];
    loop {
        match sock.recv(&mut buf).await {
            Ok(n) => {
                if let Err(e) = engine.fingerprint(&buf[..n]) {
                    engine.conns.bad_message();
                    tracing::debug!(error = %e, bytes = n, "tap message rejected");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "fp recv failed");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

pub async fn serve(engine: Arc<Engine>, sock: UnixDatagram) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match sock.recv(&mut buf).await {
            Ok(n) => {
                if let Err(e) = engine.ingest(&buf[..n]) {
                    engine.counters.bad_event.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(error = %e, bytes = n, "event rejected");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "events recv failed");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}
