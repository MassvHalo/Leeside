//! The check server: a Unix stream socket, one connection per probe, one
//! JSON line in, one JSON line out. Everything between parse and write is
//! synchronous in `Engine::check`.

use crate::engine::Engine;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// The PHP side writes one line well under this; anything longer is not a probe.
pub const MAX_LINE: u64 = 4096;
/// PHP gives up at 2 ms; a client that has not finished its line by now is gone.
pub const READ_TIMEOUT: Duration = Duration::from_millis(50);

pub fn bind(path: &Path, mode: u32, gid: Option<u32>) -> std::io::Result<UnixListener> {
    prepare(path, mode, gid, |p| {
        let std_listener = std::os::unix::net::UnixListener::bind(p)?;
        std_listener.set_nonblocking(true)?;
        UnixListener::from_std(std_listener)
    })
}

/// Remove a stale socket file, bind, set mode and group.
pub(crate) fn prepare<T>(
    path: &Path,
    mode: u32,
    gid: Option<u32>,
    bind: impl FnOnce(&Path) -> std::io::Result<T>,
) -> std::io::Result<T> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let sock = bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    Ok(sock)
}

pub async fn serve(engine: Arc<Engine>, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let engine = engine.clone();
                tokio::spawn(handle(engine, stream));
            }
            Err(e) => {
                tracing::warn!(error = %e, "check accept failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn handle(engine: Arc<Engine>, mut stream: UnixStream) {
    let (r, mut w) = stream.split();
    let mut reader = BufReader::new(r).take(MAX_LINE);
    let mut line = Vec::with_capacity(256);
    let read = tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut line)).await;
    match read {
        Ok(Ok(n)) if n > 0 => {}
        _ => return,
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    let response = engine.check(&line);
    let _ = w.write_all(&response).await;
    let _ = w.shutdown().await;
}
