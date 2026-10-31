//! Helpers for tests that run the real `sekret` binary: the server listens on a port the kernel
//! picks and the test reads the bound address back from the log.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use crate::LISTENING_TARGET;

/// What the listening line says just before the address.
const LISTENING: &str = "listening on ";

#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    #[error("server exited with {status} before listening:\n{log}")]
    Exited { status: ExitStatus, log: String },
    #[error("server did not report its address within {timeout:?}:\n{log}")]
    Timeout { timeout: Duration, log: String },
    #[error("waiting for the server: {0}")]
    Io(#[from] std::io::Error),
}

impl ListenError {
    /// Whether the server failed because another process bound its port first.
    pub fn lost_port(&self) -> bool {
        match self {
            Self::Exited { log, .. } => lost_port(log),
            _ => false,
        }
    }
}

/// Whether a server log shows that its port was already taken.
pub fn lost_port(log: &str) -> bool {
    log.to_ascii_lowercase().contains("address already in use")
}

/// A `SEKRET_LOG` value at `level` that still keeps the listening line.
pub fn log_filter(level: &str) -> String {
    format!("{level},{LISTENING_TARGET}=info")
}

pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for next in chars.by_ref() {
            if next.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

/// The log file's text without colour codes, or empty when it cannot be read.
pub fn read_log(path: &Path) -> String {
    strip_ansi(&std::fs::read_to_string(path).unwrap_or_default())
}

/// The address from the first listening line in `log`.
pub fn listening_address(log: &str) -> Option<SocketAddr> {
    log.lines().find_map(|line| {
        let (_, rest) = line.split_once(LISTENING)?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// Polls the server's log until it names the address it bound.
pub async fn wait_for_listening(child: &mut Child, log: &Path, timeout: Duration) -> Result<SocketAddr, ListenError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(address) = listening_address(&read_log(log)) {
            return Ok(address);
        }
        if let Some(status) = child.try_wait()? {
            return Err(ListenError::Exited {
                status,
                log: read_log(log),
            });
        }
        if Instant::now() >= deadline {
            return Err(ListenError::Timeout {
                timeout,
                log: read_log(log),
            });
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A loopback port bound by the test so nothing else can take it until it is released.
pub struct HeldPort {
    listener: TcpListener,
}

impl HeldPort {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind("127.0.0.1:0")?,
        })
    }

    pub fn port(&self) -> std::io::Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }

    /// Frees the port for a server about to start; the caller retries if something else wins it.
    pub fn release(self) -> std::io::Result<u16> {
        self.port()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_address_in_a_coloured_line() {
        let log = "\u{1b}[2m2026-10-31T10:00:00Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \
                   \u{1b}[2msekret_server::listening\u{1b}[0m\u{1b}[2m:\u{1b}[0m listening on 127.0.0.1:43123 \
                   \u{1b}[3murl\u{1b}[0m\u{1b}[2m=\u{1b}[0mhttp://127.0.0.1";
        assert_eq!(
            listening_address(&strip_ansi(log)),
            Some(SocketAddr::from(([127, 0, 0, 1], 43123)))
        );
    }

    #[test]
    fn no_address_until_the_line_appears() {
        assert_eq!(listening_address("INFO sekret_server: starting\n"), None);
        assert_eq!(listening_address(""), None);
    }

    #[test]
    fn a_taken_port_is_recognised() {
        assert!(lost_port("Error: io: Address already in use (os error 98)"));
        assert!(!lost_port("Error: io: permission denied"));
    }

    #[test]
    fn the_filter_keeps_the_listening_line() {
        assert_eq!(log_filter("warn"), "warn,sekret_server::listening=info");
    }

    #[test]
    fn a_released_port_is_the_one_held() -> std::io::Result<()> {
        let held = HeldPort::new()?;
        let port = held.port()?;
        assert_ne!(port, 0);
        assert_eq!(held.release()?, port);
        Ok(())
    }
}
