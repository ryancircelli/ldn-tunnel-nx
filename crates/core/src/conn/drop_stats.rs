//! One relay link's facts, for the single Info line logged when it ends (who cut it):
//!
//! `relay: link ended: age=412s how=tls-close_notify idle_rx=180ms idle_tx=40ms in=1234567B/8000r out=2345678B/9000w ray=8f3a1b2c3d4e5f60-IAD`
//!
//! `how`: `we-closed(<why>)` | `ws-close(<code>)` (the relay sent a WebSocket Close) |
//! `tls-close_notify` (TLS closed cleanly with no WebSocket Close: whoever terminates TLS, i.e.
//! the Cloudflare edge, hung up) | `tcp-eof-no-close_notify` (TCP FIN without TLS close: a
//! middlebox or a crashed peer) | `io(<error>)` (e.g. `Io(Errno(104))` = reset) |
//! `silence-timeout` (ours: nothing in or out for 30 s) | another [`Failure`].
//! `ray` is the `cf-ray` header of the upgrade response; its suffix is the edge colo.
use core::fmt;

use heapless::String;

use super::Failure;

const KEY: &[u8] = b"\ncf-ray:";
const HEAD_END: u32 = u32::from_be_bytes(*b"\r\n\r\n");

/// Kept from the TCP+TLS open until the link is dropped.
#[derive(Clone, Debug)]
pub struct LinkStats {
    up_ms: u64,
    ray: String<40>,
    /// Upgrade-response scan: bytes of [`KEY`] matched, inside the value, past the head.
    matched: usize,
    in_value: bool,
    head_done: bool,
    last4: u32,
}

/// What the shell gathers when the link drops.
#[derive(Clone, Copy, Debug, Default)]
pub struct Io<'a> {
    /// TLS plaintext bytes and the read/write calls that moved them.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub reads: u32,
    pub writes: u32,
    /// `Conn` clock of the last byte received / sent.
    pub last_rx_ms: u64,
    pub last_tx_ms: u64,
    /// How the TLS stream ended (`ldn_tunnel_tls::Stats::end`).
    pub tls_end: Option<&'a str>,
}

impl LinkStats {
    pub fn new(now_ms: u64) -> Self {
        Self { up_ms: now_ms, ray: String::new(), matched: 0, in_value: false, head_done: false, last4: 0 }
    }

    /// Every chunk read from the stream; picks `cf-ray` out of the upgrade response head
    /// (header split across reads is fine) and ignores everything after it.
    pub fn on_rx(&mut self, data: &[u8]) {
        for &b in data {
            if self.head_done {
                return;
            }
            self.last4 = (self.last4 << 8) | u32::from(b);
            if self.last4 == HEAD_END {
                self.head_done = true;
            } else if self.in_value {
                if b == b'\r' || b == b'\n' {
                    self.in_value = false;
                } else if b.is_ascii_graphic() {
                    let _ = self.ray.push(char::from(b));
                }
            } else {
                self.matched = match KEY.get(self.matched) {
                    Some(&k) if b.to_ascii_lowercase() == k => self.matched.saturating_add(1),
                    _ => usize::from(b == b'\n'),
                };
                if self.matched == KEY.len() {
                    self.in_value = self.ray.is_empty();
                    self.matched = 0;
                }
            }
        }
    }

    /// `cf-ray` of the upgrade response ("" when the relay is not behind Cloudflare).
    pub fn ray(&self) -> &str {
        &self.ray
    }

    /// The line for a link that ends now. `closing`: we closed it, and why.
    pub fn ended<'a>(&'a self, now_ms: u64, closing: Option<&'a str>, failure: Option<Failure>, io: Io<'a>) -> Ended<'a> {
        Ended { s: self, now_ms, closing, failure, io }
    }
}

pub struct Ended<'a> {
    s: &'a LinkStats,
    now_ms: u64,
    closing: Option<&'a str>,
    failure: Option<Failure>,
    io: Io<'a>,
}

impl fmt::Display for Ended<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { s, now_ms, closing, failure, io } = self;
        let ago = |t: u64| now_ms.saturating_sub(t);
        write!(f, "relay: link ended: age={}s how=", ago(s.up_ms) / 1000)?;
        match (closing, failure, io.tls_end) {
            (Some(why), ..) => write!(f, "we-closed({why})")?,
            (_, Some(Failure::PeerClosed(c)), _) => write!(f, "ws-close({c})")?,
            (_, Some(Failure::Silent), _) => f.write_str("silence-timeout")?,
            (_, Some(Failure::Transport), Some("close_notify")) => f.write_str("tls-close_notify")?,
            (_, Some(Failure::Transport), Some("UnexpectedEof")) => f.write_str("tcp-eof-no-close_notify")?,
            (_, Some(Failure::Transport), Some(e)) => write!(f, "io({e})")?,
            (_, Some(other), _) => write!(f, "{other:?}")?,
            (_, None, _) => f.write_str("unknown")?,
        }
        write!(
            f,
            " idle_rx={}ms idle_tx={}ms in={}B/{}r out={}B/{}w ray={}",
            ago(io.last_rx_ms),
            ago(io.last_tx_ms),
            io.rx_bytes,
            io.reads,
            io.tx_bytes,
            io.writes,
            if s.ray.is_empty() { "-" } else { &s.ray }
        )
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    const HEAD: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nCF-RAY: 8f3a1b2c3d4e5f60-IAD\r\nServer: cloudflare\r\n\r\n\x82\x05cf-ray: nope";

    #[test]
    fn ray_from_upgrade_head_in_any_split() {
        for cut in 0..HEAD.len() {
            let mut s = LinkStats::new(0);
            s.on_rx(&HEAD[..cut]);
            s.on_rx(&HEAD[cut..]);
            assert_eq!(s.ray(), "8f3a1b2c3d4e5f60-IAD", "cut at {cut}");
        }
        let mut s = LinkStats::new(0);
        s.on_rx(b"HTTP/1.1 101 OK\r\nx-cf-ray: no\r\n\r\ncf-ray: no\r\n");
        assert_eq!(s.ray(), "");
    }

    #[test]
    fn line_names_how_it_ended() {
        let mut s = LinkStats::new(1_000);
        s.on_rx(HEAD);
        let io = Io { rx_bytes: 5000, tx_bytes: 7000, reads: 50, writes: 70, last_rx_ms: 412_820, last_tx_ms: 412_960, tls_end: Some("close_notify") };
        let line = |c, f, io| format!("{}", s.ended(413_000, c, f, io));
        assert_eq!(
            line(None, Some(Failure::Transport), io),
            "relay: link ended: age=412s how=tls-close_notify idle_rx=180ms idle_tx=40ms in=5000B/50r out=7000B/70w ray=8f3a1b2c3d4e5f60-IAD"
        );
        let how = |c, f, end| {
            let l = line(c, f, Io { tls_end: end, ..io });
            l.split(' ').nth(4).unwrap().into()
        };
        let h: std::string::String = how(None, Some(Failure::Transport), Some("UnexpectedEof"));
        assert_eq!(h, "how=tcp-eof-no-close_notify");
        assert_eq!(how(None, Some(Failure::Transport), Some("Io(Errno(104))")), "how=io(Io(Errno(104)))");
        assert_eq!(how(None, Some(Failure::PeerClosed(1001)), None), "how=ws-close(1001)");
        assert_eq!(how(None, Some(Failure::Silent), Some("close_notify")), "how=silence-timeout");
        assert_eq!(how(Some("the session ended"), Some(Failure::Transport), None), "how=we-closed(the");
        assert_eq!(how(None, Some(Failure::Protocol), None), "how=Protocol");
        assert!(format!("{}", LinkStats::new(0).ended(0, None, None, Io::default())).ends_with("ray=-"));
    }
}
