//! Two simulated consoles and a fake relay, stepped together on one clock.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
pub mod console;
pub mod relay;

use console::Console;
use ldn_tunnel_core::ldn::LdnError;
use relay::Relay;

pub struct World {
    pub relay: Relay,
    pub c: Vec<Console>,
    pub now: u64,
}

impl World {
    pub fn new() -> Self {
        Self::with(2)
    }

    /// `n` consoles (1..=9).
    pub fn with(n: u8) -> Self {
        Self { relay: Relay::default(), c: (1..=n).map(Console::new).collect(), now: 1000 }
    }

    /// Run until nothing more happens at this instant.
    pub fn pump(&mut self) {
        for _ in 0..200 {
            let mut did = false;
            for c in &mut self.c {
                did |= c.pump(&mut self.relay, self.now);
            }
            if !did {
                return;
            }
        }
        panic!("the simulation does not settle");
    }

    pub fn advance(&mut self, ms: u64) {
        self.now += ms;
        self.pump();
    }

    /// The reply of console `i`'s pending request, stepping time in 10 ms until it arrives.
    pub fn wait(&mut self, i: usize) -> Result<(), LdnError> {
        for _ in 0..1500 {
            self.pump();
            if let Some(r) = self.c[i].replies.pop_front() {
                return r;
            }
            self.advance(10);
        }
        panic!("console {i}: no reply");
    }
}
