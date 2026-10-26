//! Ephemeral port pool (port of C++ `EphemeralPortPool`): a bitset over
//! 49152..=65535 with a round-robin hint. Ports below the range are not
//! tracked, so reserving one always succeeds (two sockets may share a
//! well-known port, as PIA does).

pub const EPHEMERAL_MIN: u16 = 49152;
const COUNT: usize = 65536 - EPHEMERAL_MIN as usize;

pub struct PortPool {
    bits: [u64; COUNT / 64],
    hint: usize,
}

impl PortPool {
    pub const fn new() -> Self {
        Self { bits: [0; COUNT / 64], hint: 0 }
    }

    fn index(port: u16) -> Option<usize> {
        port.checked_sub(EPHEMERAL_MIN).map(usize::from)
    }

    fn word(&mut self, i: usize) -> Option<(&mut u64, u64)> {
        Some((self.bits.get_mut(i / 64)?, 1u64 << (i % 64)))
    }

    fn test(&self, i: usize) -> bool {
        self.bits.get(i / 64).is_some_and(|w| w & (1u64 << (i % 64)) != 0)
    }

    /// Next free ephemeral port after the last one handed out; `None` when all are taken.
    pub fn allocate(&mut self) -> Option<u16> {
        let i = (0..COUNT).map(|n| self.hint.wrapping_add(n) % COUNT).find(|&i| !self.test(i))?;
        let (w, m) = self.word(i)?;
        *w |= m;
        self.hint = i.wrapping_add(1) % COUNT;
        u16::try_from(i).ok()?.checked_add(EPHEMERAL_MIN)
    }

    /// Claims a specific port; false if it is an ephemeral port already taken.
    pub fn reserve(&mut self, port: u16) -> bool {
        let Some((w, m)) = Self::index(port).and_then(|i| self.word(i)) else { return true };
        let free = *w & m == 0;
        *w |= m;
        free
    }

    pub fn release(&mut self, port: u16) {
        if let Some((w, m)) = Self::index(port).and_then(|i| self.word(i)) {
            *w &= !m;
        }
    }

    #[cfg(test)]
    pub fn available(&self) -> usize {
        COUNT.saturating_sub(self.bits.iter().map(|w| w.count_ones() as usize).sum())
    }

    pub fn release_all(&mut self) {
        *self = Self::new();
    }
}
