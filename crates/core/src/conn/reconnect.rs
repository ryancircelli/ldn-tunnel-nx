//! Reconnect backoff (port of `network/reconnect.cpp`, ReconnectManager). Pure: the caller
//! supplies the random seed for the jitter and the clock.

/// Mirrors `ReconnectConfig`. `max_retries == 0` means never retry, like the C++.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconnectConfig {
    pub initial_delay_ms: u32,
    pub max_delay_ms: u32,
    pub multiplier_percent: u16,
    pub jitter_percent: u8,
    pub max_retries: u16,
    pub fast_retries: u8,
    pub fast_delay_ms: u32,
}

impl ReconnectConfig {
    /// What the relay client uses (client.cpp: `RyuLdnClientConfig(cfg)`): a fast first
    /// retry after 200 ms, then 1 s doubling up to 10 s, +-10 % jitter, give up after 10.
    pub const RELAY: Self = Self {
        initial_delay_ms: 1000,
        max_delay_ms: 10_000,
        multiplier_percent: 200,
        jitter_percent: 10,
        max_retries: 10,
        fast_retries: 1,
        fast_delay_ms: 200,
    };
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self::RELAY
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryResult {
    ShouldRetry,
    MaxRetriesReached,
}

#[derive(Clone, Copy, Debug)]
pub struct Reconnect {
    cfg: ReconnectConfig,
    retry_count: u32,
    current_delay_ms: u32,
}

impl Reconnect {
    pub const fn new(cfg: ReconnectConfig) -> Self {
        let mut r = Self { cfg, retry_count: 0, current_delay_ms: 0 };
        r.calculate_delay();
        r
    }

    const fn calculate_delay(&mut self) {
        let c = &self.cfg;
        if self.retry_count < c.fast_retries as u32 {
            self.current_delay_ms = c.fast_delay_ms;
            return;
        }
        let mut delay = c.initial_delay_ms;
        let mut left = self.retry_count.saturating_sub(c.fast_retries as u32);
        // multiplier 0 would divide by zero in the C++; treat it as "no growth"
        let mult = if c.multiplier_percent == 0 { 100 } else { c.multiplier_percent as u64 };
        while left > 0 {
            let next = (delay as u64).saturating_mul(mult) / 100;
            if next >= c.max_delay_ms as u64 {
                delay = c.max_delay_ms;
                break;
            }
            delay = next as u32;
            left = left.saturating_sub(1);
        }
        self.current_delay_ms = delay;
    }

    pub const fn config(&self) -> &ReconnectConfig {
        &self.cfg
    }

    pub const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Delay for the next retry, without jitter.
    pub const fn next_delay_ms(&self) -> u32 {
        self.current_delay_ms
    }

    /// The same delay with +-`jitter_percent` taken from an xorshift32 of `seed`, kept in
    /// `1..=max_delay_ms`.
    pub fn next_delay_ms_with_jitter(&self, seed: u32) -> u32 {
        if self.cfg.jitter_percent == 0 {
            return self.current_delay_ms;
        }
        let mut h = seed;
        h ^= h << 13;
        h ^= h >> 17;
        h ^= h << 5;
        let jp = u32::from(self.cfg.jitter_percent);
        let span = jp.saturating_mul(2).saturating_add(1);
        let offset = i64::from(h.checked_rem(span).unwrap_or(0)).saturating_sub(i64::from(jp));
        let adjusted = i64::from(self.current_delay_ms).saturating_mul(offset.saturating_add(100)) / 100;
        adjusted.clamp(1, i64::from(self.cfg.max_delay_ms).max(1)) as u32
    }

    pub const fn should_retry(&self) -> RetryResult {
        if self.cfg.max_retries == 0 || self.retry_count >= self.cfg.max_retries as u32 {
            RetryResult::MaxRetriesReached
        } else {
            RetryResult::ShouldRetry
        }
    }

    /// Count a failed attempt and compute the delay after it.
    pub const fn record_failure(&mut self) {
        self.retry_count = self.retry_count.saturating_add(1);
        self.calculate_delay();
    }

    pub const fn reset(&mut self) {
        self.retry_count = 0;
        self.calculate_delay();
    }

    /// The step the client takes after a failure: `Some(delay)` (jittered; the failure is
    /// counted after taking it, so the first retry gets the fast delay) or `None` once the
    /// attempts are used up.
    pub fn next_retry(&mut self, seed: u32) -> Option<u32> {
        if self.should_retry() != RetryResult::ShouldRetry {
            return None;
        }
        let d = self.next_delay_ms_with_jitter(seed);
        self.record_failure();
        Some(d)
    }
}

impl Default for Reconnect {
    fn default() -> Self {
        Self::new(ReconnectConfig::RELAY)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg() -> ReconnectConfig {
        ReconnectConfig { jitter_percent: 0, ..ReconnectConfig::RELAY }
    }

    #[test]
    fn schedule_without_jitter() {
        let mut r = Reconnect::new(cfg());
        let got: [Option<u32>; 12] = core::array::from_fn(|_| r.next_retry(0));
        // 200 fast, then 1000, 2000, 4000, 8000, capped at 10000; ten attempts then None
        assert_eq!(
            got,
            [
                Some(200), Some(1000), Some(2000), Some(4000), Some(8000),
                Some(10_000), Some(10_000), Some(10_000), Some(10_000), Some(10_000),
                None, None
            ]
        );
        assert_eq!(r.retry_count(), 10);
        r.reset();
        assert_eq!((r.retry_count(), r.next_delay_ms()), (0, 200));
        assert_eq!(r.should_retry(), RetryResult::ShouldRetry);
    }

    #[test]
    fn defaults_and_zero_max_retries() {
        let d = Reconnect::default();
        assert_eq!(d.config().max_retries, 10);
        let never = Reconnect::new(ReconnectConfig { max_retries: 0, ..cfg() });
        assert_eq!(never.should_retry(), RetryResult::MaxRetriesReached);
    }

    #[test]
    fn no_fast_retry_starts_at_initial() {
        let r = Reconnect::new(ReconnectConfig { fast_retries: 0, ..cfg() });
        assert_eq!(r.next_delay_ms(), 1000);
    }

    #[test]
    fn jitter_bounds_and_variation() {
        let mut r = Reconnect::new(ReconnectConfig::RELAY);
        r.record_failure(); // 1000 ms base
        let mut seen = [0u32; 3];
        for (i, seed) in [12345u32, 54321, 99999].into_iter().enumerate() {
            seen[i] = r.next_delay_ms_with_jitter(seed);
            assert!((900..=1100).contains(&seen[i]), "{}", seen[i]);
            assert_eq!(seen[i], r.next_delay_ms_with_jitter(seed), "deterministic");
        }
        assert!(seen[0] != seen[1] || seen[1] != seen[2]);
        for seed in 0..5000u32 {
            let d = r.next_delay_ms_with_jitter(seed.wrapping_mul(2_654_435_761));
            assert!((900..=1100).contains(&d));
        }
        // clamped to max_delay_ms
        let mut top = Reconnect::new(ReconnectConfig::RELAY);
        for _ in 0..8 {
            top.record_failure();
        }
        for seed in 0..1000u32 {
            assert!(top.next_delay_ms_with_jitter(seed) <= 10_000);
        }
    }

    #[test]
    fn extreme_config_does_not_overflow() {
        let r = Reconnect::new(ReconnectConfig {
            initial_delay_ms: u32::MAX,
            max_delay_ms: u32::MAX,
            multiplier_percent: u16::MAX,
            jitter_percent: 100,
            max_retries: u16::MAX,
            fast_retries: 0,
            fast_delay_ms: u32::MAX,
        });
        let mut r = r;
        for _ in 0..100 {
            r.record_failure();
            let _ = r.next_delay_ms_with_jitter(7);
        }
        let z = Reconnect::new(ReconnectConfig { multiplier_percent: 0, ..ReconnectConfig::RELAY });
        let _ = z.next_delay_ms_with_jitter(1);
    }
}
