use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Buckets idle for longer than this are dropped by the periodic sweep.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// New keys are refused, not tracked, once this many are live; known keys keep working.
const MAX_KEYS: usize = 100_000;

struct Buckets<K> {
    map: HashMap<K, (f64, Instant)>,
    last_sweep: Instant,
}

/// Token bucket per key, refilled continuously at `per_minute`.
pub struct RateLimiter<K> {
    per_minute: f64,
    buckets: Mutex<Buckets<K>>,
}

/// Clients are limited per IPv4 address, and per /64 for IPv6, which is what one host usually gets.
pub fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            ))
        }
    }
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute: f64::from(per_minute.max(1)),
            buckets: Mutex::new(Buckets {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    pub fn allow(&self, key: &K) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &K, now: Instant) -> bool {
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        let full = self.per_minute;
        // Amortised: at most one pass a minute, however many requests arrive.
        if now.saturating_duration_since(buckets.last_sweep) >= SWEEP_EVERY {
            buckets.map.retain(|_, (tokens, at)| {
                *tokens + now.saturating_duration_since(*at).as_secs_f64() * full / 60.0 < full
            });
            buckets.last_sweep = now;
        }
        if !buckets.map.contains_key(key) && buckets.map.len() >= MAX_KEYS {
            return false;
        }
        let (tokens, at) = buckets.map.entry(key.clone()).or_insert((full, now));
        let refill = now.saturating_duration_since(*at).as_secs_f64() * full / 60.0;
        *tokens = (*tokens + refill).min(full);
        *at = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().map(|b| b.map.len()).unwrap_or(0)
    }
}

impl RateLimiter<IpAddr> {
    /// Limits by [`limiter_key`].
    pub fn allow_ip(&self, ip: IpAddr) -> bool {
        self.allow(&limiter_key(ip))
    }
}

/// Failures allowed before any delay.
const FREE_FAILURES: u32 = 5;
const MAX_DELAY: Duration = Duration::from_secs(15 * 60);

/// Server-wide exponential backoff after failed passphrase attempts, from any address.
pub struct FailureBackoff {
    state: Mutex<(u32, Option<Instant>)>,
}

impl Default for FailureBackoff {
    fn default() -> Self {
        Self {
            state: Mutex::new((0, None)),
        }
    }
}

impl FailureBackoff {
    /// How long to wait before another attempt is allowed, or `None` when one may go ahead.
    pub fn wait(&self) -> Option<Duration> {
        self.wait_at(Instant::now())
    }

    fn wait_at(&self, now: Instant) -> Option<Duration> {
        let Ok(state) = self.state.lock() else {
            return Some(MAX_DELAY);
        };
        let until = state.1?;
        let left = until.saturating_duration_since(now);
        (!left.is_zero()).then_some(left)
    }

    pub fn failed(&self) {
        self.failed_at(Instant::now());
    }

    fn failed_at(&self, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.0 = state.0.saturating_add(1);
        if state.0 <= FREE_FAILURES {
            return;
        }
        let exponent = (state.0 - FREE_FAILURES - 1).min(20);
        let delay = Duration::from_secs(1u64 << exponent).min(MAX_DELAY);
        state.1 = Some(now + delay);
    }

    pub fn succeeded(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = (0, None);
        }
    }

    /// Consecutive failures since the last success.
    pub fn failures(&self) -> u32 {
        self.state.lock().map(|s| s.0).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn limits_and_refills() {
        let limiter = RateLimiter::new(2);
        let start = Instant::now();
        assert!(limiter.allow_at(&"a", start));
        assert!(limiter.allow_at(&"a", start));
        assert!(!limiter.allow_at(&"a", start));
        assert!(limiter.allow_at(&"b", start));
        assert!(limiter.allow_at(&"a", start + Duration::from_secs(31)));
    }

    #[test]
    fn idle_buckets_are_swept_periodically() {
        let limiter = RateLimiter::new(60);
        let start = Instant::now();
        for i in 0..100u32 {
            assert!(limiter.allow_at(&i, start));
        }
        assert_eq!(limiter.len(), 100);
        assert!(limiter.allow_at(&1000, start + Duration::from_secs(5)));
        assert_eq!(limiter.len(), 101, "no sweep before a minute has passed");
        assert!(limiter.allow_at(&1001, start + SWEEP_EVERY + Duration::from_secs(1)));
        assert_eq!(limiter.len(), 1, "full buckets are dropped once refilled");
    }

    #[test]
    fn ipv6_addresses_share_a_bucket_per_64() -> anyhow::Result<()> {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().context("ip")?;
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().context("ip")?;
        let other: IpAddr = "2001:db8:1:3::1".parse().context("ip")?;
        assert_eq!(limiter_key(a), limiter_key(b));
        assert_ne!(limiter_key(a), limiter_key(other));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().context("ip")?;
        assert_eq!(limiter_key(mapped), "192.0.2.7".parse::<IpAddr>().context("ip")?);
        let limiter = RateLimiter::new(1);
        assert!(limiter.allow_ip(a));
        assert!(!limiter.allow_ip(b));
        assert!(limiter.allow_ip(other));
        Ok(())
    }

    #[test]
    fn failures_back_off_exponentially_until_a_success() {
        let backoff = FailureBackoff::default();
        let start = Instant::now();
        for _ in 0..FREE_FAILURES {
            backoff.failed_at(start);
            assert_eq!(backoff.wait_at(start), None);
        }
        backoff.failed_at(start);
        assert_eq!(backoff.wait_at(start), Some(Duration::from_secs(1)));
        backoff.failed_at(start);
        assert_eq!(backoff.wait_at(start), Some(Duration::from_secs(2)));
        backoff.failed_at(start);
        assert_eq!(backoff.wait_at(start), Some(Duration::from_secs(4)));
        assert_eq!(backoff.wait_at(start + Duration::from_secs(4)), None);
        for _ in 0..40 {
            backoff.failed_at(start);
        }
        assert_eq!(backoff.wait_at(start), Some(MAX_DELAY));
        backoff.succeeded();
        assert_eq!(backoff.wait_at(start), None);
        assert_eq!(backoff.failures(), 0);
    }
}
