use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Buckets idle for longer than this are dropped by the periodic sweep.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Once this many keys are live, the least recently used are forgotten to make room.
const MAX_KEYS: usize = 100_000;
/// How many keys go at once when the map is full, so the scan is not repeated for every new key.
const EVICT_BATCH: usize = MAX_KEYS / 16;

/// Removes the `count` entries with the oldest timestamps.
fn evict_oldest<K: Eq + Hash + Clone, V>(map: &mut HashMap<K, V>, count: usize, at: impl Fn(&V) -> Instant) {
    let mut ages: Vec<Instant> = map.values().map(&at).collect();
    if count == 0 || ages.is_empty() {
        return;
    }
    let index = count.min(ages.len()) - 1;
    let (_, cutoff, _) = ages.select_nth_unstable(index);
    let cutoff = *cutoff;
    let mut removed = 0;
    map.retain(|_, value| {
        if removed < count && at(value) <= cutoff {
            removed += 1;
            return false;
        }
        true
    });
}

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
            evict_oldest(&mut buckets.map, EVICT_BATCH, |(_, at)| *at);
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

/// Failures allowed from one source before any delay, so a few typos never slow the owner down.
const FREE_FAILURES: u32 = 5;
/// The longest one source waits. Other sources are unaffected, so this can be long.
const MAX_DELAY: Duration = Duration::from_secs(300);
/// Failures from every source together, within [`GLOBAL_WINDOW`], before everyone pauses.
const GLOBAL_BURST: u32 = 20;
const GLOBAL_WINDOW: Duration = Duration::from_secs(10);
/// Short, so a flood from elsewhere can only hold the owner up for a few seconds.
const GLOBAL_PAUSE: Duration = Duration::from_secs(5);
/// Sources remembered at once; the least recently failed are forgotten first.
const MAX_SOURCES: usize = 10_000;

struct Source {
    failures: u32,
    until: Option<Instant>,
    last: Instant,
}

struct Failures {
    sources: HashMap<IpAddr, Source>,
    window_start: Instant,
    window_failures: u32,
    global_until: Option<Instant>,
}

/// Exponential back-off after wrong passphrases, per source address (or IPv6 /64), with a short
/// server-wide pause when failures arrive from many sources at once.
pub struct FailureBackoff {
    state: Mutex<Failures>,
}

impl Default for FailureBackoff {
    fn default() -> Self {
        Self {
            state: Mutex::new(Failures {
                sources: HashMap::new(),
                window_start: Instant::now(),
                window_failures: 0,
                global_until: None,
            }),
        }
    }
}

fn left(until: Option<Instant>, now: Instant) -> Option<Duration> {
    let left = until?.saturating_duration_since(now);
    (!left.is_zero()).then_some(left)
}

impl FailureBackoff {
    /// How long `ip` must wait before another attempt, or `None` when one may go ahead.
    pub fn wait(&self, ip: IpAddr) -> Option<Duration> {
        self.wait_at(ip, Instant::now())
    }

    fn wait_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let Ok(state) = self.state.lock() else {
            return Some(GLOBAL_PAUSE);
        };
        let own = state
            .sources
            .get(&limiter_key(ip))
            .and_then(|source| left(source.until, now));
        let global = left(state.global_until, now);
        own.max(global)
    }

    pub fn failed(&self, ip: IpAddr) {
        self.failed_at(ip, Instant::now());
    }

    fn failed_at(&self, ip: IpAddr, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if now.saturating_duration_since(state.window_start) >= GLOBAL_WINDOW {
            state.window_start = now;
            state.window_failures = 0;
        }
        state.window_failures = state.window_failures.saturating_add(1);
        if state.window_failures > GLOBAL_BURST {
            state.global_until = Some(now + GLOBAL_PAUSE);
        }
        let key = limiter_key(ip);
        if !state.sources.contains_key(&key) && state.sources.len() >= MAX_SOURCES {
            evict_oldest(&mut state.sources, MAX_SOURCES / 16, |s| s.last);
        }
        let source = state.sources.entry(key).or_insert(Source {
            failures: 0,
            until: None,
            last: now,
        });
        source.failures = source.failures.saturating_add(1);
        source.last = now;
        if source.failures <= FREE_FAILURES {
            return;
        }
        let exponent = (source.failures - FREE_FAILURES - 1).min(20);
        source.until = Some(now + Duration::from_secs(1u64 << exponent).min(MAX_DELAY));
    }

    /// Clears `ip`'s failures; other sources keep theirs.
    pub fn succeeded(&self, ip: IpAddr) {
        if let Ok(mut state) = self.state.lock() {
            state.sources.remove(&limiter_key(ip));
        }
    }

    /// Consecutive failures from `ip` since its last success.
    pub fn failures(&self, ip: IpAddr) -> u32 {
        self.state
            .lock()
            .map(|s| s.sources.get(&limiter_key(ip)).map_or(0, |source| source.failures))
            .unwrap_or(u32::MAX)
    }
}

/// A wait rounded up, so the exact back-off is not revealed: to 5 seconds below a minute, then to
/// the next minute.
pub fn rounded_wait(wait: Duration) -> u64 {
    let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    let step = if secs < 60 { 5 } else { 60 };
    secs.max(1).div_ceil(step) * step
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
    fn failures_back_off_exponentially_until_a_success() -> anyhow::Result<()> {
        let backoff = FailureBackoff::default();
        let ip: IpAddr = "198.51.100.7".parse().context("ip")?;
        // Spaced out, so the server-wide burst never triggers here.
        let mut now = Instant::now();
        let mut fail = |backoff: &FailureBackoff| {
            now += GLOBAL_WINDOW;
            backoff.failed_at(ip, now);
            now
        };
        for _ in 0..FREE_FAILURES {
            let at = fail(&backoff);
            assert_eq!(backoff.wait_at(ip, at), None);
        }
        let mut delays = Vec::new();
        for _ in 0..12 {
            let at = fail(&backoff);
            delays.extend(backoff.wait_at(ip, at));
        }
        assert_eq!(
            &delays[..10],
            [1, 2, 4, 8, 16, 32, 64, 128, 256, 300].map(Duration::from_secs),
            "doubling stops at the cap"
        );
        assert!(delays.iter().all(|d| *d <= MAX_DELAY));
        backoff.succeeded(ip);
        assert_eq!(backoff.wait_at(ip, now), None);
        assert_eq!(backoff.failures(ip), 0);
        Ok(())
    }

    #[test]
    fn one_guess_a_minute_elsewhere_never_locks_the_owner_out() -> anyhow::Result<()> {
        let backoff = FailureBackoff::default();
        let attacker: IpAddr = "203.0.113.9".parse().context("ip")?;
        let owner: IpAddr = "192.0.2.10".parse().context("ip")?;
        let start = Instant::now();
        for minute in 0..120u64 {
            let at = start + Duration::from_secs(60 * minute);
            backoff.failed_at(attacker, at);
            assert_eq!(backoff.wait_at(owner, at), None, "minute {minute}");
        }
        assert!(
            backoff
                .wait_at(attacker, start + Duration::from_secs(60 * 119))
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn a_flood_from_many_sources_pauses_everyone_only_briefly() -> anyhow::Result<()> {
        let backoff = FailureBackoff::default();
        let owner: IpAddr = "192.0.2.10".parse().context("ip")?;
        let start = Instant::now();
        for i in 0..=GLOBAL_BURST {
            let source = IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]);
            backoff.failed_at(source, start);
        }
        let wait = backoff.wait_at(owner, start).context("a global pause")?;
        assert!(wait <= GLOBAL_PAUSE, "{wait:?}");
        assert_eq!(backoff.wait_at(owner, start + GLOBAL_PAUSE), None);
        Ok(())
    }

    #[test]
    fn sources_are_forgotten_oldest_first_when_full() -> anyhow::Result<()> {
        let backoff = FailureBackoff::default();
        let start = Instant::now();
        let first: IpAddr = "10.0.0.1".parse().context("ip")?;
        for _ in 0..=FREE_FAILURES {
            backoff.failed_at(first, start);
        }
        for i in 0..MAX_SOURCES as u32 {
            let at = start + GLOBAL_WINDOW * (i + 1);
            backoff.failed_at(IpAddr::from((u32::from_be_bytes([11, 0, 0, 0]) + i).to_be_bytes()), at);
        }
        assert_eq!(backoff.failures(first), 0, "the oldest source made room");
        Ok(())
    }

    #[test]
    fn waits_are_rounded_up() {
        assert_eq!(rounded_wait(Duration::from_millis(1)), 5);
        assert_eq!(rounded_wait(Duration::from_secs(5)), 5);
        assert_eq!(rounded_wait(Duration::from_secs(6)), 10);
        assert_eq!(rounded_wait(Duration::from_secs(59)), 60);
        assert_eq!(rounded_wait(Duration::from_secs(61)), 120);
    }

    #[test]
    fn a_full_limiter_forgets_its_oldest_keys_instead_of_refusing() {
        let limiter = RateLimiter::new(1);
        let start = Instant::now();
        assert!(limiter.allow_at(&0u32, start));
        for i in 1..MAX_KEYS as u32 {
            assert!(limiter.allow_at(&i, start + Duration::from_micros(u64::from(i))));
        }
        assert_eq!(limiter.len(), MAX_KEYS);
        let late = start + Duration::from_secs(1);
        assert!(limiter.allow_at(&u32::MAX, late), "a new key is still served");
        assert!(limiter.len() <= MAX_KEYS);
        assert!(
            limiter.allow_at(&0u32, late),
            "the oldest was forgotten, so its bucket is fresh"
        );
    }
}
