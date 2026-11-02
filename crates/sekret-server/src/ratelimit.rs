use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sekret_store::AuditEntry;

/// Buckets idle for longer than this are dropped by the periodic sweep.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Once this many keys are live, the least recently used are forgotten to make room.
const MAX_KEYS: usize = 100_000;
/// How many keys go at once when the map is full, so the scan is not repeated for every new key.
const EVICT_BATCH: usize = MAX_KEYS / 16;

/// Removes the `count` entries with the oldest timestamps.
fn evict_oldest<K: Eq + Hash + Clone, V>(map: &mut HashMap<K, V>, count: usize, at: impl Fn(&V) -> Instant) {
    take_oldest(map, count, at);
}

/// Removes and returns the `count` entries with the oldest timestamps.
fn take_oldest<K: Eq + Hash + Clone, V>(map: &mut HashMap<K, V>, count: usize, at: impl Fn(&V) -> Instant) -> Vec<V> {
    let mut ages: Vec<(Instant, K)> = map.iter().map(|(k, v)| (at(v), k.clone())).collect();
    if count == 0 || ages.is_empty() {
        return Vec::new();
    }
    let index = count.min(ages.len()) - 1;
    ages.select_nth_unstable_by_key(index, |(age, _)| *age);
    ages.truncate(index + 1);
    ages.into_iter().filter_map(|(_, key)| map.remove(&key)).collect()
}

struct Buckets<K> {
    map: HashMap<K, (f64, Instant)>,
    last_sweep: Instant,
}

/// Token bucket per key, refilled continuously at `per_minute` up to `capacity`.
pub struct RateLimiter<K> {
    capacity: f64,
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

/// A whole network rather than one host: the IPv4 /24 or IPv6 /48 that `ip` is in, which one
/// party can easily hold many addresses of.
pub fn prefix_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            IpAddr::V4(Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            IpAddr::V6(Ipv6Addr::new(segments[0], segments[1], segments[2], 0, 0, 0, 0, 0))
        }
    }
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(per_minute: u32) -> Self {
        let per_minute = f64::from(per_minute.max(1));
        Self::with_rate(per_minute, per_minute)
    }

    /// `per_hour` at once, then one more every hour / `per_hour`.
    pub fn per_hour(per_hour: u32) -> Self {
        let per_hour = f64::from(per_hour.max(1));
        Self::with_rate(per_hour, per_hour / 60.0)
    }

    fn with_rate(capacity: f64, per_minute: f64) -> Self {
        Self {
            capacity,
            per_minute,
            buckets: Mutex::new(Buckets {
                map: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    pub fn allow(&self, key: &K) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// Whether `key` has nothing left, without using anything.
    pub fn exhausted(&self, key: &K) -> bool {
        self.exhausted_at(key, Instant::now())
    }

    fn refilled(&self, tokens: f64, since: Instant, now: Instant) -> f64 {
        let refill = now.saturating_duration_since(since).as_secs_f64() * self.per_minute / 60.0;
        (tokens + refill).min(self.capacity)
    }

    fn exhausted_at(&self, key: &K, now: Instant) -> bool {
        let Ok(buckets) = self.buckets.lock() else {
            return true;
        };
        buckets
            .map
            .get(key)
            .is_some_and(|(tokens, at)| self.refilled(*tokens, *at, now) < 1.0)
    }

    fn allow_at(&self, key: &K, now: Instant) -> bool {
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        let full = self.capacity;
        // Amortised: at most one pass a minute, however many requests arrive.
        if now.saturating_duration_since(buckets.last_sweep) >= SWEEP_EVERY {
            buckets
                .map
                .retain(|_, (tokens, at)| self.refilled(*tokens, *at, now) < full);
            buckets.last_sweep = now;
        }
        if !buckets.map.contains_key(key) && buckets.map.len() >= MAX_KEYS {
            evict_oldest(&mut buckets.map, EVICT_BATCH, |(_, at)| *at);
        }
        let (tokens, at) = buckets.map.entry(key.clone()).or_insert((full, now));
        *tokens = self.refilled(*tokens, *at, now);
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
    last_eviction: Option<Instant>,
}

/// How long after forgetting sources the back-off stays wary of new ones.
const LOAD_MEMORY: Duration = Duration::from_secs(600);

/// Exponential back-off after wrong passphrases, per source address (or IPv6 /64), with a short
/// pause for every source that has failed when failures arrive from many sources at once.
/// Sources that have never failed are not paused.
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
                last_eviction: None,
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

    /// A source with no failures never waits, so a flood of wrong guesses from elsewhere cannot
    /// pause the owner; it waits its turn for the derivation instead.
    fn wait_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let Ok(state) = self.state.lock() else {
            return Some(GLOBAL_PAUSE);
        };
        let source = state.sources.get(&limiter_key(ip))?;
        let own = left(source.until, now);
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
            state.last_eviction = Some(now);
        }
        // While sources are being forgotten, one may be an evicted one coming back, so new
        // sources get one free failure rather than a fresh allowance.
        let under_load = state
            .last_eviction
            .is_some_and(|at| now.saturating_duration_since(at) < LOAD_MEMORY);
        let source = state.sources.entry(key).or_insert(Source {
            failures: if under_load { FREE_FAILURES - 1 } else { 0 },
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

/// Wrong passphrases through the host socket allowed before any delay.
pub const HOST_FREE_FAILURES: u32 = 5;
/// The longest the host socket waits. Short, since the host is how the owner recovers.
pub const HOST_MAX_DELAY: i64 = 30;

#[derive(Default)]
struct HostFailures {
    failures: u32,
    until: i64,
}

/// Back-off after wrong passphrases through the host socket, shared by everyone who can reach
/// it. Times are Unix seconds from the server's clock.
#[derive(Default)]
pub struct HostBackoff {
    state: Mutex<HostFailures>,
}

impl HostBackoff {
    /// How long the next attempt must wait, or `None` when it may go ahead.
    pub fn wait(&self, now: i64) -> Option<Duration> {
        let Ok(state) = self.state.lock() else {
            return Some(Duration::from_secs(1));
        };
        let left = state.until.saturating_sub(now);
        (left > 0).then(|| Duration::from_secs(left.unsigned_abs()))
    }

    pub fn failed(&self, now: i64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.failures = state.failures.saturating_add(1);
        if state.failures <= HOST_FREE_FAILURES {
            return;
        }
        let exponent = (state.failures - HOST_FREE_FAILURES - 1).min(20);
        state.until = now.saturating_add((1i64 << exponent).min(HOST_MAX_DELAY));
    }

    pub fn succeeded(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = HostFailures::default();
        }
    }

    /// Consecutive wrong passphrases since the last right one.
    pub fn failures(&self) -> u32 {
        self.state.lock().map(|s| s.failures).unwrap_or(u32::MAX)
    }
}

/// Refusals repeated within this long are counted rather than each written.
const REFUSAL_WINDOW: Duration = Duration::from_secs(60);
/// Callers and sources remembered at once; the least recently refused are forgotten first.
const MAX_REFUSAL_KEYS: usize = 10_000;
/// Windows opened across all keys in a minute before further new keys share one per action.
const MAX_NEW_WINDOWS: u32 = 1_000;

struct Folded {
    started: Instant,
    last: Instant,
    repeats: u32,
    latest: AuditEntry,
}

impl Folded {
    fn open(now: Instant, entry: AuditEntry) -> Self {
        Self {
            started: now,
            last: now,
            repeats: 0,
            latest: entry,
        }
    }
}

/// Folds a flood of refusal audit entries into one entry a minute per key, typically a caller
/// and source, with a count of the repeats, so refusals cannot flood the audit log.
#[derive(Default)]
pub struct AuditThrottle {
    keys: Mutex<HashMap<String, Folded>>,
    /// When the current minute of new windows began, and how many have opened in it.
    opened: Mutex<(Option<Instant>, u32)>,
}

impl AuditThrottle {
    /// The entries to write now for `entry`: itself when it opens a window, after the previous
    /// window's summary if that one had repeats; nothing when it falls inside an open window.
    pub fn admit(&self, key: String, entry: AuditEntry) -> Vec<AuditEntry> {
        self.admit_at(key, entry, Instant::now())
    }

    pub fn admit_at(&self, key: String, entry: AuditEntry, now: Instant) -> Vec<AuditEntry> {
        let Ok(mut keys) = self.keys.lock() else {
            return vec![entry];
        };
        let mut key = key;
        if !keys.contains_key(&key) && !self.may_open_window(now) {
            // Past the overall cap, every new caller and source shares one window per action.
            key = format!("overflow|{}", entry.action);
        }
        if let Some(folded) = keys.get_mut(&key)
            && now.saturating_duration_since(folded.started) < REFUSAL_WINDOW
        {
            folded.repeats = folded.repeats.saturating_add(1);
            folded.last = now;
            folded.latest = entry;
            return Vec::new();
        }
        let mut written = Vec::new();
        if !keys.contains_key(&key) && keys.len() >= MAX_REFUSAL_KEYS {
            let evicted = take_oldest(&mut keys, MAX_REFUSAL_KEYS / 16, |f| f.last);
            written.extend(evicted.into_iter().filter_map(summary));
        }
        let previous = keys.insert(key, Folded::open(now, entry.clone()));
        written.extend(previous.and_then(summary));
        written.push(entry);
        written
    }

    /// Counts a new window against the overall cap, answering whether it is still under it.
    fn may_open_window(&self, now: Instant) -> bool {
        let Ok(mut opened) = self.opened.lock() else {
            return true;
        };
        let (since, count) = &mut *opened;
        if since.is_none_or(|s| now.saturating_duration_since(s) >= REFUSAL_WINDOW) {
            *since = Some(now);
            *count = 0;
        }
        *count = count.saturating_add(1);
        *count <= MAX_NEW_WINDOWS
    }

    /// Summaries of windows that have closed with repeats in them; their keys are forgotten.
    pub fn drain(&self) -> Vec<AuditEntry> {
        self.drain_at(Instant::now())
    }

    pub fn drain_at(&self, now: Instant) -> Vec<AuditEntry> {
        let Ok(mut keys) = self.keys.lock() else {
            return Vec::new();
        };
        let closed: Vec<String> = keys
            .iter()
            .filter(|(_, f)| now.saturating_duration_since(f.started) >= REFUSAL_WINDOW)
            .map(|(k, _)| k.clone())
            .collect();
        closed
            .into_iter()
            .filter_map(|key| keys.remove(&key))
            .filter_map(summary)
            .collect()
    }
}

/// The latest refusal of a window, saying how many more there were than the one already written.
fn summary(folded: Folded) -> Option<AuditEntry> {
    if folded.repeats == 0 {
        return None;
    }
    let mut entry = folded.latest;
    entry.id = uuid::Uuid::now_v7().to_string();
    if let serde_json::Value::Object(fields) = &mut entry.detail {
        fields.insert("repeats".into(), folded.repeats.into());
        fields.insert("window_seconds".into(), REFUSAL_WINDOW.as_secs().into());
    }
    Some(entry)
}

/// A wait rounded up, so the exact back-off is not revealed: to 5 seconds below a minute, then to
/// the next minute.
pub fn rounded_wait(wait: Duration) -> u64 {
    let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    let step = if secs < 60 { 5 } else { 60 };
    secs.max(1).div_ceil(step) * step
}

/// Keys with a piece of work running, so each key may have only one at a time.
#[derive(Default)]
pub struct InFlight {
    held: Mutex<std::collections::HashSet<String>>,
}

/// Holds a key's place until dropped.
pub struct InFlightGuard {
    owner: std::sync::Arc<InFlight>,
    key: String,
}

impl InFlight {
    /// The key's place, or `None` while it already has work running.
    pub fn claim(self: &std::sync::Arc<Self>, key: String) -> Option<InFlightGuard> {
        let mut held = self.held.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !held.insert(key.clone()) {
            return None;
        }
        Some(InFlightGuard {
            owner: self.clone(),
            key,
        })
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut held = self
            .owner
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn each_key_has_one_piece_of_work_in_flight() {
        let in_flight = std::sync::Arc::new(InFlight::default());
        let first = in_flight.claim("user:a".into());
        assert!(first.is_some());
        assert!(in_flight.claim("user:a".into()).is_none(), "a second is refused");
        assert!(in_flight.claim("user:b".into()).is_some(), "others are unaffected");
        drop(first);
        assert!(in_flight.claim("user:a".into()).is_some(), "free again once it ends");
    }

    #[test]
    fn host_socket_guesses_slow_down_but_never_for_long() {
        let backoff = HostBackoff::default();
        let now = 1_000;
        for _ in 0..HOST_FREE_FAILURES {
            backoff.failed(now);
            assert_eq!(backoff.wait(now), None, "a few typos cost nothing");
        }
        let mut longest = 0;
        for _ in 0..30 {
            backoff.failed(now);
            let wait = backoff.wait(now).map_or(0, |w| w.as_secs());
            assert!(wait >= longest, "the delay only grows");
            longest = wait;
        }
        assert_eq!(longest, HOST_MAX_DELAY.unsigned_abs(), "capped");
        assert_eq!(backoff.wait(now + HOST_MAX_DELAY), None);
        backoff.succeeded();
        backoff.failed(now);
        assert_eq!(backoff.wait(now), None, "a success starts again");
        assert_eq!(backoff.failures(), 1);
    }

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
    fn exhaustion_can_be_checked_without_spending() {
        let limiter = RateLimiter::new(2);
        let start = Instant::now();
        assert!(
            !limiter.exhausted_at(&"a", start),
            "an unknown key has its full allowance"
        );
        assert!(limiter.allow_at(&"a", start));
        assert!(!limiter.exhausted_at(&"a", start));
        assert!(!limiter.exhausted_at(&"a", start), "checking spends nothing");
        assert!(limiter.allow_at(&"a", start));
        assert!(limiter.exhausted_at(&"a", start));
        assert!(!limiter.exhausted_at(&"a", start + Duration::from_secs(31)));
    }

    #[test]
    fn hourly_limits_refill_slowly() {
        let limiter = RateLimiter::per_hour(3);
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.allow_at(&"a", start));
        }
        assert!(!limiter.allow_at(&"a", start + Duration::from_secs(60)));
        assert!(limiter.allow_at(&"a", start + Duration::from_secs(21 * 60)));
        assert!(!limiter.allow_at(&"a", start + Duration::from_secs(21 * 60)));
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
    fn a_flood_from_many_sources_pauses_only_sources_that_have_failed() -> anyhow::Result<()> {
        let backoff = FailureBackoff::default();
        let owner: IpAddr = "192.0.2.10".parse().context("ip")?;
        let flooder = IpAddr::from([10, 1, 0, 0]);
        let start = Instant::now();
        for i in 0..=GLOBAL_BURST {
            let source = IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]);
            backoff.failed_at(source, start);
        }
        assert_eq!(backoff.wait_at(owner, start), None, "the owner has never failed");
        let wait = backoff.wait_at(flooder, start).context("a global pause")?;
        assert!(wait <= GLOBAL_PAUSE, "{wait:?}");
        assert_eq!(backoff.wait_at(flooder, start + GLOBAL_PAUSE), None);
        Ok(())
    }

    #[test]
    fn sources_arriving_after_evictions_get_one_free_failure() -> anyhow::Result<()> {
        let backoff = FailureBackoff::default();
        let start = Instant::now();
        let before: IpAddr = "172.16.0.1".parse().context("ip")?;
        backoff.failed_at(before, start);
        assert_eq!(backoff.wait_at(before, start), None, "no load yet: the usual allowance");
        for i in 0..MAX_SOURCES as u32 {
            let at = start + GLOBAL_WINDOW * (i + 1);
            backoff.failed_at(IpAddr::from((u32::from_be_bytes([11, 0, 0, 0]) + i).to_be_bytes()), at);
        }
        let late = start + GLOBAL_WINDOW * (MAX_SOURCES as u32 + 2);
        let returning: IpAddr = "172.16.0.2".parse().context("ip")?;
        backoff.failed_at(returning, late);
        assert_eq!(backoff.wait_at(returning, late), None, "one free failure");
        let later = late + GLOBAL_WINDOW;
        backoff.failed_at(returning, later);
        assert!(
            backoff.wait_at(returning, later).is_some(),
            "an evicted source coming back does not get five more"
        );
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

    fn refusal(n: i64) -> AuditEntry {
        AuditEntry {
            id: format!("entry-{n}"),
            created_at: n,
            actor_kind: "user".into(),
            actor_id: "u1".into(),
            actor_name: "user:u1".into(),
            action: "sys.forbidden".into(),
            project_id: None,
            environment: None,
            path: None,
            secret_key: None,
            detail: serde_json::json!({}),
            ip: "203.0.113.9".into(),
        }
    }

    #[test]
    fn a_flood_of_refusals_becomes_one_entry_and_a_count_a_minute() {
        let throttle = AuditThrottle::default();
        let start = Instant::now();
        let mut written = Vec::new();
        for n in 0..1000 {
            let at = start + Duration::from_millis(u64::try_from(n).unwrap_or(0) * 10);
            written.extend(throttle.admit_at("k".into(), refusal(n), at));
        }
        assert_eq!(written.len(), 1, "the first is written at once, the rest are counted");
        assert_eq!(written[0].created_at, 0);
        assert!(
            throttle.drain_at(start + Duration::from_secs(30)).is_empty(),
            "still open"
        );
        let summaries = throttle.drain_at(start + REFUSAL_WINDOW);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].detail["repeats"], 999);
        assert_eq!(summaries[0].created_at, 999, "the summary carries the latest refusal");
        assert!(throttle.drain_at(start + REFUSAL_WINDOW * 2).is_empty());

        let other = throttle.admit_at("other".into(), refusal(1), start);
        assert_eq!(other.len(), 1, "another caller or source has its own window");
    }

    #[test]
    fn a_new_window_writes_the_previous_summary_first() {
        let throttle = AuditThrottle::default();
        let start = Instant::now();
        assert_eq!(throttle.admit_at("k".into(), refusal(1), start).len(), 1);
        assert!(throttle.admit_at("k".into(), refusal(2), start).is_empty());
        let next = throttle.admit_at("k".into(), refusal(3), start + REFUSAL_WINDOW);
        assert_eq!(next.len(), 2);
        assert_eq!(
            (next[0].created_at, &next[0].detail["repeats"]),
            (2, &serde_json::json!(1))
        );
        assert_eq!(next[1].created_at, 3);
        let quiet = throttle.admit_at("q".into(), refusal(4), start);
        assert_eq!(quiet.len(), 1);
        assert!(
            throttle
                .drain_at(start + REFUSAL_WINDOW)
                .iter()
                .all(|e| e.created_at != 4),
            "a window with no repeats needs no summary"
        );
    }

    #[test]
    fn evicted_windows_still_write_their_counts() {
        let throttle = AuditThrottle::default();
        let start = Instant::now();
        let mut written = throttle.admit_at("k0".into(), refusal(0), start);
        written.extend(throttle.admit_at("k0".into(), refusal(1), start));
        for i in 1..=MAX_REFUSAL_KEYS as u64 {
            // Spaced out so the overall cap on new windows is not what folds them.
            let at = start + Duration::from_millis(i * 61);
            written.extend(throttle.admit_at(format!("k{i}"), refusal(2), at));
        }
        let summaries: Vec<_> = written.iter().filter(|e| e.detail.get("repeats").is_some()).collect();
        assert_eq!(summaries.len(), 1, "the evicted window with a repeat is summarised");
        assert_eq!(summaries[0].created_at, 1);
        assert_eq!(summaries[0].detail["repeats"], 1);
    }

    #[test]
    fn new_windows_are_capped_across_all_keys() {
        let throttle = AuditThrottle::default();
        let start = Instant::now();
        let mut written = Vec::new();
        let flood = MAX_NEW_WINDOWS as usize + 500;
        for i in 0..flood {
            written.extend(throttle.admit_at(format!("fresh-{i}"), refusal(5), start));
        }
        assert_eq!(
            written.len(),
            MAX_NEW_WINDOWS as usize + 1,
            "past the cap, one shared window per action"
        );
        let summaries = throttle.drain_at(start + REFUSAL_WINDOW);
        let overflow: Vec<_> = summaries.iter().filter(|e| e.detail["repeats"] == 499).collect();
        assert_eq!(overflow.len(), 1);
        let later = throttle.admit_at("fresh-again".into(), refusal(6), start + REFUSAL_WINDOW);
        assert_eq!(later.len(), 1, "the cap resets each minute");
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
