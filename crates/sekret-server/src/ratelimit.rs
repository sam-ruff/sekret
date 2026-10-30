use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

/// Token bucket per key, refilled continuously at `per_minute`.
pub struct RateLimiter<K> {
    per_minute: f64,
    buckets: Mutex<HashMap<K, (f64, Instant)>>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute: f64::from(per_minute.max(1)),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, key: &K) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &K, now: Instant) -> bool {
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        if buckets.len() > 10_000 {
            let full = self.per_minute;
            buckets.retain(|_, (tokens, at)| *tokens + now.duration_since(*at).as_secs_f64() * full / 60.0 < full);
        }
        let (tokens, at) = buckets.entry(key.clone()).or_insert((self.per_minute, now));
        let refill = now.duration_since(*at).as_secs_f64() * self.per_minute / 60.0;
        *tokens = (*tokens + refill).min(self.per_minute);
        *at = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
