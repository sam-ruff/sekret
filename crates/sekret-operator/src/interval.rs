use std::time::Duration;

/// Shortest resync allowed, so a typo cannot hammer the server.
pub const MIN_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid refresh interval {0:?}: expected a whole number followed by s, m or h, at least 10s")]
pub struct IntervalError(pub String);

/// Parses intervals such as `30s`, `5m` or `1h`.
pub fn parse_interval(value: &str) -> Result<Duration, IntervalError> {
    let invalid = || IntervalError(value.to_string());
    let trimmed = value.trim();
    let (number, multiplier) = [("s", 1), ("m", 60), ("h", 3600)]
        .into_iter()
        .find_map(|(suffix, multiplier)| trimmed.strip_suffix(suffix).map(|n| (n, multiplier)))
        .ok_or_else(invalid)?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or_else(invalid)?;
    let duration = Duration::from_secs(seconds);
    if duration < MIN_INTERVAL {
        return Err(invalid());
    }
    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds_minutes_and_hours() {
        assert_eq!(parse_interval("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_interval("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_interval("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_interval(" 10m "), Ok(Duration::from_secs(600)));
    }

    #[test]
    fn rejects_malformed_or_too_short_intervals() {
        for bad in [
            "",
            "m",
            "5",
            "5d",
            "-5m",
            "1.5h",
            "5 m",
            "5é",
            "1s",
            "0m",
            "m5",
            "99999999999999999999h",
        ] {
            assert!(parse_interval(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
