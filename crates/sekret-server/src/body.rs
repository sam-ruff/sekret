//! How much of a request body the write gate may hold before a handler runs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;

/// The largest body any route accepts: a batch of secrets.
pub const MAX_BODY: usize = 4 * 1024 * 1024;
/// A single secret, whose value may be up to 64 KiB before JSON escaping, a role's rules, or an
/// auth method with a CA bundle.
pub const LARGE_BODY: usize = 1024 * 1024;
/// Every other write.
pub const DEFAULT_BODY: usize = 256 * 1024;

/// Bytes all buffered writes may hold at once.
pub const TOTAL_BUDGET: usize = 128 * 1024 * 1024;
/// Writes one principal may have buffered at once.
pub const WRITES_PER_PRINCIPAL: usize = 8;
/// How long a write waits for room in the budget before it is turned away.
const BUDGET_WAIT: Duration = Duration::from_secs(10);
/// The budget is counted in KiB so it fits a semaphore's permits.
const UNIT: usize = 1024;

/// The most the write gate reads for a write to `path`.
pub fn body_limit(path: &str) -> usize {
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    match segments.as_slice() {
        [.., "secrets", "batch"] => MAX_BODY,
        [.., "logo"] => crate::api::logo::MAX_LOGO_BYTES,
        [.., "secrets", _] | [.., "roles", _] | [.., "auth", _] => LARGE_BODY,
        _ => DEFAULT_BODY,
    }
}

/// Caps the bytes buffered by all writes together and the writes each principal has in flight,
/// so tokens cannot add up to more memory than the server has.
pub struct WriteBudget {
    bytes: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashMap<String, usize>>>,
    per_principal: usize,
    wait: Duration,
}

/// Room for one buffered write, given back when dropped.
pub struct WritePermit {
    _bytes: OwnedSemaphorePermit,
    _entered: Entered,
}

impl Default for WriteBudget {
    fn default() -> Self {
        Self::new(TOTAL_BUDGET, WRITES_PER_PRINCIPAL, BUDGET_WAIT)
    }
}

impl WriteBudget {
    pub fn new(total_bytes: usize, per_principal: usize, wait: Duration) -> Self {
        Self {
            bytes: Arc::new(Semaphore::new(units(total_bytes))),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            per_principal,
            wait,
        }
    }

    /// Room for `bytes` on behalf of `principal`: refused at once when they already have their
    /// share of writes in flight, and after a short wait when the server as a whole has none.
    pub async fn reserve(&self, principal: &str, bytes: usize) -> Result<WritePermit, ApiError> {
        self.enter(principal)?;
        let entered = Entered {
            in_flight: self.in_flight.clone(),
            principal: principal.to_string(),
        };
        let wanted = u32::try_from(units(bytes)).map_err(|_| too_large())?;
        let acquired = tokio::time::timeout(self.wait, self.bytes.clone().acquire_many_owned(wanted)).await;
        let Ok(Ok(permit)) = acquired else {
            return Err(busy());
        };
        Ok(WritePermit {
            _bytes: permit,
            _entered: entered,
        })
    }

    fn enter(&self, principal: &str) -> Result<(), ApiError> {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return Err(busy());
        };
        let count = in_flight.entry(principal.to_string()).or_insert(0);
        if *count >= self.per_principal {
            return Err(ApiError::too_many_requests());
        }
        *count += 1;
        Ok(())
    }

    #[cfg(test)]
    fn in_flight(&self, principal: &str) -> usize {
        self.in_flight
            .lock()
            .map(|m| m.get(principal).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

/// One write counted against its principal until dropped.
struct Entered {
    in_flight: Arc<Mutex<HashMap<String, usize>>>,
    principal: String,
}

impl Drop for Entered {
    fn drop(&mut self) {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return;
        };
        let remaining = in_flight.get(&self.principal).map_or(0, |n| n.saturating_sub(1));
        if remaining == 0 {
            in_flight.remove(&self.principal);
        } else {
            in_flight.insert(self.principal.clone(), remaining);
        }
    }
}

fn units(bytes: usize) -> usize {
    bytes.div_ceil(UNIT)
}

pub fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
        "the request body is too large or arrived too slowly",
    )
}

fn busy() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "busy",
        "the server is handling too many writes; try again shortly",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn only_the_routes_that_need_room_get_it() {
        let env = "/api/v1/projects/app/environments/prod";
        assert_eq!(body_limit(&format!("{env}/secrets/batch")), MAX_BODY);
        assert_eq!(body_limit(&format!("{env}/secrets/DB_URL")), LARGE_BODY);
        assert_eq!(body_limit("/api/v1/projects/app/roles/ops"), LARGE_BODY);
        assert_eq!(body_limit("/api/v1/org/roles/ops"), LARGE_BODY);
        assert_eq!(body_limit("/api/v1/identities/id/auth/kubernetes"), LARGE_BODY);
        assert_eq!(
            body_limit("/api/v1/projects/app/logo"),
            crate::api::logo::MAX_LOGO_BYTES
        );
        for small in [
            "/api/v1/projects",
            "/api/v1/projects/app",
            "/api/v1/projects/app/environments",
            &format!("{env}/secrets/DB_URL/rollback"),
            &format!("{env}/snapshots/1/restore"),
            "/api/v1/projects/app/members",
        ] {
            assert_eq!(body_limit(small), DEFAULT_BODY, "{small}");
        }
    }

    #[tokio::test]
    async fn one_principal_cannot_hold_more_than_its_share() -> anyhow::Result<()> {
        let budget = WriteBudget::new(TOTAL_BUDGET, 2, Duration::from_secs(1));
        let first = budget
            .reserve("a", MAX_BODY)
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
        let _second = budget
            .reserve("a", MAX_BODY)
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
        let refused = budget.reserve("a", 1).await.err().context("third write")?;
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(budget.in_flight("a"), 2, "a refusal holds nothing");
        budget.reserve("b", 1).await.map_err(|e| anyhow::anyhow!(e.message))?;
        drop(first);
        budget.reserve("a", 1).await.map_err(|e| anyhow::anyhow!(e.message))?;
        Ok(())
    }

    #[tokio::test]
    async fn the_total_is_shared_and_given_back() -> anyhow::Result<()> {
        let budget = WriteBudget::new(2 * MAX_BODY, 8, Duration::from_millis(50));
        let first = budget
            .reserve("a", MAX_BODY)
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
        let _second = budget
            .reserve("b", MAX_BODY)
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
        let refused = budget.reserve("c", 1).await.err().context("over budget")?;
        assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(budget.in_flight("c"), 0, "a write turned away is not counted");
        drop(first);
        budget
            .reserve("c", MAX_BODY)
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
        Ok(())
    }
}
