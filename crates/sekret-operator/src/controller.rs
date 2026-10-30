use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Context as _;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, ListParams};
use kube::runtime::controller::{Action, Config as ControllerConfig, Controller};
use kube::runtime::{WatchStreamExt, predicates, reflector, watcher};
use kube::{Client, ResourceExt};

use crate::crd::SekretSecret;
use crate::interval::parse_interval;
use crate::kube_api::KubeApi;
use crate::reconcile::{MANAGED_BY_LABEL, MANAGED_BY_VALUE, WriteKind, reconcile};
use crate::sekret::SekretApiFactory;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);
const BACKOFF_BASE: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Per-object exponential backoff for failed syncs.
#[derive(Default)]
pub struct Backoff {
    failures: Mutex<HashMap<String, u32>>,
}

impl Backoff {
    /// Records a failure and returns the delay before the next attempt, never beyond `cap`.
    pub fn fail(&self, key: &str, cap: Duration) -> Duration {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let count = failures.entry(key.to_string()).or_default();
        let delay = BACKOFF_BASE.saturating_mul(2u32.saturating_pow(*count));
        *count = count.saturating_add(1);
        delay.min(cap.min(BACKOFF_MAX)).max(BACKOFF_BASE)
    }

    pub fn reset(&self, key: &str) {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner).remove(key);
    }
}

pub struct Context {
    kube: Arc<dyn KubeApi>,
    sekret: Arc<dyn SekretApiFactory>,
    backoff: Backoff,
}

impl Context {
    pub fn new(kube: Arc<dyn KubeApi>, sekret: Arc<dyn SekretApiFactory>) -> Self {
        Self {
            kube,
            sekret,
            backoff: Backoff::default(),
        }
    }
}

async fn reconcile_object(cr: Arc<SekretSecret>, ctx: Arc<Context>) -> Result<Action, Infallible> {
    let namespace = cr.namespace().unwrap_or_default();
    let name = cr.name_any();
    let key = format!("{namespace}/{name}");
    let interval = parse_interval(&cr.spec.refresh_interval).unwrap_or(DEFAULT_INTERVAL);
    let now = Timestamp::now().to_string();
    match reconcile(&cr, ctx.kube.as_ref(), ctx.sekret.as_ref(), &now).await {
        Ok(outcome) => {
            ctx.backoff.reset(&key);
            let written = outcome.write != WriteKind::Unchanged;
            tracing::info!(%namespace, %name, ?outcome.write, keys = outcome.secret_count, written, "synced");
            Ok(Action::requeue(interval))
        }
        Err(error) => {
            let delay = ctx.backoff.fail(&key, interval);
            tracing::warn!(%namespace, %name, reason = error.reason(), %error, retry_in = ?delay, "sync failed");
            Ok(Action::requeue(delay))
        }
    }
}

fn error_policy(_: Arc<SekretSecret>, error: &Infallible, _: Arc<Context>) -> Action {
    match *error {}
}

/// Runs the controller until a shutdown signal arrives.
///
/// Watches `SekretSecret` resources and the Secrets they own, in `namespace` or cluster-wide.
pub async fn run_controller(
    client: Client,
    ctx: Arc<Context>,
    namespace: Option<&str>,
    concurrency: u16,
) -> anyhow::Result<()> {
    let (resources, secrets): (Api<SekretSecret>, Api<Secret>) = match namespace {
        Some(ns) => (Api::namespaced(client.clone(), ns), Api::namespaced(client, ns)),
        None => (Api::all(client.clone()), Api::all(client)),
    };
    resources
        .list(&ListParams::default().limit(1))
        .await
        .context("cannot list SekretSecrets; is the CRD installed and the operator allowed to read it?")?;

    let (reader, writer) = reflector::store();
    // Only spec changes retrigger a reconcile, so our own status patches do not loop.
    let triggers = watcher(resources, watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        .predicate_filter(predicates::generation, Default::default());
    let owned = watcher::Config::default().labels(&format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}"));

    tracing::info!(namespace = namespace.unwrap_or("*"), "sekret operator started");
    Controller::for_stream(triggers, reader)
        .owns(secrets, owned)
        .with_config(ControllerConfig::default().concurrency(concurrency))
        .shutdown_on_signal()
        .run(reconcile_object, error_policy, ctx)
        .for_each(|result| async move {
            if let Err(error) = result {
                tracing::debug!(%error, "controller event");
            }
        })
        .await;
    tracing::info!("sekret operator stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap_and_resets() {
        let backoff = Backoff::default();
        let cap = Duration::from_secs(60);
        let delays: Vec<u64> = (0..6).map(|_| backoff.fail("a/b", cap).as_secs()).collect();
        assert_eq!(delays, vec![5, 10, 20, 40, 60, 60]);
        assert_eq!(
            backoff.fail("other", cap).as_secs(),
            5,
            "objects back off independently"
        );
        backoff.reset("a/b");
        assert_eq!(backoff.fail("a/b", cap).as_secs(), 5);
    }

    #[test]
    fn backoff_never_exceeds_the_global_maximum() {
        let backoff = Backoff::default();
        let delays: Vec<Duration> = (0..20).map(|_| backoff.fail("x", Duration::from_secs(3600))).collect();
        assert_eq!(delays.last().copied(), Some(BACKOFF_MAX));
    }
}
