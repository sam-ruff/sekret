use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::ObjectMeta;
use kube::{Resource, ResourceExt};
use sekret_client::{ClientError, Location};

use crate::content::{ContentError, SecretData, build_data, content_hash};
use crate::crd::{Condition, READY, SekretSecret, SekretSecretStatus};
use crate::interval::parse_interval;
use crate::kube_api::KubeApi;
use crate::sekret::SekretApiFactory;

pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "sekret-operator";
pub const TOKEN_AUDIENCE: &str = "sekret";
/// The TokenRequest API minimum, which is plenty for one login.
pub const TOKEN_EXPIRY_SECONDS: i64 = 600;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("{0}")]
    InvalidSpec(String),
    #[error("could not request a token for service account {service_account}: {message}")]
    TokenRequest { service_account: String, message: String },
    #[error("sekret login failed: {0}")]
    Login(String),
    #[error("could not fetch secrets: {0}")]
    Fetch(String),
    #[error(transparent)]
    Content(#[from] ContentError),
    #[error("Secret {0} already exists and is not owned by this SekretSecret")]
    TargetNotOwned(String),
    #[error("Secret {name} has type {existing}; delete it to switch to {wanted}")]
    TypeChanged {
        name: String,
        existing: String,
        wanted: String,
    },
    #[error("could not write Secret: {0}")]
    Write(String),
    #[error("could not update status: {0}")]
    Status(String),
}

impl SyncError {
    /// Machine-readable reason for the `Ready` condition.
    pub fn reason(&self) -> &'static str {
        match self {
            SyncError::InvalidSpec(_) => "InvalidSpec",
            SyncError::TokenRequest { .. } => "TokenRequestFailed",
            SyncError::Login(_) => "LoginFailed",
            SyncError::Fetch(_) => "FetchFailed",
            SyncError::Content(ContentError::DuplicateKey { .. }) => "DuplicateKey",
            SyncError::Content(ContentError::KeysNotFound(_)) => "KeysNotFound",
            SyncError::Content(ContentError::InvalidKey(_)) => "InvalidKey",
            SyncError::TargetNotOwned(_) => "TargetNotOwned",
            SyncError::TypeChanged { .. } => "TargetTypeChanged",
            SyncError::Write(_) => "WriteFailed",
            SyncError::Status(_) => "StatusFailed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    Created,
    Replaced,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub write: WriteKind,
    pub secret_count: u32,
    pub hash: String,
}

/// Syncs one `SekretSecret` and records the result in its status.
///
/// `now` is an RFC 3339 timestamp used for `lastSyncedAt` and condition transitions.
pub async fn reconcile(
    cr: &SekretSecret,
    kube: &dyn KubeApi,
    sekret: &dyn SekretApiFactory,
    now: &str,
) -> Result<SyncOutcome, SyncError> {
    let namespace = cr
        .namespace()
        .ok_or_else(|| SyncError::InvalidSpec("SekretSecret has no namespace".into()))?;
    let result = sync(cr, &namespace, kube, sekret).await;
    let status = next_status(cr.status.as_ref(), cr.metadata.generation, &result, now);
    let patched = kube.patch_status(namespace, cr.name_any(), status).await;
    let outcome = result?;
    patched.map_err(|e| SyncError::Status(e.to_string()))?;
    Ok(outcome)
}

async fn sync(
    cr: &SekretSecret,
    namespace: &str,
    kube: &dyn KubeApi,
    sekret: &dyn SekretApiFactory,
) -> Result<SyncOutcome, SyncError> {
    let spec = &cr.spec;
    parse_interval(&spec.refresh_interval).map_err(|e| SyncError::InvalidSpec(e.to_string()))?;
    validate_name("auth.serviceAccountName", &spec.auth.service_account_name)?;
    validate_name("target.name", &spec.target.name)?;
    validate_secret_type(&spec.target.secret_type)?;
    let owner = cr
        .controller_owner_ref(&())
        .ok_or_else(|| SyncError::InvalidSpec("SekretSecret has no uid yet".into()))?;

    let data = fetch(cr, namespace, kube, sekret).await?;
    let hash = content_hash(&data);
    let secret_count = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let desired = desired_secret(cr, namespace, owner, data);
    let outcome = |write| SyncOutcome {
        write,
        secret_count,
        hash: hash.clone(),
    };

    let existing = kube
        .get_secret(namespace.into(), spec.target.name.clone())
        .await
        .map_err(|e| SyncError::Write(e.to_string()))?;
    let Some(existing) = existing else {
        kube.create_secret(namespace.into(), desired)
            .await
            .map_err(|e| SyncError::Write(e.to_string()))?;
        return Ok(outcome(WriteKind::Created));
    };
    let uid = cr.uid().unwrap_or_default();
    if !is_controlled_by(&existing, &uid) {
        return Err(SyncError::TargetNotOwned(spec.target.name.clone()));
    }
    let existing_type = existing.type_.clone().unwrap_or_else(|| "Opaque".into());
    if existing_type != spec.target.secret_type {
        return Err(SyncError::TypeChanged {
            name: spec.target.name.clone(),
            existing: existing_type,
            wanted: spec.target.secret_type.clone(),
        });
    }
    if is_up_to_date(&existing, &desired, &hash) {
        return Ok(outcome(WriteKind::Unchanged));
    }
    let mut replacement = desired;
    replacement.metadata.resource_version = existing.metadata.resource_version;
    kube.replace_secret(namespace.into(), replacement)
        .await
        .map_err(|e| SyncError::Write(e.to_string()))?;
    Ok(outcome(WriteKind::Replaced))
}

/// Logs in as the configured identity and fetches the filtered secret data.
async fn fetch(
    cr: &SekretSecret,
    namespace: &str,
    kube: &dyn KubeApi,
    sekret: &dyn SekretApiFactory,
) -> Result<SecretData, SyncError> {
    let spec = &cr.spec;
    // The namespace always comes from the resource itself, so a SekretSecret can
    // only act as service accounts that live alongside it.
    let sa_token = kube
        .request_token(
            namespace.into(),
            spec.auth.service_account_name.clone(),
            TOKEN_AUDIENCE.into(),
            TOKEN_EXPIRY_SECONDS,
        )
        .await
        .map_err(|e| SyncError::TokenRequest {
            service_account: spec.auth.service_account_name.clone(),
            message: e.to_string(),
        })?;
    let anonymous = sekret.client(None).map_err(|e| SyncError::Login(e.to_string()))?;
    let login = anonymous
        .kubernetes_login(spec.auth.identity_id.clone(), sa_token)
        .await
        .map_err(|e| SyncError::Login(e.to_string()))?;
    let api = sekret
        .client(Some(login.access_token))
        .map_err(|e| SyncError::Fetch(e.to_string()))?;
    let location = Location {
        project: spec.project.clone(),
        environment: spec.environment.clone(),
        path: spec.path.clone(),
    };
    let raw = api.raw(location, spec.recursive).await;
    if let Err(error) = api.revoke().await {
        tracing::debug!(%error, "could not revoke sekret access token");
    }
    let raw = raw.map_err(describe_fetch_error)?;
    Ok(build_data(raw.secrets, spec.keys.as_deref())?)
}

/// Decode errors can quote the response body, which holds secret values.
fn describe_fetch_error(error: ClientError) -> SyncError {
    match error {
        ClientError::Decode(_) => SyncError::Fetch("the server returned an unreadable response".into()),
        other => SyncError::Fetch(other.to_string()),
    }
}

/// Secret types that only carry data. Types such as `kubernetes.io/service-account-token` make the
/// cluster act on the Secret, so they are refused.
pub const ALLOWED_SECRET_TYPES: [&str; 6] = [
    "Opaque",
    "kubernetes.io/basic-auth",
    "kubernetes.io/dockercfg",
    "kubernetes.io/dockerconfigjson",
    "kubernetes.io/ssh-auth",
    "kubernetes.io/tls",
];

fn validate_secret_type(value: &str) -> Result<(), SyncError> {
    if ALLOWED_SECRET_TYPES.contains(&value) {
        return Ok(());
    }
    Err(SyncError::InvalidSpec(format!(
        "target.type {value} is not allowed; use one of {}",
        ALLOWED_SECRET_TYPES.join(", ")
    )))
}

/// Accepts Kubernetes object names only, so a name cannot smuggle in another namespace.
fn validate_name(field: &str, value: &str) -> Result<(), SyncError> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        && value.starts_with(|c: char| c.is_ascii_alphanumeric())
        && value.ends_with(|c: char| c.is_ascii_alphanumeric());
    if valid {
        return Ok(());
    }
    Err(SyncError::InvalidSpec(format!(
        "{field} {value:?} is not a valid Kubernetes name"
    )))
}

fn desired_secret(
    cr: &SekretSecret,
    namespace: &str,
    owner: k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
    data: SecretData,
) -> Secret {
    let target = &cr.spec.target;
    let mut labels = target.labels.clone();
    labels.insert(MANAGED_BY_LABEL.into(), MANAGED_BY_VALUE.into());
    Secret {
        metadata: ObjectMeta {
            name: Some(target.name.clone()),
            namespace: Some(namespace.into()),
            labels: Some(labels),
            annotations: (!target.annotations.is_empty()).then(|| target.annotations.clone()),
            owner_references: Some(vec![owner]),
            ..ObjectMeta::default()
        },
        type_: Some(target.secret_type.clone()),
        data: Some(data.into_iter().map(|(k, v)| (k, ByteString(v))).collect()),
        ..Secret::default()
    }
}

fn is_controlled_by(secret: &Secret, uid: &str) -> bool {
    !uid.is_empty()
        && secret
            .owner_references()
            .iter()
            .any(|r| r.uid == uid && r.controller == Some(true))
}

fn is_up_to_date(existing: &Secret, desired: &Secret, hash: &str) -> bool {
    let existing_data: SecretData = existing
        .data
        .iter()
        .flatten()
        .map(|(k, v)| (k.clone(), v.0.clone()))
        .collect();
    content_hash(&existing_data) == hash
        && contains_all(existing.metadata.labels.as_ref(), desired.metadata.labels.as_ref())
        && contains_all(
            existing.metadata.annotations.as_ref(),
            desired.metadata.annotations.as_ref(),
        )
}

fn contains_all(have: Option<&BTreeMap<String, String>>, want: Option<&BTreeMap<String, String>>) -> bool {
    want.into_iter()
        .flatten()
        .all(|(k, v)| have.and_then(|h| h.get(k)) == Some(v))
}

fn next_status(
    previous: Option<&SekretSecretStatus>,
    generation: Option<i64>,
    result: &Result<SyncOutcome, SyncError>,
    now: &str,
) -> SekretSecretStatus {
    let mut status = previous.cloned().unwrap_or_default();
    let (ready, reason, message) = match result {
        Ok(outcome) => {
            status.last_synced_at = Some(now.into());
            status.secret_count = Some(outcome.secret_count);
            ("True", "Synced", format!("synced {} keys", outcome.secret_count))
        }
        Err(error) => ("False", error.reason(), error.to_string()),
    };
    let transitioned = status.ready().is_none_or(|c| c.status != ready);
    let last_transition_time = if transitioned {
        Some(now.to_string())
    } else {
        status.ready().and_then(|c| c.last_transition_time.clone())
    };
    status.conditions.retain(|c| c.condition_type != READY);
    status.conditions.push(Condition {
        condition_type: READY.into(),
        status: ready.into(),
        reason: reason.into(),
        message,
        last_transition_time,
        observed_generation: generation,
    });
    status.observed_generation = generation;
    status
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    use mockall::predicate::{always, eq};
    use sekret_api::{RawSecret, RawSecrets, TokenResponse};
    use sekret_client::{ClientError, MockSekretApi};

    use super::*;
    use crate::crd::{AuthSpec, SekretSecretSpec, TargetSpec};
    use crate::kube_api::MockKubeApi;
    use crate::sekret::MockSekretApiFactory;

    const NOW: &str = "2026-10-30T12:00:00Z";
    const SA_TOKEN: &str = "sa-token-do-not-leak";
    const ACCESS_TOKEN: &str = "skt_access_do_not_leak";

    fn cr() -> SekretSecret {
        let mut cr = SekretSecret::new(
            "app-config",
            SekretSecretSpec {
                project: "app".into(),
                environment: "prod".into(),
                path: "/".into(),
                recursive: false,
                keys: None,
                target: TargetSpec {
                    name: "app-env".into(),
                    secret_type: "Opaque".into(),
                    labels: BTreeMap::from([("team".into(), "web".into())]),
                    annotations: BTreeMap::new(),
                },
                refresh_interval: "5m".into(),
                auth: AuthSpec {
                    identity_id: "identity-1".into(),
                    service_account_name: "reader".into(),
                },
            },
        );
        cr.metadata.namespace = Some("apps".into());
        cr.metadata.uid = Some("uid-1".into());
        cr.metadata.generation = Some(3);
        cr
    }

    fn raw(pairs: &[(&str, &str, &str)]) -> RawSecrets {
        RawSecrets {
            project: "app".into(),
            environment: "prod".into(),
            secrets: pairs
                .iter()
                .map(|(path, key, value)| RawSecret {
                    path: (*path).into(),
                    key: (*key).into(),
                    value: (*value).into(),
                })
                .collect(),
        }
    }

    /// A factory whose login succeeds and whose fetch returns `secrets`.
    fn factory(secrets: RawSecrets) -> MockSekretApiFactory {
        let mut factory = MockSekretApiFactory::new();
        factory.expect_client().with(eq(None)).returning(|_| {
            let mut api = MockSekretApi::new();
            api.expect_kubernetes_login()
                .with(eq("identity-1".to_string()), eq(SA_TOKEN.to_string()))
                .times(1)
                .returning(|_, _| {
                    Ok(TokenResponse {
                        access_token: ACCESS_TOKEN.into(),
                        token_type: "Bearer".into(),
                        expires_in: 3600,
                    })
                });
            Ok(Box::new(api))
        });
        factory
            .expect_client()
            .with(eq(Some(ACCESS_TOKEN.to_string())))
            .returning(move |_| {
                let mut api = MockSekretApi::new();
                let secrets = secrets.clone();
                api.expect_raw()
                    .withf(|at, recursive| at.project == "app" && at.environment == "prod" && !recursive)
                    .times(1)
                    .returning(move |_, _| Ok(secrets.clone()));
                api.expect_revoke().times(1).returning(|| Ok(()));
                Ok(Box::new(api))
            });
        factory
    }

    /// A kube mock that issues tokens in `apps` and records every status patch.
    fn kube(existing: Option<Secret>, statuses: Arc<Mutex<Vec<SekretSecretStatus>>>) -> MockKubeApi {
        let mut kube = MockKubeApi::new();
        kube.expect_request_token()
            .with(
                eq("apps".to_string()),
                eq("reader".to_string()),
                eq("sekret".to_string()),
                always(),
            )
            .returning(|_, _, _, _| Ok(SA_TOKEN.into()));
        kube.expect_get_secret()
            .with(eq("apps".to_string()), eq("app-env".to_string()))
            .returning(move |_, _| Ok(existing.clone()));
        kube.expect_patch_status()
            .with(eq("apps".to_string()), eq("app-config".to_string()), always())
            .returning(move |_, _, status| {
                statuses.lock().map(|mut s| s.push(status)).ok();
                Ok(())
            });
        kube
    }

    fn last_status(statuses: &Arc<Mutex<Vec<SekretSecretStatus>>>) -> SekretSecretStatus {
        statuses
            .lock()
            .ok()
            .and_then(|s| s.last().cloned())
            .expect("status patched")
    }

    fn owned_secret(data: &[(&str, &str)]) -> Secret {
        let mut secret = desired_secret(
            &cr(),
            "apps",
            cr().controller_owner_ref(&()).expect("owner"),
            data.iter()
                .map(|(k, v)| ((*k).to_string(), v.as_bytes().to_vec()))
                .collect(),
        );
        secret.metadata.resource_version = Some("41".into());
        secret
    }

    fn assert_no_leak(statuses: &Arc<Mutex<Vec<SekretSecretStatus>>>, values: &[&str]) {
        let json = serde_json::to_string(&*statuses.lock().expect("lock")).expect("json");
        for value in values.iter().chain([&SA_TOKEN, &ACCESS_TOKEN]) {
            assert!(!json.contains(value), "status leaked {value}: {json}");
        }
    }

    #[tokio::test]
    async fn creates_the_target_secret_with_owner_and_label() {
        let statuses = Arc::default();
        let mut kube = kube(None, Arc::clone(&statuses));
        kube.expect_create_secret()
            .withf(|ns, secret| {
                let meta = &secret.metadata;
                let labels = meta.labels.clone().unwrap_or_default();
                let owner = meta.owner_references.clone().unwrap_or_default();
                ns == "apps"
                    && meta.name.as_deref() == Some("app-env")
                    && labels.get(MANAGED_BY_LABEL).map(String::as_str) == Some(MANAGED_BY_VALUE)
                    && labels.get("team").map(String::as_str) == Some("web")
                    && owner.len() == 1
                    && owner[0].uid == "uid-1"
                    && owner[0].kind == "SekretSecret"
                    && owner[0].controller == Some(true)
                    && secret.type_.as_deref() == Some("Opaque")
                    && secret
                        .data
                        .as_ref()
                        .and_then(|d| d.get("DB_URL"))
                        .map(|b| b.0.as_slice())
                        == Some(b"postgres://x".as_slice())
            })
            .times(1)
            .returning(|_, _| Ok(()));
        let sekret = factory(raw(&[("/", "DB_URL", "postgres://x")]));

        let outcome = reconcile(&cr(), &kube, &sekret, NOW).await.expect("sync");

        assert_eq!(outcome.write, WriteKind::Created);
        let status = last_status(&statuses);
        let ready = status.ready().expect("ready");
        assert_eq!((ready.status.as_str(), ready.reason.as_str()), ("True", "Synced"));
        assert_eq!(status.secret_count, Some(1));
        assert_eq!(status.last_synced_at.as_deref(), Some(NOW));
        assert_eq!(status.observed_generation, Some(3));
        assert_no_leak(&statuses, &["postgres://x"]);
    }

    #[tokio::test]
    async fn unchanged_content_skips_the_write() {
        let statuses = Arc::default();
        let mut kube = kube(Some(owned_secret(&[("A", "1")])), Arc::clone(&statuses));
        kube.expect_create_secret().never();
        kube.expect_replace_secret().never();
        let sekret = factory(raw(&[("/", "A", "1")]));

        let outcome = reconcile(&cr(), &kube, &sekret, NOW).await.expect("sync");

        assert_eq!(outcome.write, WriteKind::Unchanged);
        assert_eq!(last_status(&statuses).ready().map(|c| c.status.as_str()), Some("True"));
    }

    #[tokio::test]
    async fn changed_content_replaces_with_the_current_resource_version() {
        let statuses = Arc::default();
        let mut kube = kube(Some(owned_secret(&[("A", "old")])), Arc::clone(&statuses));
        kube.expect_replace_secret()
            .withf(|ns, secret| {
                ns == "apps"
                    && secret.metadata.resource_version.as_deref() == Some("41")
                    && secret.data.as_ref().and_then(|d| d.get("A")).map(|b| b.0.as_slice()) == Some(b"new".as_slice())
            })
            .times(1)
            .returning(|_, _| Ok(()));
        let sekret = factory(raw(&[("/", "A", "new")]));

        let outcome = reconcile(&cr(), &kube, &sekret, NOW).await.expect("sync");

        assert_eq!(outcome.write, WriteKind::Replaced);
    }

    #[tokio::test]
    async fn missing_desired_label_triggers_a_replace() {
        let statuses = Arc::default();
        let mut existing = owned_secret(&[("A", "1")]);
        existing.metadata.labels = Some(BTreeMap::from([(MANAGED_BY_LABEL.into(), MANAGED_BY_VALUE.into())]));
        let mut kube = kube(Some(existing), Arc::clone(&statuses));
        kube.expect_replace_secret().times(1).returning(|_, _| Ok(()));
        let sekret = factory(raw(&[("/", "A", "1")]));

        let outcome = reconcile(&cr(), &kube, &sekret, NOW).await.expect("sync");

        assert_eq!(outcome.write, WriteKind::Replaced);
    }

    #[tokio::test]
    async fn refuses_a_secret_owned_by_someone_else() {
        for owners in [
            None,
            Some(vec![OwnerReference {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "web".into(),
                uid: "other-uid".into(),
                controller: Some(true),
                ..OwnerReference::default()
            }]),
        ] {
            let statuses = Arc::default();
            let mut foreign = owned_secret(&[("A", "1")]);
            foreign.metadata.owner_references = owners;
            let mut kube = kube(Some(foreign), Arc::clone(&statuses));
            kube.expect_create_secret().never();
            kube.expect_replace_secret().never();
            let sekret = factory(raw(&[("/", "A", "secret-value")]));

            let error = reconcile(&cr(), &kube, &sekret, NOW).await.expect_err("refused");

            assert!(matches!(error, SyncError::TargetNotOwned(_)), "{error:?}");
            let status = last_status(&statuses);
            let ready = status.ready().expect("ready");
            assert_eq!(
                (ready.status.as_str(), ready.reason.as_str()),
                ("False", "TargetNotOwned")
            );
            assert_no_leak(&statuses, &["secret-value"]);
        }
    }

    #[tokio::test]
    async fn login_failure_sets_ready_false_without_leaking_tokens() {
        let statuses = Arc::default();
        let mut kube = kube(None, Arc::clone(&statuses));
        kube.expect_create_secret().never();
        let mut sekret = MockSekretApiFactory::new();
        sekret.expect_client().with(eq(None)).times(1).returning(|_| {
            let mut api = MockSekretApi::new();
            api.expect_kubernetes_login().returning(|_, _| {
                Err(ClientError::Api {
                    status: 401,
                    code: "unauthorized".into(),
                    message: "kubernetes rejected the token".into(),
                })
            });
            Ok(Box::new(api))
        });
        let mut previous = SekretSecretStatus {
            last_synced_at: Some("2026-10-29T00:00:00Z".into()),
            secret_count: Some(2),
            ..SekretSecretStatus::default()
        };
        previous.conditions.push(Condition {
            condition_type: READY.into(),
            status: "True".into(),
            reason: "Synced".into(),
            message: "synced 2 keys".into(),
            last_transition_time: Some("2026-10-29T00:00:00Z".into()),
            observed_generation: Some(3),
        });
        let mut resource = cr();
        resource.status = Some(previous);

        let error = reconcile(&resource, &kube, &sekret, NOW)
            .await
            .expect_err("login fails");

        assert!(matches!(error, SyncError::Login(_)), "{error:?}");
        let status = last_status(&statuses);
        let ready = status.ready().expect("ready");
        assert_eq!((ready.status.as_str(), ready.reason.as_str()), ("False", "LoginFailed"));
        assert!(
            ready.message.contains("kubernetes rejected the token"),
            "{}",
            ready.message
        );
        assert_eq!(ready.last_transition_time.as_deref(), Some(NOW));
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.secret_count, Some(2), "last good sync is kept");
        assert_eq!(status.last_synced_at.as_deref(), Some("2026-10-29T00:00:00Z"));
        assert_no_leak(&statuses, &[]);
    }

    #[tokio::test]
    async fn keys_filter_limits_what_is_written() {
        let statuses = Arc::default();
        let mut kube = kube(None, Arc::clone(&statuses));
        kube.expect_create_secret()
            .withf(|_, secret| {
                secret.data.as_ref().map(|d| d.keys().cloned().collect::<Vec<_>>()) == Some(vec!["KEEP".to_string()])
            })
            .times(1)
            .returning(|_, _| Ok(()));
        let sekret = factory(raw(&[("/", "KEEP", "1"), ("/", "DROP", "2")]));
        let mut resource = cr();
        resource.spec.keys = Some(vec!["KEEP".into()]);

        let outcome = reconcile(&resource, &kube, &sekret, NOW).await.expect("sync");

        assert_eq!(outcome.secret_count, 1);
    }

    #[tokio::test]
    async fn duplicate_keys_in_recursive_mode_fail_clearly() {
        let statuses: Arc<Mutex<Vec<SekretSecretStatus>>> = Arc::default();
        let mut kube = MockKubeApi::new();
        kube.expect_request_token().returning(|_, _, _, _| Ok(SA_TOKEN.into()));
        kube.expect_get_secret().never();
        kube.expect_create_secret().never();
        let recorded = Arc::clone(&statuses);
        kube.expect_patch_status().returning(move |_, _, status| {
            recorded.lock().map(|mut s| s.push(status)).ok();
            Ok(())
        });
        let mut sekret = MockSekretApiFactory::new();
        sekret.expect_client().with(eq(None)).returning(|_| {
            let mut api = MockSekretApi::new();
            api.expect_kubernetes_login().returning(|_, _| {
                Ok(TokenResponse {
                    access_token: ACCESS_TOKEN.into(),
                    token_type: "Bearer".into(),
                    expires_in: 60,
                })
            });
            Ok(Box::new(api))
        });
        sekret
            .expect_client()
            .with(eq(Some(ACCESS_TOKEN.to_string())))
            .returning(|_| {
                let mut api = MockSekretApi::new();
                api.expect_raw()
                    .withf(|_, recursive| *recursive)
                    .returning(|_, _| Ok(raw(&[("/db", "URL", "first-value"), ("/cache", "URL", "second-value")])));
                api.expect_revoke().returning(|| Ok(()));
                Ok(Box::new(api))
            });
        let mut resource = cr();
        resource.spec.recursive = true;

        let error = reconcile(&resource, &kube, &sekret, NOW).await.expect_err("duplicate");

        assert_eq!(error.reason(), "DuplicateKey");
        let message = last_status(&statuses)
            .ready()
            .map(|c| c.message.clone())
            .unwrap_or_default();
        assert!(
            message.contains("URL") && message.contains("/db") && message.contains("/cache"),
            "{message}"
        );
        assert_no_leak(&statuses, &["first-value", "second-value"]);
    }

    #[tokio::test]
    async fn service_account_token_is_requested_in_the_resource_namespace() {
        for namespace in ["apps", "team-b"] {
            let mut kube = MockKubeApi::new();
            kube.expect_request_token()
                .with(
                    eq(namespace.to_string()),
                    eq("reader".to_string()),
                    eq(TOKEN_AUDIENCE.to_string()),
                    eq(TOKEN_EXPIRY_SECONDS),
                )
                .times(1)
                .returning(|_, _, _, _| Err(crate::kube_api::KubeError::EmptyToken));
            kube.expect_patch_status()
                .with(eq(namespace.to_string()), always(), always())
                .returning(|_, _, _| Ok(()));
            let sekret = MockSekretApiFactory::new();
            let mut resource = cr();
            resource.metadata.namespace = Some(namespace.into());

            let error = reconcile(&resource, &kube, &sekret, NOW).await.expect_err("no token");

            assert_eq!(error.reason(), "TokenRequestFailed");
        }
    }

    #[tokio::test]
    async fn service_account_names_cannot_reference_other_namespaces() {
        for name in [
            "kube-system/admin",
            "system:serviceaccount:kube-system:admin",
            "",
            "Admin",
        ] {
            let mut kube = MockKubeApi::new();
            kube.expect_request_token().never();
            kube.expect_patch_status().returning(|_, _, _| Ok(()));
            let mut resource = cr();
            resource.spec.auth.service_account_name = name.into();

            let error = reconcile(&resource, &kube, &MockSekretApiFactory::new(), NOW)
                .await
                .expect_err("rejected");

            assert_eq!(error.reason(), "InvalidSpec", "{name:?}");
        }
    }

    #[tokio::test]
    async fn secret_types_that_kubernetes_acts_on_are_refused() {
        let mut kube = MockKubeApi::new();
        kube.expect_request_token().never();
        kube.expect_patch_status().returning(|_, _, _| Ok(()));
        let mut resource = cr();
        resource.spec.target.secret_type = "kubernetes.io/service-account-token".into();

        let error = reconcile(&resource, &kube, &MockSekretApiFactory::new(), NOW)
            .await
            .expect_err("refused");

        assert_eq!(error.reason(), "InvalidSpec");
        assert!(error.to_string().contains("service-account-token"));
    }

    #[tokio::test]
    async fn invalid_refresh_interval_is_reported() {
        let mut kube = MockKubeApi::new();
        kube.expect_request_token().never();
        let statuses: Arc<Mutex<Vec<SekretSecretStatus>>> = Arc::default();
        let recorded = Arc::clone(&statuses);
        kube.expect_patch_status().returning(move |_, _, status| {
            recorded.lock().map(|mut s| s.push(status)).ok();
            Ok(())
        });
        let mut resource = cr();
        resource.spec.refresh_interval = "soon".into();

        let error = reconcile(&resource, &kube, &MockSekretApiFactory::new(), NOW)
            .await
            .expect_err("invalid");

        assert_eq!(error.reason(), "InvalidSpec");
        assert!(
            last_status(&statuses)
                .ready()
                .is_some_and(|c| c.message.contains("soon"))
        );
    }

    #[test]
    fn decode_errors_do_not_echo_the_response_body() {
        let error = describe_fetch_error(ClientError::Decode("invalid type: string \"hunter2\"".into()));
        assert!(!error.to_string().contains("hunter2"), "{error}");
        let api = describe_fetch_error(ClientError::Api {
            status: 403,
            code: "forbidden".into(),
            message: "no access to app".into(),
        });
        assert!(api.to_string().contains("no access to app"));
    }

    #[test]
    fn transition_time_only_changes_when_readiness_flips() {
        let ok = Ok(SyncOutcome {
            write: WriteKind::Unchanged,
            secret_count: 1,
            hash: "h".into(),
        });
        let first = next_status(None, Some(1), &ok, "t1");
        let second = next_status(Some(&first), Some(1), &ok, "t2");
        assert_eq!(
            second.ready().and_then(|c| c.last_transition_time.as_deref()),
            Some("t1")
        );
        assert_eq!(second.last_synced_at.as_deref(), Some("t2"));
        let failed = next_status(Some(&second), Some(2), &Err(SyncError::Login("x".into())), "t3");
        assert_eq!(
            failed.ready().and_then(|c| c.last_transition_time.as_deref()),
            Some("t3")
        );
        assert_eq!(failed.observed_generation, Some(2));
    }
}
