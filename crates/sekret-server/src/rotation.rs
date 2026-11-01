//! Generated values and the background job that rotates them.

use std::net::{IpAddr, Ipv6Addr};

use sekret_api::SecretUpsert;
use sekret_core::permissions::{BuiltinRole, Rule};
use sekret_core::rotation::{Generator, PolicyOverride, SecretPolicy, effective, generate, is_due};
use sekret_core::seal::SealState;
use sekret_store::{Environment, PrincipalKind, Project, Secret};
use serde_json::json;

use crate::api::{AuditTarget, audit, secret_ctx};
use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::secrets::{PlannedWrite, SecretCtx, apply, plan_batch};
use crate::state::AppState;

pub fn project_policy(project: &Project) -> ApiResult<SecretPolicy> {
    match &project.secret_policy {
        Some(json) => serde_json::from_str(json).map_err(|e| ApiError::internal("project secret policy", e)),
        None => Ok(SecretPolicy::default()),
    }
}

pub fn secret_override(secret: &Secret) -> ApiResult<PolicyOverride> {
    match &secret.policy {
        Some(json) => serde_json::from_str(json).map_err(|e| ApiError::internal("secret policy", e)),
        None => Ok(PolicyOverride::Inherit),
    }
}

pub fn effective_policy(project: &Project, secret: &Secret) -> ApiResult<SecretPolicy> {
    Ok(effective(project_policy(project)?, Some(secret_override(secret)?)))
}

/// The secret a generated value is written to.
pub struct Target<'a> {
    pub project: &'a Project,
    pub env: &'a Environment,
    pub path: &'a str,
    pub key: &'a str,
}

/// Plans writing a freshly generated value to the target, creating the secret when it does not
/// exist. The caller's rules are checked exactly as for a normal write.
pub async fn plan_generated(
    ctx: &SecretCtx<'_>,
    rules: &[Rule],
    target: Target<'_>,
    generator: Option<Generator>,
    comment: String,
) -> ApiResult<PlannedWrite> {
    let Target {
        project,
        env,
        path,
        key,
    } = target;
    let path = sekret_core::validate::folder_path(path)?;
    let path = path.as_str();
    let generator = match generator {
        Some(g) => g,
        None => {
            let existing = ctx.store.get_secret(&env.id, path, key).await?;
            let policy = match existing {
                Some(s) => effective_policy(project, &s.secret)?,
                None => project_policy(project)?,
            };
            policy.generator_or_default()
        }
    };
    SecretPolicy {
        generator: Some(generator),
        rotation_days: None,
    }
    .validate()
    .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let value = generate(generator)?;
    let upsert = SecretUpsert {
        key: key.to_string(),
        value: value.to_string(),
        comment,
        tags: None,
    };
    plan_batch(ctx, rules, project, env, path, vec![upsert], vec![]).await
}

/// The actor recorded on automatic rotations.
/// Keeps the secret's own comment, so rotation does not lose what the secret is for.
fn rotation_comment(current: &str) -> String {
    if current.is_empty() {
        return "rotated automatically".into();
    }
    let kept = current.strip_prefix("rotated automatically: ").unwrap_or(current);
    format!("rotated automatically: {kept}")
}

fn rotation_principal() -> Principal {
    Principal {
        kind: PrincipalKind::Identity,
        id: "sekret-rotation".into(),
        name: "automatic rotation".into(),
        email: String::new(),
        groups: Vec::new(),
        token_id: String::new(),
        token_kind: "system".into(),
    }
}

/// Rotates every generated secret whose policy says it is due, returning the labels rotated.
/// One failure is logged and does not stop the others.
pub async fn rotate_due(state: &AppState) -> ApiResult<Vec<String>> {
    if state.keyring.state() != SealState::Unsealed {
        return Ok(Vec::new());
    }
    let _writing = state.keyring.writing().await;
    state.keyring.check_fingerprint(state.store.as_ref()).await?;
    let principal = rotation_principal();
    let now = state.clock.now();
    let rules = BuiltinRole::ProjectAdmin.rules();
    let mut rotated = Vec::new();
    for project in state.store.list_projects().await? {
        for env in state.store.list_environments(&project.id).await? {
            for s in state.store.list_secrets(&env.id, "/", true, false).await? {
                let policy = match effective_policy(&project, &s.secret) {
                    Ok(policy) => policy,
                    Err(error) => {
                        tracing::warn!(secret = %s.secret.id, error = %error.message, "unreadable secret policy");
                        continue;
                    }
                };
                if !is_due(&policy, s.version.generated, s.version.created_at, now) {
                    continue;
                }
                let label = format!(
                    "{}/{}{}/{}",
                    project.slug,
                    env.slug,
                    s.secret.path.trim_end_matches('/'),
                    s.secret.key
                );
                let outcome = async {
                    let mut ctx = secret_ctx(state, &principal)?;
                    ctx.generated = true;
                    let target = Target {
                        project: &project,
                        env: &env,
                        path: &s.secret.path,
                        key: &s.secret.key,
                    };
                    let comment = rotation_comment(&s.version.comment);
                    let planned = plan_generated(&ctx, &rules, target, None, comment).await?;
                    apply(&ctx, planned).await
                }
                .await;
                if let Err(error) = outcome {
                    tracing::warn!(secret = %label, error = %error.message, "automatic rotation failed");
                    continue;
                }
                audit(
                    state,
                    &principal,
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    "secret.rotate",
                    AuditTarget {
                        project_id: Some(&project.id),
                        environment: Some(&env.slug),
                        path: Some(&s.secret.path),
                        key: Some(&s.secret.key),
                    },
                    json!({"automatic": true}),
                )
                .await;
                rotated.push(label);
            }
        }
    }
    Ok(rotated)
}

#[cfg(test)]
mod tests {
    use super::rotation_comment;

    #[test]
    fn rotation_keeps_the_secrets_comment_without_stacking_prefixes() {
        assert_eq!(rotation_comment(""), "rotated automatically");
        assert_eq!(
            rotation_comment("stripe live key"),
            "rotated automatically: stripe live key"
        );
        assert_eq!(
            rotation_comment("rotated automatically: stripe live key"),
            "rotated automatically: stripe live key"
        );
    }
}
