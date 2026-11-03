//! Per-secret access: the project setting, each secret's restricted flag and access list, and
//! what audit readers may learn about restricted secrets.

use std::collections::{HashMap, HashSet};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use sekret_api::{
    GrantRequest, PrincipalRef, RestrictedSecret, SecretAccess as ApiSecretAccess, SecretAccessChange,
    SecretAccessSetting, SecretGrant, SetSecretAccessSetting,
};
use sekret_core::permissions::{Access, Action, LISTABLE_ACTIONS, Rule, Subject};
use sekret_core::validate;
use sekret_store::{AccessChange, Environment, PrincipalKind, Project, SecretWithVersion, StoreError};
use serde::Deserialize;
use serde_json::json;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::projects::{ensure_principal_exists, principal_names};
use super::{AuditTarget, audit, find_env, from_api_kind, load_project, to_api_kind};
use crate::auth::{ClientIp, Principal};
use crate::authz::{SecretAccess, allowed, manages_secret_access, require_any};
use crate::error::{ApiError, ApiResult};
use crate::secrets::{secret_access_off, secret_resource};
use crate::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_setting, put_setting))
        .routes(routes!(get_secret_access, patch_secret_access))
}

/// The most entries one secret's access list may hold.
pub const MAX_GRANTS: usize = 100;
/// The longest principal id an entry may name.
const MAX_PRINCIPAL_ID: usize = 256;

fn admins_only() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden",
        "only a project admin or an organisation admin can manage per-secret access",
    )
}

/// Loads a project for managing per-secret access, which needs a project or organisation admin
/// whose rules still allow `action` on the project's settings.
async fn load_for_access(
    state: &AppState,
    principal: &Principal,
    project: &str,
    action: Action,
) -> ApiResult<(Project, Vec<Rule>)> {
    let (project, rules) = load_project(state, principal, project).await?;
    if !manages_secret_access(state, principal, &project.id).await? {
        return Err(admins_only());
    }
    require_any(&rules, Subject::Settings, action)?;
    Ok((project, rules))
}

/// Restricted secrets in the project the rules let the caller read, with their list sizes.
async fn restricted_secrets(state: &AppState, project: &Project, rules: &[Rule]) -> ApiResult<Vec<RestrictedSecret>> {
    let mut sizes: HashMap<String, i64> = HashMap::new();
    for grant in state.store.list_project_grants(&project.id).await? {
        *sizes.entry(grant.secret_id).or_default() += 1;
    }
    Ok(state
        .store
        .list_restricted_secrets(&project.id)
        .await?
        .into_iter()
        .filter(|s| {
            let resource = secret_resource(&s.environment, &s.path, &s.key, &s.tags, Access::Open);
            allowed(rules, Subject::Secrets, Action::Read, &resource)
        })
        .map(|s| RestrictedSecret {
            grants: sizes.get(&s.secret_id).copied().unwrap_or(0),
            environment: s.environment,
            path: s.path,
            key: s.key,
            deleted: s.deleted,
        })
        .collect())
}

async fn setting(state: &AppState, project: &Project, rules: &[Rule]) -> ApiResult<SecretAccessSetting> {
    Ok(SecretAccessSetting {
        enabled: project.secret_access,
        restricted: restricted_secrets(state, project, rules).await?,
        restricted_count: state.store.count_restricted_secrets(&project.id).await?,
    })
}

/// Admins only, along with the restricted secrets they may see.
#[utoipa::path(get, path = "/api/v1/projects/{project}/secret-access", tag = "projects",
    params(("project" = String, Path)), responses((status = 200, body = SecretAccessSetting)), security(("bearer" = [])))]
async fn get_setting(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<SecretAccessSetting>> {
    let (project, rules) = load_for_access(&state, &principal, &project, Action::Read).await?;
    Ok(Json(setting(&state, &project, &rules).await?))
}

/// Turns per-secret access on or off for the project. It is off by default, and turning it off
/// is refused while any secret in the project is restricted, so no restriction lapses unnoticed.
#[utoipa::path(put, path = "/api/v1/projects/{project}/secret-access", tag = "projects",
    params(("project" = String, Path)), request_body = SetSecretAccessSetting,
    responses((status = 200, body = SecretAccessSetting), (status = 409, description = "secrets are still restricted")),
    security(("bearer" = [])))]
async fn put_setting(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
    Json(request): Json<SetSecretAccessSetting>,
) -> ApiResult<Json<SecretAccessSetting>> {
    let (mut project, rules) = load_for_access(&state, &principal, &project, Action::Edit).await?;
    let result = state
        .store
        .set_project_secret_access(&project.id, request.enabled)
        .await;
    if let Err(StoreError::Conflict) = result {
        let count = state.store.count_restricted_secrets(&project.id).await?;
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "secrets_restricted",
            format!(
                "{count} secret{} in this project {} restricted; unrestrict {} before turning per-secret access off",
                if count == 1 { "" } else { "s" },
                if count == 1 { "is" } else { "are" },
                if count == 1 { "it" } else { "them" },
            ),
        ));
    }
    result?;
    let changed = project.secret_access != request.enabled;
    project.secret_access = request.enabled;
    if changed {
        audit(
            &state,
            &principal,
            ip,
            "project.secret-access",
            AuditTarget {
                project_id: Some(&project.id),
                ..Default::default()
            },
            json!({"enabled": request.enabled}),
        )
        .await;
    }
    Ok(Json(setting(&state, &project, &rules).await?))
}

#[derive(Deserialize, IntoParams)]
struct KeyParams {
    #[serde(default = "root")]
    path: String,
}

fn root() -> String {
    "/".into()
}

/// The secret a request names, deleted or not, as long as the admin's rules let them see it.
/// One they may not see answers as missing.
async fn load_secret(
    state: &AppState,
    principal: &Principal,
    project: &str,
    env: &str,
    path: &str,
    key: &str,
    action: Action,
) -> ApiResult<(Project, Environment, SecretWithVersion)> {
    let (project, rules) = load_for_access(state, principal, project, action).await?;
    let env = find_env(state, &project, &rules, env).await?;
    let path = validate::folder_path(path)?;
    let found = state
        .store
        .get_secret(&env.id, &path, key)
        .await?
        .filter(|s| {
            let resource = secret_resource(&env.slug, &path, key, &s.version.tags, Access::Open);
            allowed(&rules, Subject::Secrets, Action::Read, &resource)
        })
        .ok_or_else(|| ApiError::not_found("secret"))?;
    Ok((project, env, found))
}

async fn describe(state: &AppState, s: &SecretWithVersion) -> ApiResult<ApiSecretAccess> {
    let names = principal_names(state).await?;
    let grants = state
        .store
        .list_secret_grants(&s.secret.id)
        .await?
        .into_iter()
        .map(|g| SecretGrant {
            principal_kind: to_api_kind(g.principal_kind),
            principal_name: names
                .get(&(g.principal_kind, g.principal_id.clone()))
                .cloned()
                .unwrap_or_else(|| g.principal_id.clone()),
            principal_id: g.principal_id,
            actions: g.actions,
            created_at: g.created_at,
        })
        .collect();
    Ok(ApiSecretAccess {
        restricted: s.secret.restricted,
        grants,
    })
}

/// A secret's restricted flag and access list. Admins only.
#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/access", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams),
    responses((status = 200, body = sekret_api::SecretAccess)), security(("bearer" = [])))]
async fn get_secret_access(
    State(state): State<AppState>,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
) -> ApiResult<Json<ApiSecretAccess>> {
    let (_, _, s) = load_secret(&state, &principal, &project, &env, &params.path, &key, Action::Read).await?;
    Ok(Json(describe(&state, &s).await?))
}

/// The actions an entry grants, in a fixed order with `read` always first.
fn grant_actions(requested: &[Action]) -> ApiResult<Vec<Action>> {
    if let Some(bad) = requested.iter().find(|a| !LISTABLE_ACTIONS.contains(a)) {
        return Err(ApiError::bad_request(format!(
            "an access list cannot grant {}; use read, read-value, edit or delete",
            serde_json::to_value(bad)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default()
        )));
    }
    Ok(LISTABLE_ACTIONS
        .into_iter()
        .filter(|a| *a == Action::Read || requested.contains(a))
        .collect())
}

fn check_principal_id(id: &str) -> ApiResult<()> {
    let hidden = |c: char| c.is_control() || validate::is_invisible_format(c);
    if id.trim().is_empty() || id.len() > MAX_PRINCIPAL_ID || id.chars().any(hidden) {
        return Err(ApiError::bad_request(format!(
            "principal ids must be 1 to {MAX_PRINCIPAL_ID} characters without control or invisible characters"
        )));
    }
    Ok(())
}

type Principals = Vec<(PrincipalKind, String)>;

/// Validated grants and revocations. Each principal appears at most once across both.
async fn plan_change(
    state: &AppState,
    secret_id: &str,
    now: i64,
    grant: Vec<GrantRequest>,
    revoke: Vec<PrincipalRef>,
) -> ApiResult<(Vec<sekret_store::SecretGrant>, Principals)> {
    if grant.len() + revoke.len() > MAX_GRANTS {
        return Err(ApiError::bad_request(format!(
            "at most {MAX_GRANTS} grants and revocations per request"
        )));
    }
    let mut seen = HashSet::new();
    let mut revoked = Vec::with_capacity(revoke.len());
    for r in revoke {
        let kind = from_api_kind(r.principal_kind);
        check_principal_id(&r.principal_id)?;
        if !seen.insert((kind, r.principal_id.clone())) {
            return Err(ApiError::bad_request(format!(
                "{} {} appears more than once in the request",
                kind.as_str(),
                r.principal_id
            )));
        }
        revoked.push((kind, r.principal_id));
    }
    let mut granted = Vec::with_capacity(grant.len());
    for g in grant {
        let kind = from_api_kind(g.principal_kind);
        check_principal_id(&g.principal_id)?;
        if !seen.insert((kind, g.principal_id.clone())) {
            return Err(ApiError::bad_request(format!(
                "{} {} appears more than once in the request",
                kind.as_str(),
                g.principal_id
            )));
        }
        ensure_principal_exists(state, kind, &g.principal_id).await?;
        granted.push(sekret_store::SecretGrant {
            secret_id: secret_id.to_string(),
            principal_kind: kind,
            actions: grant_actions(&g.actions)?,
            principal_id: g.principal_id,
            created_at: now,
        });
    }
    Ok((granted, revoked))
}

/// Restricts or unrestricts a secret and changes its access list, all at once. Admins only.
/// Restricting and granting need the project setting on; unrestricting and revoking always
/// work, so a project can be cleaned up before the setting is turned off. A restricted secret
/// is reachable only by the principals on its list, for the actions listed, and only as far as
/// their roles also allow; admins keep access so a secret is never orphaned.
#[utoipa::path(patch, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/access", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams),
    request_body = SecretAccessChange,
    responses((status = 200, body = sekret_api::SecretAccess), (status = 409, description = "per-secret access is off")),
    security(("bearer" = [])))]
async fn patch_secret_access(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
    Json(request): Json<SecretAccessChange>,
) -> ApiResult<Json<ApiSecretAccess>> {
    let (project, env, s) = load_secret(&state, &principal, &project, &env, &params.path, &key, Action::Edit).await?;
    let widens = request.restricted == Some(true) || !request.grant.is_empty();
    if widens && !project.secret_access {
        return Err(secret_access_off());
    }
    let (grant, revoke) = plan_change(&state, &s.secret.id, state.clock.now(), request.grant, request.revoke).await?;
    let existing = state.store.list_secret_grants(&s.secret.id).await?;
    // A revocation that matches nobody would read as done while access stays.
    if let Some((kind, id)) = revoke.iter().find(|(kind, id)| {
        !existing
            .iter()
            .any(|e| e.principal_kind == *kind && e.principal_id == *id)
    }) {
        return Err(ApiError::bad_request(format!(
            "{} {id} is not on this secret's access list",
            kind.as_str()
        )));
    }
    // Unrestricting clears the list, so a later restriction never brings back stale entries.
    let clears = request.restricted == Some(false);
    let survivors: Vec<&sekret_store::SecretGrant> = existing
        .iter()
        .filter(|e| {
            let key = (e.principal_kind, e.principal_id.clone());
            !revoke.contains(&key)
                && !grant
                    .iter()
                    .any(|g| g.principal_kind == key.0 && g.principal_id == key.1)
        })
        .collect();
    let kept = if clears { 0 } else { survivors.len() };
    if kept + grant.len() > MAX_GRANTS {
        return Err(ApiError::bad_request(format!(
            "a secret's access list holds at most {MAX_GRANTS} entries"
        )));
    }
    let mut detail = json!({
        "restricted": request.restricted,
        "granted": grant.iter().map(|g| json!({
            "principal_kind": g.principal_kind.as_str(),
            "principal_id": g.principal_id,
            "actions": g.actions,
        })).collect::<Vec<_>>(),
        "revoked": revoke.iter().map(|(kind, id)| json!({
            "principal_kind": kind.as_str(),
            "principal_id": id,
        })).collect::<Vec<_>>(),
    });
    let change = AccessChange {
        secret_id: s.secret.id.clone(),
        restricted: request.restricted,
        grant,
        revoke,
        max_grants: MAX_GRANTS,
    };
    let mut changes_anything = change.restricted.is_some_and(|r| r != s.secret.restricted)
        || !change.grant.is_empty()
        || !change.revoke.is_empty();
    let cleared = match state.store.update_secret_access(change).await {
        Ok(cleared) => cleared,
        Err(StoreError::NotFound) => return Err(ApiError::not_found("secret")),
        // Either the setting went off, or a change made at the same moment filled the list.
        Err(StoreError::Conflict) => {
            let current = state.store.get_project(&project.id).await?;
            if current.is_some_and(|p| !p.secret_access) && widens {
                return Err(secret_access_off());
            }
            return Err(ApiError::conflict(format!(
                "the access list changed meanwhile, or would hold more than {MAX_GRANTS} entries; reload and try again"
            )));
        }
        Err(other) => return Err(other.into()),
    };
    changes_anything |= !cleared.is_empty();
    detail["cleared"] = json!(
        cleared
            .iter()
            .map(|e| json!({"principal_kind": e.principal_kind.as_str(), "principal_id": e.principal_id}))
            .collect::<Vec<_>>()
    );
    if changes_anything {
        audit(
            &state,
            &principal,
            ip,
            "secret.access",
            AuditTarget {
                project_id: Some(&project.id),
                environment: Some(&env.slug),
                path: Some(&s.secret.path),
                key: Some(&s.secret.key),
                // Access-list changes are for admins, whatever the secret is now.
                restricted: true,
            },
            detail,
        )
        .await;
    }
    let updated = state
        .store
        .get_secret_by_id(&s.secret.id)
        .await?
        .ok_or_else(|| ApiError::not_found("secret"))?;
    Ok(Json(describe(&state, &updated).await?))
}

/// Which audit entries about restricted secrets `principal` may have in the project: all of them
/// for an admin, otherwise those about the restricted secrets their lists let them read, as
/// `(environment, path, key)`. Entries are marked when written, so a secret restricted then and
/// gone or opened since stays hidden.
pub async fn restricted_visible(
    state: &AppState,
    principal: &Principal,
    project: &Project,
) -> ApiResult<Option<Vec<(String, String, String)>>> {
    if manages_secret_access(state, principal, &project.id).await? {
        return Ok(None);
    }
    let restricted = state.store.list_restricted_secrets(&project.id).await?;
    if restricted.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let access = SecretAccess::listed(principal, state.store.list_project_grants(&project.id).await?);
    // Bounded so the query stays within the database's limit on parameters; past it a reader
    // simply sees fewer entries.
    Ok(Some(
        restricted
            .into_iter()
            .filter(|s| access.lists_for_read(&s.secret_id))
            .take(MAX_VISIBLE_RESTRICTED)
            .map(|s| (s.environment, s.path, s.key))
            .collect(),
    ))
}

/// The most restricted secrets whose audit entries one reader's query names.
const MAX_VISIBLE_RESTRICTED: usize = 2000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_always_read_and_refuse_create() -> anyhow::Result<()> {
        let actions = grant_actions(&[Action::Delete, Action::ReadValue]).map_err(|e| anyhow::anyhow!(e.message))?;
        assert_eq!(actions, vec![Action::Read, Action::ReadValue, Action::Delete]);
        let read = grant_actions(&[]).map_err(|e| anyhow::anyhow!(e.message))?;
        assert_eq!(read, vec![Action::Read]);
        let refused = grant_actions(&[Action::Create]).err().map(|e| e.message);
        assert!(refused.is_some_and(|m| m.contains("create")));
        Ok(())
    }

    #[test]
    fn principal_ids_are_bounded() {
        assert!(check_principal_id("ops").is_ok());
        assert!(check_principal_id("").is_err());
        assert!(check_principal_id("  ").is_err());
        assert!(check_principal_id("a\nb").is_err());
        assert!(check_principal_id("ops\u{202E}nimda").is_err(), "a bidi override");
        assert!(check_principal_id("op\u{200B}s").is_err(), "a zero-width space");
        assert!(check_principal_id("équipe-ops").is_ok(), "accents are fine");
        assert!(check_principal_id(&"x".repeat(MAX_PRINCIPAL_ID + 1)).is_err());
    }
}
