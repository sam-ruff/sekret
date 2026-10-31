use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use sekret_api::{
    BatchResult, BatchWrite, GenerateSecret, Overview, OverviewRow, PolicyOverride, RawSecret, RawSecrets,
    RestoreRequest, RollbackRequest, Secret, SecretList, SecretPolicyView, SecretUpsert, SecretVersion, SetSecret,
    Snapshot, SnapshotDetail,
};
use sekret_core::permissions::{Action, Resource, Subject};
use sekret_core::rotation::next_rotation;
use sekret_core::validate;
use sekret_store::{Environment, Project, SecretWithVersion};
use serde::Deserialize;
use serde_json::json;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::{AuditTarget, api_env, audit, find_env, load_project, secret_ctx};
use crate::auth::{ClientIp, Principal};
use crate::authz::{allowed, require};
use crate::error::{ApiError, ApiResult};
use crate::rotation::{Target, effective_policy, plan_generated, secret_override};
use crate::secrets::{
    apply, data_key, decrypt, plan_batch, plan_restore, plan_rollback, secret_resource, snapshot_changes, to_api,
};
use crate::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_secrets))
        .routes(routes!(batch_write))
        .routes(routes!(get_secret, put_secret, delete_secret))
        .routes(routes!(list_versions))
        .routes(routes!(rollback))
        .routes(routes!(generate_secret))
        .routes(routes!(get_secret_policy, put_secret_policy))
        .routes(routes!(overview))
        .routes(routes!(list_snapshots))
        .routes(routes!(get_snapshot))
        .routes(routes!(restore_snapshot))
        .routes(routes!(raw_secrets))
}

#[derive(Deserialize, IntoParams)]
struct ListParams {
    #[serde(default = "root")]
    path: String,
    #[serde(default)]
    recursive: bool,
    /// Include decrypted values where permitted.
    #[serde(default)]
    values: bool,
}

#[derive(Deserialize, IntoParams)]
struct KeyParams {
    #[serde(default = "root")]
    path: String,
}

fn root() -> String {
    "/".into()
}

struct Scope {
    project: Project,
    env: Environment,
    rules: Vec<sekret_core::permissions::Rule>,
}

async fn scope(state: &AppState, principal: &Principal, project: &str, env: &str) -> ApiResult<Scope> {
    let (project, rules) = load_project(state, principal, project).await?;
    let env = find_env(state, &project, env).await?;
    Ok(Scope { project, env, rules })
}

async fn load_secret(state: &AppState, scope: &Scope, path: &str, key: &str) -> ApiResult<(String, SecretWithVersion)> {
    let path = validate::folder_path(path)?;
    let found = state.store.get_secret(&scope.env.id, &path, key).await?;
    let readable = found.filter(|s| {
        !s.secret.deleted
            && allowed(
                &scope.rules,
                Subject::Secrets,
                Action::Read,
                &secret_resource(&scope.env.slug, &path, key, &s.version.tags),
            )
    });
    readable.map(|s| (path, s)).ok_or_else(|| ApiError::not_found("secret"))
}

/// Like `load_secret`, but also finds a deleted secret, whose history can bring it back.
/// Anything the caller may not read is reported as missing, so a refusal cannot confirm a key.
async fn load_history(
    state: &AppState,
    scope: &Scope,
    path: &str,
    key: &str,
) -> ApiResult<(String, SecretWithVersion)> {
    let path = validate::folder_path(path)?;
    let found = state.store.get_secret(&scope.env.id, &path, key).await?;
    let readable = found.filter(|s| {
        allowed(
            &scope.rules,
            Subject::Secrets,
            Action::Read,
            &secret_resource(&scope.env.slug, &path, key, &s.version.tags),
        )
    });
    readable.map(|s| (path, s)).ok_or_else(|| ApiError::not_found("secret"))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/secrets", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ListParams),
    responses((status = 200, body = SecretList)), security(("bearer" = [])))]
async fn list_secrets(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
    Query(params): Query<ListParams>,
) -> ApiResult<Json<SecretList>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let path = validate::folder_path(&params.path)?;
    let stored = state
        .store
        .list_secrets(&scope.env.id, &path, params.recursive, false)
        .await?;
    let key = if params.values {
        Some(data_key(state.keyring.root()?.as_ref(), &scope.project)?)
    } else {
        None
    };
    let mut secrets = Vec::new();
    for s in &stored {
        let resource = secret_resource(&scope.env.slug, &s.secret.path, &s.secret.key, &s.version.tags);
        if allowed(&scope.rules, Subject::Secrets, Action::Read, &resource) {
            secrets.push(to_api(
                key.as_ref(),
                &scope.project,
                &scope.env.slug,
                s,
                &scope.rules,
                params.values,
            )?);
        }
    }
    let prefix = if path == "/" {
        "/".to_string()
    } else {
        format!("{path}/")
    };
    let folders = state
        .store
        .list_folders(&scope.env.id)
        .await?
        .into_iter()
        .filter(|f| {
            let resource = Resource {
                environment: Some(&scope.env.slug),
                path: Some(&f.path),
                ..Default::default()
            };
            allowed(&scope.rules, Subject::Folders, Action::Read, &resource)
        })
        .filter_map(|f| {
            f.path
                .strip_prefix(&prefix)
                .filter(|rest| !rest.is_empty() && !rest.contains('/'))
                .map(String::from)
        })
        .collect();
    if params.values {
        let revealed = secrets.iter().filter(|s| s.value.is_some()).count();
        audit(
            &state,
            &principal,
            ip,
            "secret.read",
            AuditTarget {
                project_id: Some(&scope.project.id),
                environment: Some(&scope.env.slug),
                path: Some(&path),
                key: None,
            },
            json!({"count": revealed, "recursive": params.recursive}),
        )
        .await;
    }
    Ok(Json(SecretList { secrets, folders }))
}

async fn write(
    state: &AppState,
    principal: &Principal,
    ip: std::net::IpAddr,
    scope: &Scope,
    path: &str,
    upserts: Vec<SecretUpsert>,
    deletes: Vec<String>,
) -> ApiResult<BatchResult> {
    let ctx = secret_ctx(state, principal)?;
    let planned = plan_batch(&ctx, &scope.rules, &scope.project, &scope.env, path, upserts, deletes).await?;
    let result = apply(&ctx, planned).await?;
    let normalised = validate::folder_path(path)?;
    if result.snapshot_id.is_some() {
        audit(
            state,
            principal,
            ip,
            "secret.write",
            AuditTarget {
                project_id: Some(&scope.project.id),
                environment: Some(&scope.env.slug),
                path: Some(&normalised),
                key: None,
            },
            json!({"created": result.created, "updated": result.updated, "deleted": result.deleted}),
        )
        .await;
    }
    Ok(result)
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/environments/{env}/secrets/batch", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path)), request_body = BatchWrite,
    responses((status = 200, body = BatchResult)), security(("bearer" = [])))]
async fn batch_write(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
    Json(request): Json<BatchWrite>,
) -> ApiResult<Json<BatchResult>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    if request.upserts.len() + request.deletes.len() > 1000 {
        return Err(ApiError::bad_request("at most 1000 changes per batch"));
    }
    Ok(Json(
        write(
            &state,
            &principal,
            ip,
            &scope,
            &request.path,
            request.upserts,
            request.deletes,
        )
        .await?,
    ))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams),
    responses((status = 200, body = Secret)), security(("bearer" = [])))]
async fn get_secret(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
) -> ApiResult<Json<Secret>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let (path, s) = load_secret(&state, &scope, &params.path, &key).await?;
    let dk = data_key(state.keyring.root()?.as_ref(), &scope.project)?;
    let secret = to_api(Some(&dk), &scope.project, &scope.env.slug, &s, &scope.rules, true)?;
    if secret.value.is_some() {
        audit(
            &state,
            &principal,
            ip,
            "secret.read",
            AuditTarget {
                project_id: Some(&scope.project.id),
                environment: Some(&scope.env.slug),
                path: Some(&path),
                key: Some(&key),
            },
            json!({}),
        )
        .await;
    }
    Ok(Json(secret))
}

#[utoipa::path(put, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams), request_body = SetSecret,
    responses((status = 200, body = BatchResult)), security(("bearer" = [])))]
async fn put_secret(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
    Json(request): Json<SetSecret>,
) -> ApiResult<Json<BatchResult>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let upsert = SecretUpsert {
        key,
        value: request.value,
        comment: request.comment,
        tags: request.tags,
    };
    Ok(Json(
        write(&state, &principal, ip, &scope, &params.path, vec![upsert], vec![]).await?,
    ))
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams),
    responses((status = 200, body = BatchResult)), security(("bearer" = [])))]
async fn delete_secret(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
) -> ApiResult<Json<BatchResult>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    load_secret(&state, &scope, &params.path, &key).await?;
    Ok(Json(
        write(&state, &principal, ip, &scope, &params.path, vec![], vec![key]).await?,
    ))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/versions", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), ListParams),
    responses((status = 200, body = Vec<SecretVersion>)), security(("bearer" = [])))]
async fn list_versions(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<ListParams>,
) -> ApiResult<Json<Vec<SecretVersion>>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let (path, s) = load_history(&state, &scope, &params.path, &key).await?;
    let resource = secret_resource(&scope.env.slug, &path, &key, &s.version.tags);
    require(&scope.rules, Subject::SecretVersions, Action::Read, &resource)?;
    let may_reveal = |resource: &Resource<'_>| {
        allowed(&scope.rules, Subject::SecretVersions, Action::ReadValue, resource)
            && allowed(&scope.rules, Subject::Secrets, Action::ReadValue, resource)
    };
    let reveal_current = params.values && may_reveal(&resource);
    let dk = data_key(state.keyring.root()?.as_ref(), &scope.project)?;
    let mut versions = Vec::new();
    let mut revealed_any = false;
    for v in state.store.list_versions(&s.secret.id).await? {
        // Each version is judged by its own tags as well, so retagging cannot expose old values.
        let reveal = reveal_current && may_reveal(&secret_resource(&scope.env.slug, &path, &key, &v.tags));
        revealed_any |= reveal;
        let value = if reveal {
            decrypt(&dk, &scope.project.id, &v)?.map(|v| v.to_string())
        } else {
            None
        };
        versions.push(SecretVersion {
            version: v.version,
            value,
            value_hidden: !reveal && !v.deleted,
            deleted: v.deleted,
            comment: v.comment,
            tags: v.tags,
            actor: v.actor,
            created_at: v.created_at,
        });
    }
    if revealed_any {
        audit(
            &state,
            &principal,
            ip,
            "secret.history-read",
            AuditTarget {
                project_id: Some(&scope.project.id),
                environment: Some(&scope.env.slug),
                path: Some(&path),
                key: Some(&key),
            },
            json!({}),
        )
        .await;
    }
    Ok(Json(versions))
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/rollback", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams), request_body = RollbackRequest,
    responses((status = 200, body = BatchResult)), security(("bearer" = [])))]
async fn rollback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
    Json(request): Json<RollbackRequest>,
) -> ApiResult<Json<BatchResult>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let (path, current) = load_history(&state, &scope, &params.path, &key).await?;
    let ctx = secret_ctx(&state, &principal)?;
    let planned = plan_rollback(
        &ctx,
        &scope.rules,
        &scope.project,
        &scope.env,
        &current,
        request.version,
    )
    .await?;
    let result = apply(&ctx, planned).await?;
    audit(
        &state,
        &principal,
        ip,
        "secret.rollback",
        AuditTarget {
            project_id: Some(&scope.project.id),
            environment: Some(&scope.env.slug),
            path: Some(&path),
            key: Some(&key),
        },
        json!({"to_version": request.version}),
    )
    .await;
    Ok(Json(result))
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/generate", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams), request_body = GenerateSecret,
    responses((status = 200, body = BatchResult)), security(("bearer" = [])))]
async fn generate_secret(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
    Json(request): Json<GenerateSecret>,
) -> ApiResult<Json<BatchResult>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let path = validate::folder_path(&params.path)?;
    let mut ctx = secret_ctx(&state, &principal)?;
    ctx.generated = true;
    let target = Target {
        project: &scope.project,
        env: &scope.env,
        path: &path,
        key: &key,
    };
    let planned = plan_generated(&ctx, &scope.rules, target, request.generator, request.comment).await?;
    let result = apply(&ctx, planned).await?;
    audit(
        &state,
        &principal,
        ip,
        "secret.generate",
        AuditTarget {
            project_id: Some(&scope.project.id),
            environment: Some(&scope.env.slug),
            path: Some(&path),
            key: Some(&key),
        },
        json!({"created": !result.created.is_empty()}),
    )
    .await;
    Ok(Json(result))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/policy", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams),
    responses((status = 200, body = SecretPolicyView)), security(("bearer" = [])))]
async fn get_secret_policy(
    State(state): State<AppState>,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
) -> ApiResult<Json<SecretPolicyView>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let (_, s) = load_secret(&state, &scope, &params.path, &key).await?;
    policy_view(&scope.project, &s).map(Json)
}

fn policy_view(project: &sekret_store::Project, s: &SecretWithVersion) -> ApiResult<SecretPolicyView> {
    let effective = effective_policy(project, &s.secret)?;
    Ok(SecretPolicyView {
        setting: secret_override(&s.secret)?,
        effective,
        generated: s.version.generated,
        next_rotation_at: next_rotation(&effective, s.version.generated, s.version.created_at),
    })
}

#[utoipa::path(put, path = "/api/v1/projects/{project}/environments/{env}/secrets/{key}/policy", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), KeyParams), request_body = PolicyOverride,
    responses((status = 200, body = SecretPolicyView)), security(("bearer" = [])))]
async fn put_secret_policy(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
    Json(request): Json<PolicyOverride>,
) -> ApiResult<Json<SecretPolicyView>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let (path, mut s) = load_secret(&state, &scope, &params.path, &key).await?;
    let resource = secret_resource(&scope.env.slug, &path, &key, &s.version.tags);
    require(&scope.rules, Subject::Secrets, Action::Edit, &resource)?;
    if let PolicyOverride::Custom(policy) = &request {
        policy.validate().map_err(|e| ApiError::bad_request(e.to_string()))?;
    }
    let stored = match request {
        PolicyOverride::Inherit => None,
        custom => Some(serde_json::to_string(&custom).map_err(|e| ApiError::internal("secret policy", e))?),
    };
    state.store.set_secret_policy(&s.secret.id, stored.clone()).await?;
    s.secret.policy = stored;
    audit(
        &state,
        &principal,
        ip,
        "secret.policy",
        AuditTarget {
            project_id: Some(&scope.project.id),
            environment: Some(&scope.env.slug),
            path: Some(&path),
            key: Some(&key),
        },
        json!({"policy": request}),
    )
    .await;
    policy_view(&scope.project, &s).map(Json)
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/overview", tag = "secrets",
    params(("project" = String, Path), KeyParams), responses((status = 200, body = Overview)), security(("bearer" = [])))]
async fn overview(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
    Query(params): Query<KeyParams>,
) -> ApiResult<Json<Overview>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let path = validate::folder_path(&params.path)?;
    let mut rows: BTreeMap<(String, String), BTreeMap<String, i64>> = BTreeMap::new();
    let mut environments = Vec::new();
    for env in state.store.list_environments(&project.id).await? {
        let env_resource = Resource {
            environment: Some(&env.slug),
            ..Default::default()
        };
        if !allowed(&rules, Subject::Environments, Action::Read, &env_resource) {
            continue;
        }
        for s in state.store.list_secrets(&env.id, &path, false, false).await? {
            let resource = secret_resource(&env.slug, &s.secret.path, &s.secret.key, &s.version.tags);
            if allowed(&rules, Subject::Secrets, Action::Read, &resource) {
                rows.entry((s.secret.path.clone(), s.secret.key.clone()))
                    .or_default()
                    .insert(env.slug.clone(), s.secret.current_version);
            }
        }
        environments.push(api_env(&env));
    }
    let rows = rows
        .into_iter()
        .map(|((path, key), environments)| OverviewRow {
            path,
            key,
            environments,
        })
        .collect();
    Ok(Json(Overview { environments, rows }))
}

/// A snapshot reason without its folder when the reader may not see that folder.
fn visible_reason(reason: &str, may_see: impl Fn(&str) -> bool) -> String {
    for marker in [" in /", " for /"] {
        if let Some(at) = reason.find(marker) {
            let path = &reason[at + marker.len() - 1..];
            return if may_see(path) {
                reason.to_string()
            } else {
                reason[..at].to_string()
            };
        }
    }
    reason.to_string()
}

fn api_snapshot(scope: &Scope, s: &sekret_store::Snapshot) -> Snapshot {
    let may_see = |path: &str| {
        let folder = Resource {
            environment: Some(&scope.env.slug),
            path: Some(path),
            ..Default::default()
        };
        allowed(&scope.rules, Subject::Folders, Action::Read, &folder)
    };
    Snapshot {
        id: s.id.clone(),
        reason: visible_reason(&s.reason, may_see),
        actor: s.actor.clone(),
        created_at: s.created_at,
        secret_count: s.entries.len() as i64,
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/snapshots", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path)), responses((status = 200, body = Vec<Snapshot>)), security(("bearer" = [])))]
async fn list_snapshots(
    State(state): State<AppState>,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
) -> ApiResult<Json<Vec<Snapshot>>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let env_resource = Resource {
        environment: Some(&scope.env.slug),
        ..Default::default()
    };
    require(&scope.rules, Subject::Snapshots, Action::Read, &env_resource)?;
    let snapshots = state.store.list_snapshots(&scope.env.id, 200).await?;
    Ok(Json(snapshots.iter().map(|s| api_snapshot(&scope, s)).collect()))
}

async fn load_snapshot(state: &AppState, scope: &Scope, id: &str) -> ApiResult<sekret_store::Snapshot> {
    state
        .store
        .get_snapshot(id)
        .await?
        .filter(|s| s.environment_id == scope.env.id)
        .ok_or_else(|| ApiError::not_found("snapshot"))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/snapshots/{id}", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("id" = String, Path), KeyParams),
    responses((status = 200, body = SnapshotDetail)), security(("bearer" = [])))]
async fn get_snapshot(
    State(state): State<AppState>,
    principal: Principal,
    Path((project, env, id)): Path<(String, String, String)>,
    Query(params): Query<KeyParams>,
) -> ApiResult<Json<SnapshotDetail>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let env_resource = Resource {
        environment: Some(&scope.env.slug),
        ..Default::default()
    };
    require(&scope.rules, Subject::Snapshots, Action::Read, &env_resource)?;
    let snapshot = load_snapshot(&state, &scope, &id).await?;
    let path = validate::folder_path(&params.path)?;
    let current = state.store.list_secrets(&scope.env.id, &path, true, true).await?;
    let readable: Vec<_> = current
        .into_iter()
        .filter(|s| {
            let resource = secret_resource(&scope.env.slug, &s.secret.path, &s.secret.key, &s.version.tags);
            allowed(&scope.rules, Subject::Secrets, Action::Read, &resource)
        })
        .collect();
    Ok(Json(SnapshotDetail {
        snapshot: api_snapshot(&scope, &snapshot),
        changes: snapshot_changes(&readable, &snapshot, &path),
    }))
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/environments/{env}/snapshots/{id}/restore", tag = "secrets",
    params(("project" = String, Path), ("env" = String, Path), ("id" = String, Path)), request_body = RestoreRequest,
    responses((status = 200, body = BatchResult)), security(("bearer" = [])))]
async fn restore_snapshot(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, id)): Path<(String, String, String)>,
    Json(request): Json<RestoreRequest>,
) -> ApiResult<Json<BatchResult>> {
    let scope = scope(&state, &principal, &project, &env).await?;
    let path = validate::folder_path(&request.path)?;
    let env_resource = Resource {
        environment: Some(&scope.env.slug),
        path: Some(&path),
        ..Default::default()
    };
    require(&scope.rules, Subject::Snapshots, Action::Edit, &env_resource)?;
    let snapshot = load_snapshot(&state, &scope, &id).await?;
    let ctx = secret_ctx(&state, &principal)?;
    let planned = plan_restore(&ctx, &scope.rules, &scope.project, &scope.env, &snapshot, &path).await?;
    let result = apply(&ctx, planned).await?;
    audit(
        &state,
        &principal,
        ip,
        "snapshot.restore",
        AuditTarget {
            project_id: Some(&scope.project.id),
            environment: Some(&scope.env.slug),
            path: Some(&path),
            key: None,
        },
        json!({"snapshot": id, "created": result.created, "updated": result.updated, "deleted": result.deleted}),
    )
    .await;
    Ok(Json(result))
}

#[derive(Deserialize, IntoParams)]
struct RawParams {
    project: String,
    environment: String,
    #[serde(default = "root")]
    path: String,
    #[serde(default)]
    recursive: bool,
}

/// Every readable value under a path, for machines. Secrets the caller cannot read are left out.
#[utoipa::path(get, path = "/api/v1/secrets/raw", tag = "secrets", params(RawParams),
    responses((status = 200, body = RawSecrets)), security(("bearer" = [])))]
async fn raw_secrets(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Query(params): Query<RawParams>,
) -> ApiResult<Json<RawSecrets>> {
    let scope = scope(&state, &principal, &params.project, &params.environment).await?;
    let path = validate::folder_path(&params.path)?;
    let dk = data_key(state.keyring.root()?.as_ref(), &scope.project)?;
    let mut secrets = Vec::new();
    for s in state
        .store
        .list_secrets(&scope.env.id, &path, params.recursive, false)
        .await?
    {
        let resource = secret_resource(&scope.env.slug, &s.secret.path, &s.secret.key, &s.version.tags);
        let readable = allowed(&scope.rules, Subject::Secrets, Action::Read, &resource)
            && allowed(&scope.rules, Subject::Secrets, Action::ReadValue, &resource);
        if !readable {
            continue;
        }
        if let Some(value) = decrypt(&dk, &scope.project.id, &s.version)? {
            secrets.push(RawSecret {
                path: s.secret.path.clone(),
                key: s.secret.key.clone(),
                value: value.to_string(),
            });
        }
    }
    audit(
        &state,
        &principal,
        ip,
        "secret.read",
        AuditTarget {
            project_id: Some(&scope.project.id),
            environment: Some(&scope.env.slug),
            path: Some(&path),
            key: None,
        },
        json!({"count": secrets.len(), "recursive": params.recursive, "raw": true}),
    )
    .await;
    Ok(Json(RawSecrets {
        project: scope.project.slug,
        environment: scope.env.slug,
        secrets,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reasons_drop_folders_the_reader_cannot_see() {
        let may_see = |path: &str| !path.starts_with("/payments");
        let cases = [
            (
                "1 created, 0 updated, 0 deleted in /payments/stripe",
                "1 created, 0 updated, 0 deleted",
            ),
            (
                "1 created, 0 updated, 0 deleted in /web",
                "1 created, 0 updated, 0 deleted in /web",
            ),
            ("restored snapshot abc for /payments", "restored snapshot abc"),
            ("restored snapshot abc for /", "restored snapshot abc for /"),
            ("rolled back to version 3", "rolled back to version 3"),
        ];
        for (reason, expected) in cases {
            assert_eq!(visible_reason(reason, may_see), expected);
        }
    }
}
