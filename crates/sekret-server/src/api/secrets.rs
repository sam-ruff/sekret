use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, LazyLock};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use sekret_api::{
    BatchResult, BatchWrite, GenerateSecret, Overview, OverviewRow, PolicyOverride, RawSecret, RawSecrets,
    RestoreRequest, RollbackRequest, Secret, SecretList, SecretPolicyView, SecretUpsert, SecretVersion, SetSecret,
    Snapshot, SnapshotDetail,
};
use sekret_core::permissions::{Action, MAX_PRINCIPAL_PATTERNS, Resource, Rule, Subject, pattern_count};
use sekret_core::rotation::next_rotation;
use sekret_core::validate;
use sekret_store::{Environment, Project, SecretWithVersion};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::{AuditTarget, api_env, audit, find_env, load_project, secret_ctx};
use crate::auth::{ClientIp, Principal};
use crate::authz::{Caller, SecretAccess, allowed, require, secret_access};
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

/// Versions a history page holds when the caller does not say.
pub const DEFAULT_HISTORY_PAGE: u32 = 100;
/// The most versions one history page may hold, so revealing values decrypts a bounded amount.
pub const MAX_HISTORY_PAGE: u32 = 200;

#[derive(Deserialize, IntoParams)]
struct HistoryParams {
    #[serde(default = "root")]
    path: String,
    /// Include decrypted values where permitted.
    #[serde(default)]
    values: bool,
    /// Versions to return, newest first: 100 by default, at most 200.
    limit: Option<u32>,
    /// Only versions older than this one, to fetch the page after one ending at `before`.
    before: Option<i64>,
}

impl HistoryParams {
    fn page_size(&self) -> ApiResult<i64> {
        match self.limit {
            None => Ok(i64::from(DEFAULT_HISTORY_PAGE)),
            Some(n @ 1..=MAX_HISTORY_PAGE) => Ok(i64::from(n)),
            Some(_) => Err(ApiError::bad_request(format!(
                "limit must be between 1 and {MAX_HISTORY_PAGE}"
            ))),
        }
    }
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
    access: SecretAccess,
}

impl Scope {
    fn caller(&self) -> Caller<'_> {
        Caller {
            rules: &self.rules,
            access: &self.access,
        }
    }

    fn resource<'a>(&'a self, s: &'a sekret_store::Secret, tags: &'a [String]) -> Resource<'a> {
        secret_resource(&self.env.slug, &s.path, &s.key, tags, self.access.of(s))
    }
}

async fn scope(state: &AppState, principal: &Principal, project: &str, env: &str) -> ApiResult<Scope> {
    let (project, rules) = load_project(state, principal, project).await?;
    let env = find_env(state, &project, &rules, env).await?;
    let access = secret_access(state, principal, &project.id, &env.id).await?;
    Ok(Scope {
        project,
        env,
        rules,
        access,
    })
}

/// Pattern checks a listing may run on an async worker before it moves to the blocking pool.
const INLINE_CHECKS: usize = 20_000;

/// Long permission checks running at once: half the cores, so listings cannot take them all.
static CHECK_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
    Arc::new(Semaphore::new((cores / 2).max(1)))
});

/// The secrets in `env` the rules allow every one of `actions` on. A long list checked against
/// many patterns runs on the blocking pool, so it cannot stall the workers other requests need.
async fn permitted(
    caller: Caller<'_>,
    env: &str,
    secrets: Vec<SecretWithVersion>,
    actions: &'static [Action],
) -> ApiResult<Vec<SecretWithVersion>> {
    permitted_with(&CHECK_SLOTS, caller, env, secrets, actions).await
}

async fn permitted_with(
    slots: &Arc<Semaphore>,
    caller: Caller<'_>,
    env: &str,
    secrets: Vec<SecretWithVersion>,
    actions: &'static [Action],
) -> ApiResult<Vec<SecretWithVersion>> {
    let rules = caller.rules;
    // Bindings are capped when made, but groups come from the identity provider at sign-in.
    let checked = rules
        .iter()
        .filter(|r| r.subject == Subject::Secrets)
        .map(|r| r.conditions.paths.len() + r.conditions.keys.len())
        .sum::<usize>();
    if checked > MAX_PRINCIPAL_PATTERNS {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "too_many_patterns",
            format!(
                "your roles here hold more than {MAX_PRINCIPAL_PATTERNS} path and key patterns, counting those of \
                 your groups; ask a project admin to simplify them"
            ),
        ));
    }
    let keep = |rules: &[Rule], access: &SecretAccess, env: &str, s: &SecretWithVersion| {
        let resource = secret_resource(
            env,
            &s.secret.path,
            &s.secret.key,
            &s.version.tags,
            access.of(&s.secret),
        );
        actions
            .iter()
            .all(|action| allowed(rules, Subject::Secrets, *action, &resource))
    };
    if !runs_off_runtime(secrets.len(), rules) {
        return Ok(secrets
            .into_iter()
            .filter(|s| keep(rules, caller.access, env, s))
            .collect());
    }
    let slot = slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| ApiError::internal("permission check", e))?;
    let rules = rules.to_vec();
    let access = caller.access.clone();
    let env = env.to_string();
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        secrets.into_iter().filter(|s| keep(&rules, &access, &env, s)).collect()
    })
    .await
    .map_err(|e| ApiError::internal("permission check", e))
}

fn runs_off_runtime(items: usize, rules: &[Rule]) -> bool {
    items.saturating_mul(pattern_count(rules)) > INLINE_CHECKS
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
                &scope.resource(&s.secret, &s.version.tags),
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
            &scope.resource(&s.secret, &s.version.tags),
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
    let readable = permitted(scope.caller(), &scope.env.slug, stored, &[Action::Read]).await?;
    let mut secrets = Vec::with_capacity(readable.len());
    for s in &readable {
        secrets.push(to_api(
            key.as_ref(),
            &scope.project,
            &scope.env.slug,
            s,
            scope.caller(),
            params.values,
        )?);
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
    let planned = plan_batch(&ctx, scope.caller(), &scope.project, &scope.env, path, upserts, deletes).await?;
    let restricted: Vec<String> = planned
        .batch
        .iter()
        .flat_map(|b| &b.changes)
        .filter(|c| c.restricted)
        .map(|c| c.key.clone())
        .collect();
    let result = apply(&ctx, planned).await?;
    let normalised = validate::folder_path(path)?;
    if result.snapshot_id.is_some() {
        let mut detail = json!({"created": result.created, "updated": result.updated, "deleted": result.deleted});
        if !restricted.is_empty() {
            detail["restricted"] = json!(restricted);
        }
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
            detail,
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
    let secret = to_api(Some(&dk), &scope.project, &scope.env.slug, &s, scope.caller(), true)?;
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
        restricted: request.restricted,
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
    params(("project" = String, Path), ("env" = String, Path), ("key" = String, Path), HistoryParams),
    description = "Newest first, one page at a time. A page shorter than `limit` is the last; otherwise pass the \
        oldest version returned as `before` for the next.",
    responses((status = 200, body = Vec<SecretVersion>)), security(("bearer" = [])))]
async fn list_versions(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env, key)): Path<(String, String, String)>,
    Query(params): Query<HistoryParams>,
) -> ApiResult<Json<Vec<SecretVersion>>> {
    let limit = params.page_size()?;
    let scope = scope(&state, &principal, &project, &env).await?;
    let (path, s) = load_history(&state, &scope, &params.path, &key).await?;
    let resource = scope.resource(&s.secret, &s.version.tags);
    require(&scope.rules, Subject::SecretVersions, Action::Read, &resource)?;
    let may_reveal = |resource: &Resource<'_>| {
        allowed(&scope.rules, Subject::SecretVersions, Action::ReadValue, resource)
            && allowed(&scope.rules, Subject::Secrets, Action::ReadValue, resource)
    };
    let reveal_current = params.values && may_reveal(&resource);
    let dk = data_key(state.keyring.root()?.as_ref(), &scope.project)?;
    let mut versions = Vec::new();
    let mut revealed_any = false;
    for v in state.store.list_versions(&s.secret.id, params.before, limit).await? {
        // Each version is judged by its own tags as well, so retagging cannot expose old values.
        let own = scope.resource(&s.secret, &v.tags);
        let reveal = reveal_current && may_reveal(&own);
        revealed_any |= reveal;
        let value = if reveal {
            decrypt(&dk, &scope.project.id, &v)?.map(|v| v.to_string())
        } else {
            None
        };
        // A version whose own tags hide it keeps only its number, date and whether it was a deletion.
        let described = allowed(&scope.rules, Subject::Secrets, Action::Read, &own)
            && allowed(&scope.rules, Subject::SecretVersions, Action::Read, &own);
        let (comment, tags, actor) = if described {
            (v.comment, v.tags, v.actor)
        } else {
            (String::new(), Vec::new(), String::new())
        };
        versions.push(SecretVersion {
            version: v.version,
            value,
            value_hidden: !reveal && !v.deleted,
            deleted: v.deleted,
            comment,
            tags,
            actor,
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
        scope.caller(),
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
    let planned = plan_generated(&ctx, scope.caller(), target, request.generator, request.comment).await?;
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
    require(
        &scope.rules,
        Subject::Secrets,
        Action::Edit,
        &scope.resource(&s.secret, &s.version.tags),
    )?;
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
        let access = secret_access(&state, &principal, &project.id, &env.id).await?;
        let caller = Caller {
            rules: &rules,
            access: &access,
        };
        let stored = state.store.list_secrets(&env.id, &path, false, false).await?;
        for s in permitted(caller, &env.slug, stored, &[Action::Read]).await? {
            rows.entry((s.secret.path, s.secret.key))
                .or_default()
                .insert(env.slug.clone(), s.secret.current_version);
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

/// A batch reason's "N created, M updated, K deleted" counts replaced by a plain phrase.
fn without_counts(reason: &str) -> String {
    const END: &str = " deleted";
    let Some(end) = reason.find(END) else {
        return reason.to_string();
    };
    let is_counts = reason[..end + END.len()]
        .split(", ")
        .all(|part| part.split_once(' ').is_some_and(|(n, _)| n.parse::<u64>().is_ok()));
    if !is_counts {
        return reason.to_string();
    }
    format!("secrets changed{}", &reason[end + END.len()..])
}

/// The ids of secrets in the scope's environment the reader may read, or `None` when they may
/// read all of them.
async fn readable_secret_ids(state: &AppState, scope: &Scope) -> ApiResult<Option<HashSet<String>>> {
    let whole = Resource {
        environment: Some(&scope.env.slug),
        access: scope.access.spanning(&scope.project),
        ..Default::default()
    };
    if allowed(&scope.rules, Subject::Secrets, Action::Read, &whole) {
        return Ok(None);
    }
    let secrets = state.store.list_secrets(&scope.env.id, "/", true, true).await?;
    let readable = permitted(scope.caller(), &scope.env.slug, secrets, &[Action::Read]).await?;
    Ok(Some(readable.into_iter().map(|s| s.secret.id).collect()))
}

/// A reader who cannot see every secret gets counts of only the ones they can, and no change
/// counts, so hidden secrets cannot be watched through snapshots.
fn api_snapshot(scope: &Scope, s: &sekret_store::Snapshot, readable: Option<&HashSet<String>>) -> Snapshot {
    let may_see = |path: &str| {
        let folder = Resource {
            environment: Some(&scope.env.slug),
            path: Some(path),
            ..Default::default()
        };
        allowed(&scope.rules, Subject::Folders, Action::Read, &folder)
    };
    let reason = visible_reason(&s.reason, may_see);
    let (reason, secret_count) = match readable {
        None => (reason, s.entries.len()),
        Some(ids) => (
            without_counts(&reason),
            s.entries.iter().filter(|e| ids.contains(&e.secret_id)).count(),
        ),
    };
    Snapshot {
        id: s.id.clone(),
        reason,
        actor: s.actor.clone(),
        created_at: s.created_at,
        secret_count: i64::try_from(secret_count).unwrap_or(i64::MAX),
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
    let readable = readable_secret_ids(&state, &scope).await?;
    Ok(Json(
        snapshots
            .iter()
            .map(|s| api_snapshot(&scope, s, readable.as_ref()))
            .collect(),
    ))
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
    let readable = permitted(scope.caller(), &scope.env.slug, current, &[Action::Read]).await?;
    let readable_ids = readable_secret_ids(&state, &scope).await?;
    Ok(Json(SnapshotDetail {
        snapshot: api_snapshot(&scope, &snapshot, readable_ids.as_ref()),
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
    let current = state.store.list_secrets(&scope.env.id, &path, true, true).await?;
    let readable = permitted(scope.caller(), &scope.env.slug, current, &[Action::Read]).await?;
    let ctx = secret_ctx(&state, &principal)?;
    let planned = plan_restore(
        &ctx,
        scope.caller(),
        &scope.project,
        &scope.env,
        &snapshot,
        &path,
        &readable,
    )
    .await?;
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
    let stored = state
        .store
        .list_secrets(&scope.env.id, &path, params.recursive, false)
        .await?;
    let readable = permitted(
        scope.caller(),
        &scope.env.slug,
        stored,
        &[Action::Read, Action::ReadValue],
    )
    .await?;
    let mut secrets = Vec::new();
    for s in readable {
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
    use sekret_core::permissions::{Conditions, Effect};

    fn stored(path: &str, key: &str) -> SecretWithVersion {
        SecretWithVersion {
            secret: sekret_store::Secret {
                id: format!("{path}/{key}"),
                project_id: "p".into(),
                environment_id: "e".into(),
                path: path.into(),
                key: key.into(),
                current_version: 1,
                deleted: false,
                created_at: 0,
                updated_at: 0,
                policy: None,
                restricted: false,
            },
            version: sekret_store::SecretVersion {
                secret_id: format!("{path}/{key}"),
                version: 1,
                value: None,
                comment: String::new(),
                tags: Vec::new(),
                deleted: false,
                actor: String::new(),
                created_at: 0,
                generated: false,
            },
        }
    }

    static NO_LISTS: LazyLock<SecretAccess> = LazyLock::new(SecretAccess::default);

    fn open(rules: &[Rule]) -> Caller<'_> {
        Caller {
            rules,
            access: &NO_LISTS,
        }
    }

    /// Restricted secrets are kept only for callers whose list lets every action through,
    /// whichever thread the check runs on.
    #[tokio::test]
    async fn listings_keep_restricted_secrets_only_for_those_listed() -> anyhow::Result<()> {
        let principal = Principal {
            kind: sekret_store::PrincipalKind::Identity,
            id: "pod".into(),
            name: "pod".into(),
            email: String::new(),
            groups: Vec::new(),
            token_id: "t".into(),
            token_kind: "machine".into(),
        };
        let grant = |secret: &str, actions: &[Action]| sekret_store::SecretGrant {
            secret_id: format!("/{secret}"),
            principal_kind: sekret_store::PrincipalKind::Identity,
            principal_id: "pod".into(),
            actions: actions.to_vec(),
            created_at: 0,
        };
        let access = SecretAccess::listed(
            &principal,
            vec![
                grant("SHARED", &[Action::Read, Action::ReadValue]),
                grant("LISTED", &[Action::Read]),
            ],
        );
        for patterns in [1, 200] {
            let rules = rules(patterns);
            let mut secrets: Vec<SecretWithVersion> = ["OPEN", "SHARED", "LISTED", "HIDDEN"]
                .iter()
                .map(|key| stored("", key))
                .collect();
            for s in secrets.iter_mut().filter(|s| s.secret.key != "OPEN") {
                s.secret.restricted = true;
            }
            secrets.extend((0..200).map(|i| stored("/hidden0", &format!("K{i}"))));
            let caller = Caller {
                rules: &rules,
                access: &access,
            };
            let keys = |kept: Vec<SecretWithVersion>| kept.into_iter().map(|s| s.secret.key).collect::<Vec<_>>();
            let readable = permitted(caller, "prod", secrets.clone(), &[Action::Read])
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            assert_eq!(keys(readable), ["OPEN", "SHARED", "LISTED"], "{patterns} patterns");
            let mut values_rules = rules.clone();
            values_rules.push(Rule::allow(Subject::Secrets, &[Action::ReadValue]));
            let values = permitted(
                Caller {
                    rules: &values_rules,
                    access: &access,
                },
                "prod",
                secrets,
                &[Action::Read, Action::ReadValue],
            )
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
            assert_eq!(keys(values), ["OPEN", "SHARED"], "{patterns} patterns");
        }
        Ok(())
    }

    fn rules(patterns: usize) -> Vec<Rule> {
        vec![
            Rule::allow(Subject::Secrets, &[Action::Read]),
            Rule {
                effect: Effect::Deny,
                subject: Subject::Secrets,
                actions: vec![Action::Read],
                conditions: Conditions {
                    paths: (0..patterns).map(|i| format!("/hidden{i}/**")).collect(),
                    ..Default::default()
                },
            },
        ]
    }

    /// Small and large checks give the same answer, whichever thread they run on.
    #[tokio::test]
    async fn large_listings_are_filtered_the_same_off_the_runtime() -> anyhow::Result<()> {
        for patterns in [1, 200] {
            let rules = rules(patterns);
            let secrets: Vec<_> = (0..200)
                .map(|i| stored(if i % 2 == 0 { "/app" } else { "/hidden0/x" }, &format!("K{i}")))
                .collect();
            let off = runs_off_runtime(secrets.len(), &rules);
            assert_eq!(off, patterns > 1, "{patterns} patterns");
            let kept = permitted(open(&rules), "prod", secrets, &[Action::Read])
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            assert_eq!(kept.len(), 100);
            assert!(kept.iter().all(|s| s.secret.path == "/app"));
        }
        Ok(())
    }

    /// Groups can bring more patterns than any binding was checked against, so a listing refuses
    /// them instead of running N secrets times P patterns.
    #[tokio::test]
    async fn listings_refuse_rules_over_the_pattern_cap() -> anyhow::Result<()> {
        let mut over = rules(MAX_ROLE_PATTERNS_FOR_TEST);
        over.extend(rules(MAX_ROLE_PATTERNS_FOR_TEST));
        over.extend(rules(1));
        let refused = permitted(open(&over), "prod", vec![stored("/", "K")], &[Action::Read]).await;
        assert_eq!(refused.err().map(|e| e.code), Some("too_many_patterns"));
        let mut at_cap = rules(MAX_ROLE_PATTERNS_FOR_TEST);
        at_cap.extend(rules(MAX_ROLE_PATTERNS_FOR_TEST));
        assert!(
            permitted(open(&at_cap), "prod", vec![stored("/", "K")], &[Action::Read])
                .await
                .is_ok()
        );
        Ok(())
    }

    const MAX_ROLE_PATTERNS_FOR_TEST: usize = MAX_PRINCIPAL_PATTERNS / 2;

    #[tokio::test]
    async fn long_checks_wait_for_a_slot() -> anyhow::Result<()> {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await?;
        let secrets: Vec<_> = (0..200).map(|i| stored("/app", &format!("K{i}"))).collect();
        let rules = rules(200);
        let check = permitted_with(&slots, open(&rules), "prod", secrets, &[Action::Read]);
        tokio::pin!(check);
        let waited = tokio::time::timeout(std::time::Duration::from_millis(100), &mut check).await;
        assert!(waited.is_err(), "no slot, so the check has not run");
        drop(held);
        let kept = check.await.map_err(|e| anyhow::anyhow!(e.message))?;
        assert_eq!(kept.len(), 200);
        assert_eq!(slots.available_permits(), 1, "the slot is given back");
        Ok(())
    }

    #[tokio::test]
    async fn every_action_must_be_allowed() -> anyhow::Result<()> {
        let rules = vec![Rule::allow(Subject::Secrets, &[Action::Read])];
        let kept = permitted(
            open(&rules),
            "prod",
            vec![stored("/", "K")],
            &[Action::Read, Action::ReadValue],
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
        assert!(kept.is_empty());
        Ok(())
    }

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

    #[test]
    fn change_counts_can_be_dropped_from_reasons() {
        let cases = [
            ("3 created, 1 updated, 0 deleted in /web", "secrets changed in /web"),
            ("3 created, 1 updated, 0 deleted", "secrets changed"),
            ("restored snapshot abc for /", "restored snapshot abc for /"),
            ("rolled back a secret to version 3", "rolled back a secret to version 3"),
            ("x created, 1 updated, 0 deleted", "x created, 1 updated, 0 deleted"),
        ];
        for (reason, expected) in cases {
            assert_eq!(without_counts(reason), expected);
        }
    }
}
