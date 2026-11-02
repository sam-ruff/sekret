use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use sekret_api::{
    AddMembership, AuditEntry, AuditPage, CreateEnvironment, CreateFolder, CreateProject, Environment, Folder,
    Membership, Project, ProjectPermissions, PutRole, Role, SecretPolicy, UpdateEnvironment, UpdateProject,
};
use sekret_core::crypto::{DataKey, wrap_data_key};
use sekret_core::glob::{key_pattern_can_match, path_pattern_can_match};
use sekret_core::permissions::{
    Access, Action, BuiltinRole, MAX_PRINCIPAL_PATTERNS, MAX_ROLE_PATTERNS, Resource, Rule, Subject, covers, denied,
    dropped_rules, may_remove, pattern_count,
};
use sekret_core::validate;
use sekret_store::PrincipalKind;
use serde::Deserialize;
use serde_json::json;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::access::restricted_visible;
use super::listing::{AuditParams, audit_page};
use super::{AuditTarget, api_env, api_project, audit, find_env, from_api_kind, load_project, to_api_kind};
use crate::auth::{ClientIp, Principal};
use crate::authz::{
    Key, added_denies, admin_bindings, admin_role_needs_admin, allowed, can_see_project, deny_needs_admin, has_denies,
    holders, is_org_admin, is_project_admin, manages_secret_access, org_rules, project_management_rules, project_rules,
    reaches_admin, require, require_any,
};
use crate::error::{ApiError, ApiResult};
use crate::rotation::project_policy;
use crate::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_projects, create_project))
        .routes(routes!(get_project, update_project, delete_project))
        .routes(routes!(get_project_policy, put_project_policy))
        .routes(routes!(permissions))
        .routes(routes!(list_environments, create_environment))
        .routes(routes!(update_environment, delete_environment))
        .routes(routes!(list_folders, create_folder, delete_folder))
        .routes(routes!(list_members, add_member))
        .routes(routes!(remove_member))
        .routes(routes!(list_roles))
        .routes(routes!(put_role, delete_role))
        .routes(routes!(project_audit))
}

fn env_resource(slug: &str) -> Resource<'_> {
    Resource {
        environment: Some(slug),
        ..Default::default()
    }
}

const DEFAULT_ENVIRONMENTS: [(&str, &str); 3] =
    [("dev", "Development"), ("staging", "Staging"), ("prod", "Production")];

#[utoipa::path(get, path = "/api/v1/projects", tag = "projects", responses((status = 200, body = Vec<Project>)), security(("bearer" = [])))]
async fn list_projects(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Vec<Project>>> {
    let mut visible = Vec::new();
    for project in state.store.list_projects().await? {
        if can_see_project(&project_rules(&state, &principal, &project.id).await?) {
            visible.push(api_project(&project));
        }
    }
    Ok(Json(visible))
}

#[utoipa::path(post, path = "/api/v1/projects", tag = "projects", request_body = CreateProject,
    responses((status = 201, body = Project)), security(("bearer" = [])))]
async fn create_project(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<CreateProject>,
) -> ApiResult<(StatusCode, Json<Project>)> {
    require_any(&org_rules(&state, &principal).await?, Subject::Projects, Action::Create)?;
    validate::slug(&request.slug)?;
    validate::name(&request.name)?;
    validate::description(&request.description)?;
    let now = state.clock.now();
    let id = uuid::Uuid::new_v4().to_string();
    let wrapped_key = wrap_data_key(state.keyring.root()?.as_ref(), &DataKey::generate()?, &id)?;
    let requested = request.environments.unwrap_or_else(|| {
        DEFAULT_ENVIRONMENTS
            .iter()
            .map(|(slug, name)| CreateEnvironment {
                slug: slug.to_string(),
                name: name.to_string(),
                position: None,
            })
            .collect()
    });
    let mut environments = Vec::new();
    for (index, env) in requested.into_iter().enumerate() {
        validate::slug(&env.slug)?;
        validate::name(&env.name)?;
        environments.push(sekret_store::Environment {
            id: uuid::Uuid::new_v4().to_string(),
            project_id: id.clone(),
            slug: env.slug,
            name: env.name,
            position: env.position.unwrap_or(index as i64),
            created_at: now,
        });
    }
    let project = sekret_store::Project {
        id: id.clone(),
        slug: request.slug,
        name: request.name.trim().to_string(),
        description: request.description,
        wrapped_key,
        created_at: now,
        logo_updated_at: None,
        secret_policy: None,
        secret_access: false,
    };
    state.store.create_project(project.clone(), environments).await?;
    state
        .store
        .add_membership(sekret_store::Membership {
            project_id: id.clone(),
            principal_kind: principal.kind,
            principal_id: principal.id.clone(),
            role_slug: BuiltinRole::ProjectAdmin.slug().into(),
            created_at: now,
        })
        .await?;
    audit(
        &state,
        &principal,
        ip,
        "project.create",
        AuditTarget {
            project_id: Some(&id),
            ..Default::default()
        },
        json!({"slug": project.slug}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(api_project(&project))))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}", tag = "projects", params(("project" = String, Path, description = "Project id or slug")),
    responses((status = 200, body = Project)), security(("bearer" = [])))]
async fn get_project(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<Project>> {
    let (project, _) = load_project(&state, &principal, &project).await?;
    Ok(Json(api_project(&project)))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/secret-policy", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, body = SecretPolicy)), security(("bearer" = [])))]
async fn get_project_policy(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<SecretPolicy>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::Settings, Action::Read)?;
    Ok(Json(project_policy(&project)?))
}

/// The default for every secret in the project that does not set its own. Off unless set.
#[utoipa::path(put, path = "/api/v1/projects/{project}/secret-policy", tag = "projects", params(("project" = String, Path)),
    request_body = SecretPolicy, responses((status = 200, body = SecretPolicy)), security(("bearer" = [])))]
async fn put_project_policy(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
    Json(policy): Json<SecretPolicy>,
) -> ApiResult<Json<SecretPolicy>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::Settings, Action::Edit)?;
    // The rotation job acts on every inheriting secret, so this is as strong as writing them all.
    if !covers(
        &rules,
        &[Rule::allow(Subject::Secrets, &[Action::Create, Action::Edit])],
    ) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "escalation",
            "changing the project default needs unrestricted create and edit on secrets",
        ));
    }
    policy.validate().map_err(|e| ApiError::bad_request(e.to_string()))?;
    let stored = if policy == SecretPolicy::default() {
        None
    } else {
        Some(serde_json::to_string(&policy).map_err(|e| ApiError::internal("project secret policy", e))?)
    };
    state.store.set_project_policy(&project.id, stored).await?;
    audit(
        &state,
        &principal,
        ip,
        "project.secret-policy",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"policy": policy}),
    )
    .await;
    Ok(Json(policy))
}

#[utoipa::path(patch, path = "/api/v1/projects/{project}", tag = "projects", params(("project" = String, Path)), request_body = UpdateProject,
    responses((status = 200, body = Project)), security(("bearer" = [])))]
async fn update_project(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
    Json(request): Json<UpdateProject>,
) -> ApiResult<Json<Project>> {
    let (mut project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::Settings, Action::Edit)?;
    validate::name(&request.name)?;
    validate::description(&request.description)?;
    state
        .store
        .update_project(&project.id, request.name.trim(), &request.description)
        .await?;
    project.name = request.name.trim().to_string();
    project.description = request.description;
    audit(
        &state,
        &principal,
        ip,
        "project.update",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok(Json(api_project(&project)))
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}", tag = "projects", params(("project" = String, Path)),
    responses((status = 204)), security(("bearer" = [])))]
async fn delete_project(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<StatusCode> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::Settings, Action::Delete)?;
    // Everything in the project goes with it, so no deny may stand anywhere in what is removed.
    let removed = [
        Rule::allow(Subject::Secrets, &[Action::Delete]),
        Rule::allow(Subject::Snapshots, &[Action::Edit]),
        Rule::allow(Subject::Folders, &[Action::Delete]),
        Rule::allow(Subject::Environments, &[Action::Delete]),
    ];
    if !covers(&rules, &removed) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "escalation",
            "deleting a project needs unrestricted delete on its secrets, folders and environments",
        ));
    }
    refuse_destroying_restricted(&state, &principal, &project.id, None).await?;
    state.store.delete_project(&project.id).await?;
    audit(
        &state,
        &principal,
        ip,
        "project.delete",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"slug": project.slug}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/permissions", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, body = ProjectPermissions)), security(("bearer" = [])))]
async fn permissions(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<ProjectPermissions>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    Ok(Json(ProjectPermissions {
        rules,
        manages_secret_access: manages_secret_access(&state, &principal, &project.id).await?,
    }))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, body = Vec<Environment>)), security(("bearer" = [])))]
async fn list_environments(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<Vec<Environment>>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let envs = state.store.list_environments(&project.id).await?;
    Ok(Json(
        envs.iter()
            .filter(|e| allowed(&rules, Subject::Environments, Action::Read, &env_resource(&e.slug)))
            .map(api_env)
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/environments", tag = "projects", params(("project" = String, Path)),
    request_body = CreateEnvironment, responses((status = 201, body = Environment)), security(("bearer" = [])))]
async fn create_environment(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
    Json(request): Json<CreateEnvironment>,
) -> ApiResult<(StatusCode, Json<Environment>)> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    require(
        &rules,
        Subject::Environments,
        Action::Create,
        &env_resource(&request.slug),
    )?;
    // A hidden environment must answer the same whether or not it exists.
    if denied(
        &rules,
        Subject::Environments,
        Action::Read,
        &env_resource(&request.slug),
    ) {
        return Err(ApiError::forbidden());
    }
    validate::slug(&request.slug)?;
    validate::name(&request.name)?;
    let existing = state.store.list_environments(&project.id).await?;
    let env = sekret_store::Environment {
        id: uuid::Uuid::new_v4().to_string(),
        project_id: project.id.clone(),
        slug: request.slug,
        name: request.name.trim().to_string(),
        position: request.position.unwrap_or(existing.len() as i64),
        created_at: state.clock.now(),
    };
    state.store.create_environment(env.clone()).await?;
    audit(
        &state,
        &principal,
        ip,
        "environment.create",
        AuditTarget {
            project_id: Some(&project.id),
            environment: Some(&env.slug),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(api_env(&env))))
}

#[utoipa::path(patch, path = "/api/v1/projects/{project}/environments/{env}", tag = "projects",
    params(("project" = String, Path), ("env" = String, Path)), request_body = UpdateEnvironment,
    responses((status = 200, body = Environment)), security(("bearer" = [])))]
async fn update_environment(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
    Json(request): Json<UpdateEnvironment>,
) -> ApiResult<Json<Environment>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let mut env = find_env(&state, &project, &rules, &env).await?;
    require(&rules, Subject::Environments, Action::Edit, &env_resource(&env.slug))?;
    validate::name(&request.name)?;
    state
        .store
        .update_environment(&env.id, request.name.trim(), request.position)
        .await?;
    env.name = request.name.trim().to_string();
    env.position = request.position;
    audit(
        &state,
        &principal,
        ip,
        "environment.update",
        AuditTarget {
            project_id: Some(&project.id),
            environment: Some(&env.slug),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok(Json(api_env(&env)))
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}/environments/{env}", tag = "projects",
    params(("project" = String, Path), ("env" = String, Path)), responses((status = 204)), security(("bearer" = [])))]
async fn delete_environment(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let env = find_env(&state, &project, &rules, &env).await?;
    require(&rules, Subject::Environments, Action::Delete, &env_resource(&env.slug))?;
    let not_empty = || {
        ApiError::new(
            StatusCode::CONFLICT,
            "not_empty",
            "delete the secrets in this environment first",
        )
    };
    // Checked before the restricted secrets, so a refusal never tells hidden ones from live ones.
    if !state.store.list_secrets(&env.id, "/", true, false).await?.is_empty() {
        return Err(not_empty());
    }
    refuse_destroying_restricted(&state, &principal, &project.id, Some(&env.id)).await?;
    // Deleting an environment destroys its history, so it must be emptied through the secret routes first.
    state.store.delete_environment(&env.id).await.map_err(|e| match e {
        sekret_store::StoreError::Conflict => not_empty(),
        other => other.into(),
    })?;
    audit(
        &state,
        &principal,
        ip,
        "environment.delete",
        AuditTarget {
            project_id: Some(&project.id),
            environment: Some(&env.slug),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Destroying a restricted secret's history, with its project or environment, is for admins only,
/// since anyone else may be kept off it by its list.
async fn refuse_destroying_restricted(
    state: &AppState,
    principal: &Principal,
    project_id: &str,
    environment_id: Option<&str>,
) -> ApiResult<()> {
    let restricted = match environment_id {
        None => state.store.count_restricted_secrets(project_id).await? > 0,
        Some(env) => state
            .store
            .list_secrets(env, "/", true, true)
            .await?
            .iter()
            .any(|s| s.secret.restricted),
    };
    if !restricted || manages_secret_access(state, principal, project_id).await? {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "forbidden",
        "only a project admin can delete this, because it holds restricted secrets",
    ))
}

#[derive(Deserialize, IntoParams)]
struct PathQuery {
    path: String,
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/environments/{env}/folders", tag = "projects",
    params(("project" = String, Path), ("env" = String, Path)), responses((status = 200, body = Vec<Folder>)), security(("bearer" = [])))]
async fn list_folders(
    State(state): State<AppState>,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
) -> ApiResult<Json<Vec<Folder>>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let env = find_env(&state, &project, &rules, &env).await?;
    let folders = state.store.list_folders(&env.id).await?;
    Ok(Json(
        folders
            .into_iter()
            .filter(|f| {
                let resource = Resource {
                    environment: Some(&env.slug),
                    path: Some(&f.path),
                    ..Default::default()
                };
                allowed(&rules, Subject::Folders, Action::Read, &resource)
            })
            .map(|f| Folder {
                path: f.path,
                created_at: f.created_at,
            })
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/environments/{env}/folders", tag = "projects",
    params(("project" = String, Path), ("env" = String, Path)), request_body = CreateFolder,
    responses((status = 201, body = Folder)), security(("bearer" = [])))]
async fn create_folder(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
    Json(request): Json<CreateFolder>,
) -> ApiResult<(StatusCode, Json<Folder>)> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let env = find_env(&state, &project, &rules, &env).await?;
    let path = validate::folder_path(&request.path)?;
    if path == "/" {
        return Err(ApiError::bad_request("the root folder always exists"));
    }
    let resource = Resource {
        environment: Some(&env.slug),
        path: Some(&path),
        ..Default::default()
    };
    // Hidden folders answer as missing before anything that depends on whether they exist.
    let hidden_parent = ancestors(&path).iter().any(|parent| {
        let folder = Resource {
            environment: Some(&env.slug),
            path: Some(parent),
            ..Default::default()
        };
        denied(&rules, Subject::Folders, Action::Read, &folder)
    });
    if hidden_parent || !allowed(&rules, Subject::Folders, Action::Read, &resource) {
        return Err(ApiError::not_found("folder"));
    }
    require(&rules, Subject::Folders, Action::Create, &resource)?;
    // Missing parents are created too, so each of them needs the same permission.
    let existing: Vec<String> = state
        .store
        .list_folders(&env.id)
        .await?
        .into_iter()
        .map(|f| f.path)
        .collect();
    for parent in ancestors(&path) {
        if existing.contains(&parent) {
            continue;
        }
        let parent_resource = Resource {
            environment: Some(&env.slug),
            path: Some(&parent),
            ..Default::default()
        };
        require(&rules, Subject::Folders, Action::Create, &parent_resource)?;
    }
    let now = state.clock.now();
    crate::secrets::ensure_folder(state.store.as_ref(), &env.id, &path, now).await?;
    audit(
        &state,
        &principal,
        ip,
        "folder.create",
        AuditTarget {
            project_id: Some(&project.id),
            environment: Some(&env.slug),
            path: Some(&path),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(Folder { path, created_at: now })))
}

fn not_empty() -> ApiError {
    ApiError::conflict("the folder still contains secrets")
}

/// Proper ancestors of a normalised folder path, excluding the root: `/a/b/c` gives `/a` and `/a/b`.
fn ancestors(path: &str) -> Vec<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    (1..segments.len())
        .map(|n| format!("/{}", segments[..n].join("/")))
        .collect()
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}/environments/{env}/folders", tag = "projects",
    params(("project" = String, Path), ("env" = String, Path), PathQuery), responses((status = 204), (status = 409)), security(("bearer" = [])))]
async fn delete_folder(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, env)): Path<(String, String)>,
    Query(query): Query<PathQuery>,
) -> ApiResult<StatusCode> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    let env = find_env(&state, &project, &rules, &env).await?;
    let path = validate::folder_path(&query.path)?;
    if path == "/" {
        return Err(ApiError::bad_request("the root folder cannot be deleted"));
    }
    let resource = Resource {
        environment: Some(&env.slug),
        path: Some(&path),
        ..Default::default()
    };
    // A folder the caller cannot read answers as missing, whether or not it exists or is empty.
    if !allowed(&rules, Subject::Folders, Action::Read, &resource) {
        return Err(ApiError::not_found("folder"));
    }
    require(&rules, Subject::Folders, Action::Delete, &resource)?;
    let prefix = format!("{path}/");
    for child in state.store.list_folders(&env.id).await? {
        if !child.path.starts_with(&prefix) {
            continue;
        }
        let child_resource = Resource {
            environment: Some(&env.slug),
            path: Some(&child.path),
            ..Default::default()
        };
        // Hidden folders inside are refused like secrets inside, without naming them.
        if denied(&rules, Subject::Folders, Action::Read, &child_resource) {
            return Err(not_empty());
        }
        require(&rules, Subject::Folders, Action::Delete, &child_resource)?;
    }
    state.store.delete_folder(&env.id, &path).await.map_err(|e| match e {
        sekret_store::StoreError::Conflict => not_empty(),
        other => other.into(),
    })?;
    audit(
        &state,
        &principal,
        ip,
        "folder.delete",
        AuditTarget {
            project_id: Some(&project.id),
            environment: Some(&env.slug),
            path: Some(&path),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn principal_names(
    state: &AppState,
) -> ApiResult<std::collections::HashMap<(PrincipalKind, String), String>> {
    let mut names = std::collections::HashMap::new();
    for user in state.store.list_users().await? {
        let label = if user.email.is_empty() { user.name } else { user.email };
        names.insert((PrincipalKind::User, user.id), label);
    }
    for identity in state.store.list_identities().await? {
        names.insert((PrincipalKind::Identity, identity.id), identity.name);
    }
    Ok(names)
}

pub async fn ensure_principal_exists(state: &AppState, kind: PrincipalKind, id: &str) -> ApiResult<()> {
    let exists = match kind {
        PrincipalKind::User => state.store.get_user(id).await?.is_some(),
        PrincipalKind::Identity => state.store.get_identity(id).await?.is_some(),
        PrincipalKind::Group => !id.trim().is_empty() && id.len() <= 256,
    };
    if !exists {
        return Err(ApiError::bad_request(format!("{} {id} does not exist", kind.as_str())));
    }
    Ok(())
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/members", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, body = Vec<Membership>)), security(("bearer" = [])))]
async fn list_members(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<Vec<Membership>>> {
    let (project, rules) = load_for_management(&state, &principal, &project).await?;
    require_any(&rules, Subject::Members, Action::Read)?;
    let names = principal_names(&state).await?;
    let members = state.store.list_memberships(&project.id).await?;
    Ok(Json(
        members
            .into_iter()
            .map(|m| Membership {
                principal_kind: to_api_kind(m.principal_kind),
                principal_name: names
                    .get(&(m.principal_kind, m.principal_id.clone()))
                    .cloned()
                    .unwrap_or_else(|| m.principal_id.clone()),
                principal_id: m.principal_id,
                role: m.role_slug,
                created_at: m.created_at,
            })
            .collect(),
    ))
}

/// Loads a project for reading or changing its roles and members, judged by
/// [`project_management_rules`] so org admins can never be locked out of repairing access.
async fn load_for_management(
    state: &AppState,
    principal: &Principal,
    project: &str,
) -> ApiResult<(sekret_store::Project, Vec<Rule>)> {
    let (project, rules) = load_project(state, principal, project).await?;
    let rules = project_management_rules(state, principal, rules).await?;
    Ok((project, rules))
}

/// Whether the caller administers the project: an org admin or one of its admins.
async fn administers(
    state: &AppState,
    principal: &Principal,
    memberships: &[sekret_store::Membership],
) -> ApiResult<bool> {
    Ok(is_project_admin(memberships, principal) || is_org_admin(state, principal).await?)
}

async fn project_role_rules(state: &AppState, project_id: &str, slug: &str) -> ApiResult<Vec<Rule>> {
    let custom = state.store.list_roles(project_id).await?;
    crate::authz::role_rules(slug, &custom, false).ok_or_else(|| ApiError::bad_request(format!("unknown role {slug}")))
}

#[utoipa::path(post, path = "/api/v1/projects/{project}/members", tag = "projects", params(("project" = String, Path)),
    request_body = AddMembership, responses((status = 201)), security(("bearer" = [])))]
async fn add_member(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
    Json(request): Json<AddMembership>,
) -> ApiResult<StatusCode> {
    let (project, rules) = load_for_management(&state, &principal, &project).await?;
    require_any(&rules, Subject::Members, Action::Create)?;
    let granted = project_role_rules(&state, &project.id, &request.role).await?;
    if !covers(&rules, &granted) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "escalation",
            "you cannot grant a role with more access than you have",
        ));
    }
    let kind = from_api_kind(request.principal_kind);
    let memberships = state.store.list_memberships(&project.id).await?;
    if request.role == BuiltinRole::ProjectAdmin.slug() && !administers(&state, &principal, &memberships).await? {
        return Err(admin_role_needs_admin(&request.role));
    }
    let custom = state.store.list_roles(&project.id).await?;
    let users = state.store.list_users().await?;
    let bound = Bound {
        memberships: &memberships,
        custom: &custom,
        users: &users,
    };
    if !bound.fits_binding(kind, &request.principal_id, &request.role) {
        return Err(too_many_principal_patterns());
    }
    if has_denies(&granted)
        && reaches_admin(
            &users,
            &admin_bindings(&state, &memberships).await?,
            kind,
            &request.principal_id,
        )
        && !administers(&state, &principal, &memberships).await?
    {
        return Err(deny_needs_admin());
    }
    ensure_principal_exists(&state, kind, &request.principal_id).await?;
    state
        .store
        .add_membership(sekret_store::Membership {
            project_id: project.id.clone(),
            principal_kind: kind,
            principal_id: request.principal_id.clone(),
            role_slug: request.role.clone(),
            created_at: state.clock.now(),
        })
        .await?;
    audit(
        &state,
        &principal,
        ip,
        "member.add",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"principal_kind": kind.as_str(), "principal_id": request.principal_id, "role": request.role}),
    )
    .await;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}/members/{kind}/{id}/{role}", tag = "projects",
    params(("project" = String, Path), ("kind" = String, Path), ("id" = String, Path), ("role" = String, Path)),
    responses((status = 204)), security(("bearer" = [])))]
async fn remove_member(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, kind, id, role)): Path<(String, String, String, String)>,
) -> ApiResult<StatusCode> {
    let (project, rules) = load_for_management(&state, &principal, &project).await?;
    require_any(&rules, Subject::Members, Action::Delete)?;
    let kind = PrincipalKind::parse(&kind).ok_or_else(|| ApiError::bad_request("unknown principal kind"))?;
    let removed = project_role_rules(&state, &project.id, &role).await.unwrap_or_default();
    if !may_remove(&rules, &removed) {
        return Err(removal_escalation());
    }
    state.store.remove_membership(&project.id, kind, &id, &role).await?;
    audit(
        &state,
        &principal,
        ip,
        "member.remove",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"principal_kind": kind.as_str(), "principal_id": id, "role": role}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub fn removal_escalation() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "escalation",
        "you cannot remove access or restrictions beyond your own",
    )
}

/// A project's bindings and custom roles, for counting what each principal is bound to.
struct Bound<'a> {
    memberships: &'a [sekret_store::Membership],
    custom: &'a [sekret_store::Role],
    /// Users with the groups they last signed in with, which bring the roles bound to those groups.
    users: &'a [sekret_store::User],
}

impl Bound<'_> {
    fn holders<'k>(&'k self, kind: PrincipalKind, id: &'k str) -> Vec<Vec<Key<'k>>> {
        holders(self.users, kind, id)
    }

    /// Whether binding `role` to (`kind`, `id`) keeps everyone it reaches within the cap.
    fn fits_binding(&self, kind: PrincipalKind, id: &str, role: &str) -> bool {
        self.holders(kind, id)
            .iter()
            .all(|keys| self.patterns(keys, Some(((kind, id), role)), None) <= MAX_PRINCIPAL_PATTERNS)
    }

    /// Path and key patterns across every role bound to any of `keys`, counting `extra` as bound
    /// too and `replaced` in place of the stored role with its slug.
    fn patterns<'k>(
        &'k self,
        keys: &[Key<'k>],
        extra: Option<(Key<'k>, &'k str)>,
        replaced: Option<(&str, &[Rule])>,
    ) -> usize {
        let mut slugs: Vec<&str> = self
            .memberships
            .iter()
            .filter(|m| keys.contains(&(m.principal_kind, m.principal_id.as_str())))
            .map(|m| m.role_slug.as_str())
            .chain(extra.filter(|(key, _)| keys.contains(key)).map(|(_, slug)| slug))
            .collect();
        slugs.sort_unstable();
        slugs.dedup();
        slugs
            .into_iter()
            .map(|slug| match replaced {
                Some((changed, rules)) if changed == slug => pattern_count(rules),
                _ => crate::authz::role_rules(slug, self.custom, false).map_or(0, |r| pattern_count(&r)),
            })
            .sum()
    }

    /// Whether everyone `slug` reaches stays within the cap once it holds `rules`.
    fn fits(&self, slug: &str, rules: &[Rule]) -> bool {
        self.memberships.iter().filter(|m| m.role_slug == slug).all(|m| {
            self.holders(m.principal_kind, &m.principal_id)
                .iter()
                .all(|keys| self.patterns(keys, None, Some((slug, rules))) <= MAX_PRINCIPAL_PATTERNS)
        })
    }
}

fn too_many_principal_patterns() -> ApiError {
    ApiError::bad_request(format!(
        "a member can hold at most {MAX_PRINCIPAL_PATTERNS} path and key patterns across their roles in a project, \
         counting the roles of their groups"
    ))
}

fn builtin_role_description(role: BuiltinRole) -> &'static str {
    match role {
        BuiltinRole::OrgAdmin => "Full control of the organisation and every project",
        BuiltinRole::OrgMember => "Can create projects",
        BuiltinRole::BackupReader => "Download encrypted backups and nothing else",
        BuiltinRole::ProjectAdmin => "Full control of the project",
        BuiltinRole::Developer => "Read and write secrets, manage folders and restore snapshots",
        BuiltinRole::Viewer => "Read secrets and their metadata",
        BuiltinRole::NoAccess => "No access; useful for explicit membership with no rights",
    }
}

pub fn builtin_roles(org_scope: bool) -> Vec<Role> {
    BuiltinRole::ALL
        .into_iter()
        .filter(|r| r.is_org_scope() == org_scope)
        .map(|r| Role {
            slug: r.slug().into(),
            name: r.slug().replace('-', " "),
            description: builtin_role_description(r).into(),
            builtin: true,
            rules: r.rules(),
        })
        .collect()
}

pub fn api_role(role: sekret_store::Role) -> Role {
    Role {
        slug: role.slug,
        name: role.name,
        description: role.description,
        builtin: false,
        rules: role.rules,
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/roles", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, body = Vec<Role>)), security(("bearer" = [])))]
async fn list_roles(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<Vec<Role>>> {
    let (project, rules) = load_for_management(&state, &principal, &project).await?;
    require_any(&rules, Subject::Roles, Action::Read)?;
    let mut roles = builtin_roles(false);
    roles.extend(state.store.list_roles(&project.id).await?.into_iter().map(api_role));
    Ok(Json(roles))
}

/// Checks a custom role definition and that its author already holds everything it grants.
pub fn validate_role(slug: &str, request: &PutRole, author_rules: &[Rule], org_scope: bool) -> ApiResult<()> {
    validate::slug(slug)?;
    validate::name(&request.name)?;
    validate::description(&request.description)?;
    if BuiltinRole::from_slug(slug).is_some() {
        return Err(ApiError::bad_request("that slug belongs to a built-in role"));
    }
    let scope: &[Subject] = if org_scope { &Subject::ORG } else { &Subject::PROJECT };
    if request
        .rules
        .iter()
        .any(|r| !scope.contains(&r.subject) || r.actions.is_empty())
    {
        return Err(ApiError::bad_request(
            "rules must name subjects for this scope and at least one action",
        ));
    }
    if request.rules.len() > 100 {
        return Err(ApiError::bad_request("too many rules"));
    }
    for rule in &request.rules {
        let c = &rule.conditions;
        for list in [&c.environments, &c.paths, &c.keys, &c.tags] {
            validate::globs(list)?;
        }
        // These match exactly, so anything but a slug would silently never apply.
        if c.environments.iter().chain(&c.tags).any(|v| validate::slug(v).is_err()) {
            return Err(ApiError::bad_request(
                "environment and tag conditions must be exact lowercase slugs, without wildcards",
            ));
        }
        if let Some(bad) = c.paths.iter().find(|p| !path_pattern_can_match(p)) {
            return Err(ApiError::bad_request(format!(
                "path condition {bad:?} can never match: folders look like /payments or /payments/**, \
                 starting with / and without a trailing /, // or . and .. segments"
            )));
        }
        if let Some(bad) = c.keys.iter().find(|k| !key_pattern_can_match(k)) {
            return Err(ApiError::bad_request(format!(
                "key condition {bad:?} can never match: keys start with a letter or _ and hold only \
                 letters, digits, _, - and ."
            )));
        }
    }
    // Deny rules escape the escalation check below, so this bounds them too.
    if pattern_count(&request.rules) > MAX_ROLE_PATTERNS {
        return Err(ApiError::bad_request(format!(
            "a role can hold at most {MAX_ROLE_PATTERNS} path and key patterns"
        )));
    }
    if !covers(author_rules, &request.rules) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "escalation",
            "a role cannot grant more access than you have",
        ));
    }
    Ok(())
}

#[utoipa::path(put, path = "/api/v1/projects/{project}/roles/{slug}", tag = "projects",
    params(("project" = String, Path), ("slug" = String, Path)), request_body = PutRole,
    responses((status = 200, body = Role)), security(("bearer" = [])))]
async fn put_role(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, slug)): Path<(String, String)>,
    Json(request): Json<PutRole>,
) -> ApiResult<Json<Role>> {
    let (project, rules) = load_for_management(&state, &principal, &project).await?;
    let custom = state.store.list_roles(&project.id).await?;
    let existing = custom.iter().find(|r| r.slug == slug);
    require_any(
        &rules,
        Subject::Roles,
        if existing.is_some() {
            Action::Edit
        } else {
            Action::Create
        },
    )?;
    validate_role(&slug, &request, &rules, false)?;
    if let Some(existing) = &existing
        && !may_remove(&rules, &dropped_rules(&existing.rules, &request.rules))
    {
        return Err(removal_escalation());
    }
    let memberships = state.store.list_memberships(&project.id).await?;
    let users = state.store.list_users().await?;
    let bound = Bound {
        memberships: &memberships,
        custom: &custom,
        users: &users,
    };
    if !bound.fits(&slug, &request.rules) {
        return Err(too_many_principal_patterns());
    }
    if let Some(existing) = &existing
        && added_denies(&existing.rules, &request.rules)
    {
        let admins = admin_bindings(&state, &memberships).await?;
        let binds_admin = memberships
            .iter()
            .filter(|m| m.role_slug == slug)
            .any(|m| reaches_admin(&users, &admins, m.principal_kind, &m.principal_id));
        if binds_admin && !administers(&state, &principal, &memberships).await? {
            return Err(deny_needs_admin());
        }
    }
    let role = sekret_store::Role {
        id: uuid::Uuid::new_v4().to_string(),
        project_id: project.id.clone(),
        slug: slug.clone(),
        name: request.name.trim().to_string(),
        description: request.description,
        rules: request.rules,
        created_at: state.clock.now(),
    };
    state.store.upsert_role(role.clone()).await?;
    audit(
        &state,
        &principal,
        ip,
        "role.put",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"role": slug}),
    )
    .await;
    Ok(Json(api_role(role)))
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}/roles/{slug}", tag = "projects",
    params(("project" = String, Path), ("slug" = String, Path)), responses((status = 204)), security(("bearer" = [])))]
async fn delete_role(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((project, slug)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let (project, rules) = load_for_management(&state, &principal, &project).await?;
    require_any(&rules, Subject::Roles, Action::Delete)?;
    let removed = project_role_rules(&state, &project.id, &slug).await.unwrap_or_default();
    if !may_remove(&rules, &removed) {
        return Err(removal_escalation());
    }
    state.store.delete_role(&project.id, &slug).await?;
    audit(
        &state,
        &principal,
        ip,
        "role.delete",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"role": slug}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api_audit(entry: sekret_store::AuditEntry) -> AuditEntry {
    AuditEntry {
        id: entry.id,
        created_at: entry.created_at,
        actor_kind: entry.actor_kind,
        actor_id: entry.actor_id,
        actor_name: entry.actor_name,
        action: entry.action,
        project_id: entry.project_id,
        environment: entry.environment,
        path: entry.path,
        secret_key: entry.secret_key,
        detail: entry.detail,
        ip: entry.ip,
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/audit", tag = "projects", params(("project" = String, Path), AuditParams),
    responses((status = 200, body = AuditPage)), security(("bearer" = [])))]
async fn project_audit(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
    Query(params): Query<AuditParams>,
) -> ApiResult<Json<AuditPage>> {
    let (project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::AuditLog, Action::Read)?;
    // Entries about restricted secrets the reader is not listed on are left out by the query,
    // so totals and filters behave as if they were never written.
    let visible = restricted_visible(&state, &principal, &project).await?;
    let search_actors_only = audit_filter_scope(&rules, &params)?;
    let mut page = audit_page(&state, Some(project.id), params, search_actors_only, visible).await?;
    for entry in &mut page.entries {
        redact_audit_entry(&rules, entry);
    }
    Ok(Json(page))
}

/// Whether the reader sees every environment, folder and key in the entries a filter covers:
/// all of them, or those of the environment filtered on.
fn sees_unredacted(rules: &[Rule], environment: Option<&str>) -> bool {
    let scope = Resource {
        environment,
        access: Access::Open,
        ..Default::default()
    };
    allowed(rules, Subject::Secrets, Action::Read, &scope)
        && allowed(rules, Subject::Environments, Action::Read, &scope)
}

/// Refuses filters that would reveal what redaction hides, since a match or a count is an
/// answer even when the matching entries are redacted. Returns whether `q` must be limited
/// to actions, actors and addresses.
pub fn audit_filter_scope(rules: &[Rule], params: &AuditParams) -> ApiResult<bool> {
    let given = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let environment = given(&params.environment);
    if let Some(env) = environment.as_deref() {
        let scope = Resource {
            environment: Some(env),
            ..Default::default()
        };
        if !allowed(rules, Subject::Environments, Action::Read, &scope) {
            return Err(ApiError::forbidden());
        }
    }
    if sees_unredacted(rules, environment.as_deref()) {
        return Ok(false);
    }
    if given(&params.key).is_some() || given(&params.path).is_some() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "filter_hidden",
            "some secrets here are hidden from you, so the log cannot be filtered by key or folder; \
             filter by an environment you can fully read first",
        ));
    }
    Ok(true)
}

/// Hides key names, folders, environments and change lists the reader could not see in the
/// secrets view.
pub fn redact_audit_entry(rules: &[Rule], entry: &mut AuditEntry) {
    let Some(environment) = entry.environment.clone() else {
        return;
    };
    let whole_environment = Resource {
        environment: Some(&environment),
        access: Access::Open,
        ..Default::default()
    };
    if !allowed(rules, Subject::Environments, Action::Read, &whole_environment) {
        entry.environment = None;
        entry.path = None;
        entry.secret_key = None;
        entry.detail = json!({"redacted": true});
        return;
    }
    let environment = environment.as_str();
    if allowed(rules, Subject::Secrets, Action::Read, &whole_environment) {
        return;
    }
    let path = entry.path.as_deref();
    // An entry does not record the secret's tags, so a deny by tag hides the key.
    let key_visible = entry.secret_key.as_deref().is_some_and(|key| {
        allowed(
            rules,
            Subject::Secrets,
            Action::Read,
            &Resource {
                environment: Some(environment),
                path,
                key: Some(key),
                tags: None,
                access: Access::Open,
            },
        )
    });
    if !key_visible {
        entry.secret_key = None;
    }
    let folder_visible = path.is_some_and(|p| {
        allowed(
            rules,
            Subject::Folders,
            Action::Read,
            &Resource {
                environment: Some(environment),
                path: Some(p),
                ..Default::default()
            },
        )
    });
    if !folder_visible {
        entry.path = None;
    }
    entry.detail = json!({"redacted": true});
}
