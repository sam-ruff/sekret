use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use sekret_api::{
    AddOrgBinding, AuditPage, AuthMethodConfig, AuthMethodKind, ClientSecret, CreateClientSecret, CreateIdentity,
    CreatedClientSecret, Identity, IdentityPage, MAX_CLIENT_SECRET_USES, MAX_LIFETIME, Me, OrgBinding, PutRole, Role,
    UpdateIdentity, UpdateUser, User, UserPage,
};
use sekret_core::crypto::generate_token;
use sekret_core::permissions::{Action, Subject, covers, dropped_rules, may_remove};
use sekret_core::validate;
use sekret_store::{Binding, PrincipalKind};
use serde_json::json;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::listing::{AuditParams, IdentityParams, UserParams, audit_page, page_identities, page_users};
use super::projects::{api_role, builtin_roles, ensure_principal_exists, removal_escalation, validate_role};
use super::{AuditTarget, audit, from_api_kind, to_api_kind};
use crate::auth::{ClientIp, Principal};
use crate::authz::{org_rules, project_rules, require_any, role_rules};
use crate::error::{ApiError, ApiResult};
use crate::machine::{
    CLIENT_SECRET_PREFIX, auth_method_source, client_secret_source, redact, seal_for_storage, validate_config,
};
use crate::state::AppState;

const DEFAULT_TOKEN_TTL: i64 = 3600;
const DEFAULT_TOKEN_MAX_TTL: i64 = 24 * 3600;
const LONGEST_TTL: i64 = 365 * 24 * 3600;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(me))
        .routes(routes!(list_users))
        .routes(routes!(update_user))
        .routes(routes!(list_identities, create_identity))
        .routes(routes!(get_identity, update_identity, delete_identity))
        .routes(routes!(list_auth_methods))
        .routes(routes!(put_auth_method, delete_auth_method))
        .routes(routes!(list_client_secrets, create_client_secret))
        .routes(routes!(revoke_client_secret))
        .routes(routes!(revoke_identity_tokens))
        .routes(routes!(list_bindings, add_binding))
        .routes(routes!(remove_binding))
        .routes(routes!(list_org_roles))
        .routes(routes!(put_org_role, delete_org_role))
        .routes(routes!(org_audit))
}

#[utoipa::path(get, path = "/api/v1/me", tag = "organisation", responses((status = 200, body = Me)), security(("bearer" = [])))]
async fn me(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Me>> {
    let org_rules = org_rules(&state, &principal).await?;
    let org_roles = crate::authz::org_role_slugs(&state, &principal).await?;
    let is_org_admin = org_roles
        .iter()
        .any(|s| s == sekret_core::permissions::BuiltinRole::OrgAdmin.slug());
    Ok(Json(Me {
        kind: to_api_kind(principal.kind),
        id: principal.id,
        name: principal.name,
        email: principal.email,
        groups: principal.groups,
        org_rules,
        org_roles,
        is_org_admin,
    }))
}

fn api_user(u: sekret_store::User) -> User {
    User {
        id: u.id,
        email: u.email,
        name: u.name,
        groups: u.groups,
        disabled: u.disabled,
        created_at: u.created_at,
        last_login_at: u.last_login_at,
    }
}

#[utoipa::path(get, path = "/api/v1/users", tag = "organisation", params(UserParams),
    responses((status = 200, body = UserPage)), security(("bearer" = [])))]
async fn list_users(
    State(state): State<AppState>,
    principal: Principal,
    Query(params): Query<UserParams>,
) -> ApiResult<Json<UserPage>> {
    require_any(&org_rules(&state, &principal).await?, Subject::OrgMembers, Action::Read)?;
    let users = state.store.list_users().await?.into_iter().map(api_user).collect();
    let (items, total) = page_users(users, &params);
    Ok(Json(UserPage { items, total }))
}

#[utoipa::path(patch, path = "/api/v1/users/{id}", tag = "organisation", params(("id" = String, Path)), request_body = UpdateUser,
    responses((status = 204)), security(("bearer" = [])))]
async fn update_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(id): Path<String>,
    Json(request): Json<UpdateUser>,
) -> ApiResult<StatusCode> {
    let rules = org_rules(&state, &principal).await?;
    require_any(&rules, Subject::OrgMembers, Action::Edit)?;
    if principal.kind == PrincipalKind::User && principal.id == id && request.disabled {
        return Err(ApiError::bad_request("you cannot disable yourself"));
    }
    let user = state
        .store
        .get_user(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("user"))?;
    let target = Principal {
        kind: PrincipalKind::User,
        id: user.id,
        name: user.name,
        email: user.email,
        groups: user.groups,
        token_id: String::new(),
        token_kind: String::new(),
    };
    ensure_covers_principal(&state, &principal, &target).await?;
    state.store.set_user_disabled(&id, request.disabled).await?;
    if request.disabled {
        state.store.revoke_principal_tokens(PrincipalKind::User, &id).await?;
    }
    audit(
        &state,
        &principal,
        ip,
        "user.update",
        AuditTarget::default(),
        json!({"user": id, "disabled": request.disabled}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_identity(state: &AppState, i: sekret_store::Identity) -> ApiResult<Identity> {
    let methods = state
        .store
        .list_auth_methods(&i.id)
        .await?
        .iter()
        .filter_map(|m| AuthMethodKind::parse(&m.kind))
        .collect();
    Ok(Identity {
        id: i.id,
        name: i.name,
        description: i.description,
        token_ttl: i.token_ttl,
        token_max_ttl: i.token_max_ttl,
        trusted_cidrs: i.trusted_cidrs,
        disabled: i.disabled,
        created_at: i.created_at,
        auth_methods: methods,
    })
}

fn check_ttls(ttl: i64, max_ttl: i64) -> ApiResult<()> {
    if ttl < 60 || max_ttl < ttl || max_ttl > LONGEST_TTL {
        return Err(ApiError::bad_request(
            "token TTL must be at least 60 seconds and no more than the max TTL (at most a year)",
        ));
    }
    Ok(())
}

fn check_cidrs(cidrs: &[String]) -> ApiResult<()> {
    if cidrs.iter().any(|c| c.parse::<ipnet::IpNet>().is_err()) {
        return Err(ApiError::bad_request("trusted CIDRs must look like 10.0.0.0/8"));
    }
    Ok(())
}

/// Handing out a way to log in as an identity is as good as holding its access, so the caller
/// must already cover the identity's organisation rules and its rules in every project.
async fn ensure_covers_identity(
    state: &AppState,
    caller: &Principal,
    identity: &sekret_store::Identity,
) -> ApiResult<()> {
    let target = Principal {
        kind: PrincipalKind::Identity,
        id: identity.id.clone(),
        name: identity.name.clone(),
        email: String::new(),
        groups: Vec::new(),
        token_id: String::new(),
        token_kind: String::new(),
    };
    ensure_covers_principal(state, caller, &target).await
}

/// The caller must already hold `target`'s organisation access and its access in every project.
async fn ensure_covers_principal(state: &AppState, caller: &Principal, target: &Principal) -> ApiResult<()> {
    let escalation = || ApiError::new(StatusCode::FORBIDDEN, "escalation", "they have access you do not have");
    if !covers(&org_rules(state, caller).await?, &org_rules(state, target).await?) {
        return Err(escalation());
    }
    for project in state.store.list_projects().await? {
        let target_rules = project_rules(state, target, &project.id).await?;
        if target_rules.is_empty() {
            continue;
        }
        if !covers(&project_rules(state, caller, &project.id).await?, &target_rules) {
            return Err(escalation());
        }
    }
    Ok(())
}

async fn load_identity(state: &AppState, id: &str) -> ApiResult<sekret_store::Identity> {
    state
        .store
        .get_identity(id)
        .await?
        .ok_or_else(|| ApiError::not_found("identity"))
}

#[utoipa::path(get, path = "/api/v1/identities", tag = "organisation", params(IdentityParams),
    responses((status = 200, body = IdentityPage)), security(("bearer" = [])))]
async fn list_identities(
    State(state): State<AppState>,
    principal: Principal,
    Query(params): Query<IdentityParams>,
) -> ApiResult<Json<IdentityPage>> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Read)?;
    let mut all = Vec::new();
    for identity in state.store.list_identities().await? {
        all.push(api_identity(&state, identity).await?);
    }
    let (items, total) = page_identities(all, &params);
    Ok(Json(IdentityPage { items, total }))
}

#[utoipa::path(post, path = "/api/v1/identities", tag = "organisation", request_body = CreateIdentity,
    responses((status = 201, body = Identity)), security(("bearer" = [])))]
async fn create_identity(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<CreateIdentity>,
) -> ApiResult<(StatusCode, Json<Identity>)> {
    require_any(
        &org_rules(&state, &principal).await?,
        Subject::Identities,
        Action::Create,
    )?;
    validate::name(&request.name)?;
    let ttl = request.token_ttl.unwrap_or(DEFAULT_TOKEN_TTL);
    let max_ttl = request.token_max_ttl.unwrap_or(DEFAULT_TOKEN_MAX_TTL.max(ttl));
    check_ttls(ttl, max_ttl)?;
    check_cidrs(&request.trusted_cidrs)?;
    let identity = sekret_store::Identity {
        id: uuid::Uuid::new_v4().to_string(),
        name: request.name.trim().to_string(),
        description: request.description,
        token_ttl: ttl,
        token_max_ttl: max_ttl,
        trusted_cidrs: request.trusted_cidrs,
        disabled: false,
        created_at: state.clock.now(),
    };
    state.store.create_identity(identity.clone()).await?;
    audit(
        &state,
        &principal,
        ip,
        "identity.create",
        AuditTarget::default(),
        json!({"identity": identity.id, "name": identity.name}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(api_identity(&state, identity).await?)))
}

#[utoipa::path(get, path = "/api/v1/identities/{id}", tag = "organisation", params(("id" = String, Path)),
    responses((status = 200, body = Identity)), security(("bearer" = [])))]
async fn get_identity(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<Identity>> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Read)?;
    let identity = load_identity(&state, &id).await?;
    Ok(Json(api_identity(&state, identity).await?))
}

#[utoipa::path(patch, path = "/api/v1/identities/{id}", tag = "organisation", params(("id" = String, Path)), request_body = UpdateIdentity,
    responses((status = 200, body = Identity)), security(("bearer" = [])))]
async fn update_identity(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(id): Path<String>,
    Json(request): Json<UpdateIdentity>,
) -> ApiResult<Json<Identity>> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Edit)?;
    validate::name(&request.name)?;
    check_ttls(request.token_ttl, request.token_max_ttl)?;
    check_cidrs(&request.trusted_cidrs)?;
    let mut identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    identity.name = request.name.trim().to_string();
    identity.description = request.description;
    identity.token_ttl = request.token_ttl;
    identity.token_max_ttl = request.token_max_ttl;
    identity.trusted_cidrs = request.trusted_cidrs;
    identity.disabled = request.disabled;
    state.store.update_identity(identity.clone()).await?;
    if identity.disabled {
        state
            .store
            .revoke_principal_tokens(PrincipalKind::Identity, &id)
            .await?;
    }
    audit(
        &state,
        &principal,
        ip,
        "identity.update",
        AuditTarget::default(),
        json!({"identity": id}),
    )
    .await;
    Ok(Json(api_identity(&state, identity).await?))
}

#[utoipa::path(delete, path = "/api/v1/identities/{id}", tag = "organisation", params(("id" = String, Path)),
    responses((status = 204)), security(("bearer" = [])))]
async fn delete_identity(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    require_any(
        &org_rules(&state, &principal).await?,
        Subject::Identities,
        Action::Delete,
    )?;
    let identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    state.store.delete_identity(&id).await?;
    audit(
        &state,
        &principal,
        ip,
        "identity.delete",
        AuditTarget::default(),
        json!({"identity": id}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/identities/{id}/auth", tag = "organisation", params(("id" = String, Path)),
    responses((status = 200, body = Vec<AuthMethodConfig>)), security(("bearer" = [])))]
async fn list_auth_methods(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<AuthMethodConfig>>> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Read)?;
    load_identity(&state, &id).await?;
    let methods = state.store.list_auth_methods(&id).await?;
    let configs = methods
        .into_iter()
        .map(|m| {
            serde_json::from_value(m.config)
                .map(redact)
                .map_err(|e| ApiError::internal("auth method config", e))
        })
        .collect::<ApiResult<Vec<AuthMethodConfig>>>()?;
    Ok(Json(configs))
}

#[utoipa::path(put, path = "/api/v1/identities/{id}/auth/{kind}", tag = "organisation", params(("id" = String, Path), ("kind" = String, Path)),
    request_body = AuthMethodConfig, responses((status = 204)), security(("bearer" = [])))]
async fn put_auth_method(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((id, kind)): Path<(String, String)>,
    Json(config): Json<AuthMethodConfig>,
) -> ApiResult<StatusCode> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Edit)?;
    let identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    if AuthMethodKind::parse(&kind) != Some(config.kind()) {
        return Err(ApiError::bad_request("the path and body name different auth methods"));
    }
    validate_config(&config, state.config.allow_insecure_http)?;
    let stored = match state.store.get_auth_method(&id, &kind).await? {
        Some(method) => Some(
            serde_json::from_value::<AuthMethodConfig>(method.config)
                .map_err(|e| ApiError::internal("auth method config", e))?,
        ),
        None => None,
    };
    let config = seal_for_storage(state.keyring.root()?.as_ref(), &id, config, stored.as_ref())?;
    let value = serde_json::to_value(&config).map_err(|e| ApiError::internal("auth method config", e))?;
    let key = state.keyring.integrity(state.store.as_ref()).await?;
    let method = crate::auth::sign_auth_method(
        &key,
        sekret_store::AuthMethod {
            identity_id: id.clone(),
            kind: kind.clone(),
            config: value,
            created_at: state.clock.now(),
            mac: None,
        },
    )?;
    state.store.put_auth_method(method).await?;
    // Tokens issued under the old configuration should not outlive it.
    if stored.is_some() {
        state
            .store
            .revoke_tokens_from_source(&auth_method_source(&id, &kind))
            .await?;
    }
    audit(
        &state,
        &principal,
        ip,
        "identity.auth-put",
        AuditTarget::default(),
        json!({"identity": id, "method": kind}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/api/v1/identities/{id}/auth/{kind}", tag = "organisation", params(("id" = String, Path), ("kind" = String, Path)),
    responses((status = 204)), security(("bearer" = [])))]
async fn delete_auth_method(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((id, kind)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Edit)?;
    let identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    state.store.delete_auth_method(&id, &kind).await?;
    state
        .store
        .revoke_tokens_from_source(&auth_method_source(&id, &kind))
        .await?;
    // Universal logins are tied to client secrets rather than the method, so retire those too.
    if AuthMethodKind::parse(&kind) == Some(AuthMethodKind::Universal) {
        for secret in state.store.list_client_secrets(&id).await? {
            state.store.revoke_client_secret(&id, &secret.id).await?;
            state
                .store
                .revoke_tokens_from_source(&client_secret_source(&secret.id))
                .await?;
        }
    }
    audit(
        &state,
        &principal,
        ip,
        "identity.auth-delete",
        AuditTarget::default(),
        json!({"identity": id, "method": kind}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

fn api_client_secret(s: sekret_store::ClientSecret) -> ClientSecret {
    ClientSecret {
        id: s.id,
        description: s.description,
        prefix: s.prefix,
        created_at: s.created_at,
        expires_at: s.expires_at,
        uses_remaining: s.uses_remaining,
        revoked: s.revoked,
        last_used_at: s.last_used_at,
    }
}

#[utoipa::path(get, path = "/api/v1/identities/{id}/client-secrets", tag = "organisation", params(("id" = String, Path)),
    responses((status = 200, body = Vec<ClientSecret>)), security(("bearer" = [])))]
async fn list_client_secrets(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<ClientSecret>>> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Read)?;
    Ok(Json(
        state
            .store
            .list_client_secrets(&id)
            .await?
            .into_iter()
            .map(api_client_secret)
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/v1/identities/{id}/client-secrets", tag = "organisation", params(("id" = String, Path)),
    request_body = CreateClientSecret, responses((status = 201, body = CreatedClientSecret)), security(("bearer" = [])))]
async fn create_client_secret(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(id): Path<String>,
    Json(request): Json<CreateClientSecret>,
) -> ApiResult<(StatusCode, Json<CreatedClientSecret>)> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Edit)?;
    let identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    if request.ttl.is_some_and(|t| !(1..=MAX_LIFETIME).contains(&t)) {
        return Err(ApiError::bad_request(
            "ttl must be between 1 second and 10 years; leave it out for a secret that never expires",
        ));
    }
    if request
        .max_uses
        .is_some_and(|u| !(1..=MAX_CLIENT_SECRET_USES).contains(&u))
    {
        return Err(ApiError::bad_request("max_uses must be between 1 and 1,000,000,000"));
    }
    let now = state.clock.now();
    let expires_at = match request.ttl {
        Some(ttl) => Some(
            now.checked_add(ttl)
                .ok_or_else(|| ApiError::bad_request("ttl is too long"))?,
        ),
        None => None,
    };
    let secret = generate_token(CLIENT_SECRET_PREFIX)?;
    let key = state.keyring.integrity(state.store.as_ref()).await?;
    let mut record = sekret_store::ClientSecret {
        id: uuid::Uuid::new_v4().to_string(),
        identity_id: id.clone(),
        description: request.description,
        secret_hash: crate::auth::client_secret_lookup(&key, &secret)?,
        prefix: secret.chars().take(8).collect(),
        created_at: now,
        expires_at,
        uses_remaining: request.max_uses,
        revoked: false,
        last_used_at: None,
        mac: None,
    };
    record.mac = Some(crate::auth::client_secret_mac(
        &key,
        &record,
        crate::auth::Form::Current,
    )?);
    state.store.create_client_secret(record.clone()).await?;
    audit(
        &state,
        &principal,
        ip,
        "identity.client-secret-create",
        AuditTarget::default(),
        json!({"identity": id, "prefix": record.prefix}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(CreatedClientSecret {
            client_id: id,
            client_secret: secret.to_string(),
            secret: api_client_secret(record),
        }),
    ))
}

#[utoipa::path(delete, path = "/api/v1/identities/{id}/client-secrets/{secret}", tag = "organisation",
    params(("id" = String, Path), ("secret" = String, Path)), responses((status = 204)), security(("bearer" = [])))]
async fn revoke_client_secret(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((id, secret)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Edit)?;
    let identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    state.store.revoke_client_secret(&id, &secret).await?;
    state
        .store
        .revoke_tokens_from_source(&client_secret_source(&secret))
        .await?;
    audit(
        &state,
        &principal,
        ip,
        "identity.client-secret-revoke",
        AuditTarget::default(),
        json!({"identity": id, "secret": secret}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/v1/identities/{id}/revoke-tokens", tag = "organisation", params(("id" = String, Path)),
    responses((status = 204)), security(("bearer" = [])))]
async fn revoke_identity_tokens(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    require_any(&org_rules(&state, &principal).await?, Subject::Identities, Action::Edit)?;
    let identity = load_identity(&state, &id).await?;
    ensure_covers_identity(&state, &principal, &identity).await?;
    state
        .store
        .revoke_principal_tokens(PrincipalKind::Identity, &id)
        .await?;
    audit(
        &state,
        &principal,
        ip,
        "identity.revoke-tokens",
        AuditTarget::default(),
        json!({"identity": id}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/org/bindings", tag = "organisation", responses((status = 200, body = Vec<OrgBinding>)), security(("bearer" = [])))]
async fn list_bindings(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Vec<OrgBinding>>> {
    require_any(&org_rules(&state, &principal).await?, Subject::OrgMembers, Action::Read)?;
    let users = state.store.list_users().await?;
    let identities = state.store.list_identities().await?;
    let name = |kind: PrincipalKind, id: &str| match kind {
        PrincipalKind::User => users.iter().find(|u| u.id == id).map(|u| {
            if u.email.is_empty() {
                u.name.clone()
            } else {
                u.email.clone()
            }
        }),
        PrincipalKind::Identity => identities.iter().find(|i| i.id == id).map(|i| i.name.clone()),
        PrincipalKind::Group => Some(id.to_string()),
    };
    let bindings = state.store.list_org_bindings().await?;
    Ok(Json(
        bindings
            .into_iter()
            .map(|b| OrgBinding {
                principal_kind: to_api_kind(b.principal_kind),
                principal_name: name(b.principal_kind, &b.principal_id).unwrap_or_else(|| b.principal_id.clone()),
                principal_id: b.principal_id,
                role: b.role_slug,
            })
            .collect(),
    ))
}

async fn org_role_rules(state: &AppState, slug: &str) -> ApiResult<Vec<sekret_core::permissions::Rule>> {
    let custom = state.store.list_roles("").await?;
    role_rules(slug, &custom, true).ok_or_else(|| ApiError::bad_request(format!("unknown organisation role {slug}")))
}

#[utoipa::path(post, path = "/api/v1/org/bindings", tag = "organisation", request_body = AddOrgBinding,
    responses((status = 201)), security(("bearer" = [])))]
async fn add_binding(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<AddOrgBinding>,
) -> ApiResult<StatusCode> {
    let rules = org_rules(&state, &principal).await?;
    require_any(&rules, Subject::OrgMembers, Action::Create)?;
    if !covers(&rules, &org_role_rules(&state, &request.role).await?) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "escalation",
            "you cannot grant a role with more access than you have",
        ));
    }
    let kind = from_api_kind(request.principal_kind);
    ensure_principal_exists(&state, kind, &request.principal_id).await?;
    state
        .store
        .add_org_binding(Binding {
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
        "org.binding-add",
        AuditTarget::default(),
        json!({"principal_kind": kind.as_str(), "principal_id": request.principal_id, "role": request.role}),
    )
    .await;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(delete, path = "/api/v1/org/bindings/{kind}/{id}/{role}", tag = "organisation",
    params(("kind" = String, Path), ("id" = String, Path), ("role" = String, Path)), responses((status = 204)), security(("bearer" = [])))]
async fn remove_binding(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path((kind, id, role)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let rules = org_rules(&state, &principal).await?;
    require_any(&rules, Subject::OrgMembers, Action::Delete)?;
    let kind = PrincipalKind::parse(&kind).ok_or_else(|| ApiError::bad_request("unknown principal kind"))?;
    if !may_remove(&rules, &org_role_rules(&state, &role).await.unwrap_or_default()) {
        return Err(removal_escalation());
    }
    state.store.remove_org_binding(kind, &id, &role).await?;
    audit(
        &state,
        &principal,
        ip,
        "org.binding-remove",
        AuditTarget::default(),
        json!({"principal_kind": kind.as_str(), "principal_id": id, "role": role}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/org/roles", tag = "organisation", responses((status = 200, body = Vec<Role>)), security(("bearer" = [])))]
async fn list_org_roles(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Vec<Role>>> {
    require_any(&org_rules(&state, &principal).await?, Subject::OrgRoles, Action::Read)?;
    let mut roles = builtin_roles(true);
    roles.extend(state.store.list_roles("").await?.into_iter().map(api_role));
    Ok(Json(roles))
}

#[utoipa::path(put, path = "/api/v1/org/roles/{slug}", tag = "organisation", params(("slug" = String, Path)), request_body = PutRole,
    responses((status = 200, body = Role)), security(("bearer" = [])))]
async fn put_org_role(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(slug): Path<String>,
    Json(request): Json<PutRole>,
) -> ApiResult<Json<Role>> {
    let rules = org_rules(&state, &principal).await?;
    let existing = state.store.list_roles("").await?.into_iter().find(|r| r.slug == slug);
    require_any(
        &rules,
        Subject::OrgRoles,
        if existing.is_some() {
            Action::Edit
        } else {
            Action::Create
        },
    )?;
    validate_role(&slug, &request, &rules, true)?;
    if let Some(existing) = &existing
        && !may_remove(&rules, &dropped_rules(&existing.rules, &request.rules))
    {
        return Err(removal_escalation());
    }
    let role = sekret_store::Role {
        id: uuid::Uuid::new_v4().to_string(),
        project_id: String::new(),
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
        "org.role-put",
        AuditTarget::default(),
        json!({"role": slug}),
    )
    .await;
    Ok(Json(api_role(role)))
}

#[utoipa::path(delete, path = "/api/v1/org/roles/{slug}", tag = "organisation", params(("slug" = String, Path)),
    responses((status = 204)), security(("bearer" = [])))]
async fn delete_org_role(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(slug): Path<String>,
) -> ApiResult<StatusCode> {
    let rules = org_rules(&state, &principal).await?;
    require_any(&rules, Subject::OrgRoles, Action::Delete)?;
    if !may_remove(&rules, &org_role_rules(&state, &slug).await.unwrap_or_default()) {
        return Err(removal_escalation());
    }
    state.store.delete_role("", &slug).await?;
    audit(
        &state,
        &principal,
        ip,
        "org.role-delete",
        AuditTarget::default(),
        json!({"role": slug}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/api/v1/audit", tag = "organisation", params(AuditParams),
    responses((status = 200, body = AuditPage)), security(("bearer" = [])))]
async fn org_audit(
    State(state): State<AppState>,
    principal: Principal,
    Query(params): Query<AuditParams>,
) -> ApiResult<Json<AuditPage>> {
    require_any(
        &org_rules(&state, &principal).await?,
        Subject::OrgAuditLog,
        Action::Read,
    )?;
    Ok(Json(audit_page(&state, None, params, false).await?))
}
