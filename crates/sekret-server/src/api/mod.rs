pub mod listing;
pub mod logo;
mod org;
mod projects;
mod secrets;
mod sys;

pub use sys::{HostSocket, clean_stale_staging, host_router, staging_base};

use std::net::IpAddr;

use sekret_core::permissions::Rule;
use sekret_store::{AuditEntry, Environment, Project};
use serde_json::Value;
use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::Principal;
use crate::authz::{can_see_project, project_rules};
use crate::error::{ApiError, ApiResult};
use crate::secrets::SecretCtx;
use crate::state::AppState;
use crate::{human, machine};

#[derive(Default)]
pub struct AuditTarget<'a> {
    pub project_id: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub path: Option<&'a str>,
    pub key: Option<&'a str>,
}

/// Records an audit entry. Failures are logged rather than failing the request.
pub async fn audit(
    state: &AppState,
    principal: &Principal,
    ip: IpAddr,
    action: &str,
    target: AuditTarget<'_>,
    detail: Value,
) {
    let entry = AuditEntry {
        id: uuid::Uuid::now_v7().to_string(),
        created_at: state.clock.now(),
        actor_kind: principal.kind.as_str().to_string(),
        actor_id: principal.id.clone(),
        actor_name: principal.actor(),
        action: action.to_string(),
        project_id: target.project_id.map(String::from),
        environment: target.environment.map(String::from),
        path: target.path.map(String::from),
        secret_key: target.key.map(String::from),
        detail,
        ip: ip.to_string(),
    };
    if let Err(error) = state.store.insert_audit(entry).await {
        tracing::error!(%error, action, "failed to write audit entry");
    }
}

/// Loads a project the principal can see, answering 404 otherwise so existence does not leak.
pub async fn load_project(
    state: &AppState,
    principal: &Principal,
    id_or_slug: &str,
) -> ApiResult<(Project, Vec<Rule>)> {
    let project = state
        .store
        .get_project(id_or_slug)
        .await?
        .ok_or_else(|| ApiError::not_found("project"))?;
    let rules = project_rules(state, principal, &project.id).await?;
    if !can_see_project(&rules) {
        return Err(ApiError::not_found("project"));
    }
    Ok((project, rules))
}

pub async fn find_env(state: &AppState, project: &Project, slug: &str) -> ApiResult<Environment> {
    state
        .store
        .list_environments(&project.id)
        .await?
        .into_iter()
        .find(|e| e.slug == slug)
        .ok_or_else(|| ApiError::not_found("environment"))
}

pub fn secret_ctx<'a>(state: &'a AppState, principal: &Principal) -> ApiResult<SecretCtx<'a>> {
    Ok(SecretCtx {
        store: state.store.as_ref(),
        root_key: state.keyring.root()?,
        now: state.clock.now(),
        actor: principal.actor(),
        snapshots_to_keep: state.config.snapshots_to_keep,
        generated: false,
    })
}

pub fn api_project(p: &Project) -> sekret_api::Project {
    sekret_api::Project {
        id: p.id.clone(),
        slug: p.slug.clone(),
        name: p.name.clone(),
        description: p.description.clone(),
        created_at: p.created_at,
        logo_url: p
            .logo_updated_at
            .map(|v| format!("/api/v1/projects/{}/logo?v={v}", p.id)),
    }
}

pub fn api_env(e: &Environment) -> sekret_api::Environment {
    sekret_api::Environment {
        id: e.id.clone(),
        slug: e.slug.clone(),
        name: e.name.clone(),
        position: e.position,
    }
}

pub fn to_api_kind(kind: sekret_store::PrincipalKind) -> sekret_api::PrincipalKind {
    match kind {
        sekret_store::PrincipalKind::User => sekret_api::PrincipalKind::User,
        sekret_store::PrincipalKind::Group => sekret_api::PrincipalKind::Group,
        sekret_store::PrincipalKind::Identity => sekret_api::PrincipalKind::Identity,
    }
}

pub fn from_api_kind(kind: sekret_api::PrincipalKind) -> sekret_store::PrincipalKind {
    match kind {
        sekret_api::PrincipalKind::User => sekret_store::PrincipalKind::User,
        sekret_api::PrincipalKind::Group => sekret_store::PrincipalKind::Group,
        sekret_api::PrincipalKind::Identity => sekret_store::PrincipalKind::Identity,
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "sekret", description = "Secrets management API"),
    // Used only in query parameters, which do not pull their schemas in on their own.
    components(schemas(
        sekret_api::SortOrder,
        listing::Status,
        listing::UserSort,
        listing::IdentitySort,
        logo::LogoFile,
    )),
    modifiers(&BearerAuth),
    tags((name = "system"), (name = "auth"), (name = "projects"), (name = "secrets"), (name = "organisation"))
)]
pub struct ApiDoc;

struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info.version = sekret_core::VERSION.to_string();
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
            );
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(human::auth_config))
        .routes(routes!(human::logout))
        .routes(routes!(human::cli_start))
        .routes(routes!(human::cli_pending))
        .routes(routes!(human::cli_approve))
        .routes(routes!(human::cli_poll))
        .routes(routes!(machine::oidc_login))
        .routes(routes!(machine::kubernetes_login))
        .routes(routes!(machine::universal_login))
        .routes(routes!(machine::renew))
        .routes(routes!(machine::revoke))
        .merge(org::router())
        .merge(projects::router())
        .merge(logo::router())
        .merge(secrets::router())
        .merge(sys::router())
}
