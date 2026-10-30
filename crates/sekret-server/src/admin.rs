use sekret_api::AuthMethodConfig;
use sekret_core::crypto::{DataKey, RootKey, unwrap_data_key, wrap_data_key};
use sekret_core::permissions::BuiltinRole;
use sekret_store::{Binding, PrincipalKind, Store, UserLogin};

use crate::auth::{TokenKind, TokenRequest, mint_token};
use crate::error::{ApiError, ApiResult};
use crate::machine::reseal;
use crate::state::AppState;

pub const BOOTSTRAP_SUBJECT: &str = "local|bootstrap-admin";

/// Creates (or reuses) the local break-glass admin and returns a short-lived admin token.
pub async fn bootstrap_admin(state: &AppState, ttl: i64) -> ApiResult<String> {
    let now = state.clock.now();
    let user = state
        .store
        .upsert_user(UserLogin {
            subject: BOOTSTRAP_SUBJECT.into(),
            email: String::new(),
            name: "bootstrap-admin".into(),
            groups: vec![],
            now,
        })
        .await?;
    state.store.set_user_disabled(&user.id, false).await?;
    state
        .store
        .add_org_binding(Binding {
            principal_kind: PrincipalKind::User,
            principal_id: user.id.clone(),
            role_slug: BuiltinRole::OrgAdmin.slug().into(),
            created_at: now,
        })
        .await?;
    let minted = mint_token(
        state,
        TokenRequest {
            kind: TokenKind::Admin,
            principal_kind: PrincipalKind::User,
            principal_id: &user.id,
            ttl,
            max_ttl: ttl,
            description: "bootstrap admin".into(),
            source: String::new(),
        },
    )
    .await?;
    Ok(minted.token.to_string())
}

/// Re-wraps every project data key under `new_root` and records its fingerprint.
pub async fn rotate_root_key(store: &dyn Store, old_root: &RootKey, new_root: &RootKey) -> ApiResult<usize> {
    let projects = store.list_projects().await?;
    let mut rewrapped = Vec::with_capacity(projects.len());
    for project in &projects {
        let key: DataKey = unwrap_data_key(old_root, &project.wrapped_key, &project.id)
            .map_err(|e| ApiError::internal("unwrapping project key", e))?;
        rewrapped.push((project.id.clone(), wrap_data_key(new_root, &key, &project.id)?));
    }
    let mut resealed = Vec::new();
    for identity in store.list_identities().await? {
        for mut method in store.list_auth_methods(&identity.id).await? {
            let config: AuthMethodConfig =
                serde_json::from_value(method.config).map_err(|e| ApiError::internal("auth method config", e))?;
            let Some(config) = reseal(old_root, new_root, &identity.id, &config)? else {
                continue;
            };
            method.config = serde_json::to_value(&config).map_err(|e| ApiError::internal("auth method config", e))?;
            resealed.push(method);
        }
    }
    let count = rewrapped.len();
    store
        .replace_wrapped_keys(rewrapped, resealed, &new_root.fingerprint())
        .await?;
    Ok(count)
}
