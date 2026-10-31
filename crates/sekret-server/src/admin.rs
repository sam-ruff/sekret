use sekret_api::AuthMethodConfig;
use sekret_core::crypto::{
    DataKey, RootKey, ValueContext, decrypt_value, encrypt_value, unwrap_data_key, wrap_data_key,
};
use sekret_core::permissions::BuiltinRole;
use sekret_store::{Binding, EncryptedValue, PrincipalKind, Rekey, SealConfig, Store, UserLogin};

use crate::auth::{TokenKind, TokenRequest, mint_token};
use crate::error::{ApiError, ApiResult};
use crate::machine::reseal;
use crate::state::AppState;

pub const BOOTSTRAP_SUBJECT: &str = "local|bootstrap-admin";

/// Creates (or reuses) the local break-glass admin and returns a short-lived admin token.
pub async fn bootstrap_admin(state: &AppState, ttl: i64) -> ApiResult<String> {
    Ok(bootstrap_admin_token(state, ttl).await?.0)
}

/// [`bootstrap_admin`], also returning when the token expires, in Unix seconds.
pub async fn bootstrap_admin_token(state: &AppState, ttl: i64) -> ApiResult<(String, i64)> {
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
            auth_time: None,
        },
    )
    .await?;
    Ok((minted.token.to_string(), minted.record.expires_at))
}

/// Re-encrypts each value under a fresh data key for its project, so nothing written under the
/// old keys stays readable with them.
fn reencrypt_values(
    project_id: &str,
    old_key: &DataKey,
    new_key: &DataKey,
    values: Vec<EncryptedValue>,
) -> ApiResult<Vec<EncryptedValue>> {
    values
        .into_iter()
        .map(|value| {
            let ctx = ValueContext {
                project_id,
                secret_id: &value.secret_id,
                version: value.version,
            };
            let plain = decrypt_value(old_key, &value.value, ctx)
                .map_err(|e| ApiError::internal("decrypting a value for re-encryption", e))?;
            Ok(EncryptedValue {
                value: encrypt_value(new_key, &plain, ctx)?,
                ..value
            })
        })
        .collect()
}

/// Replaces the root key: every project gets a fresh data key wrapped under `new_root`, every
/// secret value (history included) is re-encrypted under it, machine credentials are resealed
/// and the fingerprint recorded, all in one transaction. In passphrase mode `seal` carries the new
/// wrap; its epoch goes up and it is signed with the new root key.
pub async fn rotate_root_key(
    store: &dyn Store,
    old_root: &RootKey,
    new_root: &RootKey,
    seal: Option<SealConfig>,
) -> ApiResult<usize> {
    let projects = store.list_projects().await?;
    let mut rewrapped = Vec::with_capacity(projects.len());
    let mut values = Vec::new();
    for project in &projects {
        let old_key: DataKey = unwrap_data_key(old_root, &project.wrapped_key, &project.id)
            .map_err(|e| ApiError::internal("unwrapping project key", e))?;
        let new_key = DataKey::generate()?;
        let stored = store.list_encrypted_values(&project.id).await?;
        values.extend(reencrypt_values(&project.id, &old_key, &new_key, stored)?);
        rewrapped.push((project.id.clone(), wrap_data_key(new_root, &new_key, &project.id)?));
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
    let seal = seal.map(|config| crate::seal::signed(new_root, config)).transpose()?;
    store
        .replace_wrapped_keys(Rekey {
            keys: rewrapped,
            values,
            auth_methods: resealed,
            fingerprint: new_root.fingerprint(),
            seal,
        })
        .await?;
    Ok(count)
}
