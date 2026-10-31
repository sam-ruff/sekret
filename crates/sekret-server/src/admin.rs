use std::path::PathBuf;

use sekret_api::AuthMethodConfig;
use sekret_core::crypto::{
    DataKey, RootKey, ValueContext, decrypt_value, encrypt_value, unwrap_data_key, wrap_data_key,
};
use sekret_core::permissions::BuiltinRole;
use sekret_core::seal::UnlockPolicy;
use sekret_store::{Binding, EncryptedValue, PrincipalKind, Rekey, SealConfig, Store, UserLogin};

use crate::auth::{TokenKind, TokenRequest, mint_token};
use crate::error::{ApiError, ApiResult};
use crate::machine::reseal;
use crate::seal::{HighWater, cautious_flags, verify_config};
use crate::state::AppState;

pub const BOOTSTRAP_SUBJECT: &str = "local|bootstrap-admin";
/// The longest a break-glass admin token may last: a day.
pub const MAX_BOOTSTRAP_TTL: i64 = 86_400;

/// Creates (or reuses) the local break-glass admin and returns a short-lived admin token.
pub async fn bootstrap_admin(state: &AppState, ttl: i64) -> ApiResult<String> {
    Ok(bootstrap_admin_token(state, ttl).await?.0)
}

/// [`bootstrap_admin`], also returning when the token expires, in Unix seconds.
pub async fn bootstrap_admin_token(state: &AppState, ttl: i64) -> ApiResult<(String, i64)> {
    if !(1..=MAX_BOOTSTRAP_TTL).contains(&ttl) {
        return Err(ApiError::bad_request(format!(
            "an admin token lasts between 1 and {MAX_BOOTSTRAP_TTL} seconds"
        )));
    }
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

/// A stored configuration about to be signed again with a new key: kept as it is when its
/// signature holds under `old_root` and it is not older than the recorded marks, otherwise reset
/// to grant no unlock, so a database writer's change or rollback is never signed as it stands.
pub fn trusted_or_reset(old_root: &RootKey, config: SealConfig, marks: HighWater) -> SealConfig {
    let Err(distrust) = verify_config(old_root, &config, marks) else {
        return config;
    };
    tracing::error!(
        action = distrust.action(),
        "the seal configuration failed its integrity check; resetting it to the manual unlock policy"
    );
    SealConfig {
        unlock_policy: UnlockPolicy::Manual,
        remembered: None,
        flags: cautious_flags(config.flags, false),
        ..config
    }
}

/// How a root key replacement treats the seal configuration and data it cannot read.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rotation<'a> {
    /// The epoch marks recorded outside the database; the new signature goes above them.
    pub marks: HighWater,
    /// Leave unreadable rows as they are instead of refusing.
    pub skip_unreadable: bool,
    /// Where the marks are, so they move to the new root key with the database.
    pub epoch_files: &'a [PathBuf],
}

/// What a root key replacement did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationReport {
    pub projects: usize,
    /// Rows that could not be read and were left as they were, by id; never their contents.
    pub skipped: Vec<String>,
}

/// Re-encrypts each value under a fresh data key for its project, so nothing written under the
/// old keys stays readable with them. Values that do not decrypt are named in `unreadable`.
fn reencrypt_values(
    project_id: &str,
    old_key: &DataKey,
    new_key: &DataKey,
    values: Vec<EncryptedValue>,
    unreadable: &mut Vec<String>,
) -> ApiResult<Vec<EncryptedValue>> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let ctx = ValueContext {
            project_id,
            secret_id: &value.secret_id,
            version: value.version,
        };
        let Ok(plain) = decrypt_value(old_key, &value.value, ctx) else {
            unreadable.push(format!(
                "secret {} version {} in project {project_id}",
                value.secret_id, value.version
            ));
            continue;
        };
        out.push(EncryptedValue {
            value: encrypt_value(new_key, &plain, ctx)?,
            ..value
        });
    }
    Ok(out)
}

fn unreadable_rows(rows: &[String]) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::CONFLICT,
        "unreadable_data",
        format!(
            "{} stored item(s) no longer decrypt, so the root key was not replaced: {}. Retry with skip_unreadable \
             (--skip-unreadable) to leave them as they are",
            rows.len(),
            rows.join("; ")
        ),
    )
}

/// Replaces the root key: every project gets a fresh data key wrapped under `new_root`, every
/// secret value (history included) is re-encrypted under it, machine credentials are resealed
/// and the fingerprint recorded, all in one transaction. In passphrase mode `seal` carries the new
/// wrap. Either way the stored seal configuration moves past its epoch and the recorded marks and
/// is signed with the new root key, so the next start does not take it for tampering.
pub async fn rotate_root_key(
    store: &dyn Store,
    old_root: &RootKey,
    new_root: &RootKey,
    seal: Option<SealConfig>,
    rotation: Rotation<'_>,
) -> ApiResult<RotationReport> {
    let seal = match seal {
        Some(config) => Some(config),
        None => store
            .get_seal_config()
            .await?
            .map(|config| trusted_or_reset(old_root, config, rotation.marks)),
    };
    let mut unreadable = Vec::new();
    let projects = store.list_projects().await?;
    let mut rewrapped = Vec::with_capacity(projects.len());
    let mut values = Vec::new();
    for project in &projects {
        let Ok(old_key) = unwrap_data_key(old_root, &project.wrapped_key, &project.id) else {
            unreadable.push(format!("data key of project {}", project.id));
            continue;
        };
        let new_key = DataKey::generate()?;
        let stored = store.list_encrypted_values(&project.id).await?;
        values.extend(reencrypt_values(
            &project.id,
            &old_key,
            &new_key,
            stored,
            &mut unreadable,
        )?);
        rewrapped.push((project.id.clone(), wrap_data_key(new_root, &new_key, &project.id)?));
    }
    let mut resealed = Vec::new();
    for identity in store.list_identities().await? {
        for mut method in store.list_auth_methods(&identity.id).await? {
            let config: AuthMethodConfig =
                serde_json::from_value(method.config).map_err(|e| ApiError::internal("auth method config", e))?;
            let config = match reseal(old_root, new_root, &identity.id, &config) {
                Ok(Some(config)) => config,
                Ok(None) => continue,
                Err(_) => {
                    unreadable.push(format!("{} credential of identity {}", method.kind, identity.id));
                    continue;
                }
            };
            method.config = serde_json::to_value(&config).map_err(|e| ApiError::internal("auth method config", e))?;
            resealed.push(method);
        }
    }
    if !unreadable.is_empty() && !rotation.skip_unreadable {
        return Err(unreadable_rows(&unreadable));
    }
    for row in &unreadable {
        tracing::warn!(row = %row, "left unreadable data as it was while replacing the root key");
    }
    let projects = rewrapped.len();
    let seal = seal
        .map(|config| crate::seal::signed(new_root, config, rotation.marks.floor()))
        .transpose()?;
    let epoch = seal.as_ref().map_or(rotation.marks.floor(), |config| config.epoch);
    let fingerprint = new_root.fingerprint();
    crate::seal::begin_rekey(rotation.epoch_files, &old_root.fingerprint(), &fingerprint)
        .map_err(|e| ApiError::internal("preparing the seal epoch marks for the new root key", e))?;
    let replaced = store
        .replace_wrapped_keys(Rekey {
            keys: rewrapped,
            values,
            auth_methods: resealed,
            fingerprint: fingerprint.clone(),
            seal,
        })
        .await;
    if let Err(error) = replaced {
        if let Err(error) =
            crate::seal::record_epoch(rotation.epoch_files, rotation.marks.floor(), &old_root.fingerprint())
        {
            tracing::warn!(%error, "could not put the seal epoch marks back to the old root key");
        }
        return Err(error.into());
    }
    // The database has moved on; marks that still name both keys keep working until fixed.
    if let Err(error) = crate::seal::record_epoch(rotation.epoch_files, epoch, &fingerprint) {
        tracing::error!(
            %error,
            "the root key was replaced, but an epoch mark still accepts the old one; check it can be written"
        );
    }
    Ok(RotationReport {
        projects,
        skipped: unreadable,
    })
}
