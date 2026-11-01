use std::path::PathBuf;

use sekret_api::AuthMethodConfig;
use sekret_core::crypto::{
    DataKey, IntegrityKey, RootKey, ValueContext, decrypt_value, encrypt_value, unwrap_data_key, wrap_data_key,
};
use sekret_core::permissions::BuiltinRole;
use sekret_store::{
    AuthMethod, Binding, EncryptedValue, INTEGRITY_KEY_META, PrincipalKind, Rekey, SealConfig, Store, UserLogin,
};

use crate::auth::{TokenKind, TokenRequest, mint_token};
use crate::error::{ApiError, ApiResult};
use crate::machine::reseal;
use crate::seal::{HighWater, distrusted, kept_flags, verify_config};
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
/// An unsigned one grants nothing already, but its flags are not trusted to start a migration.
pub fn trusted_or_reset(old_root: &RootKey, config: SealConfig, marks: HighWater) -> SealConfig {
    let verdict = verify_config(old_root, &config, marks);
    let Err(distrust) = verdict else {
        return SealConfig {
            flags: kept_flags(&config, verdict, marks),
            ..config
        };
    };
    tracing::error!(
        action = distrust.action(),
        "the seal configuration failed its integrity check; resetting it to the manual unlock policy"
    );
    distrusted(config, distrust, marks)
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
    /// Why the epoch marks could not be moved to the new key after the change was committed.
    pub stale_marks: Option<String>,
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
/// secret value (history included) is re-encrypted under it, machine credentials are resealed,
/// the integrity key is wrapped again, so tokens and client secrets keep working, and the
/// fingerprint is recorded, all in one transaction. In passphrase mode `seal` carries the new
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
        let new_key = DataKey::generate()?;
        let Ok(old_key) = unwrap_data_key(old_root, &project.wrapped_key, &project.id) else {
            unreadable.push(format!("data key of project {}", project.id));
            // Its values are lost with the old key either way, but a fresh key lets the project
            // take new ones, and the new root opens every project key, as unlocking requires.
            rewrapped.push((project.id.clone(), wrap_data_key(new_root, &new_key, &project.id)?));
            continue;
        };
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
    let integrity = match store.get_meta(INTEGRITY_KEY_META).await? {
        None => crate::seal::load_integrity_key(store, old_root).await?,
        Some(wrapped) => match IntegrityKey::unwrap(old_root, &wrapped) {
            Ok(key) => key,
            Err(_) => {
                // A fresh one means signing in again and new client secrets, rather than
                // vouching for whatever the database holds now.
                unreadable.push("the integrity key, so every token, client secret and auth method".into());
                IntegrityKey::generate()?
            }
        },
    };
    let mut resealed = Vec::new();
    for identity in store.list_identities().await? {
        for mut method in store.list_auth_methods(&identity.id).await? {
            let config: AuthMethodConfig = serde_json::from_value(method.config.clone())
                .map_err(|e| ApiError::internal("auth method config", e))?;
            let config = match reseal(old_root, new_root, &identity.id, &config) {
                Ok(Some(config)) => config,
                Ok(None) => continue,
                Err(_) => {
                    unreadable.push(format!("{} credential of identity {}", method.kind, identity.id));
                    continue;
                }
            };
            // Only a method that was this server's keeps a signature over its new form.
            let vouched = crate::auth::auth_method_verified(&integrity, &method);
            method.config = serde_json::to_value(&config).map_err(|e| ApiError::internal("auth method config", e))?;
            method = match vouched {
                true => crate::auth::sign_auth_method(&integrity, method)?,
                false => AuthMethod { mac: None, ..method },
            };
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
        .map(|config| crate::seal::sign(new_root, config, rotation.marks.floor()))
        .transpose()?;
    let epoch = seal.as_ref().map_or(rotation.marks.floor(), |config| config.epoch);
    let migrated = seal
        .as_ref()
        .is_some_and(|config| crate::seal::migrations_done(config.flags));
    let fingerprint = new_root.fingerprint();
    let new_pin = new_root.pin()?;
    let before = crate::seal::begin_rekey(rotation.epoch_files, &old_root.pin()?, &new_pin, epoch)
        .map_err(|e| ApiError::internal("preparing the seal epoch marks for the new root key", e))?;
    let replaced = store
        .replace_wrapped_keys(Rekey {
            keys: rewrapped,
            values,
            auth_methods: resealed,
            fingerprint,
            seal,
            integrity_key: Some(integrity.wrap(new_root)?),
        })
        .await;
    if let Err(error) = replaced {
        if let Err(error) = crate::seal::abort_rekey(&before) {
            tracing::warn!(%error, "could not put the seal epoch marks back to the old root key");
        }
        return Err(error.into());
    }
    // The database has moved on, so this is reported rather than undone. Marks that still name
    // both keys already sit at the new epoch, so an older copy under the old key counts as a
    // rollback meanwhile.
    let stale_marks = crate::seal::record_mark(rotation.epoch_files, epoch, &new_pin, migrated)
        .err()
        .map(|error| {
            tracing::error!(%error, "the root key was replaced, but an epoch mark still accepts the old one");
            format!(
                "the root key was replaced, but an epoch mark still accepts the old one ({error}); make it writable, \
                 then run `sekret admin reset-epoch` with the server stopped"
            )
        });
    Ok(RotationReport {
        projects,
        skipped: unreadable,
        stale_marks,
    })
}
