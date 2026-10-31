//! The root key's life in memory: first-boot setup, sealing, unlocking and remembered unlocks.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use sekret_api::SysStatus;
use sekret_core::crypto::{CryptoError, RootKey};
use sekret_core::seal::{
    DeviceKey, MAX_PASSPHRASE_BYTES, PassphraseError, SealBinding, SealMode, SealState, UnlockPolicy, UnsealedBy,
    Unwrapped, WrappedRootKey, generate_setup_code, recall_root_key, remember_root_key, seal_config_mac,
    setup_code_matches, unwrap_root_key_checked, validate_passphrase, verify_seal_config, wrap_root_key,
};
use sekret_store::{AuditEntry, SealConfig, Store, StoreError};
use tokio::sync::{OwnedSemaphorePermit, RwLockReadGuard, RwLockWriteGuard, Semaphore};
use zeroize::Zeroizing;

use crate::config::SealSettings;
use crate::error::{ApiError, ApiResult};
use crate::files::{
    SECRET_FILE_LIMIT, read_epoch, read_limited, read_private, remove_device_key_file, write_epoch, write_new_private,
};
use crate::{ROOT_KEY_META, StartupError, check_root_key};

/// Shown as the address of audit entries written by the server itself.
const LOCAL: &str = "local";
/// How long replacing the root key waits for changes already being written.
const REKEY_WAIT: Duration = Duration::from_secs(30);

struct Slot {
    root: Option<Arc<RootKey>>,
    mode: Option<SealMode>,
    /// The policy stored at setup, once checked against the root key; configuration may override it.
    policy: UnlockPolicy,
    /// The database holds a remembered wrap of the root key.
    remembered: bool,
    setup_code: Option<Zeroizing<String>>,
    unsealed_by: Option<UnsealedBy>,
}

/// Holds the root key while unsealed. Everything that needs it asks here and gets the sealed
/// error otherwise.
pub struct Keyring {
    slot: RwLock<Slot>,
    /// Serialises setup, unlocking, sealing and changes to the seal configuration.
    gate: tokio::sync::Mutex<()>,
    /// One Argon2 derivation at a time. The permit moves into the blocking task, so a cancelled
    /// request cannot let another derivation start while its own still runs.
    kdf: Arc<Semaphore>,
    /// Requests that write root-key-dependent data hold this for reading; replacing the root key
    /// holds it for writing, so nothing is written under a key that is about to go.
    rekey: tokio::sync::RwLock<()>,
}

impl Keyring {
    fn with(slot: Slot) -> Self {
        Self {
            slot: RwLock::new(slot),
            gate: tokio::sync::Mutex::new(()),
            kdf: Arc::new(Semaphore::new(1)),
            rekey: tokio::sync::RwLock::new(()),
        }
    }

    pub fn unsealed(root: RootKey, mode: SealMode) -> Self {
        Self::unsealed_shared(Arc::new(root), mode)
    }

    pub fn unsealed_shared(root: Arc<RootKey>, mode: SealMode) -> Self {
        let unsealed_by = match mode {
            SealMode::Passphrase => UnsealedBy::Passphrase,
            SealMode::KeyFile => UnsealedBy::KeyFile,
        };
        Self::with(Slot {
            root: Some(root),
            mode: Some(mode),
            policy: UnlockPolicy::Manual,
            remembered: false,
            setup_code: None,
            unsealed_by: Some(unsealed_by),
        })
    }

    pub fn sealed(policy: UnlockPolicy, remembered: bool) -> Self {
        Self::with(Slot {
            root: None,
            mode: Some(SealMode::Passphrase),
            policy,
            remembered,
            setup_code: None,
            unsealed_by: None,
        })
    }

    /// Without a setup code, setup can only happen on the host.
    pub fn uninitialised(setup_code: Option<Zeroizing<String>>) -> Self {
        Self::with(Slot {
            root: None,
            mode: None,
            policy: UnlockPolicy::Manual,
            remembered: false,
            setup_code,
            unsealed_by: None,
        })
    }

    fn read<T>(&self, f: impl FnOnce(&Slot) -> T) -> ApiResult<T> {
        let slot = self
            .slot
            .read()
            .map_err(|_| ApiError::internal("keyring", "lock poisoned"))?;
        Ok(f(&slot))
    }

    fn write<T>(&self, f: impl FnOnce(&mut Slot) -> T) -> ApiResult<T> {
        let mut slot = self
            .slot
            .write()
            .map_err(|_| ApiError::internal("keyring", "lock poisoned"))?;
        Ok(f(&mut slot))
    }

    /// The root key, or 503 while sealed or uninitialised.
    pub fn root(&self) -> ApiResult<Arc<RootKey>> {
        self.read(|slot| match (&slot.root, slot.mode) {
            (Some(root), _) => Ok(root.clone()),
            (None, None) => Err(ApiError::uninitialised()),
            (None, Some(_)) => Err(ApiError::sealed()),
        })?
    }

    /// Treats a poisoned lock as sealed, which fails closed.
    pub fn state(&self) -> SealState {
        self.read(|slot| match (&slot.root, slot.mode) {
            (Some(_), _) => SealState::Unsealed,
            (None, None) => SealState::Uninitialised,
            (None, Some(_)) => SealState::Sealed,
        })
        .unwrap_or(SealState::Sealed)
    }

    pub fn mode(&self) -> Option<SealMode> {
        self.read(|slot| slot.mode).ok().flatten()
    }

    /// How the root key got into memory, while unsealed.
    pub fn unsealed_by(&self) -> Option<UnsealedBy> {
        self.read(|slot| slot.root.as_ref().and(slot.unsealed_by))
            .ok()
            .flatten()
    }

    /// The one-time setup code, while uninitialised and web setup is on.
    pub fn setup_code(&self) -> Option<Zeroizing<String>> {
        self.read(|slot| slot.setup_code.clone()).ok().flatten()
    }

    fn stored_policy(&self) -> UnlockPolicy {
        self.read(|slot| slot.policy).unwrap_or_default()
    }

    fn remembered(&self) -> bool {
        self.read(|slot| slot.remembered).unwrap_or(false)
    }

    fn setup_code_matches(&self, given: &str) -> bool {
        self.read(|slot| {
            slot.setup_code
                .as_ref()
                .is_some_and(|code| setup_code_matches(code, given))
        })
        .unwrap_or(false)
    }

    fn install(&self, root: Arc<RootKey>, config: &SealConfig, by: UnsealedBy) -> ApiResult<()> {
        self.write(|slot| {
            slot.root = Some(root);
            slot.mode = Some(config.mode);
            slot.policy = config.unlock_policy;
            slot.remembered = config.remembered.is_some();
            slot.setup_code = None;
            slot.unsealed_by = Some(by);
        })
    }

    fn record(&self, config: &SealConfig) -> ApiResult<()> {
        self.write(|slot| {
            slot.policy = config.unlock_policy;
            slot.remembered = config.remembered.is_some();
        })
    }

    /// Swaps in a new root key, but only while unsealed: a seal that got in first stays sealed.
    fn replace_root(&self, root: Arc<RootKey>) -> ApiResult<bool> {
        self.write(|slot| {
            if slot.root.is_none() {
                return false;
            }
            slot.root = Some(root);
            true
        })
    }

    /// Drops the root key from memory. Other holders of the `Arc` finish their request first.
    fn drop_root(&self) -> ApiResult<()> {
        self.write(|slot| {
            slot.root = None;
            slot.unsealed_by = None;
        })
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.gate.lock().await
    }

    /// A permit to run one key derivation, or `kdf_busy` straight away when one is running.
    pub fn kdf_permit(&self) -> ApiResult<OwnedSemaphorePermit> {
        self.kdf.clone().try_acquire_owned().map_err(|_| ApiError::kdf_busy())
    }

    /// A permit to run one key derivation, waiting for the one running to finish.
    pub async fn kdf_permit_queued(&self) -> ApiResult<OwnedSemaphorePermit> {
        self.kdf
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ApiError::internal("keyring", "derivation permits closed"))
    }

    /// Held while writing anything encrypted under the root key or a project's data key.
    pub async fn writing(&self) -> RwLockReadGuard<'_, ()> {
        self.rekey.read().await
    }

    /// Waits for writes in progress, but not forever: a stuck request fails the rotation cleanly
    /// rather than holding every other writer up behind it.
    async fn rekeying(&self) -> ApiResult<RwLockWriteGuard<'_, ()>> {
        tokio::time::timeout(REKEY_WAIT, self.rekey.write())
            .await
            .map_err(|_| ApiError::rekey_busy())
    }

    /// Refuses when the database's root key is not the one in memory, as after the key was
    /// rotated on the host while this server ran. Checked before writing under the root key.
    pub async fn check_fingerprint(&self, store: &dyn Store) -> ApiResult<()> {
        let root = self.root()?;
        match store.get_meta(ROOT_KEY_META).await? {
            Some(stored) if stored == root.fingerprint() => Ok(()),
            _ => Err(ApiError::root_key_changed()),
        }
    }
}

/// The unlock policy in force: configuration wins over the database.
pub fn effective_policy(settings: &SealSettings, keyring: &Keyring) -> UnlockPolicy {
    settings.unlock.unwrap_or_else(|| keyring.stored_policy())
}

/// What anyone may see: the state, and before setup what configuration has already decided.
pub fn public_status(settings: &SealSettings, keyring: &Keyring) -> SysStatus {
    let state = keyring.state();
    if state == SealState::Uninitialised {
        return status(settings, keyring);
    }
    SysStatus {
        state,
        seal_mode: None,
        unlock_policy: None,
        configured: false,
        remembered: false,
        unsealed_by: None,
        web_setup: settings.web_setup,
        version: sekret_core::VERSION.to_string(),
    }
}

/// Everything, for organisation admins.
pub fn status(settings: &SealSettings, keyring: &Keyring) -> SysStatus {
    let state = keyring.state();
    if state == SealState::Uninitialised {
        // Before setup, show what configuration has already decided so the wizard can skip it.
        let passphrase = settings.mode != Some(SealMode::KeyFile);
        return SysStatus {
            state,
            seal_mode: settings.mode,
            unlock_policy: settings.unlock.filter(|_| passphrase),
            configured: settings.unlock.is_some(),
            remembered: false,
            unsealed_by: None,
            web_setup: settings.web_setup,
            version: sekret_core::VERSION.to_string(),
        };
    }
    let mode = keyring.mode();
    let passphrase = mode == Some(SealMode::Passphrase);
    let remember_file_present = settings
        .remember_file
        .as_deref()
        .is_some_and(|path| path.symlink_metadata().is_ok());
    SysStatus {
        state,
        seal_mode: mode,
        unlock_policy: passphrase.then(|| effective_policy(settings, keyring)),
        configured: settings.unlock.is_some(),
        remembered: passphrase && keyring.remembered() && remember_file_present,
        unsealed_by: keyring.unsealed_by(),
        web_setup: settings.web_setup,
        version: sekret_core::VERSION.to_string(),
    }
}

fn binding<'a>(fingerprint: &'a str, config: &'a SealConfig) -> SealBinding<'a> {
    SealBinding {
        mode: config.mode,
        policy: config.unlock_policy,
        fingerprint,
        epoch: config.epoch,
        wrapped: config.wrapped.as_ref(),
        remembered: config.remembered.as_deref(),
    }
}

/// Moves the configuration to its next epoch and signs it with `root`.
pub fn signed(root: &RootKey, mut config: SealConfig) -> Result<SealConfig, CryptoError> {
    config.epoch += 1;
    let fingerprint = root.fingerprint();
    config.mac = Some(seal_config_mac(root, &binding(&fingerprint, &config))?);
    Ok(config)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Valid,
    /// Written before configurations were signed, and grants no unlock without a person.
    Missing,
    /// Changed by something that did not hold the root key.
    Invalid,
}

/// Whether a configuration lets the server unlock without a person: a remembered wrap or a
/// policy other than `manual`.
fn grants_unlock(config: &SealConfig) -> bool {
    config.unlock_policy != UnlockPolicy::Manual || config.remembered.is_some()
}

/// A missing signature is only accepted from a configuration that grants nothing; otherwise
/// clearing the signature would launder whatever a database writer put there.
pub fn check_signature(root: &RootKey, config: &SealConfig) -> Signature {
    let Some(mac) = &config.mac else {
        if grants_unlock(config) {
            return Signature::Invalid;
        }
        return Signature::Missing;
    };
    let fingerprint = root.fingerprint();
    match verify_seal_config(root, &binding(&fingerprint, config), mac) {
        Ok(()) => Signature::Valid,
        Err(_) => Signature::Invalid,
    }
}

/// The highest seal configuration epoch recorded outside the database.
pub fn high_water(paths: &[PathBuf]) -> Option<i64> {
    paths
        .iter()
        .filter_map(|path| match read_epoch(path) {
            Ok(epoch) => epoch,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "ignoring an unreadable seal epoch file");
                None
            }
        })
        .max()
}

/// Records `epoch` as the high-water mark beside each file. Marks are only raised, except when
/// `reset`, which a fresh setup uses so files left by an older install do not count against it.
pub fn record_epoch(paths: &[PathBuf], epoch: i64, reset: bool) {
    for path in paths {
        if !reset && matches!(read_epoch(path), Ok(Some(existing)) if existing >= epoch) {
            continue;
        }
        if let Err(error) = write_epoch(path, epoch) {
            tracing::warn!(%error, path = %path.display(), "could not record the seal configuration epoch");
        }
    }
}

/// Signs and stores a changed configuration, and raises the epoch marks.
async fn save(
    store: &dyn Store,
    settings: &SealSettings,
    root: &RootKey,
    now: i64,
    mut config: SealConfig,
) -> ApiResult<SealConfig> {
    config.updated_at = now;
    let config = signed(root, config)?;
    store.update_seal_config(config.clone()).await?;
    record_epoch(&settings.epoch_files, config.epoch, false);
    Ok(config)
}

/// Writes an audit entry for something the server did on its own behalf.
pub async fn audit_system(store: &dyn Store, now: i64, ip: &str, action: &str, detail: serde_json::Value) {
    audit_as(store, now, ip, "system", action, detail).await;
}

/// Writes an audit entry under a named system actor, such as `remember` for an unlock at start.
pub async fn audit_as(store: &dyn Store, now: i64, ip: &str, actor: &str, action: &str, detail: serde_json::Value) {
    let entry = AuditEntry {
        id: uuid::Uuid::now_v7().to_string(),
        created_at: now,
        actor_kind: "identity".into(),
        actor_id: actor.into(),
        actor_name: format!("identity:{actor}"),
        action: action.to_string(),
        project_id: None,
        environment: None,
        path: None,
        secret_key: None,
        detail,
        ip: ip.to_string(),
    };
    if let Err(error) = store.insert_audit(entry).await {
        tracing::error!(%error, action, "failed to write audit entry");
    }
}

/// A stored configuration after checking it with the root key just recovered.
pub struct Checked {
    pub config: SealConfig,
    pub tampered: bool,
}

/// Verifies the seal configuration once the root key is known. An unsigned one that grants
/// nothing, from before signing existed, is signed now. One whose signature fails, or that is
/// older than the epoch recorded outside the database, was changed by a database writer: it falls
/// back to the `manual` policy with nothing remembered, is signed again and audited.
pub async fn check_config(
    store: &dyn Store,
    settings: &SealSettings,
    now: i64,
    ip: &str,
    root: &RootKey,
    mut config: SealConfig,
) -> ApiResult<Checked> {
    let signature = check_signature(root, &config);
    let high_water = high_water(&settings.epoch_files);
    let rolled_back = signature == Signature::Valid && high_water.is_some_and(|mark| config.epoch < mark);
    match (signature, rolled_back) {
        (Signature::Valid, false) => {
            record_epoch(&settings.epoch_files, config.epoch, false);
            Ok(Checked {
                config,
                tampered: false,
            })
        }
        (Signature::Missing, _) => {
            let config = save(store, settings, root, now, config).await?;
            tracing::info!("signed the seal configuration");
            Ok(Checked {
                config,
                tampered: false,
            })
        }
        (Signature::Invalid, _) | (Signature::Valid, true) => {
            let action = if rolled_back {
                tracing::error!(
                    epoch = config.epoch,
                    recorded = high_water,
                    "the seal configuration is older than the one last seen; it was put back from an earlier copy. \
                     Using the manual unlock policy and forgetting any remembered unlock"
                );
                "sys.seal_config.rolled_back"
            } else {
                tracing::error!(
                    "the seal configuration was changed without the root key; using the manual unlock policy and \
                     forgetting any remembered unlock"
                );
                "sys.seal_config.tampered"
            };
            if let Some(path) = &settings.remember_file
                && let Err(error) = remove_device_key_file(path)
            {
                tracing::warn!(%error, "could not remove the remember file");
            }
            config.unlock_policy = UnlockPolicy::Manual;
            config.remembered = None;
            // Past the mark, so the reset itself is not taken for a rollback next time.
            config.epoch = config.epoch.max(high_water.unwrap_or(0));
            let config = save(store, settings, root, now, config).await?;
            audit_system(store, now, ip, action, serde_json::json!({})).await;
            Ok(Checked { config, tampered: true })
        }
    }
}

/// The stored configuration, checked with `root` before anything is changed and saved again, so
/// a change made by a database writer is never signed as if the server had made it.
async fn load_checked(
    store: &dyn Store,
    settings: &SealSettings,
    now: i64,
    ip: &str,
    root: &RootKey,
) -> ApiResult<Checked> {
    let config = store.get_seal_config().await?.ok_or_else(ApiError::uninitialised)?;
    check_config(store, settings, now, ip, root, config).await
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("the server is already initialised")]
    AlreadyInitialised,
    #[error(transparent)]
    Passphrase(#[from] PassphraseError),
    #[error("passphrase mode needs a passphrase")]
    MissingPassphrase,
    #[error(
        "key-file mode needs a root key file path; start the server with --root-key-file pointing at a file that does not exist yet"
    )]
    NoKeyFilePath,
    #[error("{0} already exists; key-file setup writes a new key and will not replace one")]
    KeyFileExists(PathBuf),
    #[error("this database already holds data under another root key; start the server with that root key")]
    ExistingData,
    #[error("writing {path}: {error}")]
    Io { path: PathBuf, error: std::io::Error },
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Store(StoreError),
    #[error("{0}")]
    Api(String),
}

impl From<StoreError> for InitError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict => InitError::AlreadyInitialised,
            other => InitError::Store(other),
        }
    }
}

impl From<InitError> for ApiError {
    fn from(error: InitError) -> Self {
        match error {
            InitError::AlreadyInitialised => ApiError::conflict(error.to_string()),
            InitError::Passphrase(error) => ApiError::weak_passphrase(error),
            InitError::MissingPassphrase
            | InitError::NoKeyFilePath
            | InitError::KeyFileExists(_)
            | InitError::ExistingData => ApiError::bad_request(error.to_string()),
            InitError::Io { .. } => ApiError::internal("writing the root key file", error),
            InitError::Crypto(error) => error.into(),
            InitError::Store(error) => error.into(),
            InitError::Api(message) => ApiError::internal("setup", message),
        }
    }
}

/// What first-boot setup should create.
pub struct InitPlan {
    pub mode: SealMode,
    pub passphrase: Option<Zeroizing<String>>,
    /// The policy in force: configuration's when it sets one, else the one asked for.
    pub unlock_policy: UnlockPolicy,
    pub key_file: Option<PathBuf>,
    /// Use a key file that is already there instead of refusing; for unattended setup.
    pub reuse_key_file: bool,
    /// Where to start the epoch marks.
    pub epoch_files: Vec<PathBuf>,
}

/// Whether the database holds anything a new root key could not read.
async fn holds_data(store: &dyn Store) -> Result<bool, StoreError> {
    Ok(!store.list_projects().await?.is_empty() || !store.list_identities().await?.is_empty())
}

/// Creates the root key and records how it is protected, signed. The caller holds the keyring
/// gate, and passes a derivation permit when one is in use.
pub async fn initialise(
    store: &dyn Store,
    now: i64,
    plan: InitPlan,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<(Arc<RootKey>, SealConfig), InitError> {
    if store.get_seal_config().await?.is_some() {
        return Err(InitError::AlreadyInitialised);
    }
    let existing = store.get_meta(ROOT_KEY_META).await?;
    if holds_data(store).await? && existing.is_none() {
        return Err(InitError::ExistingData);
    }
    let mut config = SealConfig {
        mode: plan.mode,
        wrapped: None,
        unlock_policy: UnlockPolicy::Manual,
        remembered: None,
        epoch: 0,
        mac: None,
        created_at: now,
        updated_at: now,
    };
    let (root, written) = match plan.mode {
        SealMode::Passphrase => {
            let passphrase = plan.passphrase.ok_or(InitError::MissingPassphrase)?;
            validate_passphrase(&passphrase)?;
            if existing.is_some() {
                return Err(InitError::ExistingData);
            }
            let root = Arc::new(RootKey::generate()?);
            config.wrapped = Some(wrap_blocking(root.clone(), passphrase, permit).await?);
            config.unlock_policy = plan.unlock_policy;
            (root, None)
        }
        SealMode::KeyFile => {
            let path = plan.key_file.ok_or(InitError::NoKeyFilePath)?;
            let (root, written) = key_file_root(&path, plan.reuse_key_file, existing.as_deref())?;
            (Arc::new(root), written)
        }
    };
    let config = signed(&root, config)?;
    if let Err(error) = store.init_seal_config(config.clone(), &root.fingerprint()).await {
        if let Some(path) = written {
            let _ = std::fs::remove_file(&path);
        }
        return Err(error.into());
    }
    record_epoch(&plan.epoch_files, config.epoch, true);
    Ok((root, config))
}

/// The key-file root key, and the path when this call created the file.
fn key_file_root(path: &Path, reuse: bool, existing: Option<&str>) -> Result<(RootKey, Option<PathBuf>), InitError> {
    let io = |error| InitError::Io {
        path: path.to_path_buf(),
        error,
    };
    if path.symlink_metadata().is_ok() {
        if !reuse {
            return Err(InitError::KeyFileExists(path.to_path_buf()));
        }
        let root = RootKey::parse(&read_key_material(path).map_err(io)?)?;
        if existing.is_some_and(|fp| fp != root.fingerprint()) {
            return Err(InitError::ExistingData);
        }
        return Ok((root, None));
    }
    if existing.is_some() {
        return Err(InitError::ExistingData);
    }
    let root = RootKey::generate()?;
    write_new_private(path, root.to_key_file_text().as_bytes()).map_err(io)?;
    Ok((root, Some(path.to_path_buf())))
}

/// Runs Argon2 off the async workers, holding `permit` until the derivation itself finishes.
pub async fn wrap_blocking(
    root: Arc<RootKey>,
    passphrase: Zeroizing<String>,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<WrappedRootKey, CryptoError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        wrap_root_key(&root, &passphrase)
    })
    .await
    .map_err(|_| CryptoError::Kdf)?
}

/// Runs Argon2 off the async workers, holding `permit` until the derivation itself finishes.
pub async fn unwrap_blocking(
    wrapped: WrappedRootKey,
    passphrase: Zeroizing<String>,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<Unwrapped, CryptoError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        unwrap_root_key_checked(&wrapped, &passphrase)
    })
    .await
    .map_err(|_| CryptoError::Kdf)?
}

/// Secrets the server reads once at start, outside its configuration.
#[derive(Default)]
pub struct StartupSecrets {
    /// For the `passphrase-file` policy, from a file or `SEKRET_UNLOCK_PASSPHRASE`.
    pub unlock_passphrase: Option<Zeroizing<String>>,
    /// Set to initialise an empty database without a person.
    pub auto_init: Option<AutoInit>,
}

pub struct AutoInit {
    /// The first passphrase in passphrase mode, from `setup.passphrase_file`. Under the
    /// `passphrase-file` policy the unlock passphrase is used when absent.
    pub passphrase: Option<Zeroizing<String>>,
}

pub struct Opened {
    pub keyring: Keyring,
    /// This start initialised the database, so a break-glass token may be wanted.
    pub auto_initialised: bool,
}

/// Follows symlinks, unlike the remember file, because Kubernetes mounts secrets through them.
fn read_key_material(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    read_limited(path, SECRET_FILE_LIMIT)
}

fn read_key_file(path: &Path) -> Result<Option<RootKey>, StartupError> {
    match read_key_material(path) {
        Ok(material) => {
            Ok(Some(RootKey::parse(&material).map_err(|e| {
                StartupError::KeyFile(format!("{}: {e}", path.display()))
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StartupError::KeyFile(format!("{}: {error}", path.display()))),
    }
}

fn startup(error: ApiError) -> StartupError {
    StartupError::Init(error.message)
}

/// Records an unlock that happened without anyone entering the passphrase.
async fn audit_unlock_at_start(store: &dyn Store, now: i64, by: UnsealedBy) {
    let actor = match by {
        UnsealedBy::Remember => "remember",
        UnsealedBy::PassphraseFile => "passphrase-file",
        UnsealedBy::KeyFile => "key-file",
        UnsealedBy::Passphrase => "unseal",
    };
    audit_as(
        store,
        now,
        LOCAL,
        actor,
        "sys.unseal",
        serde_json::json!({"at_start": true}),
    )
    .await;
}

/// Decides how the server starts from what the database and configuration hold.
pub async fn open_keyring(
    store: &dyn Store,
    now: i64,
    settings: &SealSettings,
    secrets: StartupSecrets,
) -> Result<Opened, StartupError> {
    let key = match &settings.root_key_file {
        Some(path) => read_key_file(path)?,
        None => None,
    };
    let opened = |keyring| Opened {
        keyring,
        auto_initialised: false,
    };
    if let Some(config) = store.get_seal_config().await? {
        check_mode(settings, config.mode)?;
        return match (config.mode, key) {
            (mode, Some(key)) => {
                check_root_key(store, &key.fingerprint()).await?;
                if mode == SealMode::Passphrase {
                    tracing::warn!("started unsealed from the root key file; this database is in passphrase mode");
                }
                let checked = check_config(store, settings, now, LOCAL, &key, config)
                    .await
                    .map_err(startup)?;
                crate::machine::migrate_reviewer_tokens(store, &key).await;
                let keyring = Keyring::unsealed(key, SealMode::KeyFile);
                keyring
                    .install(keyring.root().map_err(startup)?, &checked.config, UnsealedBy::KeyFile)
                    .map_err(startup)?;
                audit_unlock_at_start(store, now, UnsealedBy::KeyFile).await;
                Ok(opened(keyring))
            }
            (SealMode::KeyFile, None) => Err(StartupError::MissingRootKey),
            (SealMode::Passphrase, None) => {
                let keyring = Keyring::sealed(config.unlock_policy, config.remembered.is_some());
                unlock_at_start(store, now, settings, &keyring, config, secrets.unlock_passphrase).await?;
                Ok(opened(keyring))
            }
        };
    }
    let has_root = store.get_meta(ROOT_KEY_META).await?.is_some();
    match secrets.auto_init {
        Some(_) if has_root => {
            tracing::info!("the database already has a root key, so automatic setup is skipped");
        }
        Some(auto) => return auto_initialise(store, now, settings, auto, secrets.unlock_passphrase).await,
        None => {}
    }
    if let Some(key) = key {
        // An install from before sealing existed, or a test: record key-file mode and carry on.
        // The mode is checked first, so a refused start leaves the database as it was.
        check_mode(settings, SealMode::KeyFile)?;
        let fingerprint = key.fingerprint();
        check_root_key(store, &fingerprint).await?;
        let config = SealConfig {
            mode: SealMode::KeyFile,
            wrapped: None,
            unlock_policy: UnlockPolicy::Manual,
            remembered: None,
            epoch: 0,
            mac: None,
            created_at: now,
            updated_at: now,
        };
        let config = signed(&key, config).map_err(|e| StartupError::Init(e.to_string()))?;
        match store.init_seal_config(config.clone(), &fingerprint).await {
            Ok(()) => record_epoch(&settings.epoch_files, config.epoch, true),
            Err(StoreError::Conflict) => {}
            Err(error) => return Err(error.into()),
        }
        crate::machine::migrate_reviewer_tokens(store, &key).await;
        audit_unlock_at_start(store, now, UnsealedBy::KeyFile).await;
        return Ok(opened(Keyring::unsealed(key, SealMode::KeyFile)));
    }
    if has_root {
        return Err(StartupError::MissingRootKey);
    }
    // Without web setup nobody could use a code, so none is made or shown.
    let code = match settings.web_setup {
        true => Some(generate_setup_code().map_err(|e| StartupError::Init(e.to_string()))?),
        false => None,
    };
    Ok(opened(Keyring::uninitialised(code)))
}

async fn auto_initialise(
    store: &dyn Store,
    now: i64,
    settings: &SealSettings,
    auto: AutoInit,
    unlock_passphrase: Option<Zeroizing<String>>,
) -> Result<Opened, StartupError> {
    let mode = settings.mode.unwrap_or(SealMode::Passphrase);
    let unlock_policy = settings.unlock.unwrap_or_default();
    if mode == SealMode::Passphrase && unlock_policy == UnlockPolicy::Remember && settings.remember_file.is_none() {
        return Err(StartupError::Init(
            "the remember policy needs seal.remember_file to be set".into(),
        ));
    }
    // The unlock passphrase only stands in under the policy that keeps it anyway.
    let fallback = unlock_passphrase.filter(|_| unlock_policy == UnlockPolicy::PassphraseFile);
    let passphrase = auto.passphrase.or(fallback);
    if mode == SealMode::Passphrase && passphrase.is_none() {
        return Err(StartupError::Init(
            "automatic setup in passphrase mode needs setup.passphrase_file (or, with the passphrase-file unlock \
             policy, seal.passphrase_file or SEKRET_UNLOCK_PASSPHRASE)"
                .into(),
        ));
    }
    let plan = InitPlan {
        mode,
        passphrase,
        unlock_policy,
        key_file: settings.root_key_file.clone(),
        reuse_key_file: true,
        epoch_files: settings.epoch_files.clone(),
    };
    let (root, config) = initialise(store, now, plan, None)
        .await
        .map_err(|e| StartupError::Init(e.to_string()))?;
    let keyring = Keyring::unsealed_shared(root, mode);
    keyring.record(&config).map_err(startup)?;
    if mode == SealMode::Passphrase
        && let Err(error) = remember_after_unlock(store, now, settings, &keyring).await
    {
        tracing::warn!(error = %error.message, "could not remember the unlock");
    }
    audit_system(
        store,
        now,
        LOCAL,
        "sys.init",
        serde_json::json!({"mode": mode.as_str(), "automatic": true}),
    )
    .await;
    tracing::info!(mode = mode.as_str(), "initialised automatically");
    Ok(Opened {
        keyring,
        auto_initialised: true,
    })
}

fn check_mode(settings: &SealSettings, stored: SealMode) -> Result<(), StartupError> {
    match settings.mode {
        Some(configured) if configured != stored => Err(StartupError::ModeConflict {
            configured: configured.as_str(),
            stored: stored.as_str(),
        }),
        _ => Ok(()),
    }
}

/// Applies the `remember` or `passphrase-file` policy. Failing to unlock leaves the server sealed.
async fn unlock_at_start(
    store: &dyn Store,
    now: i64,
    settings: &SealSettings,
    keyring: &Keyring,
    config: SealConfig,
    passphrase: Option<Zeroizing<String>>,
) -> Result<(), StartupError> {
    let (root, by, rewrap) = match effective_policy(settings, keyring) {
        UnlockPolicy::Manual => return Ok(()),
        UnlockPolicy::PassphraseFile => {
            let Some(passphrase) = passphrase else {
                tracing::warn!(
                    "unlock policy is passphrase-file but no passphrase file or SEKRET_UNLOCK_PASSPHRASE was given; staying sealed"
                );
                return Ok(());
            };
            let Some(wrapped) = config.wrapped.clone() else {
                return Err(StartupError::Init("passphrase mode without a wrapped root key".into()));
            };
            let permit = keyring.kdf_permit().ok();
            match unwrap_blocking(wrapped, passphrase.clone(), permit).await {
                Ok(opened) => (
                    opened.root,
                    UnsealedBy::PassphraseFile,
                    Some((passphrase, opened.needs_rewrap)),
                ),
                Err(error) => {
                    tracing::warn!(%error, "the unlock passphrase did not open the root key; staying sealed");
                    return Ok(());
                }
            }
        }
        UnlockPolicy::Remember => match recall(settings, &config) {
            Ok(root) => (root, UnsealedBy::Remember, None),
            Err(reason) => {
                tracing::warn!(%reason, "not unlocking from the remember file; staying sealed");
                return Ok(());
            }
        },
    };
    check_root_key(store, &root.fingerprint()).await?;
    let checked = check_config(store, settings, now, LOCAL, &root, config)
        .await
        .map_err(startup)?;
    keyring.record(&checked.config).map_err(startup)?;
    if checked.tampered {
        tracing::error!("not unlocking automatically after the seal configuration was tampered with; unlock by hand");
        return Ok(());
    }
    crate::machine::migrate_reviewer_tokens(store, &root).await;
    let root = Arc::new(root);
    keyring.install(root.clone(), &checked.config, by).map_err(startup)?;
    audit_unlock_at_start(store, now, by).await;
    tracing::info!("unlocked at start");
    if let Some((passphrase, force)) = rewrap {
        upgrade_wrap(store, settings, now, keyring, &root, passphrase, force).await;
    }
    Ok(())
}

/// Re-wraps the root key when the stored wrap is cheaper than today's Argon2 cost, or when
/// `force`, as for a wrap made before passphrases were normalised. Best effort.
async fn upgrade_wrap(
    store: &dyn Store,
    settings: &SealSettings,
    now: i64,
    keyring: &Keyring,
    root: &Arc<RootKey>,
    passphrase: Zeroizing<String>,
    force: bool,
) {
    let result: ApiResult<bool> = async {
        let config = load_checked(store, settings, now, LOCAL, root).await?.config;
        let cheap = config.wrapped.as_ref().is_some_and(|w| w.params.needs_upgrade());
        if config.wrapped.is_none() || !(cheap || force) {
            return Ok(false);
        }
        let permit = keyring.kdf_permit_queued().await?;
        let wrapped = wrap_blocking(root.clone(), passphrase, Some(permit)).await?;
        let config = SealConfig {
            wrapped: Some(wrapped),
            ..config
        };
        let config = save(store, settings, root, now, config).await?;
        keyring.record(&config)?;
        Ok(true)
    }
    .await;
    match result {
        Ok(true) => tracing::info!("re-wrapped the root key"),
        Ok(false) => {}
        Err(error) => tracing::warn!(error = %error.message, "could not re-wrap the root key"),
    }
}

fn recall(settings: &SealSettings, config: &SealConfig) -> Result<RootKey, String> {
    let Some(remembered) = &config.remembered else {
        return Err("nothing is remembered yet; the next manual unlock remembers it".into());
    };
    let Some(path) = &settings.remember_file else {
        return Err("no remember file is configured".into());
    };
    let material = read_private(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let device = DeviceKey::parse(&material).map_err(|e| format!("{}: {e}", path.display()))?;
    let secret = settings.remember_secret.as_ref();
    recall_root_key(remembered, &device, secret).map_err(|_| match secret {
        Some(_) => format!(
            "{} does not belong to this server, was changed, or the remember secret is wrong",
            path.display()
        ),
        None => format!(
            "{} does not belong to this server or was changed; if it was made with a remember secret, configure it",
            path.display()
        ),
    })
}

/// After a manual unlock under the `remember` policy, writes a fresh device key and its wrap.
/// The caller holds the keyring gate.
pub async fn remember_after_unlock(
    store: &dyn Store,
    now: i64,
    settings: &SealSettings,
    keyring: &Keyring,
) -> ApiResult<()> {
    if effective_policy(settings, keyring) != UnlockPolicy::Remember {
        return Ok(());
    }
    let Some(path) = &settings.remember_file else {
        tracing::warn!("unlock policy is remember but no remember file is configured; set seal.remember_file");
        return Ok(());
    };
    let root = keyring.root()?;
    let mut config = load_checked(store, settings, now, LOCAL, &root).await?.config;
    if config.remembered.is_some() && recall(settings, &config).is_ok() {
        return Ok(());
    }
    let device = DeviceKey::generate()?;
    remove_device_key_file(path).map_err(|e| ApiError::internal("removing the old remember file", e))?;
    write_new_private(path, device.to_key_file_text().as_bytes())
        .map_err(|e| ApiError::internal("writing the remember file", e))?;
    config.remembered = Some(remember_root_key(&root, &device, settings.remember_secret.as_ref())?);
    let config = save(store, settings, &root, now, config).await?;
    keyring.record(&config)?;
    tracing::info!(path = %path.display(), "remembered the unlock for later starts");
    Ok(())
}

/// Deletes the remember file and the database wrap. The caller holds the keyring gate. Dropping
/// the wrap is what matters, so a file that cannot be removed is only logged.
pub async fn forget(store: &dyn Store, now: i64, settings: &SealSettings, keyring: &Keyring) -> ApiResult<()> {
    if let Some(path) = &settings.remember_file
        && let Err(error) = remove_device_key_file(path)
    {
        tracing::warn!(%error, "could not remove the remember file");
    }
    let root = keyring.root()?;
    let mut config = load_checked(store, settings, now, LOCAL, &root).await?.config;
    if config.remembered.is_none() {
        return Ok(());
    }
    config.remembered = None;
    let config = save(store, settings, &root, now, config).await?;
    keyring.record(&config)
}

/// Request-level operations on the keyring, shared by the API handlers and the host socket.
pub mod ops {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};

    use serde_json::json;

    use super::*;
    use crate::api::{AuditTarget, audit};
    use crate::auth::Principal;
    use crate::state::AppState;

    /// Where an attempt came from. The host socket is reached only through file permissions,
    /// so it is not held back by the network's rate limits and back-off.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Source {
        Network(IpAddr),
        HostSocket,
    }

    impl Source {
        pub fn ip(self) -> IpAddr {
            match self {
                Source::Network(ip) => ip,
                Source::HostSocket => IpAddr::V4(Ipv4Addr::LOCALHOST),
            }
        }

        fn limited(self) -> bool {
            matches!(self, Source::Network(_))
        }

        fn label(self) -> &'static str {
            match self {
                Source::Network(_) => "network",
                Source::HostSocket => "host-socket",
            }
        }
    }

    /// Runs `work` as a task of its own and waits for it. A client that hangs up then cannot
    /// stop a key change, an install and its audit entry, or a failure count, halfway.
    pub async fn detached<T: Send + 'static>(
        work: impl Future<Output = ApiResult<T>> + Send + 'static,
    ) -> ApiResult<T> {
        tokio::spawn(work)
            .await
            .map_err(|e| ApiError::internal("background task", e))?
    }

    pub fn require_passphrase_mode(state: &AppState) -> ApiResult<()> {
        if state.keyring.mode() != Some(SealMode::Passphrase) {
            return Err(ApiError::conflict("only a server in passphrase mode can do that"));
        }
        Ok(())
    }

    /// Refused before any derivation, so an oversized body costs nothing.
    pub fn check_length(passphrase: &str) -> ApiResult<()> {
        if passphrase.len() > MAX_PASSPHRASE_BYTES {
            return Err(ApiError::bad_request(format!(
                "a passphrase is at most {MAX_PASSPHRASE_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn not_backing_off(state: &AppState, source: Source) -> ApiResult<()> {
        if !source.limited() {
            return Ok(());
        }
        match state.passphrase_backoff.wait(source.ip()) {
            Some(wait) => Err(ApiError::passphrase_backoff(wait)),
            None => Ok(()),
        }
    }

    async fn permit(state: &AppState, source: Source) -> ApiResult<OwnedSemaphorePermit> {
        match source {
            Source::Network(_) => state.keyring.kdf_permit(),
            Source::HostSocket => state.keyring.kdf_permit_queued().await,
        }
    }

    async fn passphrase_config(state: &AppState) -> ApiResult<(SealConfig, WrappedRootKey)> {
        let config = state
            .store
            .get_seal_config()
            .await?
            .ok_or_else(ApiError::uninitialised)?;
        let wrapped = config
            .wrapped
            .clone()
            .ok_or_else(|| ApiError::conflict("only a server in passphrase mode can do that"))?;
        Ok((config, wrapped))
    }

    /// Who to blame for a wrong passphrase, and the audit action that records it.
    struct Failure<'a> {
        principal: &'a Principal,
        action: &'a str,
    }

    /// Unwraps with `passphrase`. A wrong one counts against the source's back-off and is
    /// audited here, inside the detached task, so abandoning the request skips neither.
    async fn open_with(
        state: &AppState,
        source: Source,
        wrapped: WrappedRootKey,
        passphrase: Zeroizing<String>,
        permit: OwnedSemaphorePermit,
        failure: Failure<'_>,
    ) -> ApiResult<Unwrapped> {
        match unwrap_blocking(wrapped, passphrase, Some(permit)).await {
            Ok(opened) => {
                if source.limited() {
                    state.passphrase_backoff.succeeded(source.ip());
                }
                Ok(opened)
            }
            Err(CryptoError::Decrypt) => {
                if source.limited() {
                    state.passphrase_backoff.failed(source.ip());
                }
                let failures = state.passphrase_backoff.failures(source.ip());
                audit(
                    state,
                    failure.principal,
                    source.ip(),
                    failure.action,
                    AuditTarget::default(),
                    json!({"consecutive_failures": failures, "via": source.label()}),
                )
                .await;
                Err(ApiError::invalid_passphrase())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub enum Unsealed {
        Already,
        Now { tampered: bool },
    }

    /// Unseals with the passphrase, audits it, and runs the steps after an unlock. A wrong
    /// passphrase is `invalid_passphrase`. Call it through [`detached`].
    pub async fn unseal(state: &AppState, source: Source, passphrase: Zeroizing<String>) -> ApiResult<Unsealed> {
        check_length(&passphrase)?;
        match state.keyring.state() {
            SealState::Unsealed => return Ok(Unsealed::Already),
            SealState::Uninitialised => return Err(ApiError::uninitialised()),
            SealState::Sealed => {}
        }
        not_backing_off(state, source)?;
        let permit = permit(state, source).await?;
        let _gate = state.keyring.lock().await;
        if state.keyring.state() == SealState::Unsealed {
            return Ok(Unsealed::Already);
        }
        let (config, wrapped) = passphrase_config(state).await?;
        let principal = Principal::system("unseal");
        let failure = Failure {
            principal: &principal,
            action: "sys.unseal.failed",
        };
        let opened = open_with(state, source, wrapped, passphrase.clone(), permit, failure).await?;
        check_root_key(state.store.as_ref(), &opened.root.fingerprint())
            .await
            .map_err(|e| ApiError::internal("root key check", e))?;
        let ip = source.ip().to_string();
        let checked = check_config(
            state.store.as_ref(),
            &state.config.seal,
            state.clock.now(),
            &ip,
            &opened.root,
            config,
        )
        .await?;
        crate::machine::migrate_reviewer_tokens(state.store.as_ref(), &opened.root).await;
        let root = Arc::new(opened.root);
        state
            .keyring
            .install(root.clone(), &checked.config, UnsealedBy::Passphrase)?;
        audit(
            state,
            &principal,
            source.ip(),
            "sys.unseal",
            AuditTarget::default(),
            json!({"via": source.label()}),
        )
        .await;
        after_unlock_locked(state, &root, Some((passphrase, opened.needs_rewrap)), checked.tampered).await;
        Ok(Unsealed::Now {
            tampered: checked.tampered,
        })
    }

    /// The optional steps after an unlock: re-wrapping when the wrap is cheap or predates
    /// normalisation, and remembering the unlock. Neither fails the request. The caller holds
    /// the gate.
    async fn after_unlock_locked(
        state: &AppState,
        root: &Arc<RootKey>,
        rewrap: Option<(Zeroizing<String>, bool)>,
        tampered: bool,
    ) {
        let now = state.clock.now();
        if let Some((passphrase, force)) = rewrap {
            upgrade_wrap(
                state.store.as_ref(),
                &state.config.seal,
                now,
                &state.keyring,
                root,
                passphrase,
                force,
            )
            .await;
        }
        if tampered {
            return;
        }
        if let Err(error) = remember_after_unlock(state.store.as_ref(), now, &state.config.seal, &state.keyring).await {
            tracing::warn!(error = %error.message, "could not remember the unlock");
        }
    }

    /// Drops the root key. Waits for any unlock or passphrase change in progress, so one that
    /// finishes after the seal cannot put a key back.
    pub async fn seal(state: &AppState) -> ApiResult<()> {
        require_passphrase_mode(state)?;
        let _gate = state.keyring.lock().await;
        state.keyring.drop_root()
    }

    /// Replaces the root key under a new passphrase and re-encrypts everything, so the old
    /// passphrase opens nothing in the live database. Returns whether the stored configuration had
    /// been tampered with. Call it through [`detached`].
    pub async fn change_passphrase(
        state: &AppState,
        source: Source,
        principal: &Principal,
        current: Zeroizing<String>,
        new: Zeroizing<String>,
    ) -> ApiResult<bool> {
        require_passphrase_mode(state)?;
        check_length(&current)?;
        check_length(&new)?;
        validate_passphrase(&new).map_err(ApiError::weak_passphrase)?;
        not_backing_off(state, source)?;
        let permit = permit(state, source).await?;
        let _gate = state.keyring.lock().await;
        let (config, wrapped) = passphrase_config(state).await?;
        let failure = Failure {
            principal,
            action: "sys.passphrase.failed",
        };
        let old_root = open_with(state, source, wrapped, current, permit, failure).await?.root;
        check_root_key(state.store.as_ref(), &old_root.fingerprint())
            .await
            .map_err(|e| ApiError::internal("root key check", e))?;
        let now = state.clock.now();
        let ip = source.ip().to_string();
        let settings = &state.config.seal;
        let checked = check_config(state.store.as_ref(), settings, now, &ip, &old_root, config).await?;
        let new_root = Arc::new(RootKey::generate()?);
        let permit = state.keyring.kdf_permit_queued().await?;
        let wrapped = wrap_blocking(new_root.clone(), new, Some(permit)).await?;
        let config = SealConfig {
            wrapped: Some(wrapped),
            remembered: None,
            updated_at: now,
            ..checked.config
        };
        let still_unsealed = {
            let _writers = state.keyring.rekeying().await?;
            crate::admin::rotate_root_key(state.store.as_ref(), &old_root, &new_root, Some(config)).await?;
            state.keyring.replace_root(new_root.clone())?
        };
        if let Some(stored) = state.store.get_seal_config().await? {
            record_epoch(&settings.epoch_files, stored.epoch, false);
            state.keyring.record(&stored)?;
        }
        if let Some(path) = &settings.remember_file
            && let Err(error) = remove_device_key_file(path)
        {
            tracing::warn!(%error, "could not remove the old remember file");
        }
        audit(
            state,
            principal,
            source.ip(),
            "sys.passphrase",
            AuditTarget::default(),
            json!({"root_key_rotated": true}),
        )
        .await;
        if still_unsealed {
            after_unlock_locked(state, &new_root, None, checked.tampered).await;
        }
        Ok(checked.tampered)
    }

    /// `remember` and `passphrase-file` keep the root key or passphrase reachable without a
    /// person, so they need the current passphrase; going back to `manual` does not. Call it
    /// through [`detached`].
    pub async fn set_unlock_policy(
        state: &AppState,
        source: Source,
        principal: &Principal,
        policy: UnlockPolicy,
        passphrase: Option<Zeroizing<String>>,
    ) -> ApiResult<()> {
        require_passphrase_mode(state)?;
        let settings = &state.config.seal;
        if settings.unlock.is_some() {
            return Err(ApiError::conflict(
                "the unlock policy is set in the server configuration; change it there",
            ));
        }
        if policy == UnlockPolicy::Remember && settings.remember_file.is_none() {
            return Err(ApiError::bad_request(
                "the remember policy needs seal.remember_file in the server configuration",
            ));
        }
        let confirm = match policy {
            UnlockPolicy::Manual => None,
            UnlockPolicy::Remember | UnlockPolicy::PassphraseFile => {
                let passphrase = passphrase.ok_or_else(ApiError::passphrase_required)?;
                check_length(&passphrase)?;
                not_backing_off(state, source)?;
                Some((passphrase, permit(state, source).await?))
            }
        };
        let _gate = state.keyring.lock().await;
        let root = state.keyring.root()?;
        let now = state.clock.now();
        let ip = source.ip().to_string();
        let mut config = load_checked(state.store.as_ref(), settings, now, &ip, &root)
            .await?
            .config;
        if let Some((passphrase, permit)) = confirm {
            let wrapped = config
                .wrapped
                .clone()
                .ok_or_else(|| ApiError::conflict("only a server in passphrase mode can do that"))?;
            let failure = Failure {
                principal,
                action: "sys.passphrase.failed",
            };
            let opened = open_with(state, source, wrapped, passphrase, permit, failure).await?;
            if opened.root.fingerprint() != root.fingerprint() {
                return Err(ApiError::invalid_passphrase());
            }
        }
        config.unlock_policy = policy;
        if policy != UnlockPolicy::Remember {
            if let Some(path) = &settings.remember_file
                && let Err(error) = remove_device_key_file(path)
            {
                tracing::warn!(%error, "could not remove the remember file");
            }
            config.remembered = None;
        }
        let config = save(state.store.as_ref(), settings, &root, now, config).await?;
        state.keyring.record(&config)?;
        audit(
            state,
            principal,
            source.ip(),
            "sys.unlock_policy",
            AuditTarget::default(),
            json!({"policy": policy.as_str()}),
        )
        .await;
        after_unlock_locked(state, &root, None, false).await;
        Ok(())
    }

    /// Call it through [`detached`].
    pub async fn forget_unlock(state: &AppState, principal: &Principal, ip: IpAddr) -> ApiResult<()> {
        require_passphrase_mode(state)?;
        let _gate = state.keyring.lock().await;
        forget(
            state.store.as_ref(),
            state.clock.now(),
            &state.config.seal,
            &state.keyring,
        )
        .await?;
        audit(
            state,
            principal,
            ip,
            "sys.forget_unlock",
            AuditTarget::default(),
            json!({}),
        )
        .await;
        Ok(())
    }

    pub fn invalid_setup_code() -> ApiError {
        ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_setup_code",
            "the setup code is wrong; it is in the server log",
        )
    }

    /// What `sys/init` asked for.
    pub struct InitRequest {
        pub setup_code: Zeroizing<String>,
        pub mode: SealMode,
        pub passphrase: Option<Zeroizing<String>>,
        pub unlock_policy: UnlockPolicy,
    }

    /// First-boot setup through the API, audited either way. Returns a break-glass admin token
    /// and when it expires. Call it through [`detached`].
    pub async fn init(state: &AppState, ip: IpAddr, request: InitRequest) -> ApiResult<(String, i64)> {
        let principal = Principal::system("setup");
        let mode = request.mode;
        match init_inner(state, request).await {
            Ok(()) => {}
            Err(error) => {
                // Refusals that cost nothing and say nothing, such as setup being off, are not news.
                if error.code != "conflict" && error.code != "setup_disabled" {
                    audit(
                        state,
                        &principal,
                        ip,
                        "sys.init.failed",
                        AuditTarget::default(),
                        json!({"error": error.code}),
                    )
                    .await;
                }
                return Err(error);
            }
        }
        audit(
            state,
            &principal,
            ip,
            "sys.init",
            AuditTarget::default(),
            json!({"mode": mode.as_str()}),
        )
        .await;
        let token = crate::admin::bootstrap_admin_token(state, INIT_TOKEN_TTL).await?;
        let _gate = state.keyring.lock().await;
        if let Ok(root) = state.keyring.root() {
            after_unlock_locked(state, &root, None, false).await;
        }
        Ok(token)
    }

    const INIT_TOKEN_TTL: i64 = 3600;

    async fn init_inner(state: &AppState, request: InitRequest) -> ApiResult<()> {
        let settings = &state.config.seal;
        if !settings.web_setup {
            return Err(ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "setup_disabled",
                "setup through the API is turned off; stop the server and run `sekret admin init` on the host",
            ));
        }
        let InitRequest {
            setup_code,
            mode,
            passphrase,
            unlock_policy,
        } = request;
        if setup_code.len() > sekret_core::seal::MAX_SETUP_CODE_BYTES {
            return Err(ApiError::bad_request("the setup code is too long"));
        }
        if let Some(passphrase) = &passphrase {
            check_length(passphrase)?;
        }
        // Everything that costs nothing is checked before a derivation permit is taken, so
        // wrong codes cannot keep the permit busy.
        if state.keyring.state() != SealState::Uninitialised {
            return Err(ApiError::conflict("the server is already initialised"));
        }
        if !state.keyring.setup_code_matches(&setup_code) {
            return Err(invalid_setup_code());
        }
        if let Some(configured) = settings.mode
            && configured != mode
        {
            return Err(ApiError::bad_request(format!(
                "this server is configured for {} mode",
                configured.as_str()
            )));
        }
        let policy = settings.unlock.unwrap_or(unlock_policy);
        if mode == SealMode::Passphrase && policy == UnlockPolicy::Remember && settings.remember_file.is_none() {
            return Err(ApiError::bad_request(
                "the remember policy needs seal.remember_file in the server configuration",
            ));
        }
        let permit = match mode {
            SealMode::Passphrase => Some(state.keyring.kdf_permit()?),
            SealMode::KeyFile => None,
        };
        let _gate = state.keyring.lock().await;
        if state.keyring.state() != SealState::Uninitialised {
            return Err(ApiError::conflict("the server is already initialised"));
        }
        let plan = InitPlan {
            mode,
            passphrase,
            unlock_policy: policy,
            key_file: settings.root_key_file.clone(),
            reuse_key_file: false,
            epoch_files: settings.epoch_files.clone(),
        };
        let (root, config) = initialise(state.store.as_ref(), state.clock.now(), plan, permit).await?;
        let by = match mode {
            SealMode::Passphrase => UnsealedBy::Passphrase,
            SealMode::KeyFile => UnsealedBy::KeyFile,
        };
        state.keyring.install(root, &config, by)?;
        if let Some(written) = &settings.setup_code_file
            && let Err(error) = crate::files::remove_if_unchanged(written)
        {
            tracing::warn!(%error, "could not remove the setup code file");
        }
        Ok(())
    }
}
