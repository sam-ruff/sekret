//! The root key's life in memory: first-boot setup, sealing, unlocking and remembered unlocks.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use sekret_api::SysStatus;
use sekret_core::crypto::{CryptoError, RootKey};
use sekret_core::seal::{
    DeviceKey, MAX_PASSPHRASE_BYTES, PassphraseError, SealBinding, SealMode, SealState, UnlockPolicy, UnsealedBy,
    WrappedRootKey, generate_setup_code, recall_root_key, remember_root_key, seal_config_mac, setup_code_matches,
    unwrap_root_key, validate_passphrase, verify_seal_config, wrap_root_key,
};
use sekret_store::{AuditEntry, SealConfig, Store, StoreError};
use tokio::sync::{OwnedSemaphorePermit, RwLockReadGuard, RwLockWriteGuard, Semaphore};
use zeroize::Zeroizing;

use crate::config::SealSettings;
use crate::error::{ApiError, ApiResult};
use crate::files::{SECRET_FILE_LIMIT, read_limited, read_private, remove_device_key_file, write_new_private};
use crate::{ROOT_KEY_META, StartupError, check_root_key};

/// Shown as the address of audit entries written by the server itself.
const LOCAL: &str = "local";

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
    /// Serialises setup, unlocking and changes to the seal configuration.
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

    fn write(&self, f: impl FnOnce(&mut Slot)) -> ApiResult<()> {
        let mut slot = self
            .slot
            .write()
            .map_err(|_| ApiError::internal("keyring", "lock poisoned"))?;
        f(&mut slot);
        Ok(())
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

    fn replace_root(&self, root: Arc<RootKey>) -> ApiResult<()> {
        self.write(|slot| slot.root = Some(root))
    }

    /// Drops the root key from memory. Other holders of the `Arc` finish their request first.
    fn seal(&self) -> ApiResult<()> {
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

    /// Held while writing anything encrypted under the root key or a project's data key.
    pub async fn writing(&self) -> RwLockReadGuard<'_, ()> {
        self.rekey.read().await
    }

    async fn rekeying(&self) -> RwLockWriteGuard<'_, ()> {
        self.rekey.write().await
    }
}

/// The unlock policy in force: configuration wins over the database.
pub fn effective_policy(settings: &SealSettings, keyring: &Keyring) -> UnlockPolicy {
    settings.unlock.unwrap_or_else(|| keyring.stored_policy())
}

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
    /// Written before configurations were signed.
    Missing,
    /// Changed by something that did not hold the root key.
    Invalid,
}

pub fn check_signature(root: &RootKey, config: &SealConfig) -> Signature {
    let Some(mac) = &config.mac else {
        return Signature::Missing;
    };
    let fingerprint = root.fingerprint();
    match verify_seal_config(root, &binding(&fingerprint, config), mac) {
        Ok(()) => Signature::Valid,
        Err(_) => Signature::Invalid,
    }
}

/// Signs and stores a changed configuration.
async fn save(store: &dyn Store, root: &RootKey, now: i64, mut config: SealConfig) -> ApiResult<SealConfig> {
    config.updated_at = now;
    let config = signed(root, config)?;
    store.update_seal_config(config.clone()).await?;
    Ok(config)
}

/// Writes an audit entry for something the server did on its own behalf.
pub async fn audit_system(store: &dyn Store, now: i64, ip: &str, action: &str, detail: serde_json::Value) {
    let entry = AuditEntry {
        id: uuid::Uuid::now_v7().to_string(),
        created_at: now,
        actor_kind: "identity".into(),
        actor_id: "system".into(),
        actor_name: "identity:system".into(),
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

/// Verifies the seal configuration once the root key is known. An unsigned one, from before
/// signing existed, is signed now. One whose signature fails was changed by a database writer:
/// it falls back to the `manual` policy with nothing remembered, is signed again and audited as
/// `sys.seal_config.tampered`.
pub async fn check_config(
    store: &dyn Store,
    settings: &SealSettings,
    now: i64,
    ip: &str,
    root: &RootKey,
    mut config: SealConfig,
) -> ApiResult<Checked> {
    match check_signature(root, &config) {
        Signature::Valid => Ok(Checked {
            config,
            tampered: false,
        }),
        Signature::Missing => {
            // Only the server writes a remembered wrap, so one being there shows remember was chosen.
            if config.unlock_policy == UnlockPolicy::Remember && config.remembered.is_none() {
                tracing::warn!(
                    "the seal configuration predates signing and asks to remember the unlock with nothing \
                     remembered yet; using manual until an admin sets the policy again"
                );
                config.unlock_policy = UnlockPolicy::Manual;
            }
            let config = save(store, root, now, config).await?;
            tracing::info!("signed the seal configuration");
            Ok(Checked {
                config,
                tampered: false,
            })
        }
        Signature::Invalid => {
            tracing::error!(
                "the seal configuration was changed without the root key; using the manual unlock policy and \
                 forgetting any remembered unlock"
            );
            if let Some(path) = &settings.remember_file
                && let Err(error) = remove_device_key_file(path)
            {
                tracing::warn!(%error, "could not remove the remember file");
            }
            config.unlock_policy = UnlockPolicy::Manual;
            config.remembered = None;
            let config = save(store, root, now, config).await?;
            audit_system(store, now, ip, "sys.seal_config.tampered", serde_json::json!({})).await;
            Ok(Checked { config, tampered: true })
        }
    }
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
    pub unlock_policy: UnlockPolicy,
    pub key_file: Option<PathBuf>,
    /// Use a key file that is already there instead of refusing; for unattended setup.
    pub reuse_key_file: bool,
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
    let mut text = root.to_base64();
    text.push('\n');
    write_new_private(path, text.as_bytes()).map_err(io)?;
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
) -> Result<RootKey, CryptoError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        unwrap_root_key(&wrapped, &passphrase)
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
    /// The first passphrase in passphrase mode; the unlock passphrase is used when absent.
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
                let keyring = Keyring::unsealed(key, SealMode::KeyFile);
                keyring
                    .install(keyring.root().map_err(startup)?, &checked.config, UnsealedBy::KeyFile)
                    .map_err(startup)?;
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
        match store.init_seal_config(config, &fingerprint).await {
            Ok(()) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(error.into()),
        }
        check_mode(settings, SealMode::KeyFile)?;
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
    let plan = InitPlan {
        mode,
        passphrase: auto.passphrase.or(unlock_passphrase),
        unlock_policy,
        key_file: settings.root_key_file.clone(),
        reuse_key_file: true,
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
    let (root, by, passphrase) = match effective_policy(settings, keyring) {
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
                Ok(root) => (root, UnsealedBy::PassphraseFile, Some(passphrase)),
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
    let root = Arc::new(root);
    keyring.install(root.clone(), &checked.config, by).map_err(startup)?;
    tracing::info!("unlocked at start");
    if let Some(passphrase) = passphrase {
        upgrade_wrap(store, now, keyring, &root, passphrase).await;
    }
    Ok(())
}

/// Re-wraps the root key at today's Argon2 cost when the stored wrap is cheaper. Best effort.
async fn upgrade_wrap(
    store: &dyn Store,
    now: i64,
    keyring: &Keyring,
    root: &Arc<RootKey>,
    passphrase: Zeroizing<String>,
) {
    let result: ApiResult<bool> = async {
        let Some(config) = store.get_seal_config().await? else {
            return Ok(false);
        };
        if !config.wrapped.as_ref().is_some_and(|w| w.params.needs_upgrade()) {
            return Ok(false);
        }
        let permit = keyring.kdf_permit()?;
        let wrapped = wrap_blocking(root.clone(), passphrase, Some(permit)).await?;
        let config = SealConfig {
            wrapped: Some(wrapped),
            ..config
        };
        let config = save(store, root, now, config).await?;
        keyring.record(&config)?;
        Ok(true)
    }
    .await;
    match result {
        Ok(true) => tracing::info!("re-wrapped the root key at the current key derivation cost"),
        Ok(false) => {}
        Err(error) => tracing::warn!(error = %error.message, "could not re-wrap the root key at the current cost"),
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
    let Some(mut config) = store.get_seal_config().await? else {
        return Err(ApiError::uninitialised());
    };
    if config.remembered.is_some() && recall(settings, &config).is_ok() {
        return Ok(());
    }
    let root = keyring.root()?;
    let device = DeviceKey::generate()?;
    remove_device_key_file(path).map_err(|e| ApiError::internal("removing the old remember file", e))?;
    let mut text = device.to_base64();
    text.push('\n');
    write_new_private(path, text.as_bytes()).map_err(|e| ApiError::internal("writing the remember file", e))?;
    config.remembered = Some(remember_root_key(&root, &device, settings.remember_secret.as_ref())?);
    let config = save(store, &root, now, config).await?;
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
    let Some(mut config) = store.get_seal_config().await? else {
        return Err(ApiError::uninitialised());
    };
    if config.remembered.is_none() {
        return Ok(());
    }
    config.remembered = None;
    let root = keyring.root()?;
    let config = save(store, &root, now, config).await?;
    keyring.record(&config)
}

/// Request-level operations on the keyring, shared by the API handlers.
pub mod ops {
    use super::*;
    use crate::state::AppState;

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

    fn not_backing_off(state: &AppState) -> ApiResult<()> {
        match state.passphrase_backoff.wait() {
            Some(wait) => Err(ApiError::passphrase_backoff(wait)),
            None => Ok(()),
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

    /// Unwraps with `passphrase`, counting a wrong one against the server-wide backoff.
    async fn open_with(
        state: &AppState,
        wrapped: WrappedRootKey,
        passphrase: Zeroizing<String>,
        permit: OwnedSemaphorePermit,
    ) -> ApiResult<RootKey> {
        match unwrap_blocking(wrapped, passphrase, Some(permit)).await {
            Ok(root) => {
                state.passphrase_backoff.succeeded();
                Ok(root)
            }
            Err(CryptoError::Decrypt) => {
                state.passphrase_backoff.failed();
                Err(ApiError::invalid_passphrase())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub enum Unsealed {
        Already,
        Now { tampered: bool },
    }

    /// Unseals with the passphrase. A wrong one is `invalid_passphrase`.
    pub async fn unseal(state: &AppState, ip: &str, passphrase: Zeroizing<String>) -> ApiResult<Unsealed> {
        check_length(&passphrase)?;
        match state.keyring.state() {
            SealState::Unsealed => return Ok(Unsealed::Already),
            SealState::Uninitialised => return Err(ApiError::uninitialised()),
            SealState::Sealed => {}
        }
        not_backing_off(state)?;
        let permit = state.keyring.kdf_permit()?;
        let _gate = state.keyring.lock().await;
        if state.keyring.state() == SealState::Unsealed {
            return Ok(Unsealed::Already);
        }
        let (config, wrapped) = passphrase_config(state).await?;
        let root = open_with(state, wrapped, passphrase, permit).await?;
        check_root_key(state.store.as_ref(), &root.fingerprint())
            .await
            .map_err(|e| ApiError::internal("root key check", e))?;
        let checked = check_config(
            state.store.as_ref(),
            &state.config.seal,
            state.clock.now(),
            ip,
            &root,
            config,
        )
        .await?;
        state
            .keyring
            .install(Arc::new(root), &checked.config, UnsealedBy::Passphrase)?;
        Ok(Unsealed::Now {
            tampered: checked.tampered,
        })
    }

    /// The optional steps after a manual unlock: re-wrapping at today's cost and remembering the
    /// unlock. Neither fails the request.
    pub async fn after_unlock(state: &AppState, passphrase: Option<Zeroizing<String>>, tampered: bool) {
        let _gate = state.keyring.lock().await;
        let now = state.clock.now();
        if let (Some(passphrase), Ok(root)) = (passphrase, state.keyring.root()) {
            upgrade_wrap(state.store.as_ref(), now, &state.keyring, &root, passphrase).await;
        }
        if tampered {
            return;
        }
        if let Err(error) = remember_after_unlock(state.store.as_ref(), now, &state.config.seal, &state.keyring).await {
            tracing::warn!(error = %error.message, "could not remember the unlock");
        }
    }

    pub fn seal(state: &AppState) -> ApiResult<()> {
        require_passphrase_mode(state)?;
        state.keyring.seal()
    }

    /// Replaces the root key under a new passphrase and re-encrypts everything, so the old
    /// passphrase opens nothing in the live database. Returns whether the stored configuration had
    /// been tampered with.
    pub async fn change_passphrase(
        state: &AppState,
        current: Zeroizing<String>,
        new: Zeroizing<String>,
    ) -> ApiResult<bool> {
        require_passphrase_mode(state)?;
        check_length(&current)?;
        check_length(&new)?;
        validate_passphrase(&new).map_err(ApiError::weak_passphrase)?;
        not_backing_off(state)?;
        let permit = state.keyring.kdf_permit()?;
        let _gate = state.keyring.lock().await;
        let (config, wrapped) = passphrase_config(state).await?;
        let old_root = open_with(state, wrapped, current, permit).await?;
        check_root_key(state.store.as_ref(), &old_root.fingerprint())
            .await
            .map_err(|e| ApiError::internal("root key check", e))?;
        let tampered = check_signature(&old_root, &config) == Signature::Invalid;
        let new_root = Arc::new(RootKey::generate()?);
        let permit = state.keyring.kdf_permit()?;
        let wrapped = wrap_blocking(new_root.clone(), new, Some(permit)).await?;
        let config = SealConfig {
            wrapped: Some(wrapped),
            remembered: None,
            unlock_policy: if tampered {
                UnlockPolicy::Manual
            } else {
                config.unlock_policy
            },
            updated_at: state.clock.now(),
            ..config
        };
        {
            let _writers = state.keyring.rekeying().await;
            crate::admin::rotate_root_key(state.store.as_ref(), &old_root, &new_root, Some(config)).await?;
            state.keyring.replace_root(new_root)?;
        }
        if let Some(stored) = state.store.get_seal_config().await? {
            state.keyring.record(&stored)?;
        }
        if let Some(path) = &state.config.seal.remember_file
            && let Err(error) = remove_device_key_file(path)
        {
            tracing::warn!(%error, "could not remove the old remember file");
        }
        Ok(tampered)
    }

    /// `remember` and `passphrase-file` keep the root key or passphrase reachable without a
    /// person, so they need the current passphrase; going back to `manual` does not.
    pub async fn set_unlock_policy(
        state: &AppState,
        policy: UnlockPolicy,
        passphrase: Option<Zeroizing<String>>,
    ) -> ApiResult<()> {
        require_passphrase_mode(state)?;
        if state.config.seal.unlock.is_some() {
            return Err(ApiError::conflict(
                "the unlock policy is set in the server configuration; change it there",
            ));
        }
        if policy == UnlockPolicy::Remember && state.config.seal.remember_file.is_none() {
            return Err(ApiError::bad_request(
                "the remember policy needs seal.remember_file in the server configuration",
            ));
        }
        let permit = match policy {
            UnlockPolicy::Manual => None,
            UnlockPolicy::Remember | UnlockPolicy::PassphraseFile => {
                let passphrase = passphrase.as_ref().ok_or_else(ApiError::passphrase_required)?;
                check_length(passphrase)?;
                not_backing_off(state)?;
                Some(state.keyring.kdf_permit()?)
            }
        };
        let _gate = state.keyring.lock().await;
        let mut config = state
            .store
            .get_seal_config()
            .await?
            .ok_or_else(ApiError::uninitialised)?;
        let root = state.keyring.root()?;
        if let (Some(permit), Some(passphrase)) = (permit, passphrase) {
            let wrapped = config
                .wrapped
                .clone()
                .ok_or_else(|| ApiError::conflict("only a server in passphrase mode can do that"))?;
            let opened = open_with(state, wrapped, passphrase, permit).await?;
            if opened.fingerprint() != root.fingerprint() {
                return Err(ApiError::invalid_passphrase());
            }
        }
        config.unlock_policy = policy;
        if policy != UnlockPolicy::Remember {
            if let Some(path) = &state.config.seal.remember_file
                && let Err(error) = remove_device_key_file(path)
            {
                tracing::warn!(%error, "could not remove the remember file");
            }
            config.remembered = None;
        }
        let config = save(state.store.as_ref(), &root, state.clock.now(), config).await?;
        state.keyring.record(&config)
    }

    pub async fn forget_unlock(state: &AppState) -> ApiResult<()> {
        require_passphrase_mode(state)?;
        let _gate = state.keyring.lock().await;
        forget(
            state.store.as_ref(),
            state.clock.now(),
            &state.config.seal,
            &state.keyring,
        )
        .await
    }

    pub fn invalid_setup_code() -> ApiError {
        ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_setup_code",
            "the setup code is wrong; it is in the server log",
        )
    }

    /// First-boot setup through the API.
    pub async fn init(
        state: &AppState,
        setup_code: &str,
        mode: SealMode,
        passphrase: Option<Zeroizing<String>>,
        unlock_policy: UnlockPolicy,
    ) -> ApiResult<()> {
        let settings = &state.config.seal;
        if !settings.web_setup {
            return Err(ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "setup_disabled",
                "setup through the API is turned off; run `sekret admin init` on the host",
            ));
        }
        if setup_code.len() > sekret_core::seal::MAX_SETUP_CODE_BYTES {
            return Err(ApiError::bad_request("the setup code is too long"));
        }
        if let Some(passphrase) = &passphrase {
            check_length(passphrase)?;
        }
        let permit = match mode {
            SealMode::Passphrase => Some(state.keyring.kdf_permit()?),
            SealMode::KeyFile => None,
        };
        let _gate = state.keyring.lock().await;
        if state.keyring.state() != SealState::Uninitialised {
            return Err(ApiError::conflict("the server is already initialised"));
        }
        if !state.keyring.setup_code_matches(setup_code) {
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
        let plan = InitPlan {
            mode,
            passphrase,
            unlock_policy,
            key_file: settings.root_key_file.clone(),
            reuse_key_file: false,
        };
        let (root, config) = initialise(state.store.as_ref(), state.clock.now(), plan, permit).await?;
        let by = match mode {
            SealMode::Passphrase => UnsealedBy::Passphrase,
            SealMode::KeyFile => UnsealedBy::KeyFile,
        };
        state.keyring.install(root, &config, by)?;
        if let Some(path) = &settings.setup_code_file
            && let Err(error) = crate::files::remove_if_present(path)
        {
            tracing::warn!(%error, path = %path.display(), "could not remove the setup code file");
        }
        Ok(())
    }
}
