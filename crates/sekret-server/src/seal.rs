//! The root key's life in memory: first-boot setup, sealing, unlocking and remembered unlocks.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use sekret_api::SysStatus;
use sekret_core::crypto::{CryptoError, IntegrityKey, RootKey};
use sekret_core::seal::{
    DeviceKey, MAX_PASSPHRASE_BYTES, PassphraseError, SealBinding, SealFlags, SealMode, SealState, UnlockPolicy,
    UnsealedBy, Unwrapped, WrappedRootKey, generate_setup_code, recall_root_key, remember_root_key, seal_config_mac,
    setup_code_matches, unwrap_root_key_checked, validate_passphrase, verify_seal_config, wrap_root_key,
};
use sekret_store::{AuditEntry, INTEGRITY_KEY_META, SealConfig, Store, StoreError};
use tokio::sync::{OwnedSemaphorePermit, RwLockReadGuard, RwLockWriteGuard, Semaphore};
use zeroize::Zeroizing;

use crate::config::SealSettings;
use crate::error::{ApiError, ApiResult};
use crate::files::{
    EpochMark, SECRET_FILE_LIMIT, read_epoch, read_limited, read_mark, read_private, remove_device_key_file,
    write_mark, write_new_private,
};
use crate::{ROOT_KEY_META, StartupError};

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
    /// Opened from the database on first use while unsealed, and dropped with the root key.
    integrity: Option<Arc<IntegrityKey>>,
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
    /// Host socket attempts waiting for the gate; network attempts give way to them.
    host_waiting: std::sync::atomic::AtomicUsize,
}

impl Keyring {
    fn with(slot: Slot) -> Self {
        Self {
            slot: RwLock::new(slot),
            gate: tokio::sync::Mutex::new(()),
            kdf: Arc::new(Semaphore::new(1)),
            rekey: tokio::sync::RwLock::new(()),
            host_waiting: std::sync::atomic::AtomicUsize::new(0),
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
            integrity: None,
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
            integrity: None,
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
            integrity: None,
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

    /// The mode comes from what opened the key, and from the stored configuration only when
    /// `trusted`, so a database writer's change to the mode never reaches the keyring.
    fn install(&self, root: Arc<RootKey>, config: &SealConfig, by: UnsealedBy, trusted: bool) -> ApiResult<()> {
        let mode = proven_mode(config, by, trusted);
        self.write(|slot| {
            slot.root = Some(root);
            slot.mode = Some(mode);
            slot.policy = config.unlock_policy;
            slot.remembered = config.remembered.is_some();
            slot.setup_code = None;
            slot.unsealed_by = Some(by);
            slot.integrity = None;
        })
    }

    /// The integrity key, opened from the database the first time it is needed while unsealed.
    pub async fn integrity(&self, store: &dyn Store) -> ApiResult<Arc<IntegrityKey>> {
        let root = self.root()?;
        if let Some(key) = self.read(|slot| slot.integrity.clone())? {
            return Ok(key);
        }
        let key = Arc::new(load_integrity_key(store, &root).await?);
        self.write(|slot| match (&slot.root, &slot.integrity) {
            (_, Some(cached)) => Ok(cached.clone()),
            (Some(_), None) => {
                slot.integrity = Some(key.clone());
                Ok(key)
            }
            (None, None) => Err(ApiError::sealed()),
        })?
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
            slot.integrity = None;
        })
    }

    /// The gate serialising unlocks and seal changes. Whoever needs a derivation permit as well
    /// takes the gate first, then the permit, so the two can never deadlock.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.gate.lock().await
    }

    /// The gate, or `None` straight away when someone holds it.
    pub fn try_lock(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.gate.try_lock().ok()
    }

    /// The gate for the host socket, ahead of every network attempt still waiting for it.
    pub async fn lock_for_host(&self) -> tokio::sync::MutexGuard<'_, ()> {
        struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        self.host_waiting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _waiting = Waiting(&self.host_waiting);
        self.gate.lock().await
    }

    /// Whether a host socket attempt is waiting, so a network attempt should step aside.
    pub fn host_waiting(&self) -> bool {
        self.host_waiting.load(std::sync::atomic::Ordering::SeqCst) > 0
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

/// The mode a newly opened key puts the keyring in. See [`Keyring::install`].
fn proven_mode(config: &SealConfig, by: UnsealedBy, trusted: bool) -> SealMode {
    match by {
        UnsealedBy::KeyFile if trusted => config.mode,
        UnsealedBy::KeyFile => SealMode::KeyFile,
        UnsealedBy::Passphrase | UnsealedBy::PassphraseFile | UnsealedBy::Remember => SealMode::Passphrase,
    }
}

/// The integrity key stored under `root`, made and stored first when there is none. Whoever
/// stores one first wins, so two servers or requests never end up with different keys.
pub async fn load_integrity_key(store: &dyn Store, root: &RootKey) -> ApiResult<IntegrityKey> {
    let open = |wrapped: &str| {
        IntegrityKey::unwrap(root, wrapped).map_err(|error| {
            tracing::error!(%error, "the stored integrity key does not open with the root key");
            ApiError::internal(
                "integrity key",
                "the stored integrity key does not open with the root key",
            )
        })
    };
    if let Some(wrapped) = store.get_meta(INTEGRITY_KEY_META).await? {
        return open(&wrapped);
    }
    let key = IntegrityKey::generate()?;
    if store.insert_meta(INTEGRITY_KEY_META, &key.wrap(root)?).await? {
        return Ok(key);
    }
    let wrapped = store
        .get_meta(INTEGRITY_KEY_META)
        .await?
        .ok_or_else(|| ApiError::internal("integrity key", "stored and gone again"))?;
    open(&wrapped)
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
        remember_available: false,
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
            remember_available: passphrase && settings.remember_file.is_some(),
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
        remember_available: passphrase && settings.remember_file.is_some(),
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
        flags: config.flags,
    }
}

/// The epoch after both `epoch` and `floor`, the highest mark recorded outside the database.
pub fn next_epoch(epoch: i64, floor: i64) -> Result<i64, CryptoError> {
    epoch.max(floor).checked_add(1).ok_or(CryptoError::Malformed)
}

/// Moves the configuration past its own epoch and `floor`, then signs it with `root`.
pub fn signed(root: &RootKey, mut config: SealConfig, floor: i64) -> Result<SealConfig, CryptoError> {
    config.epoch = next_epoch(config.epoch, floor)?;
    config.flags.wrap_form_signed = true;
    let fingerprint = root.fingerprint();
    config.mac = Some(seal_config_mac(root, &binding(&fingerprint, &config))?);
    Ok(config)
}

/// The flags for a configuration that is being reset after tampering or a rollback, or signed for
/// the first time: whatever the stored copy says, nothing is migrated again and a remember secret
/// stays required until `forget-unlock`, since the stored flag may have been cleared.
pub fn cautious_flags(flags: SealFlags) -> SealFlags {
    SealFlags {
        reviewer_tokens_migrated: true,
        remember_secret: true,
        wrap_form_signed: flags.wrap_form_signed,
        credentials_keyed: true,
    }
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
    // Nothing can follow the last epoch, so a configuration there could never be changed again.
    if config.epoch == i64::MAX {
        return Signature::Invalid;
    }
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

/// The seal configuration epochs recorded outside the database.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HighWater {
    pub highest: Option<i64>,
    /// A mark exists but is unreadable, malformed or a symlink, so the true mark is unknown.
    pub broken: bool,
    /// There is no mark at all, though one could have been written, so any that existed were
    /// deleted.
    pub absent: bool,
}

impl HighWater {
    /// The lowest epoch the next signed configuration may sit above.
    pub fn floor(self) -> i64 {
        self.highest.unwrap_or(0)
    }

    /// Whether a configuration at `epoch` may be older than one already seen. A broken mark fails
    /// closed: it counts as a rollback.
    pub fn rolled_back(self, epoch: i64) -> bool {
        self.broken || self.highest.is_some_and(|mark| epoch < mark)
    }

    /// Whether marks a configuration says were written are missing. Every configuration signed
    /// since the wrap's form was covered also raised the marks, so one with no mark anywhere a
    /// mark could be written means they were deleted.
    pub fn lost_for(self, config: &SealConfig) -> bool {
        self.absent && config.flags.wrap_form_signed && config.epoch > 0
    }
}

pub fn high_water(paths: &[PathBuf]) -> HighWater {
    let mut marks = HighWater::default();
    for path in paths {
        match read_epoch(path) {
            Ok(Some(epoch)) => marks.highest = Some(marks.highest.map_or(epoch, |m| m.max(epoch))),
            Ok(None) => {}
            Err(error) => {
                tracing::error!(%error, path = %path.display(), "a seal epoch mark cannot be read; treating it as a rollback");
                marks.broken = true;
            }
        }
    }
    // Only probed when nothing was found, which is rare once a server has run.
    if marks.highest.is_none() && !marks.broken {
        marks.absent = paths.iter().any(|path| crate::files::can_create(path).is_ok());
    }
    marks
}

/// The root keys every mark that names any agrees on, as recorded, or `None` when no mark names
/// one: there are no marks, or they were all written before keys were recorded. A mark that
/// cannot be read says nothing here; [`high_water`] already treats it as a rollback.
pub fn accepted_roots(paths: &[PathBuf]) -> Option<Vec<String>> {
    let mut accepted: Option<Vec<String>> = None;
    for path in paths {
        let Ok(Some(mark)) = read_mark(path) else {
            continue;
        };
        if mark.roots.is_empty() {
            continue;
        }
        accepted = Some(match accepted {
            None => mark.roots,
            Some(previous) => previous.into_iter().filter(|r| mark.roots.contains(r)).collect(),
        });
    }
    accepted
}

/// Whether the marks name `root`: `None` when no mark names any key, otherwise whether every
/// mark that names one names this one, by its pin or, in marks from before pins, its fingerprint.
pub fn marks_name(paths: &[PathBuf], root: &RootKey) -> Option<bool> {
    let mut named = None;
    for path in paths {
        let Ok(Some(mark)) = read_mark(path) else {
            continue;
        };
        if mark.roots.is_empty() {
            continue;
        }
        let here = mark.roots.iter().any(|recorded| root.is_named_by(recorded));
        named = Some(named.unwrap_or(true) && here);
    }
    named
}

/// Whether the marks allow a database under `root`.
pub fn root_recognised(paths: &[PathBuf], root: &RootKey) -> bool {
    marks_name(paths, root).unwrap_or(true)
}

/// What the marks record for `root`.
pub fn pin(root: &RootKey) -> std::io::Result<String> {
    root.pin().map_err(std::io::Error::other)
}

/// Whether `root` opens every project's data key, and every stored value under it. A database
/// writer can wrap new data keys under a root key of their own, and sign anything with it, but
/// cannot make the values already stored decrypt under those keys. To get a key of their own
/// past this they would have to delete every stored value, which cannot go unnoticed. Without
/// `values`, only the data keys are checked, for an operator adopting a key on the host.
async fn opens_existing_data(store: &dyn Store, root: &RootKey, values: bool) -> Result<bool, StoreError> {
    use sekret_core::crypto::{ValueContext, decrypt_value, unwrap_data_key};
    for project in store.list_projects().await? {
        let Ok(key) = unwrap_data_key(root, &project.wrapped_key, &project.id) else {
            return Ok(false);
        };
        if !values {
            continue;
        }
        for value in store.list_encrypted_values(&project.id).await? {
            let ctx = ValueContext {
                project_id: &project.id,
                secret_id: &value.secret_id,
                version: value.version,
            };
            if decrypt_value(&key, &value.value, ctx).is_err() {
                tracing::error!(
                    project = %project.id,
                    secret = %value.secret_id,
                    version = value.version,
                    "a stored value does not decrypt under this root key"
                );
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Refuses a root key that does not match the database's fingerprint, then one the epoch marks
/// outside the database do not name. Where no mark names it, every project key and every stored
/// value must open with it. The fingerprint is recorded only when the database has none and the
/// key passed. A database writer can change everything the database holds, but not the marks or
/// the values already encrypted, so swapping in a root key of their own fails here unless they
/// also delete every stored value.
pub async fn check_root(store: &dyn Store, epoch_files: &[PathBuf], root: &RootKey) -> Result<(), StartupError> {
    check_root_against(store, root, Some(epoch_files)).await
}

/// [`check_root`] without the marks, for the host command that adopts a new root key.
pub async fn check_database_root(store: &dyn Store, root: &RootKey) -> Result<(), StartupError> {
    check_root_against(store, root, None).await
}

/// A key that is simply not this database's is `WrongRootKey`; one the database agrees with but
/// the marks do not is `UnrecognisedRootKey`, which is what a swapped or restored database shows.
async fn check_root_against(
    store: &dyn Store,
    root: &RootKey,
    epoch_files: Option<&[PathBuf]>,
) -> Result<(), StartupError> {
    let fingerprint = root.fingerprint();
    let stored = store.get_meta(ROOT_KEY_META).await?;
    if stored.as_ref().is_some_and(|s| *s != fingerprint) {
        return Err(StartupError::WrongRootKey);
    }
    // Marks that name the key already vouch for it, and then data damaged since does not lock
    // everyone out. Without them, everything stored must open.
    let vouched = epoch_files.and_then(|paths| marks_name(paths, root)) == Some(true);
    if !vouched && !opens_existing_data(store, root, epoch_files.is_some()).await? {
        return Err(StartupError::WrongRootKey);
    }
    if let Some(paths) = epoch_files
        && !root_recognised(paths, root)
    {
        return Err(StartupError::UnrecognisedRootKey);
    }
    if stored.is_none() {
        store.set_meta(ROOT_KEY_META, &fingerprint).await?;
    }
    Ok(())
}

/// The refusal a request gets when [`check_root`] fails.
pub fn root_refused(error: StartupError) -> ApiError {
    match error {
        StartupError::UnrecognisedRootKey | StartupError::WrongRootKey => ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "root_key_not_recognised",
            error.to_string(),
        ),
        other => ApiError::internal("root key check", other),
    }
}

fn write_or_skip(path: &Path, existing: &std::io::Result<Option<EpochMark>>, mark: &EpochMark) -> std::io::Result<()> {
    match write_mark(path, mark) {
        Ok(()) => Ok(()),
        // Where no mark has ever been written, as beside a read-only key file, nothing goes stale.
        Err(error) if matches!(existing, Ok(None)) => {
            tracing::warn!(%error, path = %path.display(), "could not create a seal epoch mark");
            Ok(())
        }
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", path.display()),
        )),
    }
}

/// Records `epoch` and the root key in use beside each file. Epochs are only ever raised here; a
/// broken mark is replaced. Only `sekret admin reset-epoch` lowers them, through [`reset_epoch`].
/// The caller has checked the root with [`check_root`], or is replacing it. Failing to update a
/// mark that exists is an error, since it would otherwise go stale without anyone knowing.
pub fn record_epoch(paths: &[PathBuf], epoch: i64, fingerprint: &str) -> std::io::Result<()> {
    let mut failed = None;
    for path in paths {
        let existing = read_mark(path);
        let mark = EpochMark {
            epoch: match &existing {
                Ok(Some(mark)) => mark.epoch.max(epoch),
                _ => epoch,
            },
            roots: vec![fingerprint.to_string()],
        };
        if matches!(&existing, Ok(Some(current)) if *current == mark) {
            continue;
        }
        if let Err(error) = write_or_skip(path, &existing, &mark) {
            tracing::error!(%error, "could not record the seal configuration epoch");
            failed.get_or_insert(error);
        }
    }
    failed.map_or(Ok(()), Err)
}

/// Before the root key is replaced, lets each existing mark accept both keys, so a crash between
/// the database commit and [`record_epoch`] leaves a server that still starts. The marks also
/// rise to `epoch`, the new configuration's, so until they are narrowed to the new key a copy
/// of the database from before the change counts as a rollback. Returns the marks as they were,
/// for [`abort_rekey`].
pub fn begin_rekey(paths: &[PathBuf], old: &str, new: &str, epoch: i64) -> std::io::Result<Vec<(PathBuf, EpochMark)>> {
    let mut before = Vec::new();
    for path in paths {
        let existing = read_mark(path);
        // A missing or broken mark names no root, so it refuses neither key meanwhile.
        let Ok(Some(current)) = &existing else {
            continue;
        };
        let mark = EpochMark {
            epoch: current.epoch.max(epoch),
            roots: vec![old.to_string(), new.to_string()],
        };
        before.push((path.clone(), current.clone()));
        if let Err(error) = write_or_skip(path, &existing, &mark) {
            if let Err(undo) = abort_rekey(&before) {
                tracing::warn!(error = %undo, "could not put the seal epoch marks back");
            }
            return Err(error);
        }
    }
    Ok(before)
}

/// Puts back the marks [`begin_rekey`] changed, for a replacement that was not committed.
pub fn abort_rekey(before: &[(PathBuf, EpochMark)]) -> std::io::Result<()> {
    let mut failed = None;
    for (path, mark) in before {
        if let Err(error) = write_mark(path, mark) {
            failed.get_or_insert(error);
        }
    }
    failed.map_or(Ok(()), Err)
}

/// Sets every mark to `epoch` and `fingerprint`, lowering them if need be. Only for when the
/// epochs have run out, through the explicit operator command.
pub fn reset_epoch(paths: &[PathBuf], epoch: i64, fingerprint: &str) -> std::io::Result<()> {
    for path in paths {
        let mark = EpochMark {
            epoch,
            roots: vec![fingerprint.to_string()],
        };
        write_mark(path, &mark)?;
    }
    Ok(())
}

fn mark_error(error: std::io::Error) -> ApiError {
    ApiError::internal("recording the seal configuration epoch", error)
}

/// Signs and stores a changed configuration above the recorded marks, and raises them.
async fn save(
    store: &dyn Store,
    settings: &SealSettings,
    root: &RootKey,
    now: i64,
    mut config: SealConfig,
) -> ApiResult<SealConfig> {
    config.updated_at = now;
    let floor = high_water(&settings.epoch_files).floor();
    let config = signed(root, config, floor)?;
    store.update_seal_config(config.clone()).await?;
    record_epoch(&settings.epoch_files, config.epoch, &pin(root).map_err(mark_error)?).map_err(mark_error)?;
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
        detail: crate::peer::annotate(detail, ip),
        ip: ip.to_string(),
    };
    if let Err(error) = store.insert_audit(entry).await {
        tracing::error!(%error, action, "failed to write audit entry");
    }
}

/// A stored configuration after checking it with the root key just recovered.
pub struct Checked {
    pub config: SealConfig,
    /// It failed its signature or was older than the recorded marks.
    pub tampered: bool,
    /// It is signed by this server and current, so it may be changed and signed again. When
    /// false, `config` is only an in-memory view with nothing granted.
    pub trusted: bool,
}

/// Why a stored configuration cannot be relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distrust {
    /// Its signature fails, or it is unsigned where signing already existed.
    Tampered,
    /// Validly signed, but older than an epoch recorded outside the database.
    RolledBack,
}

impl Distrust {
    pub fn action(self) -> &'static str {
        match self {
            Distrust::Tampered => "sys.seal_config.tampered",
            Distrust::RolledBack => "sys.seal_config.rolled_back",
        }
    }
}

/// Checks a configuration without changing anything. `Ok(true)` is a configuration from before
/// signing existed that may be signed now.
pub fn verify_config(root: &RootKey, config: &SealConfig, marks: HighWater) -> Result<bool, Distrust> {
    match check_signature(root, config) {
        Signature::Valid if marks.rolled_back(config.epoch) || marks.lost_for(config) => Err(Distrust::RolledBack),
        Signature::Valid => Ok(false),
        // Marks only exist once signing does, so an unsigned configuration beside one was stripped.
        Signature::Missing if marks.highest.is_none() && !marks.broken => Ok(true),
        Signature::Missing | Signature::Invalid => Err(Distrust::Tampered),
    }
}

/// Verifies the seal configuration once the root key is known. An unsigned one that grants
/// nothing, from before signing existed, is signed now. One older than the marks recorded outside
/// the database was put back from an earlier copy: it falls back to the `manual` policy with
/// nothing remembered and is signed again above the marks. One whose signature fails was changed
/// by a database writer: its fields are never signed. Only when `proven` holds the wrap that a
/// passphrase has just opened is a clean configuration made from it and signed; otherwise the
/// result is an unsigned, in-memory `manual` view. Either way it is audited.
pub async fn check_config(
    store: &dyn Store,
    settings: &SealSettings,
    now: i64,
    ip: &str,
    root: &RootKey,
    config: SealConfig,
    proven: Option<&WrappedRootKey>,
) -> ApiResult<Checked> {
    let marks = high_water(&settings.epoch_files);
    let distrust = match verify_config(root, &config, marks) {
        Ok(false) if config.flags.wrap_form_signed => {
            record_epoch(&settings.epoch_files, config.epoch, &pin(root).map_err(mark_error)?).map_err(mark_error)?;
            return Ok(Checked {
                config,
                tampered: false,
                trusted: true,
            });
        }
        // Signed before the wrap's form marker was; signing again covers it from now on.
        Ok(false) => {
            return Ok(Checked {
                config: save(store, settings, root, now, config).await?,
                tampered: false,
                trusted: true,
            });
        }
        Ok(true) => {
            // A database writer can strip a signature as easily as a database from before
            // signing lacks one, so nothing unsigned may start a migration.
            let config = SealConfig {
                flags: cautious_flags(config.flags),
                ..config
            };
            let config = save(store, settings, root, now, config).await?;
            tracing::info!("signed the seal configuration");
            return Ok(Checked {
                config,
                tampered: false,
                trusted: true,
            });
        }
        Err(distrust) => distrust,
    };
    match distrust {
        Distrust::RolledBack => tracing::error!(
            epoch = config.epoch,
            recorded = marks.highest,
            broken_mark = marks.broken,
            "the seal configuration is older than the one last seen; it was put back from an earlier copy. \
             Using the manual unlock policy and forgetting any remembered unlock"
        ),
        Distrust::Tampered => tracing::error!(
            "the seal configuration was changed without the root key; using the manual unlock policy and \
             forgetting any remembered unlock"
        ),
    }
    if let Some(path) = &settings.remember_file
        && let Err(error) = remove_device_key_file(path)
    {
        tracing::warn!(%error, "could not remove the remember file");
    }
    let flags = cautious_flags(config.flags);
    let repaired = match (distrust, proven) {
        // Every field was signed by this server at some point, so a reset copy may be signed.
        (Distrust::RolledBack, _) => Some(config.clone()),
        (Distrust::Tampered, Some(wrap)) if config.mode == SealMode::Passphrase => Some(SealConfig {
            wrapped: Some(wrap.clone()),
            ..config.clone()
        }),
        (Distrust::Tampered, _) => None,
    };
    let checked = match repaired {
        Some(clean) => {
            let clean = SealConfig {
                unlock_policy: UnlockPolicy::Manual,
                remembered: None,
                flags,
                ..clean
            };
            Checked {
                config: save(store, settings, root, now, clean).await?,
                tampered: true,
                trusted: true,
            }
        }
        None => {
            tracing::error!(
                "the tampered seal configuration is left unsigned; unseal with the passphrase, or run `sekret admin \
                 reset-epoch` on the host, to repair it"
            );
            Checked {
                config: SealConfig {
                    unlock_policy: UnlockPolicy::Manual,
                    remembered: None,
                    flags,
                    ..config
                },
                tampered: true,
                trusted: false,
            }
        }
    };
    audit_system(
        store,
        now,
        ip,
        distrust.action(),
        serde_json::json!({"repaired": checked.trusted}),
    )
    .await;
    Ok(checked)
}

pub fn untrusted_config() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::CONFLICT,
        "seal_config_tampered",
        "the seal configuration failed its integrity check; unseal with the passphrase, or run `sekret admin \
         reset-epoch` on the host, to repair it",
    )
}

/// The stored configuration, checked with `root` before anything is changed and saved again, so
/// a change made by a database writer is never signed as if the server had made it. Refused while
/// the stored configuration cannot be trusted.
async fn load_trusted(
    store: &dyn Store,
    settings: &SealSettings,
    now: i64,
    ip: &str,
    root: &RootKey,
) -> ApiResult<SealConfig> {
    let config = store.get_seal_config().await?.ok_or_else(ApiError::uninitialised)?;
    let checked = check_config(store, settings, now, ip, root, config, None).await?;
    if !checked.trusted {
        return Err(untrusted_config());
    }
    Ok(checked.config)
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
        flags: SealFlags::default(),
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
    // Marks left from an earlier install are never lowered by something a database wipe can
    // trigger; the new configuration starts above them instead, and migrates nothing.
    let marks = high_water(&plan.epoch_files);
    if marks.highest.is_some() || marks.broken {
        config.flags.reviewer_tokens_migrated = true;
    }
    // A database with no root key yet holds no credentials to vouch for.
    config.flags.credentials_keyed |= existing.is_none();
    if !root_recognised(&plan.epoch_files, &root) {
        // Only setup, which needs the host or the setup code, may move the marks to a new key.
        tracing::warn!("the epoch marks name the root key of an earlier install; they now name the new one");
    }
    let config = signed(&root, config, marks.floor())?;
    if let Err(error) = store.init_seal_config(config.clone(), &root.fingerprint()).await {
        if let Some(path) = written {
            let _ = std::fs::remove_file(&path);
        }
        return Err(error.into());
    }
    // The database is set up by now, so a mark that cannot be written is reported, not undone.
    if let Err(error) = pin(&root).and_then(|pin| record_epoch(&plan.epoch_files, config.epoch, &pin)) {
        tracing::error!(%error, "setup finished, but the seal epoch marks could not be updated");
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

/// Where a host command writes a new root key before the database moves to it, and which it
/// renames over the key file once the database has.
pub fn pending_key_file(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".new");
    PathBuf::from(name)
}

/// Points at a new key left beside the key file by a host command that stopped part way.
fn key_file_refused(error: StartupError, settings: &SealSettings) -> StartupError {
    let Some(path) = &settings.root_key_file else {
        return error;
    };
    let pending = pending_key_file(path);
    let relevant = matches!(error, StartupError::WrongRootKey | StartupError::MissingRootKey);
    if !relevant || pending.symlink_metadata().is_err() {
        return error;
    }
    StartupError::KeyFile(format!(
        "{}: {error}. {} holds a newer root key left by a host command that stopped before it finished; if the \
         database had already moved to it, move that file over {} and start again",
        path.display(),
        pending.display(),
        path.display()
    ))
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
                check_root(store, &settings.epoch_files, &key)
                    .await
                    .map_err(|e| key_file_refused(e, settings))?;
                if mode == SealMode::Passphrase {
                    tracing::warn!("started unsealed from the root key file; this database is in passphrase mode");
                }
                let checked = check_config(store, settings, now, LOCAL, &key, config, None)
                    .await
                    .map_err(startup)?;
                migrate_once(store, settings, now, &key).await;
                let keyring = Keyring::unsealed(key, SealMode::KeyFile);
                keyring
                    .install(
                        keyring.root().map_err(startup)?,
                        &checked.config,
                        UnsealedBy::KeyFile,
                        checked.trusted,
                    )
                    .map_err(startup)?;
                audit_unlock_at_start(store, now, UnsealedBy::KeyFile).await;
                Ok(opened(keyring))
            }
            (SealMode::KeyFile, None) => Err(key_file_refused(StartupError::MissingRootKey, settings)),
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
        check_root(store, &settings.epoch_files, &key)
            .await
            .map_err(|e| key_file_refused(e, settings))?;
        let config = SealConfig {
            mode: SealMode::KeyFile,
            wrapped: None,
            unlock_policy: UnlockPolicy::Manual,
            remembered: None,
            epoch: 0,
            mac: None,
            flags: SealFlags {
                // A database with no root key yet holds no credentials to vouch for.
                credentials_keyed: !has_root,
                ..SealFlags::default()
            },
            created_at: now,
            updated_at: now,
        };
        // A deleted configuration row must not lower the marks, so this starts above them. Marks
        // mean a configuration existed, so the row was removed and nothing is migrated again.
        let marks = high_water(&settings.epoch_files);
        let config = match marks.highest.is_some() || marks.broken {
            true => SealConfig {
                flags: cautious_flags(config.flags),
                ..config
            },
            false => config,
        };
        let config = signed(&key, config, marks.floor()).map_err(|e| StartupError::Init(e.to_string()))?;
        match store.init_seal_config(config.clone(), &fingerprint).await {
            Ok(()) => record_epoch(&settings.epoch_files, config.epoch, &pin(&key)?)?,
            Err(StoreError::Conflict) => {}
            Err(error) => return Err(error.into()),
        }
        migrate_once(store, settings, now, &key).await;
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
    let mut proven = None;
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
            proven = Some(wrapped.clone());
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
    check_root(store, &settings.epoch_files, &root).await?;
    let checked = check_config(store, settings, now, LOCAL, &root, config, proven.as_ref())
        .await
        .map_err(startup)?;
    keyring.record(&checked.config).map_err(startup)?;
    if checked.tampered {
        tracing::error!("not unlocking automatically after the seal configuration was tampered with; unlock by hand");
        return Ok(());
    }
    migrate_once(store, settings, now, &root).await;
    let root = Arc::new(root);
    keyring
        .install(root.clone(), &checked.config, by, checked.trusted)
        .map_err(startup)?;
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
        let config = load_trusted(store, settings, now, LOCAL, root).await?;
        let cheap = config.wrapped.as_ref().is_some_and(|w| w.params.needs_upgrade());
        if config.wrapped.is_none() || !(cheap || force) {
            return Ok(false);
        }
        // Never waits for the permit: callers hold the gate, and waiting here could deadlock
        // with anyone holding a permit. The next unlock tries again.
        let Ok(permit) = keyring.kdf_permit() else {
            tracing::info!("a key derivation is running; re-wrapping the root key at a later unlock");
            return Ok(false);
        };
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
    let mut config = load_trusted(store, settings, now, LOCAL, &root).await?;
    let secret = settings.remember_secret.as_ref();
    if config.flags.remember_secret && secret.is_none() {
        tracing::error!(
            "the remembered unlock was made with a remember secret, which is not configured now; not remembering \
             this unlock under a weaker key. Configure the remember secret again, or forget the unlock first to \
             remember without one"
        );
        audit_system(
            store,
            now,
            LOCAL,
            "sys.remember.refused",
            serde_json::json!({"reason": "remember secret missing"}),
        )
        .await;
        return Ok(());
    }
    if config.remembered.is_some() && recall(settings, &config).is_ok() {
        // Wraps from before the flag existed record it the first time they are seen with a secret.
        if secret.is_some() && !config.flags.remember_secret {
            config.flags.remember_secret = true;
            let config = save(store, settings, &root, now, config).await?;
            keyring.record(&config)?;
        }
        return Ok(());
    }
    let device = DeviceKey::generate()?;
    remove_device_key_file(path).map_err(|e| ApiError::internal("removing the old remember file", e))?;
    write_new_private(path, device.to_key_file_text().as_bytes())
        .map_err(|e| ApiError::internal("writing the remember file", e))?;
    config.remembered = Some(remember_root_key(&root, &device, secret)?);
    config.flags.remember_secret |= secret.is_some();
    let config = save(store, settings, &root, now, config).await?;
    keyring.record(&config)?;
    tracing::info!(path = %path.display(), "remembered the unlock for later starts");
    Ok(())
}

/// Deletes the remember file and the database wrap, and is the only thing that stops a remember
/// secret being required. The caller holds the keyring gate. Dropping the wrap is what matters,
/// so a file that cannot be removed is only logged.
pub async fn forget(store: &dyn Store, now: i64, settings: &SealSettings, keyring: &Keyring) -> ApiResult<()> {
    if let Some(path) = &settings.remember_file
        && let Err(error) = remove_device_key_file(path)
    {
        tracing::warn!(%error, "could not remove the remember file");
    }
    let root = keyring.root()?;
    let mut config = load_trusted(store, settings, now, LOCAL, &root).await?;
    if config.remembered.is_none() && !config.flags.remember_secret {
        return Ok(());
    }
    config.remembered = None;
    config.flags.remember_secret = false;
    let config = save(store, settings, &root, now, config).await?;
    keyring.record(&config)
}

/// Runs each one-off migration that has not run yet, and records it in the signed configuration,
/// so data in an old form put back by a database writer is never migrated again: reviewer tokens
/// sealed in the old format are moved, and credentials from before the integrity key are vouched
/// for. Best effort; at start, or with the keyring gate held.
pub async fn migrate_once(store: &dyn Store, settings: &SealSettings, now: i64, root: &RootKey) {
    let result: ApiResult<()> = async {
        let config = load_trusted(store, settings, now, LOCAL, root).await?;
        let mut flags = config.flags;
        if flags.reviewer_tokens_migrated && flags.credentials_keyed {
            return Ok(());
        }
        let key = load_integrity_key(store, root).await?;
        if !flags.reviewer_tokens_migrated && crate::machine::migrate_reviewer_tokens(store, root, &key).await {
            flags.reviewer_tokens_migrated = true;
        }
        if !flags.credentials_keyed {
            let signed = crate::auth::vouch_for_legacy_credentials(store, &key).await?;
            tracing::info!(signed, "vouched for the credentials stored before the integrity key");
            flags.credentials_keyed = true;
        }
        if flags != config.flags {
            save(store, settings, root, now, SealConfig { flags, ..config }).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        tracing::warn!(error = %error.message, "could not record a one-off migration");
    }
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
    /// so it skips the network's limits and line, and has a short back-off of its own.
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
        tokio::spawn(crate::peer::scoped(crate::peer::current(), work))
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

    /// How long a network attempt with no recent failures waits in line for the derivation.
    const QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

    /// The keyring gate and a derivation permit, taken in that order everywhere so the two can
    /// never deadlock. Network sources with no recent failures wait their turn in a short,
    /// bounded line; sources that have failed recently are refused at once when busy, and
    /// backing-off ones are refused outright. The host socket goes ahead of the network line,
    /// unless it is backing off after wrong passphrases of its own.
    async fn admit(
        state: &AppState,
        source: Source,
    ) -> ApiResult<(tokio::sync::MutexGuard<'_, ()>, OwnedSemaphorePermit)> {
        let Source::Network(ip) = source else {
            if let Some(wait) = state.host_backoff.wait(state.clock.now()) {
                return Err(ApiError::passphrase_backoff(wait));
            }
            let gate = state.keyring.lock_for_host().await;
            return Ok((gate, state.keyring.kdf_permit_queued().await?));
        };
        if let Some(wait) = state.passphrase_backoff.wait(ip) {
            return Err(ApiError::passphrase_backoff(wait));
        }
        if !state.passphrase_attempts.allow(&crate::ratelimit::prefix_key(ip)) {
            return Err(ApiError::too_many_requests());
        }
        if state.passphrase_backoff.failures(ip) > 0 || state.keyring.host_waiting() {
            let gate = state.keyring.try_lock().ok_or_else(ApiError::kdf_busy)?;
            return Ok((gate, state.keyring.kdf_permit()?));
        }
        let place = state
            .kdf_queue
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::kdf_busy())?;
        let gate = tokio::time::timeout(QUEUE_WAIT, state.keyring.lock())
            .await
            .map_err(|_| ApiError::kdf_busy())?;
        drop(place);
        // However busy the network line is, an unseal from the host socket goes next.
        if state.keyring.host_waiting() {
            return Err(ApiError::kdf_busy());
        }
        Ok((gate, state.keyring.kdf_permit()?))
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
                match source {
                    Source::Network(ip) => state.passphrase_backoff.succeeded(ip),
                    Source::HostSocket => state.host_backoff.succeeded(),
                }
                Ok(opened)
            }
            Err(CryptoError::Decrypt) => {
                let failures = match source {
                    Source::Network(ip) => {
                        state.passphrase_backoff.failed(ip);
                        state.passphrase_backoff.failures(ip)
                    }
                    Source::HostSocket => {
                        state.host_backoff.failed(state.clock.now());
                        state.host_backoff.failures()
                    }
                };
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
        let (_gate, permit) = admit(state, source).await?;
        if state.keyring.state() == SealState::Unsealed {
            return Ok(Unsealed::Already);
        }
        let (config, wrapped) = passphrase_config(state).await?;
        let principal = Principal::system("unseal");
        let failure = Failure {
            principal: &principal,
            action: "sys.unseal.failed",
        };
        let opened = open_with(state, source, wrapped.clone(), passphrase.clone(), permit, failure).await?;
        if let Err(error) = check_root(state.store.as_ref(), &state.config.seal.epoch_files, &opened.root).await {
            let refused = root_refused(error);
            audit(
                state,
                &principal,
                source.ip(),
                "sys.unseal.refused",
                AuditTarget::default(),
                json!({"reason": refused.code, "via": source.label()}),
            )
            .await;
            return Err(refused);
        }
        let ip = source.ip().to_string();
        let checked = check_config(
            state.store.as_ref(),
            &state.config.seal,
            state.clock.now(),
            &ip,
            &opened.root,
            config,
            Some(&wrapped),
        )
        .await?;
        let root = Arc::new(opened.root);
        state
            .keyring
            .install(root.clone(), &checked.config, UnsealedBy::Passphrase, checked.trusted)?;
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
        migrate_once(state.store.as_ref(), &state.config.seal, now, root).await;
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
        skip_unreadable: bool,
    ) -> ApiResult<bool> {
        require_passphrase_mode(state)?;
        refuse_beside_key_file(state)?;
        check_length(&current)?;
        check_length(&new)?;
        validate_passphrase(&new).map_err(ApiError::weak_passphrase)?;
        let (_gate, permit) = admit(state, source).await?;
        let (config, wrapped) = passphrase_config(state).await?;
        let failure = Failure {
            principal,
            action: "sys.passphrase.failed",
        };
        let old_root = open_with(state, source, wrapped.clone(), current, permit, failure)
            .await?
            .root;
        check_root(state.store.as_ref(), &state.config.seal.epoch_files, &old_root)
            .await
            .map_err(root_refused)?;
        let now = state.clock.now();
        let ip = source.ip().to_string();
        let settings = &state.config.seal;
        let checked = check_config(
            state.store.as_ref(),
            settings,
            now,
            &ip,
            &old_root,
            config,
            Some(&wrapped),
        )
        .await?;
        // Only what this server signed may be signed again under the new key.
        if !checked.trusted {
            return Err(untrusted_config());
        }
        let new_root = Arc::new(RootKey::generate()?);
        let permit = state.keyring.kdf_permit_queued().await?;
        let wrapped = wrap_blocking(new_root.clone(), new, Some(permit)).await?;
        let config = SealConfig {
            wrapped: Some(wrapped),
            remembered: None,
            updated_at: now,
            ..checked.config
        };
        let rotation = crate::admin::Rotation {
            marks: high_water(&settings.epoch_files),
            skip_unreadable,
            epoch_files: &settings.epoch_files,
        };
        let (report, still_unsealed) = {
            let _writers = state.keyring.rekeying().await?;
            let report =
                crate::admin::rotate_root_key(state.store.as_ref(), &old_root, &new_root, Some(config), rotation)
                    .await?;
            (report, state.keyring.replace_root(new_root.clone())?)
        };
        if let Some(stored) = state.store.get_seal_config().await? {
            state.keyring.record(&stored)?;
        }
        if !report.skipped.is_empty() {
            audit(
                state,
                principal,
                source.ip(),
                "sys.passphrase.skipped",
                AuditTarget::default(),
                json!({"unreadable": report.skipped}),
            )
            .await;
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
        if report.stale_marks.is_some() {
            return Err(stale_marks());
        }
        Ok(checked.tampered)
    }

    /// A passphrase change replaces the root key, and a key file read at start would still hold
    /// the old one, so the server could not start again and the stale file would keep opening
    /// old backups. Refused while one is in use or configured and present.
    fn refuse_beside_key_file(state: &AppState) -> ApiResult<()> {
        let from_file = state.keyring.unsealed_by() == Some(UnsealedBy::KeyFile);
        let present = state
            .config
            .seal
            .root_key_file
            .as_deref()
            .is_some_and(|path| path.symlink_metadata().is_ok());
        if !from_file && !present {
            return Ok(());
        }
        Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "root_key_file_in_use",
            "this server reads its root key from seal.root_key_file, which would still hold the old key after a \
             passphrase change and stop the server starting; remove that file, restart, unseal with the passphrase \
             and change it then",
        ))
    }

    /// The change is done, but the operator has to repair a mark it could not move. Which mark,
    /// and why, is only in the server log.
    fn stale_marks() -> ApiError {
        ApiError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "epoch_mark_stale",
            "the passphrase was changed, but a seal epoch mark could not be moved to the new root key; see the \
             server log, make the mark writable, then run `sekret admin reset-epoch` with the server stopped",
        )
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
        let (_gate, confirm) = match policy {
            UnlockPolicy::Manual => (state.keyring.lock().await, None),
            UnlockPolicy::Remember | UnlockPolicy::PassphraseFile => {
                let passphrase = passphrase.ok_or_else(ApiError::passphrase_required)?;
                check_length(&passphrase)?;
                let (gate, permit) = admit(state, source).await?;
                (gate, Some((passphrase, permit)))
            }
        };
        let root = state.keyring.root()?;
        let now = state.clock.now();
        let ip = source.ip().to_string();
        let (stored, wrapped) = passphrase_config(state).await?;
        let mut proven = None;
        if let Some((passphrase, permit)) = confirm {
            let failure = Failure {
                principal,
                action: "sys.passphrase.failed",
            };
            let opened = open_with(state, source, wrapped.clone(), passphrase, permit, failure).await?;
            if opened.root.fingerprint() != root.fingerprint() {
                return Err(ApiError::invalid_passphrase());
            }
            proven = Some(wrapped);
        }
        let checked = check_config(state.store.as_ref(), settings, now, &ip, &root, stored, proven.as_ref()).await?;
        if !checked.trusted {
            return Err(untrusted_config());
        }
        let mut config = checked.config;
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

    /// What a backup carries instead of the live configuration.
    pub struct BackupSeal {
        pub root: Arc<RootKey>,
        /// The live configuration without the remembered wrap, signed for the copy.
        pub copy: SealConfig,
    }

    /// Checks the live configuration and signs the copy a backup carries. The copy never holds
    /// the remembered wrap. The live configuration then moves past the copy's epoch, so the copy
    /// can never be put back into the live database without looking like a rollback. A
    /// configuration that fails its checks is never signed: the backup is refused and audited.
    pub async fn backup_seal(state: &AppState, principal: &Principal, ip: IpAddr) -> ApiResult<BackupSeal> {
        let _gate = state.keyring.lock().await;
        let root = state.keyring.root()?;
        let settings = &state.config.seal;
        let store = state.store.as_ref();
        let now = state.clock.now();
        let config = store.get_seal_config().await?.ok_or_else(ApiError::uninitialised)?;
        let marks = high_water(&settings.epoch_files);
        let verdict = verify_config(&root, &config, marks);
        if let Err(distrust) = verdict {
            tracing::error!(
                action = distrust.action(),
                "refusing a backup: the seal configuration failed its integrity check, so it was changed by \
                 something without the root key"
            );
            audit_system(
                store,
                now,
                &ip.to_string(),
                distrust.action(),
                json!({"during": "backup"}),
            )
            .await;
            audit(
                state,
                principal,
                ip,
                "sys.backup.refused",
                AuditTarget::default(),
                json!({"reason": distrust.action()}),
            )
            .await;
            return Err(untrusted_config());
        }
        // An unsigned configuration's flags may be a database writer's.
        let config = match verdict {
            Ok(true) => SealConfig {
                flags: cautious_flags(config.flags),
                ..config
            },
            _ => config,
        };
        let copy = signed(
            &root,
            SealConfig {
                remembered: None,
                ..config.clone()
            },
            marks.floor(),
        )?;
        let live = SealConfig {
            epoch: copy.epoch,
            ..config
        };
        let live = save(store, settings, &root, now, live).await?;
        state.keyring.record(&live)?;
        Ok(BackupSeal { root, copy })
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
        let _gate = state.keyring.lock().await;
        if state.keyring.state() != SealState::Uninitialised {
            return Err(ApiError::conflict("the server is already initialised"));
        }
        let permit = match mode {
            SealMode::Passphrase => Some(state.keyring.kdf_permit()?),
            SealMode::KeyFile => None,
        };
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
        state.keyring.install(root, &config, by, true)?;
        if let Some(written) = &settings.setup_code_file
            && let Err(error) = crate::files::remove_if_unchanged(written)
        {
            tracing::warn!(%error, "could not remove the setup code file");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    /// Two root keys and what the marks record for each.
    struct Keys {
        old: RootKey,
        new: RootKey,
        old_pin: String,
        new_pin: String,
    }

    fn keys() -> anyhow::Result<Keys> {
        let old = RootKey::generate().context("old")?;
        let new = RootKey::generate().context("new")?;
        Ok(Keys {
            old_pin: old.pin().context("pin")?,
            new_pin: new.pin().context("pin")?,
            old,
            new,
        })
    }

    fn marks(dir: &Path) -> Vec<PathBuf> {
        vec![dir.join("sekret.db.epoch"), dir.join("unlock.key.epoch")]
    }

    #[test]
    fn marks_record_the_root_and_only_raise_the_epoch() -> anyhow::Result<()> {
        let k = keys()?;
        let dir = tempfile::tempdir().context("dir")?;
        let paths = marks(dir.path());
        assert_eq!(accepted_roots(&paths), None);
        assert!(root_recognised(&paths, &k.old), "no marks refuse nothing");
        record_epoch(&paths, 5, &k.old_pin).context("record")?;
        assert_eq!(accepted_roots(&paths), Some(vec![k.old_pin.clone()]));
        assert!(!root_recognised(&paths, &k.new));
        record_epoch(&paths, 3, &k.old_pin).context("record")?;
        assert_eq!(high_water(&paths).highest, Some(5));
        reset_epoch(&paths, 1, &k.new_pin).context("reset")?;
        assert_eq!(high_water(&paths).highest, Some(1));
        assert!(root_recognised(&paths, &k.new) && !root_recognised(&paths, &k.old));
        Ok(())
    }

    #[test]
    fn a_rekey_in_progress_accepts_both_keys_until_it_is_recorded() -> anyhow::Result<()> {
        let k = keys()?;
        let dir = tempfile::tempdir().context("dir")?;
        let paths = marks(dir.path());
        record_epoch(&paths[..1], 4, &k.old_pin).context("record")?;
        begin_rekey(&paths, &k.old_pin, &k.new_pin, 5).context("begin")?;
        assert!(!paths[1].exists(), "a missing mark is not created halfway");
        assert!(root_recognised(&paths, &k.old) && root_recognised(&paths, &k.new));
        // A copy from before the change, at epoch 4, already counts as a rollback.
        assert_eq!(high_water(&paths).highest, Some(5));
        assert!(high_water(&paths).rolled_back(4));
        record_epoch(&paths, 5, &k.new_pin).context("record")?;
        assert_eq!(accepted_roots(&paths), Some(vec![k.new_pin.clone()]));
        assert!(paths[1].exists());
        Ok(())
    }

    #[test]
    fn an_aborted_rekey_puts_the_marks_back_as_they_were() -> anyhow::Result<()> {
        let k = keys()?;
        let dir = tempfile::tempdir().context("dir")?;
        let paths = marks(dir.path());
        record_epoch(&paths[..1], 4, &k.old_pin).context("record")?;
        let before = begin_rekey(&paths, &k.old_pin, &k.new_pin, 9).context("begin")?;
        abort_rekey(&before).context("abort")?;
        assert_eq!(high_water(&paths).highest, Some(4));
        assert_eq!(accepted_roots(&paths), Some(vec![k.old_pin.clone()]));
        assert!(!paths[1].exists());
        Ok(())
    }

    #[test]
    fn marks_that_disagree_accept_only_what_they_share() -> anyhow::Result<()> {
        let k = keys()?;
        let dir = tempfile::tempdir().context("dir")?;
        let paths = marks(dir.path());
        record_epoch(&paths[..1], 4, &k.old_pin).context("record")?;
        record_epoch(&paths[1..], 4, &k.new_pin).context("record")?;
        assert_eq!(accepted_roots(&paths), Some(vec![]));
        assert!(!root_recognised(&paths, &k.old) && !root_recognised(&paths, &k.new));
        // Marks from before fingerprints say nothing either way.
        std::fs::write(&paths[1], "sekret-seal-epoch 4\n").context("old mark")?;
        assert!(root_recognised(&paths, &k.old));
        Ok(())
    }

    #[test]
    fn marks_from_before_pins_still_name_their_key_by_fingerprint() -> anyhow::Result<()> {
        let k = keys()?;
        let dir = tempfile::tempdir().context("dir")?;
        let paths = marks(dir.path());
        record_epoch(&paths[..1], 4, &k.old.fingerprint()).context("short")?;
        record_epoch(&paths[1..], 4, &k.old_pin).context("pin")?;
        assert_eq!(marks_name(&paths, &k.old), Some(true), "one key, recorded both ways");
        assert_eq!(marks_name(&paths, &k.new), Some(false));
        // Recording again moves the old mark to the pin.
        record_epoch(&paths, 4, &k.old_pin).context("record")?;
        assert_eq!(accepted_roots(&paths), Some(vec![k.old_pin.clone()]));
        Ok(())
    }

    #[test]
    fn deleted_marks_count_as_a_rollback_once_a_configuration_says_they_existed() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let paths = marks(dir.path());
        let config = SealConfig {
            mode: SealMode::KeyFile,
            wrapped: None,
            unlock_policy: UnlockPolicy::Manual,
            remembered: None,
            epoch: 3,
            mac: None,
            flags: SealFlags {
                wrap_form_signed: true,
                ..SealFlags::default()
            },
            created_at: 0,
            updated_at: 0,
        };
        let none = high_water(&paths);
        assert!(none.absent && none.lost_for(&config));
        assert!(!none.lost_for(&SealConfig {
            epoch: 0,
            ..config.clone()
        }));
        assert!(
            !none.lost_for(&SealConfig {
                flags: SealFlags::default(),
                ..config.clone()
            }),
            "signed before marks were tied to the wrap form"
        );
        // Where no mark could ever be written, nothing is inferred.
        let nowhere = vec![dir.path().join("missing/sekret.db.epoch")];
        assert!(!high_water(&nowhere).absent);
        assert!(!high_water(&[]).absent);
        record_epoch(&paths[..1], 3, "0123456789abcdef").context("record")?;
        assert!(!high_water(&paths).absent);
        Ok(())
    }

    #[test]
    fn the_mode_comes_from_what_opened_the_key() {
        let config = |mode| SealConfig {
            mode,
            wrapped: None,
            unlock_policy: UnlockPolicy::Manual,
            remembered: None,
            epoch: 1,
            mac: None,
            flags: SealFlags::default(),
            created_at: 0,
            updated_at: 0,
        };
        // A database writer flipped the mode; a passphrase still proves passphrase mode.
        assert_eq!(
            proven_mode(&config(SealMode::KeyFile), UnsealedBy::Passphrase, false),
            SealMode::Passphrase
        );
        assert_eq!(
            proven_mode(&config(SealMode::KeyFile), UnsealedBy::Remember, true),
            SealMode::Passphrase
        );
        // A key file proves nothing about a wrap, so only a trusted configuration says passphrase.
        assert_eq!(
            proven_mode(&config(SealMode::Passphrase), UnsealedBy::KeyFile, false),
            SealMode::KeyFile
        );
        assert_eq!(
            proven_mode(&config(SealMode::Passphrase), UnsealedBy::KeyFile, true),
            SealMode::Passphrase
        );
    }

    #[tokio::test]
    async fn network_attempts_see_a_waiting_host_unseal() -> anyhow::Result<()> {
        let keyring = Arc::new(Keyring::sealed(UnlockPolicy::Manual, false));
        let held = keyring.lock().await;
        assert!(!keyring.host_waiting());
        let waiting = keyring.clone();
        let host = tokio::spawn(async move {
            let _gate = waiting.lock_for_host().await;
        });
        while !keyring.host_waiting() {
            tokio::task::yield_now().await;
        }
        drop(held);
        host.await.context("host")?;
        assert!(!keyring.host_waiting(), "cleared once the host has the gate");

        // A host attempt abandoned while waiting does not keep network attempts out.
        let held = keyring.lock().await;
        let abandoned = tokio::time::timeout(Duration::from_millis(20), keyring.lock_for_host()).await;
        assert!(abandoned.is_err());
        assert!(!keyring.host_waiting());
        drop(held);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_mark_that_exists_but_cannot_be_updated_is_an_error() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return Ok(());
        }
        let dir = tempfile::tempdir().context("dir")?;
        let fixed = dir.path().join("fixed");
        let fresh = dir.path().join("fresh");
        std::fs::create_dir(&fixed).context("fixed")?;
        std::fs::create_dir(&fresh).context("fresh")?;
        let existing = vec![fixed.join("sekret.db.epoch")];
        let never_written = vec![fresh.join("root.key.epoch")];
        let k = keys()?;
        record_epoch(&existing, 1, &k.old_pin).context("record")?;
        for locked in [&fixed, &fresh] {
            std::fs::set_permissions(locked, std::fs::Permissions::from_mode(0o500)).context("chmod")?;
        }
        let stale = record_epoch(&existing, 2, &k.old_pin);
        let skipped = record_epoch(&never_written, 2, &k.old_pin);
        let read_only = high_water(&never_written);
        for locked in [&fixed, &fresh] {
            std::fs::set_permissions(locked, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        }
        assert!(stale.is_err(), "a mark left behind would go stale unnoticed");
        skipped.context("a mark that never existed, such as beside a read-only key file, is skipped")?;
        assert!(
            !read_only.absent,
            "no mark could ever be written there, so none was deleted"
        );
        assert!(begin_rekey(&existing, &k.old_pin, &k.new_pin, 2).is_ok());
        Ok(())
    }
}
