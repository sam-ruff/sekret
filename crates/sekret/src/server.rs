use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Subcommand;
use sekret_core::crypto::RootKey;
use sekret_core::seal::{
    MAX_BACKUP_LEN, SealFlags, SealMode, UnlockPolicy, decrypt_backup, parse_backup, trim_input, unwrap_root_key,
    unwrap_root_key_checked, validate_passphrase, wrap_root_key,
};
use sekret_server::admin::{Rotation, RotationReport};
use sekret_server::clock::{Clock, SystemClock};
use sekret_server::config::{SealSettings, ServerConfig};
use sekret_server::files::{
    SECRET_FILE_LIMIT, WrittenFile, can_create, read_limited, remove_device_key_file, write_new_private,
    write_new_recorded,
};
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::seal::{
    AutoInit, Distrust, HighWater, InitPlan, Keyring, StartupSecrets, audit_as, cautious_flags, check_database_root,
    check_root, high_water, initialise, open_keyring, record_epoch, reset_epoch, root_recognised, signed,
    verify_config,
};
use sekret_server::state::{AppState, Dependencies, build_state};
use sekret_store::{InstanceLock, Open, SealConfig, SqlStore, Store};
use serde_json::json;
use zeroize::Zeroizing;

use crate::prompt::{Prompter, Terminal, read_new_passphrase, read_passphrase};
use crate::settings::{self, EnvSecrets, Report, ServerArgs, Setup, Sources, StoreArgs, StoreLocation, sqlite_path};

const MAX_ADMIN_TOKEN_TTL: i64 = sekret_server::admin::MAX_BOOTSTRAP_TTL;
/// How long a starting server waits for the database lock, for restarts that overlap.
const LOCK_WAIT: Duration = Duration::from_secs(30);
/// How often a running server checks it still holds the database lock.
const LOCK_CHECK_EVERY: Duration = Duration::from_secs(10);

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Print a short-lived organisation admin token for first-time setup or recovery.
    Bootstrap {
        #[command(flatten)]
        store: StoreArgs,
        /// Seconds the token lasts, at most 86400.
        #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(i64).range(1..=MAX_ADMIN_TOKEN_TTL))]
        ttl: i64,
        /// Passphrase mode: read the passphrase from this file, or `-` for stdin, instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Initialise the database on the host, for servers with web setup turned off. Restart the
    /// server afterwards. `sekret sys init` does the same through the API when web setup is on.
    Init {
        #[command(flatten)]
        store: StoreArgs,
        /// Keep the root key in --root-key-file instead of under a passphrase.
        #[arg(long)]
        key_file_mode: bool,
        /// Read the passphrase from this file, or `-` for stdin, instead of asking twice.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// manual, remember or passphrase-file. remember also needs seal.remember_file on the server.
        #[arg(long, value_parser = parse_unlock, default_value = "manual")]
        unlock: UnlockPolicy,
        /// Seconds the admin token lasts, at most 86400.
        #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(i64).range(1..=MAX_ADMIN_TOKEN_TTL))]
        ttl: i64,
    },
    /// Print a new random root key, base64 encoded.
    GenerateRootKey,
    /// Replace the root key and re-encrypt every secret under it. Stop the server first.
    RotateRootKey {
        #[command(flatten)]
        store: StoreArgs,
        /// Key-file mode: the new key. Passphrase mode: optional, a new key is generated without it.
        #[arg(long)]
        new_root_key_file: Option<PathBuf>,
        /// Passphrase mode: the current passphrase, from this file or `-` for stdin. Always checked.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Leave values, project keys and stored credentials that no longer decrypt as they are,
        /// and audit them, instead of refusing to rotate.
        #[arg(long)]
        skip_unreadable: bool,
    },
    /// Re-sign the seal configuration above every epoch mark and raise the marks to it. For after
    /// restoring an older database in place, or when a mark is damaged. Stop the server first. A
    /// configuration that fails its signature, or is older than the marks, is reset to the manual
    /// unlock policy.
    ResetEpoch {
        #[command(flatten)]
        store: StoreArgs,
        /// Passphrase mode: the passphrase, from this file or `-` for stdin, instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Accept a root key the epoch marks do not name, such as after restoring a database made
        /// under an earlier root key, and record it in the marks.
        #[arg(long)]
        adopt_root_key: bool,
    },
    /// Switch between passphrase and key-file mode under a new root key, re-encrypting
    /// everything, so the old key file or passphrase opens nothing. Stop the server first.
    SetSealMode {
        #[command(flatten)]
        store: StoreArgs,
        /// passphrase or key-file.
        #[arg(value_parser = parse_seal_mode)]
        mode: SealMode,
        /// The current passphrase when leaving passphrase mode, or the new one when entering it.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Leave values, project keys and stored credentials that no longer decrypt as they are,
        /// and audit them, instead of refusing to switch.
        #[arg(long)]
        skip_unreadable: bool,
    },
    /// Write the database from a `.skb` backup to a new SQLite file, offline.
    Restore {
        /// The `.skb` file from `sekret sys backup`.
        #[arg(long)]
        backup: PathBuf,
        /// Where to restore, `sqlite://NEW.db`; the file must not exist.
        #[arg(long)]
        database_url: String,
        /// Passphrase-mode backups: read the passphrase from this file, or `-` for stdin.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Key-file-mode backups: the root key file.
        #[arg(long)]
        root_key_file: Option<PathBuf>,
    },
    /// Exit non-zero unless this binary embeds the web interface.
    WebCheck,
}

fn parse_seal_mode(raw: &str) -> Result<SealMode, String> {
    SealMode::parse(raw).ok_or_else(|| "expected passphrase or key-file".into())
}

fn parse_unlock(raw: &str) -> Result<UnlockPolicy, String> {
    UnlockPolicy::parse(raw).ok_or_else(|| "expected manual, remember or passphrase-file".into())
}

/// Follows symlinks, because Kubernetes mounts secret files through them.
fn read_secret_bytes(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_limited(path, SECRET_FILE_LIMIT).with_context(|| format!("reading {}", path.display()))
}

pub fn read_root_key(path: &Path) -> anyhow::Result<RootKey> {
    RootKey::parse(&read_secret_bytes(path)?).context("parsing root key")
}

fn state(config: ServerConfig, store: Arc<dyn Store>, keyring: Keyring) -> anyhow::Result<AppState> {
    let allow_http = config.allow_insecure_http;
    Ok(build_state(Dependencies {
        store,
        keyring,
        config,
        clock: Arc::new(SystemClock),
        http: Arc::new(ReqwestOidcHttp::new(allow_http)?),
        token_reviewer: Arc::new(ReqwestTokenReviewer::new(allow_http)),
    }))
}

/// A passphrase file, with a leading byte order mark and one trailing line ending dropped like
/// every other source.
fn read_passphrase_source(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let text = read_secret_bytes(path)?;
    let text = std::str::from_utf8(&text).context("the passphrase file is not UTF-8")?;
    Ok(Zeroizing::new(trim_input(text).to_string()))
}

/// The passphrase for the passphrase-file policy: the file when configured, else the value taken
/// from the environment. A file that cannot be read leaves the server sealed instead of stopping it.
fn unlock_passphrase(path: Option<&Path>, env: Option<Zeroizing<String>>) -> Option<Zeroizing<String>> {
    let Some(path) = path else {
        return env.map(|value| Zeroizing::new(trim_input(&value).to_string()));
    };
    match read_passphrase_source(path) {
        Ok(passphrase) => Some(passphrase),
        Err(error) => {
            tracing::warn!("cannot read the unlock passphrase file: {error:#}; staying sealed");
            None
        }
    }
}

/// Reads only the passphrases this start can use: the unlock passphrase under the
/// passphrase-file policy, and the setup passphrase only for a database without a root key.
async fn startup_secrets(
    store: &dyn Store,
    seal: &SealSettings,
    setup: &Setup,
    env_unlock: Option<Zeroizing<String>>,
) -> anyhow::Result<StartupSecrets> {
    let stored = store.get_seal_config().await?;
    let has_root = store.get_meta(sekret_server::ROOT_KEY_META).await?.is_some();
    let auto_init_runs = setup.auto_init && stored.is_none() && !has_root;
    let passphrase_mode = match &stored {
        Some(config) => config.mode == SealMode::Passphrase,
        None => seal.mode != Some(SealMode::KeyFile),
    };
    let policy = seal
        .unlock
        .or(stored.as_ref().map(|c| c.unlock_policy))
        .unwrap_or_default();
    let unlock_passphrase = match passphrase_mode && policy == UnlockPolicy::PassphraseFile {
        true => unlock_passphrase(setup.unlock_passphrase_file.as_deref(), env_unlock),
        false => {
            if env_unlock.is_some() {
                tracing::info!("SEKRET_UNLOCK_PASSPHRASE is set but not used by this server's unlock policy; ignored");
            }
            None
        }
    };
    if !auto_init_runs {
        if let Some(path) = &setup.passphrase_file
            && stored.is_some()
            && path.exists()
        {
            tracing::warn!(path = %path.display(), "the setup passphrase file is still there after setup; delete it");
        }
        return Ok(StartupSecrets {
            unlock_passphrase,
            auto_init: None,
        });
    }
    if let Some(path) = &setup.admin_token_file {
        can_create(path).with_context(|| {
            format!(
                "the admin token file {} must not exist yet and its directory must be writable",
                path.display()
            )
        })?;
    }
    let passphrase = setup
        .passphrase_file
        .as_deref()
        .map(read_passphrase_source)
        .transpose()?;
    Ok(StartupSecrets {
        unlock_passphrase,
        auto_init: Some(AutoInit { passphrase }),
    })
}

fn log_report(report: &Report) {
    for setting in &report.settings {
        tracing::info!(
            setting = setting.name,
            value = %setting.value,
            from = setting.origin.as_str(),
            "configuration"
        );
    }
    for warning in &report.warnings {
        tracing::warn!("{warning}");
    }
}

fn lock_error(error: sekret_store::StoreError) -> anyhow::Error {
    if InstanceLock::is_held_error(&error) {
        anyhow::anyhow!("{error}")
    } else {
        anyhow::anyhow!("taking the database lock: {error}")
    }
}

/// Takes the database's instance lock, or explains that something else has it.
async fn lock(database_url: &str) -> anyhow::Result<InstanceLock> {
    InstanceLock::acquire(database_url).await.map_err(lock_error)
}

/// The URL of a database that must already exist, so an admin command never leaves an empty
/// database or lock file behind a mistyped path.
fn existing_database(database_url: &str) -> anyhow::Result<String> {
    if let Some(path) = sqlite_path(database_url)
        && path.symlink_metadata().is_err()
    {
        bail!(
            "there is no database at {}; check --database-url or database.url",
            path.display()
        );
    }
    Ok(sekret_store::without_create(database_url))
}

const NO_EPOCH_MARK: &str = "there is nowhere outside the database to keep the seal epoch mark, so someone who can \
                             write to the database could swap in a root key of their own; set seal.epoch_file \
                             (--epoch-file or SEKRET_EPOCH_FILE) to a path on a disk the database cannot reach, \
                             the same for the server and the admin commands";

/// The epoch marks, refusing a setup with none: a Postgres database without a remember file,
/// root key file or `seal.epoch_file`.
fn require_marks(paths: Vec<PathBuf>) -> anyhow::Result<Vec<PathBuf>> {
    if paths.is_empty() {
        bail!("{NO_EPOCH_MARK}");
    }
    Ok(paths)
}

/// A configured epoch file is the one mark chosen on purpose, so where it cannot be written is
/// an error rather than a mark quietly skipped.
fn check_epoch_file(path: Option<&Path>) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    match sekret_server::files::read_mark(path) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => can_create(path).with_context(|| {
            format!(
                "the seal epoch file {} cannot be created; its directory must exist and be writable",
                path.display()
            )
        }),
        // Read again, and replaced, by the seal checks, which treat it as a rollback.
        Err(_) => Ok(()),
    }
}

fn marks_of(location: &StoreLocation) -> anyhow::Result<Vec<PathBuf>> {
    check_epoch_file(location.epoch_file.as_deref())?;
    require_marks(location.epoch_files())
}

/// Returns only when the lock is lost: the Postgres session dropped or the database file at the
/// path was replaced. Serving on without it could let a second writer in.
async fn watch_lock(lock: &mut InstanceLock) -> anyhow::Error {
    loop {
        tokio::time::sleep(LOCK_CHECK_EVERY).await;
        if let Err(error) = lock.check().await {
            tracing::error!(%error, "stopping: this server no longer holds the database lock");
            return anyhow::anyhow!("{error}");
        }
    }
}

pub async fn run_server(args: ServerArgs, env_secrets: EnvSecrets, sources: &Sources) -> anyhow::Result<()> {
    if args.print_config {
        print!("{}", settings::EXAMPLE);
        return Ok(());
    }
    let file = settings::load(args.store.config.as_deref())?;
    let epoch_file = args.store.epoch_file.clone().or(file.seal.epoch_file.clone());
    let settings::Resolved {
        mut config,
        setup,
        report,
    } = settings::resolve_with(&args, file, &env_secrets, sources)?;
    log_report(&report);
    check_epoch_file(epoch_file.as_deref())?;
    config.seal.epoch_files = require_marks(std::mem::take(&mut config.seal.epoch_files))?;
    // Held for the life of the server, so admin commands cannot write underneath it.
    let mut lock = InstanceLock::acquire_within(&config.database_url, LOCK_WAIT)
        .await
        .map_err(lock_error)?;
    let store: Arc<dyn Store> = Arc::new(
        SqlStore::connect(&config.database_url)
            .await
            .context("opening database")?,
    );
    let secrets = startup_secrets(store.as_ref(), &config.seal, &setup, env_secrets.unlock_passphrase).await?;
    drop(env_secrets.remember_secret);
    let opened = open_keyring(store.as_ref(), SystemClock.now(), &config.seal, secrets).await?;
    if let Some(code) = opened.keyring.setup_code() {
        config.seal.setup_code_file = announce_setup_code(&config, &code, setup.code_file.as_deref())?;
    } else if opened.keyring.state() == sekret_core::seal::SealState::Uninitialised {
        let message = "sekret is not set up and web setup is off; stop the server, run `sekret admin init` on this host, then start it";
        tracing::warn!("{message}");
        eprintln!("{message}");
    }
    let state = state(config, store, opened.keyring)?;
    if opened.auto_initialised {
        if let Some(path) = &setup.admin_token_file {
            let token = sekret_server::admin::bootstrap_admin(&state, 3600)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            write_new_private(path, format!("{token}\n").as_bytes())
                .with_context(|| format!("writing the admin token to {}", path.display()))?;
            tracing::info!(path = %path.display(), "wrote a break-glass admin token valid for an hour");
        }
        if let Some(path) = &setup.passphrase_file
            && path.exists()
        {
            tracing::warn!(path = %path.display(), "setup is done; delete the setup passphrase file");
        }
    }
    tokio::select! {
        served = sekret_server::serve(state) => served?,
        lost = watch_lock(&mut lock) => return Err(lost),
    }
    Ok(())
}

/// The only place the setup code is shown. It goes to stderr as well as the log, so a quiet log
/// level cannot hide it. Returns the code file written, so setup can remove it once used.
fn announce_setup_code(config: &ServerConfig, code: &str, file: Option<&Path>) -> anyhow::Result<Option<WrittenFile>> {
    let where_to = format!(
        "finish setting up at {}/setup or with `sekret sys init`; a restart makes a new code",
        config.public_url
    );
    tracing::info!("setup code: {code}");
    tracing::info!("{where_to}");
    eprintln!("sekret setup code: {code}\n{where_to}");
    let Some(path) = file else {
        return Ok(None);
    };
    let written = write_new_recorded(path, format!("{code}\n").as_bytes())
        .with_context(|| format!("writing the setup code to {}", path.display()))?;
    Ok(Some(written))
}

fn admin_config(database_url: &str) -> ServerConfig {
    let mut config = ServerConfig::for_tests(database_url);
    config.allow_insecure_http = false;
    config
}

/// Records what an admin command on the host did, from the address `local`.
async fn audit_admin(store: &dyn Store, action: &str, detail: serde_json::Value) {
    audit_as(store, SystemClock.now(), "local", "admin-cli", action, detail).await;
}

/// Warns, without changing anything, when the stored configuration fails its signature or is
/// older than the recorded epoch marks.
fn warn_if_tampered(root: &RootKey, config: Option<&SealConfig>, marks: HighWater) {
    let Some(Err(distrust)) = config.map(|c| verify_config(root, c, marks)) else {
        return;
    };
    let what = match distrust {
        Distrust::Tampered => "was changed without the root key",
        Distrust::RolledBack => "is older than the one last seen",
    };
    eprintln!(
        "warning: the seal configuration {what}; the server falls back to the manual unlock policy when it next \
         unlocks. `sekret admin reset-epoch` re-signs it if this was expected, such as after restoring in place"
    );
}

/// How [`obtain_root`] treats a root key the epoch marks do not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkCheck {
    Enforce,
    /// Only for `reset-epoch --adopt-root-key`, which then records the key in the marks.
    Adopt,
}

/// Where an admin command finds the root key and the epoch marks.
struct RootSource<'a> {
    /// Read instead of asking for the passphrase, when it exists.
    key_file: Option<&'a Path>,
    epoch_files: &'a [PathBuf],
    passphrase_file: Option<&'a Path>,
    marks: MarkCheck,
}

/// The root key on the host, offline: from the key file, or by unwrapping it with the passphrase.
/// Also returns the passphrase when one was used.
async fn obtain_root(
    store: &dyn Store,
    source: RootSource<'_>,
    prompter: &dyn Prompter,
) -> anyhow::Result<(RootKey, Option<SealConfig>, Option<Zeroizing<String>>)> {
    let config = store.get_seal_config().await?;
    let key_file = source.key_file.filter(|p| p.exists());
    let passphrase_mode = config.as_ref().is_some_and(|c| c.mode == SealMode::Passphrase);
    let (root, passphrase) = match (passphrase_mode, key_file, &config) {
        (_, Some(path), _) => (read_root_key(path)?, None),
        (true, None, Some(config)) => {
            let (root, passphrase) = unwrap_with_passphrase(config, source.passphrase_file, prompter)?;
            (root, Some(passphrase))
        }
        _ => bail!("this database is in key-file mode; pass --root-key-file"),
    };
    match source.marks {
        MarkCheck::Enforce => check_root(store, source.epoch_files, &root).await?,
        MarkCheck::Adopt => check_database_root(store, &root).await?,
    }
    warn_if_tampered(&root, config.as_ref(), high_water(source.epoch_files));
    Ok((root, config, passphrase))
}

fn unwrap_with_passphrase(
    config: &SealConfig,
    passphrase_file: Option<&Path>,
    prompter: &dyn Prompter,
) -> anyhow::Result<(RootKey, Zeroizing<String>)> {
    let wrapped = config
        .wrapped
        .clone()
        .context("passphrase mode without a wrapped root key")?;
    let passphrase = read_passphrase(passphrase_file, "Passphrase: ", prompter)?;
    let root = unwrap_root_key_checked(&wrapped, &passphrase)
        .map_err(|_| anyhow::anyhow!("the passphrase is wrong"))?
        .root;
    Ok((root, passphrase))
}

async fn connect(database_url: &str) -> anyhow::Result<SqlStore> {
    SqlStore::connect(database_url).await.context("opening database")
}

/// An existing database, locked against the server and other admin commands, with any
/// migrations applied: nothing else can be using it.
async fn open_locked(store: &StoreArgs, sources: &Sources) -> anyhow::Result<(StoreLocation, InstanceLock, SqlStore)> {
    let location = store.locate(sources)?;
    let url = existing_database(&location.database_url)?;
    let lock = lock(&url).await?;
    let sql = SqlStore::open(&url, Open::Migrate).await.context("opening database")?;
    Ok((location, lock, sql))
}

pub async fn run_admin(command: AdminCommand, sources: &Sources) -> anyhow::Result<()> {
    let prompter = Terminal;
    match command {
        AdminCommand::GenerateRootKey => {
            println!("{}", RootKey::generate()?.to_base64().as_str());
        }
        AdminCommand::WebCheck => {
            if !sekret_server::web_embedded() {
                bail!("no web interface embedded");
            }
            println!("web interface embedded");
        }
        AdminCommand::Bootstrap {
            store,
            ttl,
            passphrase_file,
        } => {
            // No instance lock: this writes nothing under the root key, and it is how admin
            // access is recovered on a server that is running.
            let location = store.locate(sources)?;
            // Never migrates: a running server of another version would break under it.
            let url = existing_database(&location.database_url)?;
            let sql: Arc<dyn Store> = Arc::new(SqlStore::open(&url, Open::Exact).await.context("opening database")?);
            let epoch_files = marks_of(&location)?;
            let source = RootSource {
                key_file: location.root_key_file.as_deref(),
                epoch_files: &epoch_files,
                passphrase_file: passphrase_file.as_deref(),
                marks: MarkCheck::Enforce,
            };
            let (root, config, _) = obtain_root(sql.as_ref(), source, &prompter).await?;
            let mode = config.map_or(SealMode::KeyFile, |c| c.mode);
            let state = state(
                admin_config(&location.database_url),
                sql.clone(),
                Keyring::unsealed(root, mode),
            )?;
            let token = sekret_server::admin::bootstrap_admin(&state, ttl)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            audit_admin(sql.as_ref(), "admin.bootstrap", json!({"ttl": ttl})).await;
            println!("{token}");
        }
        AdminCommand::Init {
            store,
            key_file_mode,
            passphrase_file,
            unlock,
            ttl,
        } => {
            let location = store.locate(sources)?;
            let _lock = lock(&location.database_url).await?;
            let sql: Arc<dyn Store> = Arc::new(connect(&location.database_url).await?);
            let mode = if key_file_mode {
                SealMode::KeyFile
            } else {
                SealMode::Passphrase
            };
            let passphrase = match mode {
                SealMode::Passphrase => Some(read_new_passphrase(passphrase_file.as_deref(), &prompter)?),
                SealMode::KeyFile => None,
            };
            let plan = InitPlan {
                mode,
                passphrase,
                unlock_policy: unlock,
                key_file: location.root_key_file.clone(),
                reuse_key_file: false,
                epoch_files: marks_of(&location)?,
            };
            let (root, _) = initialise(sql.as_ref(), SystemClock.now(), plan, None).await?;
            let state = state(
                admin_config(&location.database_url),
                sql.clone(),
                Keyring::unsealed_shared(root, mode),
            )?;
            let token = sekret_server::admin::bootstrap_admin(&state, ttl)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            audit_admin(
                sql.as_ref(),
                "admin.init",
                json!({"mode": mode.as_str(), "unlock_policy": unlock.as_str()}),
            )
            .await;
            eprintln!(
                "initialised in {} mode; restart the server, then sign in with this token:",
                mode.as_str()
            );
            if unlock == UnlockPolicy::Remember {
                eprintln!("the remember policy needs seal.remember_file set in the server's configuration");
            }
            println!("{token}");
        }
        AdminCommand::RotateRootKey {
            store,
            new_root_key_file,
            passphrase_file,
            skip_unreadable,
        } => {
            let (location, _lock, sql) = open_locked(&store, sources).await?;
            rotate(
                &sql,
                &location,
                RotateInputs {
                    new_root_key_file: new_root_key_file.as_deref(),
                    passphrase_file: passphrase_file.as_deref(),
                    skip_unreadable,
                },
                &prompter,
            )
            .await?;
        }
        AdminCommand::ResetEpoch {
            store,
            passphrase_file,
            adopt_root_key,
        } => {
            let (location, _lock, sql) = open_locked(&store, sources).await?;
            let marks = match adopt_root_key {
                true => MarkCheck::Adopt,
                false => MarkCheck::Enforce,
            };
            reset_epoch_marks(&sql, &location, passphrase_file.as_deref(), marks, &prompter).await?;
        }
        AdminCommand::SetSealMode {
            store,
            mode,
            passphrase_file,
            skip_unreadable,
        } => {
            let (location, _lock, sql) = open_locked(&store, sources).await?;
            let inputs = SealModeInputs {
                mode,
                passphrase_file: passphrase_file.as_deref(),
                skip_unreadable,
            };
            set_seal_mode(&sql, &location, inputs, &prompter).await?;
        }
        AdminCommand::Restore {
            backup,
            database_url,
            passphrase_file,
            root_key_file,
        } => {
            // Locks the target's name without creating the file, which must not exist yet.
            let _lock = lock(&sekret_store::without_create(&database_url)).await?;
            restore(
                &backup,
                &database_url,
                passphrase_file.as_deref(),
                root_key_file.as_deref(),
                &prompter,
            )
            .await?;
        }
    }
    Ok(())
}

/// Replaces the root key offline and re-encrypts everything. In passphrase mode the passphrase is
/// always checked against the stored wrap, even when a key file is present, because the new wrap
/// is made with it and a typo would lock the owner out.
struct RotateInputs<'a> {
    new_root_key_file: Option<&'a Path>,
    passphrase_file: Option<&'a Path>,
    skip_unreadable: bool,
}

async fn rotate(
    sql: &SqlStore,
    location: &StoreLocation,
    inputs: RotateInputs<'_>,
    prompter: &dyn Prompter,
) -> anyhow::Result<()> {
    let epoch_files = marks_of(location)?;
    let marks = high_water(&epoch_files);
    let config = sql.get_seal_config().await?;
    let (old, seal) = match config.filter(|c| c.mode == SealMode::Passphrase) {
        Some(config) => {
            let (old, passphrase) = unwrap_with_passphrase(&config, inputs.passphrase_file, prompter)?;
            if let Some(path) = location.root_key_file.as_deref().filter(|p| p.exists())
                && read_root_key(path)?.fingerprint() != old.fingerprint()
            {
                bail!(
                    "{} holds a different root key from the one the passphrase opens",
                    path.display()
                );
            }
            validate_passphrase(&passphrase)?;
            check_root(sql, &epoch_files, &old).await?;
            // Only a configuration signed by the server, and not older than the marks, keeps
            // what it grants, and only a signed one keeps its flags.
            let verdict = verify_config(&old, &config, marks);
            warn_if_tampered(&old, Some(&config), marks);
            (old, Some((config, passphrase, verdict)))
        }
        None => {
            let path = location
                .root_key_file
                .as_deref()
                .filter(|p| p.exists())
                .context("this database is in key-file mode; pass --root-key-file")?;
            let old = read_root_key(path)?;
            check_root(sql, &epoch_files, &old).await?;
            (old, None)
        }
    };
    let new = match (inputs.new_root_key_file, &seal) {
        (Some(path), _) => read_root_key(path)?,
        (None, Some(_)) => RootKey::generate()?,
        (None, None) => bail!("key-file mode needs --new-root-key-file"),
    };
    let seal_config = match &seal {
        None => None,
        Some((config, passphrase, verdict)) => Some(SealConfig {
            wrapped: Some(wrap_root_key(&new, passphrase)?),
            // The remembered wrap holds the old key; the next manual unlock remembers again.
            remembered: None,
            unlock_policy: if verdict.is_err() {
                UnlockPolicy::Manual
            } else {
                config.unlock_policy
            },
            flags: if *verdict == Ok(false) {
                config.flags
            } else {
                cautious_flags(config.flags, false)
            },
            updated_at: SystemClock.now(),
            ..config.clone()
        }),
    };
    let report = replace_root(sql, &old, &new, seal_config, &epoch_files, inputs.skip_unreadable).await?;
    let count = report.projects;
    audit_admin(
        sql,
        "admin.rotate_root_key",
        json!({"projects": count, "fingerprint": new.fingerprint(), "skipped": report.skipped}),
    )
    .await;
    match seal {
        Some(_) => eprintln!(
            "replaced the root key and re-encrypted the secrets of {count} projects; it is wrapped under the \
             passphrase you entered. Backups taken before this still open with that passphrase and the old key."
        ),
        None => eprintln!(
            "replaced the root key and re-encrypted the secrets of {count} projects; start the server with the new \
             root key file"
        ),
    }
    stale_marks(&report)
}

/// Fails a command whose change was committed but whose epoch marks were left behind.
fn stale_marks(report: &RotationReport) -> anyhow::Result<()> {
    match &report.stale_marks {
        Some(message) => bail!("{message}"),
        None => Ok(()),
    }
}

/// Replaces the root key with `new`, re-encrypting everything, and moves the epoch marks with it.
/// Rows that no longer decrypt are refused unless `skip_unreadable`, then only reported.
async fn replace_root(
    sql: &SqlStore,
    old: &RootKey,
    new: &RootKey,
    seal: Option<SealConfig>,
    epoch_files: &[PathBuf],
    skip_unreadable: bool,
) -> anyhow::Result<RotationReport> {
    let rotation = Rotation {
        marks: high_water(epoch_files),
        skip_unreadable,
        epoch_files,
    };
    let report = sekret_server::admin::rotate_root_key(sql, old, new, seal, rotation)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    for row in &report.skipped {
        eprintln!("warning: left unreadable {row} as it was");
    }
    Ok(report)
}

struct SealModeInputs<'a> {
    mode: SealMode,
    passphrase_file: Option<&'a Path>,
    skip_unreadable: bool,
}

/// The flags a configuration keeps when it is re-signed under a new mode: all of them when it is
/// signed and sound, otherwise nothing migrated again, since an unsigned configuration's flags
/// may be a database writer's. With no configuration, marks mean one existed.
fn carried_flags(root: &RootKey, current: Option<&SealConfig>, marks: HighWater) -> SealFlags {
    match current.map(|c| (c, verify_config(root, c, marks))) {
        Some((c, Ok(false))) => c.flags,
        Some((c, Ok(true) | Err(_))) => cautious_flags(c.flags, false),
        None if marks.highest.is_some() || marks.broken => cautious_flags(SealFlags::default(), false),
        None => SealFlags::default(),
    }
}

/// Switches mode under a newly generated root key, like a passphrase change, so neither an old
/// copy of the key file nor the old passphrase with an old wrap opens the live database.
async fn set_seal_mode(
    sql: &SqlStore,
    location: &StoreLocation,
    inputs: SealModeInputs<'_>,
    prompter: &dyn Prompter,
) -> anyhow::Result<()> {
    let mode = inputs.mode;
    let current = sql.get_seal_config().await?;
    let current_mode = current.as_ref().map_or(SealMode::KeyFile, |c| c.mode);
    if current_mode == mode {
        bail!("the database is already in {} mode", mode.as_str());
    }
    let now = SystemClock.now();
    let epoch_files = marks_of(location)?;
    let marks = high_water(&epoch_files);
    let new = RootKey::generate()?;
    let report = match mode {
        SealMode::KeyFile => {
            let path = location
                .root_key_file
                .as_deref()
                .context("pass --root-key-file: the new root key is written there")?;
            let source = RootSource {
                key_file: None,
                epoch_files: &epoch_files,
                passphrase_file: inputs.passphrase_file,
                marks: MarkCheck::Enforce,
            };
            let (old, config, _) = obtain_root(sql, source, prompter).await?;
            let config = config.context("no seal configuration")?;
            let seal = SealConfig {
                mode: SealMode::KeyFile,
                wrapped: None,
                unlock_policy: UnlockPolicy::Manual,
                remembered: None,
                flags: carried_flags(&old, Some(&config), marks),
                updated_at: now,
                ..config
            };
            write_new_private(path, new.to_key_file_text().as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            let replaced = replace_root(sql, &old, &new, Some(seal), &epoch_files, inputs.skip_unreadable).await;
            if replaced.is_err() {
                let _ = std::fs::remove_file(path);
            }
            let report = replaced?;
            if let Some(remember) = &location.remember_file
                && let Err(error) = remove_device_key_file(remember)
            {
                eprintln!("could not remove the remember file {}: {error}", remember.display());
            }
            eprintln!(
                "now in key-file mode under a new root key; start the server with --root-key-file {}. The old \
                 passphrase no longer opens the live database, but backups taken before this still open with it",
                path.display()
            );
            report
        }
        SealMode::Passphrase => {
            let path = location
                .root_key_file
                .as_deref()
                .context("pass --root-key-file with the current root key")?;
            let old = read_root_key(path)?;
            check_root(sql, &epoch_files, &old).await?;
            let passphrase = read_new_passphrase(inputs.passphrase_file, prompter)?;
            let flags = carried_flags(&old, current.as_ref(), marks);
            if current.is_none() {
                // Replacing the key re-signs the stored configuration, so there has to be one.
                let base = SealConfig {
                    mode: SealMode::KeyFile,
                    wrapped: None,
                    unlock_policy: UnlockPolicy::Manual,
                    remembered: None,
                    epoch: 0,
                    mac: None,
                    flags,
                    created_at: now,
                    updated_at: now,
                };
                sql.init_seal_config(signed(&old, base, marks.floor())?, &old.fingerprint())
                    .await?;
            }
            let stored = sql.get_seal_config().await?.context("no seal configuration")?;
            let seal = SealConfig {
                mode: SealMode::Passphrase,
                wrapped: Some(wrap_root_key(&new, &passphrase)?),
                unlock_policy: UnlockPolicy::Manual,
                remembered: None,
                flags,
                updated_at: now,
                ..stored
            };
            let report = replace_root(sql, &old, &new, Some(seal), &epoch_files, inputs.skip_unreadable).await?;
            eprintln!(
                "now in passphrase mode under a new root key; start the server without --root-key-file and unseal \
                 it. {} and every copy of it no longer open the live database, so delete them; backups taken \
                 before this still open with that key",
                path.display()
            );
            report
        }
    };
    audit_admin(
        sql,
        "admin.set_seal_mode",
        json!({
            "mode": mode.as_str(),
            "root_key_rotated": true,
            "fingerprint": new.fingerprint(),
            "projects": report.projects,
            "skipped": report.skipped,
        }),
    )
    .await;
    stale_marks(&report)
}

/// What `reset-epoch` keeps of a configuration, given what checking it found. A sound one keeps
/// everything, though an unsigned one never starts a migration. One older than the marks keeps
/// its fields, which this root signed once, but grants nothing. One that fails its signature only
/// keeps what the operator has just proved (the passphrase wrap, or key-file mode) and grants
/// nothing.
fn reset_config(config: SealConfig, verdict: Result<bool, Distrust>) -> SealConfig {
    match verdict {
        Ok(false) => config,
        Ok(true) => SealConfig {
            flags: cautious_flags(config.flags, false),
            ..config
        },
        Err(Distrust::RolledBack) => SealConfig {
            unlock_policy: UnlockPolicy::Manual,
            remembered: None,
            flags: cautious_flags(config.flags, false),
            ..config
        },
        Err(Distrust::Tampered) => SealConfig {
            mode: match config.wrapped {
                Some(_) if config.mode == SealMode::Passphrase => SealMode::Passphrase,
                _ => SealMode::KeyFile,
            },
            wrapped: config.wrapped.filter(|_| config.mode == SealMode::Passphrase),
            unlock_policy: UnlockPolicy::Manual,
            remembered: None,
            flags: cautious_flags(config.flags, false),
            ..config
        },
    }
}

/// The explicit operator command for marks that disagree with the database. The configuration is
/// checked with the root key and the marks, reset by [`reset_config`], signed above the marks and
/// the marks raised to it, so no configuration signed earlier can be replayed afterwards. Only
/// when the epochs have run out are the marks lowered, starting again from the bottom. With
/// `--adopt-root-key` the marks are also moved to the database's root key.
async fn reset_epoch_marks(
    sql: &SqlStore,
    location: &StoreLocation,
    passphrase_file: Option<&Path>,
    marks_check: MarkCheck,
    prompter: &dyn Prompter,
) -> anyhow::Result<()> {
    let paths = marks_of(location)?;
    let source = RootSource {
        key_file: location.root_key_file.as_deref(),
        epoch_files: &paths,
        passphrase_file,
        marks: marks_check,
    };
    let (root, config, _) = obtain_root(sql, source, prompter).await?;
    let config = config.context("the database has no seal configuration yet")?;
    let fingerprint = root.fingerprint();
    let adopted = !root_recognised(&paths, &fingerprint);
    let marks = high_water(&paths);
    let verdict = verify_config(&root, &config, marks);
    let base = SealConfig {
        updated_at: SystemClock.now(),
        ..reset_config(config, verdict)
    };
    let (config, restarted) = match signed(&root, base.clone(), marks.floor()) {
        Ok(config) => (config, false),
        Err(_) => (signed(&root, SealConfig { epoch: 0, ..base }, 0)?, true),
    };
    sql.update_seal_config(config.clone()).await?;
    match restarted {
        true => reset_epoch(&paths, config.epoch, &fingerprint),
        false => record_epoch(&paths, config.epoch, &fingerprint),
    }
    .context("writing the epoch marks")?;
    audit_admin(
        sql,
        "admin.reset_epoch",
        json!({
            "epoch": config.epoch,
            "was_sound": verdict.is_ok(),
            "rolled_back": verdict == Err(Distrust::RolledBack),
            "adopted_root_key": adopted,
        }),
    )
    .await;
    let note = match verdict {
        Ok(_) => "",
        Err(Distrust::RolledBack) => {
            "; it was older than the marks, so the unlock policy is now manual and any remembered unlock is forgotten"
        }
        Err(Distrust::Tampered) => "; it had failed its signature, so the unlock policy is now manual",
    };
    eprintln!(
        "signed the seal configuration at epoch {} and raised {} epoch mark(s) to it{note}",
        config.epoch,
        paths.len(),
    );
    if adopted {
        eprintln!("the epoch marks now name root key {fingerprint}");
    }
    Ok(())
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Opens the restored file read-only and checks it is intact and belongs to `fingerprint`.
async fn verify_restored(path: &Path, fingerprint: &str) -> anyhow::Result<()> {
    use sqlx::{ConnectOptions, Row};
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .immutable(true)
        .connect()
        .await
        .context("opening the restored database")?;
    let check: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut conn)
        .await
        .context("checking the restored database")?
        .try_get(0)
        .context("integrity check")?;
    if check != "ok" {
        bail!("the restored database failed its integrity check: {check}");
    }
    let stored: String = sqlx::query("SELECT value FROM meta WHERE key = 'root_key_fingerprint'")
        .fetch_one(&mut conn)
        .await
        .context("reading the restored root key fingerprint")?
        .try_get("value")
        .context("fingerprint")?;
    if stored != fingerprint {
        bail!("the restored database belongs to another root key");
    }
    sqlx::Connection::close(conn).await.context("closing")?;
    Ok(())
}

/// The temporary name a restore uses beside `target`, before the process id.
fn restore_prefix(target: &Path) -> anyhow::Result<std::ffi::OsString> {
    let mut name = std::ffi::OsString::from(".");
    name.push(target.file_name().context("the target has no file name")?);
    name.push(".restore-");
    Ok(name)
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Removes what an interrupted restore left beside `target`: staging directories and files.
fn clean_stale_restores(target: &Path) -> anyhow::Result<()> {
    let prefix = restore_prefix(target)?;
    let prefix = prefix.to_string_lossy();
    let Ok(entries) = std::fs::read_dir(parent_dir(target)) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(prefix.as_ref()) {
            continue;
        }
        let path = entry.path();
        let removed = match entry.file_type() {
            Ok(kind) if kind.is_dir() => std::fs::remove_dir_all(&path),
            Ok(kind) if kind.is_file() => std::fs::remove_file(&path),
            _ => continue,
        };
        match removed {
            Ok(()) => eprintln!("removed {} left by an interrupted restore", path.display()),
            Err(error) => eprintln!("could not remove {}: {error}", path.display()),
        }
    }
    Ok(())
}

/// Whether `file` is still the file at `path`.
#[cfg(unix)]
fn same_file(file: &std::fs::File, path: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let open = file.metadata().context("the open file")?;
    let named = std::fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
    Ok(named.is_file() && (open.dev(), open.ino()) == (named.dev(), named.ino()))
}

#[cfg(not(unix))]
fn same_file(_file: &std::fs::File, _path: &Path) -> anyhow::Result<bool> {
    Ok(true)
}

/// A path that reaches an open file through its descriptor, whatever happens to its name.
#[cfg(target_os = "linux")]
fn fd_path(file: &std::fs::File) -> PathBuf {
    use std::os::unix::io::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Creates `target` from an open file, never through a name someone else could swap. A hard
/// link fails if the target appeared meanwhile, so nothing is ever overwritten.
#[cfg(target_os = "linux")]
fn link_open_file(file: &std::fs::File, _staged: &Path, target: &Path) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from = CString::new(fd_path(file).as_os_str().as_bytes()).context("descriptor path")?;
    let to = CString::new(target.as_os_str().as_bytes()).context("target path")?;
    // SAFETY: both arguments are NUL-terminated strings that outlive the call.
    let linked = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if linked != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("creating {}", target.display()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn link_open_file(_file: &std::fs::File, staged: &Path, target: &Path) -> anyhow::Result<()> {
    std::fs::hard_link(staged, target).with_context(|| format!("moving the database to {}", target.display()))
}

/// Writes the snapshot into a fresh owner-only directory beside the target, so nobody else can
/// reach or swap it, checks it, confirms through the open handle that the checked file is the one
/// written, then gives that file the target's name.
async fn place_restored(target: &Path, snapshot: &[u8], fingerprint: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let prefix = restore_prefix(target)?;
    let staging = tempfile::Builder::new()
        .prefix(&prefix)
        .tempdir_in(parent_dir(target))
        .context("creating a private staging directory")?;
    let staged = staging.path().join("restored.db");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    file.write_all(snapshot).context("writing the restored database")?;
    file.sync_all().context("syncing the restored database")?;
    verify_restored(&staged, fingerprint).await?;
    if !same_file(&file, &staged)? {
        bail!(
            "{} was replaced while it was checked; not restoring it",
            staged.display()
        );
    }
    link_open_file(&file, &staged, target)?;
    sekret_server::files::sync_parent(target).context("syncing the directory")?;
    Ok(())
}

async fn restore(
    backup: &Path,
    database_url: &str,
    passphrase_file: Option<&Path>,
    root_key_file: Option<&Path>,
    prompter: &dyn Prompter,
) -> anyhow::Result<()> {
    let target =
        sqlite_path(database_url).context("restore writes a SQLite database; pass --database-url sqlite://FILE")?;
    clean_stale_restores(&target)?;
    if target.symlink_metadata().is_ok() {
        bail!(
            "{} already exists; restore refuses to overwrite a database",
            target.display()
        );
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let leftover = sibling(&target, suffix);
        if leftover.symlink_metadata().is_ok() {
            bail!(
                "{} exists; it belongs to another database and would corrupt the restored one, so remove it first",
                leftover.display()
            );
        }
    }
    let file = read_limited(backup, MAX_BACKUP_LEN as u64).with_context(|| format!("reading {}", backup.display()))?;
    let parsed = parse_backup(&file).context("this is not a sekret backup")?;
    // Nothing from the header is shown until the body has proved it, since a crafted file could
    // carry terminal escape sequences.
    let root = match (root_key_file, parsed.header.wrapped()?) {
        (Some(path), _) => read_root_key(path)?,
        (None, Some(wrapped)) => {
            let passphrase = read_passphrase(passphrase_file, "Backup passphrase: ", prompter)?;
            unwrap_root_key(&wrapped, &passphrase).map_err(|_| anyhow::anyhow!("the passphrase is wrong"))?
        }
        (None, None) => bail!("this backup was made in key-file mode; pass --root-key-file"),
    };
    if root.fingerprint() != parsed.header.root_fingerprint {
        bail!("that root key does not belong to this backup");
    }
    let snapshot = decrypt_backup(&root, &parsed).context("the backup is damaged or was changed")?;
    let version = one_line(&parsed.header.version);
    eprintln!(
        "backup taken at {} (Unix seconds) by sekret {version}, root key fingerprint {}",
        parsed.header.created_at,
        root.fingerprint()
    );
    place_restored(&target, &snapshot, &root.fingerprint()).await?;
    let restored = SqlStore::open(database_url, Open::Migrate)
        .await
        .context("opening the restored database")?;
    mark_restored(&restored, database_url, &root).await;
    audit_admin(
        &restored,
        "admin.restore",
        json!({"backup_created_at": parsed.header.created_at, "backup_version": parsed.header.version}),
    )
    .await;
    eprintln!(
        "restored {} from a backup taken by sekret {version}; start a server on it",
        target.display()
    );
    Ok(())
}

/// Text from a file that was not written here, safe to print on one terminal line.
fn one_line(text: &str) -> String {
    sekret_client::terminal_safe(text).replace(['\n', '\t'], " ")
}

/// Starts the restored database's own epoch mark at its configuration and root key, which the
/// restore has just proved. A mark already there for another root key is left for the operator.
async fn mark_restored(restored: &SqlStore, database_url: &str, root: &RootKey) {
    let paths = sekret_server::config::epoch_files(database_url, None, None, None);
    let fingerprint = root.fingerprint();
    if !root_recognised(&paths, &fingerprint) {
        eprintln!(
            "warning: an epoch mark beside the restored database names another root key, so a server will refuse \
             it; if that mark is from an older database, run `sekret admin reset-epoch --adopt-root-key`"
        );
        return;
    }
    let epoch = match restored.get_seal_config().await {
        Ok(Some(config)) => config.epoch,
        _ => return,
    };
    if let Err(error) = record_epoch(&paths, epoch, &fingerprint) {
        eprintln!("warning: could not write the epoch mark beside the restored database: {error}");
    }
}
