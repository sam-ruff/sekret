use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::Subcommand;
use sekret_core::crypto::RootKey;
use sekret_core::seal::{
    MAX_BACKUP_LEN, SealMode, UnlockPolicy, decrypt_backup, parse_backup, trim_input, unwrap_root_key,
    unwrap_root_key_checked, validate_passphrase, wrap_root_key,
};
use sekret_server::clock::{Clock, SystemClock};
use sekret_server::config::{SealSettings, ServerConfig};
use sekret_server::files::{
    SECRET_FILE_LIMIT, WrittenFile, can_create, read_limited, write_new_private, write_new_recorded,
};
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::seal::{
    AutoInit, InitPlan, Keyring, Signature, StartupSecrets, audit_as, check_signature, initialise, open_keyring,
    record_epoch, signed,
};
use sekret_server::state::{AppState, Dependencies, build_state};
use sekret_store::{InstanceLock, SealConfig, SqlStore, Store};
use serde_json::json;
use zeroize::Zeroizing;

use crate::prompt::{Prompter, Terminal, read_new_passphrase, read_passphrase};
use crate::settings::{self, EnvSecrets, Report, ServerArgs, Setup, Sources, StoreArgs, StoreLocation, sqlite_path};

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Print a short-lived organisation admin token for first-time setup or recovery.
    Bootstrap {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long, default_value_t = 3600)]
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
        #[arg(long, default_value_t = 3600)]
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
    },
    /// Switch between passphrase and key-file mode. Stop the server first.
    SetSealMode {
        #[command(flatten)]
        store: StoreArgs,
        /// passphrase or key-file.
        #[arg(value_parser = parse_seal_mode)]
        mode: SealMode,
        /// The current passphrase when leaving passphrase mode, or the new one when entering it.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
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

/// Takes the database's instance lock, or explains that something else has it.
async fn lock(database_url: &str) -> anyhow::Result<InstanceLock> {
    InstanceLock::acquire(database_url).await.map_err(|error| {
        if InstanceLock::is_held_error(&error) {
            anyhow::anyhow!("{error}")
        } else {
            anyhow::anyhow!("taking the database lock: {error}")
        }
    })
}

pub async fn run_server(args: ServerArgs, env_secrets: EnvSecrets) -> anyhow::Result<()> {
    if args.print_config {
        print!("{}", settings::EXAMPLE);
        return Ok(());
    }
    let file = settings::load(args.store.config.as_deref())?;
    let settings::Resolved {
        mut config,
        setup,
        report,
    } = settings::resolve_with(&args, file, &env_secrets, &Sources::process())?;
    log_report(&report);
    // Held for the life of the server, so admin commands cannot write underneath it.
    let _lock = lock(&config.database_url).await?;
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
    sekret_server::serve(state).await?;
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

/// Warns, without changing anything, when the stored configuration fails its signature.
fn warn_if_tampered(root: &RootKey, config: Option<&SealConfig>) {
    if config.is_some_and(|c| check_signature(root, c) == Signature::Invalid) {
        eprintln!(
            "warning: the seal configuration was changed without the root key; the server will reset it to the \
             manual unlock policy when it next unlocks"
        );
    }
}

/// The root key on the host, offline: from the key file, or by unwrapping it with the passphrase.
/// Also returns the passphrase when one was used.
async fn obtain_root(
    store: &dyn Store,
    location: &StoreLocation,
    passphrase_file: Option<&Path>,
    prompter: &dyn Prompter,
) -> anyhow::Result<(RootKey, Option<SealConfig>, Option<Zeroizing<String>>)> {
    let config = store.get_seal_config().await?;
    let key_file = location.root_key_file.as_deref().filter(|p| p.exists());
    let passphrase_mode = config.as_ref().is_some_and(|c| c.mode == SealMode::Passphrase);
    let (root, passphrase) = match (passphrase_mode, key_file, &config) {
        (_, Some(path), _) => (read_root_key(path)?, None),
        (true, None, Some(config)) => {
            let (root, passphrase) = unwrap_with_passphrase(config, passphrase_file, prompter)?;
            (root, Some(passphrase))
        }
        _ => bail!("this database is in key-file mode; pass --root-key-file"),
    };
    sekret_server::check_root_key(store, &root.fingerprint()).await?;
    warn_if_tampered(&root, config.as_ref());
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

pub async fn run_admin(command: AdminCommand) -> anyhow::Result<()> {
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
            let location = store.locate()?;
            let sql: Arc<dyn Store> = Arc::new(connect(&location.database_url).await?);
            let (root, config, _) = obtain_root(sql.as_ref(), &location, passphrase_file.as_deref(), &prompter).await?;
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
            let location = store.locate()?;
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
                epoch_files: location.epoch_files(),
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
        } => {
            let location = store.locate()?;
            let _lock = lock(&location.database_url).await?;
            let sql = connect(&location.database_url).await?;
            rotate(
                &sql,
                &location,
                new_root_key_file.as_deref(),
                passphrase_file.as_deref(),
                &prompter,
            )
            .await?;
        }
        AdminCommand::SetSealMode {
            store,
            mode,
            passphrase_file,
        } => {
            let location = store.locate()?;
            let _lock = lock(&location.database_url).await?;
            let sql = connect(&location.database_url).await?;
            set_seal_mode(&sql, &location, mode, passphrase_file.as_deref(), &prompter).await?;
        }
        AdminCommand::Restore {
            backup,
            database_url,
            passphrase_file,
            root_key_file,
        } => {
            let _lock = lock(&database_url).await?;
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
async fn rotate(
    sql: &SqlStore,
    location: &StoreLocation,
    new_root_key_file: Option<&Path>,
    passphrase_file: Option<&Path>,
    prompter: &dyn Prompter,
) -> anyhow::Result<()> {
    let config = sql.get_seal_config().await?;
    let (old, seal) = match config.filter(|c| c.mode == SealMode::Passphrase) {
        Some(config) => {
            let (old, passphrase) = unwrap_with_passphrase(&config, passphrase_file, prompter)?;
            if let Some(path) = location.root_key_file.as_deref().filter(|p| p.exists())
                && read_root_key(path)?.fingerprint() != old.fingerprint()
            {
                bail!(
                    "{} holds a different root key from the one the passphrase opens",
                    path.display()
                );
            }
            validate_passphrase(&passphrase)?;
            sekret_server::check_root_key(sql, &old.fingerprint()).await?;
            // Only a configuration signed by the server keeps what it grants.
            let tampered = check_signature(&old, &config) != Signature::Valid;
            warn_if_tampered(&old, Some(&config));
            (old, Some((config, passphrase, tampered)))
        }
        None => {
            let path = location
                .root_key_file
                .as_deref()
                .filter(|p| p.exists())
                .context("this database is in key-file mode; pass --root-key-file")?;
            let old = read_root_key(path)?;
            sekret_server::check_root_key(sql, &old.fingerprint()).await?;
            (old, None)
        }
    };
    let new = match (new_root_key_file, &seal) {
        (Some(path), _) => read_root_key(path)?,
        (None, Some(_)) => RootKey::generate()?,
        (None, None) => bail!("key-file mode needs --new-root-key-file"),
    };
    let seal_config = match &seal {
        None => None,
        Some((config, passphrase, tampered)) => Some(SealConfig {
            wrapped: Some(wrap_root_key(&new, passphrase)?),
            // The remembered wrap holds the old key; the next manual unlock remembers again.
            remembered: None,
            unlock_policy: if *tampered {
                UnlockPolicy::Manual
            } else {
                config.unlock_policy
            },
            updated_at: SystemClock.now(),
            ..config.clone()
        }),
    };
    let count = sekret_server::admin::rotate_root_key(sql, &old, &new, seal_config)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    if let Some(stored) = sql.get_seal_config().await? {
        record_epoch(&location.epoch_files(), stored.epoch, false);
    }
    audit_admin(
        sql,
        "admin.rotate_root_key",
        json!({"projects": count, "fingerprint": new.fingerprint()}),
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
    Ok(())
}

async fn set_seal_mode(
    sql: &SqlStore,
    location: &StoreLocation,
    mode: SealMode,
    passphrase_file: Option<&Path>,
    prompter: &dyn Prompter,
) -> anyhow::Result<()> {
    let current = sql.get_seal_config().await?;
    let current_mode = current.as_ref().map_or(SealMode::KeyFile, |c| c.mode);
    if current_mode == mode {
        bail!("the database is already in {} mode", mode.as_str());
    }
    let now = SystemClock.now();
    let config = match mode {
        SealMode::KeyFile => {
            let path = location
                .root_key_file
                .as_deref()
                .context("pass --root-key-file: the root key is written there")?;
            let empty = StoreLocation {
                database_url: location.database_url.clone(),
                root_key_file: None,
                remember_file: None,
            };
            let (root, config, _) = obtain_root(sql, &empty, passphrase_file, prompter).await?;
            write_new_private(path, root.to_key_file_text().as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            let config = config.context("no seal configuration")?;
            let config = SealConfig {
                mode: SealMode::KeyFile,
                wrapped: None,
                unlock_policy: UnlockPolicy::Manual,
                remembered: None,
                updated_at: now,
                ..config
            };
            let config = signed(&root, config)?;
            sql.update_seal_config(config.clone()).await?;
            eprintln!(
                "now in key-file mode; start the server with --root-key-file {}",
                path.display()
            );
            config
        }
        SealMode::Passphrase => {
            let path = location
                .root_key_file
                .as_deref()
                .context("pass --root-key-file with the current root key")?;
            let root = read_root_key(path)?;
            sekret_server::check_root_key(sql, &root.fingerprint()).await?;
            let passphrase = read_new_passphrase(passphrase_file, prompter)?;
            let config = SealConfig {
                mode: SealMode::Passphrase,
                wrapped: Some(wrap_root_key(&root, &passphrase)?),
                unlock_policy: UnlockPolicy::Manual,
                remembered: None,
                epoch: current.as_ref().map_or(0, |c| c.epoch),
                mac: None,
                created_at: current.as_ref().map_or(now, |c| c.created_at),
                updated_at: now,
            };
            let config = signed(&root, config)?;
            match current {
                Some(_) => sql.update_seal_config(config.clone()).await?,
                None => sql.init_seal_config(config.clone(), &root.fingerprint()).await?,
            }
            eprintln!(
                "now in passphrase mode; start the server without --root-key-file and unseal it, then remove {}",
                path.display()
            );
            config
        }
    };
    record_epoch(&location.epoch_files(), config.epoch, false);
    audit_admin(sql, "admin.set_seal_mode", json!({"mode": mode.as_str()})).await;
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
    eprintln!(
        "backup taken at {} (Unix seconds) by sekret {}, root key fingerprint {}",
        parsed.header.created_at, parsed.header.version, parsed.header.root_fingerprint
    );
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
    place_restored(&target, &snapshot, &root.fingerprint()).await?;
    let restored = connect(database_url).await?;
    audit_admin(
        &restored,
        "admin.restore",
        json!({"backup_created_at": parsed.header.created_at, "backup_version": parsed.header.version}),
    )
    .await;
    eprintln!(
        "restored {} from a backup taken by sekret {}; start a server on it",
        target.display(),
        parsed.header.version
    );
    Ok(())
}
