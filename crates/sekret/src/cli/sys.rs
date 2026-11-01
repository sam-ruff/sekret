//! `sekret sys`: setup, sealing, unlocking and backups against a running server.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;
use sekret_api::{
    ChangePassphrase, InitRequest, SealMode, SealState, SetUnlockPolicy, SysStatus, UnlockPolicy, UnsealRequest,
    UnsealedBy,
};
use sekret_client::SekretApi;

use crate::prompt::{Prompter, read_new_passphrase_for_api, read_passphrase_for_api, read_stdin_line, read_text_file};

#[derive(Debug, Subcommand)]
pub enum SysCommand {
    /// Show whether the server is set up and unlocked. Exits 0 when unsealed, 2 when sealed and
    /// 3 when not set up yet. Org admins also see how it was unlocked and its unlock policy.
    Status {
        #[arg(long)]
        json: bool,
        /// Ask the server's Unix socket on this host instead of its URL.
        #[arg(long)]
        socket: Option<PathBuf>,
        #[command(flatten)]
        owner: SocketOwner,
    },
    /// Set up a new server through its API with the code from its log, and print a one-time admin
    /// token. With web setup turned off, run `sekret admin init` on the host instead.
    Init {
        /// The setup code. Visible to other users in the process list; prefer --setup-code-file.
        #[arg(long, conflicts_with = "setup_code_file")]
        setup_code: Option<String>,
        /// Read the setup code from this file, or `-` for stdin.
        #[arg(long)]
        setup_code_file: Option<PathBuf>,
        /// Keep the root key in the server's --root-key-file instead of under a passphrase.
        #[arg(long)]
        key_file_mode: bool,
        /// Read the passphrase from this file, or `-` for stdin, instead of asking twice.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// manual, remember or passphrase-file; asked when not given.
        #[arg(long, value_parser = parse_unlock)]
        unlock: Option<UnlockPolicy>,
    },
    /// Unlock a sealed server with its passphrase.
    Unseal {
        /// Read the passphrase from this file, or `-` for stdin, instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Unseal through the server's Unix socket on this host (server.unix_socket), which the
        /// network's rate limits and back-off do not apply to.
        #[arg(long)]
        socket: Option<PathBuf>,
        #[command(flatten)]
        owner: SocketOwner,
    },
    /// Drop the root key from the server's memory until someone unseals it. Org admins only.
    Seal,
    /// Change the passphrase that protects the root key. Org admins only.
    ChangePassphrase {
        /// The current passphrase, from this file or `-` for stdin.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// The new passphrase, from this file.
        #[arg(long)]
        new_passphrase_file: Option<PathBuf>,
        /// Leave values, project keys and stored credentials that no longer decrypt as they are,
        /// and audit them, instead of refusing the change.
        #[arg(long)]
        skip_unreadable: bool,
    },
    /// Choose how the server unlocks after a restart: manual, remember or passphrase-file.
    /// remember and passphrase-file ask for the current passphrase.
    UnlockPolicy {
        #[arg(value_parser = parse_unlock)]
        policy: UnlockPolicy,
        /// The current passphrase, from this file or `-` for stdin, instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Delete the remembered unlock, so the next start needs the passphrase. Org admins only.
    ForgetUnlock,
    /// Download an encrypted backup. Needs the backups read permission.
    Backup {
        /// File to write (mode 0600), or `-` for stdout.
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
}

/// Who the host socket must belong to, besides root and the person running the command.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct SocketOwner {
    /// The user sekret runs as, by name or number. The socket must belong to root, you or this
    /// user, or nothing is sent to it.
    #[arg(long = "socket-owner", env = "SEKRET_SOCKET_OWNER", value_name = "USER")]
    pub name: Option<String>,
}

impl SysCommand {
    /// The host socket the command should use instead of the server's URL, if any, and the
    /// owner named for it.
    pub fn socket(&self) -> Option<(&std::path::Path, Option<&str>)> {
        match self {
            SysCommand::Status {
                socket: Some(socket),
                owner,
                ..
            }
            | SysCommand::Unseal {
                socket: Some(socket),
                owner,
                ..
            } => Some((socket.as_path(), owner.name.as_deref())),
            _ => None,
        }
    }
}

/// The full status for organisation admins, else what anyone may see.
async fn best_status(api: &dyn SekretApi) -> anyhow::Result<SysStatus> {
    match api.sys_status_detail().await {
        Ok(status) => Ok(status),
        Err(error) if matches!(error.status(), Some(401 | 403 | 404)) => Ok(api.sys_status().await?),
        Err(error) => Err(error.into()),
    }
}

fn parse_unlock(raw: &str) -> Result<UnlockPolicy, String> {
    UnlockPolicy::parse(raw).ok_or_else(|| "expected manual, remember or passphrase-file".into())
}

/// The exit code `sekret sys status` uses for each state.
pub fn exit_code(state: SealState) -> i32 {
    match state {
        SealState::Unsealed => 0,
        SealState::Sealed => 2,
        SealState::Uninitialised => 3,
    }
}

fn state_name(state: SealState) -> &'static str {
    match state {
        SealState::Unsealed => "unsealed",
        SealState::Sealed => "sealed",
        SealState::Uninitialised => "uninitialised",
    }
}

fn unsealed_by_name(by: UnsealedBy) -> &'static str {
    match by {
        UnsealedBy::Passphrase => "passphrase",
        UnsealedBy::Remember => "remember",
        UnsealedBy::KeyFile => "key-file",
        UnsealedBy::PassphraseFile => "passphrase-file",
    }
}

/// The setup code from the flag, a file, stdin with `-`, or a question.
fn setup_code(code: Option<String>, file: Option<PathBuf>, prompter: &dyn Prompter) -> anyhow::Result<String> {
    let text = match (code, file) {
        (Some(code), _) => return Ok(code),
        (None, Some(path)) if path.as_os_str() == "-" => read_stdin_line()?,
        (None, Some(path)) => read_text_file(&path)?,
        (None, None) => return prompter.line("Setup code (from the server log): "),
    };
    Ok(text.trim().to_string())
}

pub fn describe(status: &SysStatus) -> String {
    let mut text = format!("state: {}\n", state_name(status.state));
    if let Some(mode) = status.seal_mode {
        text.push_str(&format!("mode: {}\n", mode.as_str()));
    }
    if let Some(policy) = status.unlock_policy {
        let origin = if status.configured {
            " (set in configuration)"
        } else {
            ""
        };
        text.push_str(&format!("unlock: {}{origin}\n", policy.as_str()));
    }
    if let Some(by) = status.unsealed_by {
        let note = match (by, status.seal_mode) {
            (UnsealedBy::KeyFile, Some(SealMode::Passphrase)) => " (a root key file overrode the passphrase)",
            _ => "",
        };
        text.push_str(&format!("unlocked by: {}{note}\n", unsealed_by_name(by)));
    }
    if status.remembered {
        text.push_str("remembered: yes (the next restart unlocks itself, even after sealing by hand)\n");
    }
    if status.state == SealState::Uninitialised && !status.web_setup {
        text.push_str("setup: run `sekret admin init` on the server host\n");
    }
    text.push_str(&format!("version: {}\n", super::format::one_line(&status.version)));
    text
}

const UNLOCK_CHOICES: &str = "\
How should the server unlock after a restart?
  manual           unlock by hand after every start; the passphrase only ever lives in memory (most secure)
  remember         unlock by hand once; the server keeps a key file on its own disk and unlocks itself until that file is lost
  passphrase-file  the server reads the passphrase from a file or environment variable at start; the passphrase sits on disk
Unlock policy [manual]: ";

fn ask_unlock(prompter: &dyn Prompter) -> anyhow::Result<UnlockPolicy> {
    let answer = prompter.line(UNLOCK_CHOICES)?;
    match answer.trim().to_ascii_lowercase().as_str() {
        "" | "m" => Ok(UnlockPolicy::Manual),
        "r" => Ok(UnlockPolicy::Remember),
        "p" => Ok(UnlockPolicy::PassphraseFile),
        other => UnlockPolicy::parse(other)
            .ok_or_else(|| anyhow::anyhow!("expected manual, remember or passphrase-file, not {other:?}")),
    }
}

fn is_printable_token(token: &str) -> bool {
    !token.is_empty() && !token.chars().any(char::is_whitespace) && sekret_client::terminal_safe(token) == token
}

/// Raw backup bytes would be read by the terminal as escape sequences.
pub fn refuse_binary_to_terminal(command: &SysCommand, stdout_is_terminal: bool) -> anyhow::Result<()> {
    let SysCommand::Backup { output } = command else {
        return Ok(());
    };
    if output.as_os_str() == "-" && stdout_is_terminal {
        anyhow::bail!("a backup is binary; redirect it to a file or name one with -o FILE");
    }
    Ok(())
}

/// Runs a `sekret sys` command and returns the process exit code.
pub async fn run(
    api: &dyn SekretApi,
    command: SysCommand,
    prompter: &dyn Prompter,
    out: &mut dyn Write,
) -> anyhow::Result<i32> {
    match command {
        SysCommand::Status { json, .. } => {
            let status = best_status(api).await?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&status)?)?;
            } else {
                write!(out, "{}", describe(&status))?;
            }
            return Ok(exit_code(status.state));
        }
        SysCommand::Init {
            setup_code: code,
            setup_code_file,
            key_file_mode,
            passphrase_file,
            unlock,
        } => {
            let setup_code = setup_code(code, setup_code_file, prompter)?;
            let (mode, passphrase, unlock_policy) = if key_file_mode {
                (SealMode::KeyFile, None, None)
            } else {
                let passphrase = read_new_passphrase_for_api(passphrase_file.as_deref(), prompter)?;
                let policy = match (unlock, &passphrase_file) {
                    (Some(policy), _) => policy,
                    (None, Some(_)) => UnlockPolicy::Manual,
                    (None, None) => ask_unlock(prompter)?,
                };
                (SealMode::Passphrase, Some(passphrase), Some(policy))
            };
            let response = api
                .sys_init(InitRequest {
                    setup_code: setup_code.into(),
                    mode,
                    passphrase,
                    unlock_policy,
                })
                .await?;
            let token = &response.admin_token;
            if !is_printable_token(token) {
                anyhow::bail!("the server sent an admin token that is not a single printable word; not printing it");
            }
            writeln!(out, "{token}")?;
            eprintln!(
                "sekret is set up in {} mode. The line above is a break-glass admin token, valid for an hour \
                 and shown only once; use it with SEKRET_TOKEN, or sign in with `sekret login`.",
                mode.as_str()
            );
            if mode == SealMode::Passphrase {
                eprintln!("There is no recovery key: if the passphrase is lost, so is everything in sekret.");
            }
        }
        SysCommand::Unseal { passphrase_file, .. } => {
            let passphrase = read_passphrase_for_api(passphrase_file.as_deref(), "Passphrase: ", prompter)?;
            let status = api.sys_unseal(UnsealRequest { passphrase }).await?;
            write!(out, "{}", describe(&status))?;
        }
        SysCommand::Seal => {
            let status = api.sys_seal().await?;
            write!(out, "{}", describe(&status))?;
        }
        SysCommand::ChangePassphrase {
            passphrase_file,
            new_passphrase_file,
            skip_unreadable,
        } => {
            let current = read_passphrase_for_api(passphrase_file.as_deref(), "Current passphrase: ", prompter)?;
            let new = read_new_passphrase_for_api(new_passphrase_file.as_deref(), prompter)?;
            api.sys_change_passphrase(ChangePassphrase {
                current,
                new,
                skip_unreadable,
            })
            .await?;
            writeln!(out, "passphrase changed")?;
        }
        SysCommand::UnlockPolicy {
            policy,
            passphrase_file,
        } => {
            let passphrase = match policy {
                UnlockPolicy::Manual => None,
                UnlockPolicy::Remember | UnlockPolicy::PassphraseFile => Some(read_passphrase_for_api(
                    passphrase_file.as_deref(),
                    "Current passphrase: ",
                    prompter,
                )?),
            };
            let status = api
                .sys_set_unlock_policy(SetUnlockPolicy { policy, passphrase })
                .await?;
            write!(out, "{}", describe(&status))?;
        }
        SysCommand::ForgetUnlock => {
            let status = api.sys_forget_unlock().await?;
            write!(out, "{}", describe(&status))?;
        }
        SysCommand::Backup { output } => {
            let backup = api.sys_backup().await?;
            if output.as_os_str() == "-" {
                out.write_all(&backup)?;
            } else {
                sekret_server::files::write_private_atomic(&output, &backup)
                    .with_context(|| format!("writing {}", output.display()))?;
                eprintln!("wrote {} bytes to {}", backup.len(), output.display());
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::tests::Scripted;
    use mockall::predicate::function;
    use sekret_api::InitResponse;
    use sekret_client::MockSekretApi;

    fn status(state: SealState) -> SysStatus {
        SysStatus {
            state,
            seal_mode: Some(SealMode::Passphrase),
            unlock_policy: Some(UnlockPolicy::Manual),
            configured: true,
            remembered: false,
            remember_available: false,
            unsealed_by: None,
            web_setup: true,
            version: "0.1.0".into(),
        }
    }

    fn init_command(setup_code: Option<&str>) -> SysCommand {
        SysCommand::Init {
            setup_code: setup_code.map(String::from),
            setup_code_file: None,
            key_file_mode: false,
            passphrase_file: None,
            unlock: None,
        }
    }

    fn init_response() -> InitResponse {
        InitResponse {
            status: status(SealState::Unsealed),
            admin_token: "skt_admin".into(),
            admin_token_expires_at: 3600,
        }
    }

    #[tokio::test]
    async fn status_exit_codes_follow_the_state() -> anyhow::Result<()> {
        for (state, code) in [
            (SealState::Unsealed, 0),
            (SealState::Sealed, 2),
            (SealState::Uninitialised, 3),
        ] {
            let mut api = MockSekretApi::new();
            api.expect_sys_status_detail().returning(move || Ok(status(state)));
            let mut out = Vec::new();
            let exit = run(&api, plain_status(false), &Scripted::new(&[]), &mut out).await?;
            assert_eq!(exit, code);
            let text = String::from_utf8(out)?;
            assert!(text.contains(state_name(state)));
            assert!(text.contains("unlock: manual (set in configuration)"));
        }
        let mut api = MockSekretApi::new();
        api.expect_sys_status_detail()
            .returning(|| Ok(status(SealState::Sealed)));
        let mut out = Vec::new();
        run(&api, plain_status(true), &Scripted::new(&[]), &mut out).await?;
        let parsed: serde_json::Value = serde_json::from_slice(&out)?;
        assert_eq!(parsed["state"], "sealed");
        Ok(())
    }

    fn plain_status(json: bool) -> SysCommand {
        SysCommand::Status {
            json,
            socket: None,
            owner: SocketOwner::default(),
        }
    }

    #[tokio::test]
    async fn without_admin_rights_status_shows_what_anyone_may_see() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_status_detail().returning(|| {
            Err(sekret_client::ClientError::Api {
                status: 401,
                code: "unauthorised".into(),
                message: String::new(),
                retry_after: None,
            })
        });
        api.expect_sys_status().times(1).returning(|| {
            Ok(SysStatus {
                seal_mode: None,
                unlock_policy: None,
                configured: false,
                ..status(SealState::Sealed)
            })
        });
        let mut out = Vec::new();
        assert_eq!(run(&api, plain_status(false), &Scripted::new(&[]), &mut out).await?, 2);
        assert!(String::from_utf8(out)?.contains("sealed"));
        let mut failing = MockSekretApi::new();
        failing
            .expect_sys_status_detail()
            .returning(|| Err(sekret_client::ClientError::Network("down".into())));
        assert!(
            run(&failing, plain_status(false), &Scripted::new(&[]), &mut Vec::new())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn interactive_init_defaults_to_manual_unlock() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_init()
            .with(function(|r: &InitRequest| {
                r.setup_code.as_str() == "ABCD-EFGH-JKMN"
                    && r.mode == SealMode::Passphrase
                    && r.passphrase.as_deref().map(String::as_str) == Some("violet tractor sings beneath")
                    && r.unlock_policy == Some(UnlockPolicy::Manual)
            }))
            .times(1)
            .returning(|_| Ok(init_response()));
        let answers = Scripted::new(&[
            "ABCD-EFGH-JKMN",
            "violet tractor sings beneath",
            "violet tractor sings beneath",
            "",
        ]);
        let mut out = Vec::new();
        let command = init_command(None);
        run(&api, command, &answers, &mut out).await?;
        assert_eq!(String::from_utf8(out)?, "skt_admin\n");
        Ok(())
    }

    async fn init_answering(choice: &str, expected: UnlockPolicy) -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_init()
            .with(function(move |r: &InitRequest| r.unlock_policy == Some(expected)))
            .times(1)
            .returning(|_| Ok(init_response()));
        let answers = Scripted::new(&["violet tractor sings beneath", "violet tractor sings beneath", choice]);
        let command = init_command(Some("code"));
        run(&api, command, &answers, &mut Vec::new()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn weakening_the_unlock_policy_sends_the_passphrase() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_set_unlock_policy()
            .with(function(|r: &SetUnlockPolicy| {
                r.policy == UnlockPolicy::Remember
                    && r.passphrase.as_deref().map(String::as_str) == Some("violet tractor sings beneath")
            }))
            .times(1)
            .returning(|_| Ok(status(SealState::Unsealed)));
        api.expect_sys_set_unlock_policy()
            .with(function(|r: &SetUnlockPolicy| {
                r.policy == UnlockPolicy::Manual && r.passphrase.is_none()
            }))
            .times(1)
            .returning(|_| Ok(status(SealState::Unsealed)));
        let remember = SysCommand::UnlockPolicy {
            policy: UnlockPolicy::Remember,
            passphrase_file: None,
        };
        run(
            &api,
            remember,
            &Scripted::new(&["violet tractor sings beneath"]),
            &mut Vec::new(),
        )
        .await?;
        let manual = SysCommand::UnlockPolicy {
            policy: UnlockPolicy::Manual,
            passphrase_file: None,
        };
        run(&api, manual, &Scripted::new(&[]), &mut Vec::new()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn the_setup_code_can_come_from_a_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("code");
        std::fs::write(&path, "ABCD-EFGH-JKMN\n").context("write")?;
        let mut api = MockSekretApi::new();
        api.expect_sys_init()
            .with(function(|r: &InitRequest| r.setup_code.as_str() == "ABCD-EFGH-JKMN"))
            .times(1)
            .returning(|_| Ok(init_response()));
        let command = SysCommand::Init {
            setup_code: None,
            setup_code_file: Some(path),
            key_file_mode: true,
            passphrase_file: None,
            unlock: None,
        };
        run(&api, command, &Scripted::new(&[]), &mut Vec::new()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn an_admin_token_with_control_characters_is_not_printed() -> anyhow::Result<()> {
        let init = || SysCommand::Init {
            setup_code: Some("ABCD".into()),
            setup_code_file: None,
            key_file_mode: true,
            passphrase_file: None,
            unlock: None,
        };
        for hostile in [
            "skt_\u{1b}]52;c;cm0gLXJm\u{7}",
            "skt_a\nrm -rf ~",
            "skt_\u{9b}2J",
            "skt_\u{202e}x",
            "",
        ] {
            let mut api = MockSekretApi::new();
            api.expect_sys_init().returning(move |_| {
                Ok(InitResponse {
                    admin_token: hostile.into(),
                    ..init_response()
                })
            });
            let mut out = Vec::new();
            let refused = run(&api, init(), &Scripted::new(&[]), &mut out)
                .await
                .err()
                .with_context(|| format!("{hostile:?} must be refused"))?;
            assert!(refused.to_string().contains("not printing it"), "{refused}");
            assert!(out.is_empty(), "{hostile:?}");
        }
        let mut api = MockSekretApi::new();
        api.expect_sys_init().returning(|_| Ok(init_response()));
        let mut out = Vec::new();
        run(&api, init(), &Scripted::new(&[]), &mut out).await?;
        assert_eq!(out, b"skt_admin\n");
        Ok(())
    }

    #[test]
    fn a_backup_is_never_written_to_a_terminal() {
        let to_stdout = SysCommand::Backup { output: "-".into() };
        assert!(refuse_binary_to_terminal(&to_stdout, true).is_err());
        assert!(refuse_binary_to_terminal(&to_stdout, false).is_ok(), "a pipe is fine");
        let to_file = SysCommand::Backup {
            output: "backup.bin".into(),
        };
        assert!(refuse_binary_to_terminal(&to_file, true).is_ok());
        assert!(refuse_binary_to_terminal(&SysCommand::Seal, true).is_ok());
    }

    #[test]
    fn status_shows_a_key_file_overriding_the_passphrase() {
        let text = describe(&SysStatus {
            unsealed_by: Some(UnsealedBy::KeyFile),
            remembered: true,
            ..status(SealState::Unsealed)
        });
        assert!(
            text.contains("unlocked by: key-file (a root key file overrode the passphrase)"),
            "{text}"
        );
        assert!(text.contains("even after sealing by hand"), "{text}");
    }

    #[tokio::test]
    async fn every_unlock_policy_can_be_chosen_interactively() -> anyhow::Result<()> {
        init_answering("remember", UnlockPolicy::Remember).await?;
        init_answering("r", UnlockPolicy::Remember).await?;
        init_answering("passphrase-file", UnlockPolicy::PassphraseFile).await?;
        init_answering("p", UnlockPolicy::PassphraseFile).await?;
        init_answering(" Manual ", UnlockPolicy::Manual).await
    }

    #[tokio::test]
    async fn an_unknown_unlock_choice_is_refused() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_init().never();
        let answers = Scripted::new(&["violet tractor sings beneath", "violet tractor sings beneath", "yes"]);
        let command = init_command(Some("code"));
        let result = run(&api, command, &answers, &mut Vec::new()).await;
        assert!(result.is_err_and(|e| e.to_string().contains("expected manual, remember or passphrase-file")));
        Ok(())
    }

    #[tokio::test]
    async fn a_weak_passphrase_never_reaches_the_server() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_init().never();
        let answers = Scripted::new(&["password1234", "password1234"]);
        let command = init_command(Some("code"));
        assert!(run(&api, command, &answers, &mut Vec::new()).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn unseal_sends_the_passphrase() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_sys_unseal()
            // Sent as read: the server drops the byte order mark and line ending, once.
            .with(function(|r: &UnsealRequest| {
                r.passphrase.as_str() == "\u{feff}violet tractor sings beneath\r\n"
            }))
            .times(1)
            .returning(|_| Ok(status(SealState::Unsealed)));
        let mut out = Vec::new();
        run(
            &api,
            SysCommand::Unseal {
                passphrase_file: None,
                socket: None,
                owner: SocketOwner::default(),
            },
            &Scripted::new(&["\u{feff}violet tractor sings beneath\r\n"]),
            &mut out,
        )
        .await?;
        assert!(String::from_utf8(out)?.starts_with("state: unsealed"));
        Ok(())
    }

    #[tokio::test]
    async fn backups_are_written_owner_only() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("backup.skb");
        let mut api = MockSekretApi::new();
        api.expect_sys_backup().returning(|| Ok(b"SKB1data".to_vec()));
        run(
            &api,
            SysCommand::Backup { output: path.clone() },
            &Scripted::new(&[]),
            &mut Vec::new(),
        )
        .await?;
        assert_eq!(std::fs::read(&path)?, b"SKB1data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        let mut out = Vec::new();
        run(
            &api,
            SysCommand::Backup { output: "-".into() },
            &Scripted::new(&[]),
            &mut out,
        )
        .await?;
        assert_eq!(out, b"SKB1data");
        Ok(())
    }
}
