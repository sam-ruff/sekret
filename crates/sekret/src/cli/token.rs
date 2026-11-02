//! `sekret token`: hands the login `sekret login` saved to another program, such as the Ansible
//! lookup, and with `--context` says which server, project and environment the settings pick.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::Args;
use serde::Serialize;

use super::ClientArgs;
use super::config::{self, CaFile, Credentials, ProjectFile, Resolved, ServerSource};
use super::format::one_line;

/// Nothing saved for the server: `sekret login` has not been run for it, or `logout` removed it.
pub const EXIT_NOT_LOGGED_IN: i32 = 3;
/// A saved login whose token has expired.
pub const EXIT_EXPIRED: i32 = 4;

#[derive(Debug, Args)]
pub struct TokenArgs {
    /// Print the token even to a terminal.
    #[arg(long, conflicts_with = "context")]
    pub show: bool,
    /// Print the server, project, environment, path and CA file the settings pick, as JSON, and
    /// where each came from. Never the token.
    #[arg(long)]
    pub context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    Token(String),
    Missing,
    Expired,
}

/// The login saved for `server`. A token from `--token` or `SEKRET_TOKEN` is never consulted.
pub fn saved(credentials: &Credentials, server: &str, now: i64) -> Saved {
    match credentials.servers.get(server) {
        None => Saved::Missing,
        Some(stored) if stored.expires_at <= now => Saved::Expired,
        Some(stored) => Saved::Token(stored.token.clone()),
    }
}

/// Prints the token, or says why there is none and returns the matching exit code.
pub fn emit(
    saved: Saved,
    server: &str,
    to_terminal: bool,
    show: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<i32> {
    let server = one_line(server);
    match saved {
        Saved::Missing => {
            writeln!(err, "sekret: not logged in to {server}; run `sekret login`")?;
            Ok(EXIT_NOT_LOGGED_IN)
        }
        Saved::Expired => {
            writeln!(
                err,
                "sekret: the login for {server} has expired; run `sekret login` again"
            )?;
            Ok(EXIT_EXPIRED)
        }
        Saved::Token(_) if to_terminal && !show => bail!(
            "not printing a token to a terminal, where it would stay in the scrollback; pipe it to the program \
             that needs it, or pass --show"
        ),
        Saved::Token(token) => {
            writeln!(out, "{token}")?;
            Ok(0)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Flag,
    Environment,
    ProjectFile,
    /// A server only the project file names, which `sekret login` was run for.
    LoggedIn,
    UserConfig,
    Default,
}

/// Which settings were named on the command line or in the environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Given {
    pub server_flag: bool,
    pub server_env: bool,
    /// `--ca-file` rather than `SEKRET_CA_FILE`, which clap merges.
    pub ca_flag: bool,
    pub project_flag: bool,
    pub project_env: bool,
    pub environment_flag: bool,
    pub environment_env: bool,
    pub path_flag: bool,
    pub path_env: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Context {
    pub server: String,
    pub server_source: Source,
    /// False for a server only an unconfirmed project file names: nothing may be sent to it.
    pub server_confirmed: bool,
    pub project: Option<String>,
    pub project_source: Option<Source>,
    pub environment: Option<String>,
    pub environment_source: Option<Source>,
    pub path: String,
    pub path_source: Source,
    pub ca_file: Option<PathBuf>,
    pub ca_file_source: Option<Source>,
    pub project_file: Option<PathBuf>,
}

fn named(flag: bool, env: bool) -> Option<Source> {
    if flag {
        return Some(Source::Flag);
    }
    env.then_some(Source::Environment)
}

/// What the settings pick and where each part came from, refusing a choice only an unconfirmed
/// project file made and a project or environment `env use` left for another project file.
pub fn context(resolved: &Resolved, given: Given, file: &ProjectFile) -> anyhow::Result<Context> {
    resolved.checked_project()?;
    if let Some(scope) = &resolved.unconfirmed_choice {
        bail!(
            "{} picks the project and environment here and has not been confirmed; run `sekret export` once at a \
             terminal in this folder to confirm it, or set the project and environment explicitly",
            one_line(&scope.file.display().to_string())
        );
    }
    let from_file = |set: bool| set.then_some(Source::ProjectFile);
    let server_source = named(given.server_flag, given.server_env).unwrap_or(match resolved.source {
        ServerSource::Explicit => Source::UserConfig,
        ServerSource::LoggedIn => Source::LoggedIn,
        ServerSource::ProjectFile => Source::ProjectFile,
    });
    let project_source = resolved
        .project
        .as_ref()
        .and(named(given.project_flag, given.project_env).or(from_file(file.project.is_some())));
    let environment_source = resolved
        .environment
        .as_ref()
        .and(named(given.environment_flag, given.environment_env).or(from_file(file.environment.is_some())));
    let path_source = named(given.path_flag, given.path_env)
        .or(from_file(file.path.is_some()))
        .unwrap_or(Source::Default);
    let (ca_file, ca_file_source) = match &resolved.ca_file {
        Some(CaFile::Given(path)) => (
            Some(path.clone()),
            Some(if given.ca_flag {
                Source::Flag
            } else {
                Source::Environment
            }),
        ),
        Some(CaFile::UserConfig(path)) => (Some(path.clone()), Some(Source::UserConfig)),
        None => (None, None),
    };
    Ok(Context {
        server: resolved.server.clone(),
        server_source,
        server_confirmed: resolved.server_confirmed(),
        project: resolved.project.clone(),
        project_source,
        environment: resolved.environment.clone(),
        environment_source,
        path: resolved.path.clone(),
        path_source,
        ca_file,
        ca_file_source,
        project_file: resolved.project_file.clone(),
    })
}

fn flag_in(argv: &[String], flags: &[&str]) -> bool {
    argv.iter().take_while(|arg| *arg != "--").any(|arg| {
        flags
            .iter()
            .any(|flag| arg == flag || arg.starts_with(&format!("{flag}=")))
    })
}

fn given(args: &ClientArgs) -> Given {
    let argv: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let var = |name: &str| std::env::var(name).is_ok_and(|v| !v.is_empty());
    let set = |value: &Option<String>| value.as_ref().is_some_and(|v| !v.is_empty());
    let server_flag = set(&args.server) && flag_in(&argv, &["--server"]);
    let path_flag = set(&args.path) && flag_in(&argv, &["--path"]);
    let project_flag = set(&args.project);
    let environment_flag = set(&args.environment);
    Given {
        server_flag,
        server_env: !server_flag && var("SEKRET_URL"),
        ca_flag: args.ca_file.is_some() && flag_in(&argv, &["--ca-file"]),
        project_flag,
        project_env: !project_flag && var("SEKRET_PROJECT"),
        environment_flag,
        environment_env: !environment_flag && var("SEKRET_ENVIRONMENT"),
        path_flag,
        path_env: !path_flag && var("SEKRET_PATH"),
    }
}

/// JSON with every character outside ASCII written as `\uXXXX`, so a project or path a project
/// file chose cannot put control or direction characters on a terminal.
pub fn ascii_json(value: &impl Serialize) -> anyhow::Result<String> {
    let text = serde_json::to_string(value)?;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
    Ok(out)
}

/// Which server the saved login is for, refusing one only an unconfirmed project file names and
/// saying so when a confirmed project file chose it.
fn token_server(resolved: &Resolved, err: &mut dyn Write) -> anyhow::Result<()> {
    let file = resolved
        .project_file
        .as_ref()
        .map(|path| one_line(&path.display().to_string()))
        .unwrap_or_else(|| config::PROJECT_FILE.to_string());
    match resolved.source {
        ServerSource::ProjectFile => bail!(
            "{} comes only from {file}, which you have not confirmed; pass --server, or run `sekret login` at a \
             terminal",
            one_line(&resolved.server)
        ),
        ServerSource::LoggedIn => {
            writeln!(err, "sekret: using {}, which {file} names", one_line(&resolved.server))?;
            Ok(())
        }
        ServerSource::Explicit => Ok(()),
    }
}

pub fn run(args: &ClientArgs, token: &TokenArgs, out: &mut dyn Write) -> anyhow::Result<i32> {
    let resolved = super::resolve_with_token(args, None)?;
    if token.context {
        config::check_transport(&resolved.server, args.allow_insecure_http.unwrap_or(false))?;
        if let Some(ca @ CaFile::UserConfig(_)) = &resolved.ca_file {
            ca.read().context("the user config's CA file")?;
        }
        let mut ignored = Vec::new();
        let (file, _) = config::load_project_file(&std::env::current_dir()?, &mut ignored)?;
        let context = context(&resolved, given(args), &file)?;
        writeln!(out, "{}", ascii_json(&context)?)?;
        return Ok(0);
    }
    token_server(&resolved, &mut std::io::stderr())?;
    let credentials = super::read_credentials(&config::credentials_path()?)?;
    let to_terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
    emit(
        saved(&credentials, &resolved.server, super::now()),
        &resolved.server,
        to_terminal,
        token.show,
        out,
        &mut std::io::stderr(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config::{ChoiceScope, StoredToken};

    const SERVER: &str = "https://sekret.example.com";

    fn with(expires_at: i64) -> Credentials {
        let mut credentials = Credentials::default();
        credentials.servers.insert(
            SERVER.into(),
            StoredToken {
                token: "tok".into(),
                expires_at,
            },
        );
        credentials
    }

    fn print(saved: Saved, to_terminal: bool, show: bool) -> anyhow::Result<(i32, String, String)> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = emit(saved, SERVER, to_terminal, show, &mut out, &mut err)?;
        Ok((code, String::from_utf8(out)?, String::from_utf8(err)?))
    }

    #[test]
    fn a_saved_login_is_told_apart_from_a_missing_or_expired_one() {
        assert_eq!(saved(&with(100), SERVER, 50), Saved::Token("tok".into()));
        assert_eq!(saved(&with(100), SERVER, 100), Saved::Expired);
        assert_eq!(saved(&with(100), "https://other.example.com", 50), Saved::Missing);
    }

    #[test]
    fn each_outcome_has_its_own_exit_code_and_only_a_token_reaches_stdout() -> anyhow::Result<()> {
        assert_eq!(
            print(Saved::Token("tok".into()), false, false)?,
            (0, "tok\n".into(), String::new())
        );
        let (code, out, err) = print(Saved::Missing, false, false)?;
        assert_eq!((code, out.as_str()), (EXIT_NOT_LOGGED_IN, ""));
        assert!(err.contains("not logged in"), "{err}");
        let (code, out, err) = print(Saved::Expired, false, false)?;
        assert_eq!((code, out.as_str()), (EXIT_EXPIRED, ""));
        assert!(err.contains("expired"), "{err}");
        Ok(())
    }

    #[test]
    fn a_terminal_gets_the_token_only_with_show() -> anyhow::Result<()> {
        let refused = print(Saved::Token("tok".into()), true, false)
            .err()
            .context("refused")?;
        assert!(format!("{refused:#}").contains("--show"));
        assert_eq!(print(Saved::Token("tok".into()), true, true)?.1, "tok\n");
        Ok(())
    }

    fn resolved() -> Resolved {
        Resolved {
            server: SERVER.into(),
            token: None,
            ca_file: None,
            project: Some("app".into()),
            environment: Some("prod".into()),
            path: "/".into(),
            source: ServerSource::Explicit,
            allow: Vec::new(),
            unconfirmed_allow: None,
            chosen_by_file: None,
            unconfirmed_choice: None,
            project_file: None,
            stale_shell: None,
        }
    }

    #[test]
    fn context_names_where_each_setting_came_from() -> anyhow::Result<()> {
        let file = ProjectFile {
            environment: Some("prod".into()),
            path: Some("/api".into()),
            ..Default::default()
        };
        let mut picked = resolved();
        picked.path = "/api".into();
        picked.ca_file = Some(CaFile::UserConfig(PathBuf::from("/ca.pem")));
        let given = Given {
            server_env: true,
            project_flag: true,
            ..Default::default()
        };
        let context = context(&picked, given, &file)?;
        assert_eq!(context.server_source, Source::Environment);
        assert_eq!(context.project_source, Some(Source::Flag));
        assert_eq!(context.environment_source, Some(Source::ProjectFile));
        assert_eq!(context.path_source, Source::ProjectFile);
        assert_eq!(context.ca_file_source, Some(Source::UserConfig));
        let json = serde_json::to_string(&context)?;
        assert!(!json.contains("token"), "{json}");
        Ok(())
    }

    #[test]
    fn context_defaults_and_absences_are_explicit() -> anyhow::Result<()> {
        let mut picked = resolved();
        picked.project = None;
        picked.environment = None;
        let context = context(&picked, Given::default(), &ProjectFile::default())?;
        assert_eq!(context.server_source, Source::UserConfig);
        assert_eq!((context.project_source, context.environment_source), (None, None));
        assert_eq!(context.path_source, Source::Default);
        Ok(())
    }

    #[test]
    fn context_refuses_an_unconfirmed_file_choice_and_a_stale_shell() -> anyhow::Result<()> {
        let mut unconfirmed = resolved();
        unconfirmed.unconfirmed_choice = Some(ChoiceScope {
            file: PathBuf::from("/repo/.sekret.toml"),
            server: SERVER.into(),
            project: "app".into(),
            environment: "prod".into(),
        });
        let refused = context(&unconfirmed, Given::default(), &ProjectFile::default())
            .err()
            .context("unconfirmed")?;
        assert!(format!("{refused:#}").contains("sekret export"), "{refused:#}");
        let mut stale = resolved();
        stale.stale_shell = Some("SEKRET_PROJECT is other in this shell".into());
        assert!(context(&stale, Given::default(), &ProjectFile::default()).is_err());
        Ok(())
    }

    #[test]
    fn flags_are_found_in_either_form_and_never_after_a_double_dash() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(flag_in(&argv(&["sekret", "token", "--server", "x"]), &["--server"]));
        assert!(flag_in(&argv(&["sekret", "--server=x", "token"]), &["--server"]));
        assert!(!flag_in(&argv(&["sekret", "token", "--", "--server"]), &["--server"]));
        assert!(!flag_in(&argv(&["sekret", "--servers", "token"]), &["--server"]));
        assert!(flag_in(
            &argv(&["sekret", "token", "--ca-file=-odd.pem"]),
            &["--ca-file"]
        ));
    }

    #[test]
    fn a_server_only_a_project_file_names_is_never_confirmed() -> anyhow::Result<()> {
        let file = ProjectFile {
            server: Some(SERVER.into()),
            ..Default::default()
        };
        let mut picked = resolved();
        picked.source = ServerSource::ProjectFile;
        let unconfirmed = context(&picked, Given::default(), &file)?;
        assert_eq!(unconfirmed.server_source, Source::ProjectFile);
        assert!(!unconfirmed.server_confirmed);
        picked.source = ServerSource::LoggedIn;
        let logged_in = context(&picked, Given::default(), &file)?;
        assert_eq!(logged_in.server_source, Source::LoggedIn);
        assert!(logged_in.server_confirmed);
        let named = context(
            &picked,
            Given {
                server_flag: true,
                ..Default::default()
            },
            &file,
        )?;
        assert_eq!(named.server_source, Source::Flag);
        Ok(())
    }

    #[test]
    fn a_ca_file_from_the_environment_is_told_apart_from_the_flag() -> anyhow::Result<()> {
        let mut picked = resolved();
        picked.ca_file = Some(CaFile::Given(PathBuf::from("/ca.pem")));
        let from_env = context(&picked, Given::default(), &ProjectFile::default())?;
        assert_eq!(from_env.ca_file_source, Some(Source::Environment));
        let flagged = Given {
            ca_flag: true,
            ..Default::default()
        };
        assert_eq!(
            context(&picked, flagged, &ProjectFile::default())?.ca_file_source,
            Some(Source::Flag)
        );
        Ok(())
    }

    #[test]
    fn plain_token_refuses_an_unconfirmed_project_file_server_and_names_a_logged_in_one() -> anyhow::Result<()> {
        let mut picked = resolved();
        picked.project_file = Some(PathBuf::from("/repo/.sekret.toml"));
        picked.source = ServerSource::ProjectFile;
        let mut err = Vec::new();
        let refused = token_server(&picked, &mut err).err().context("refused")?;
        assert!(format!("{refused:#}").contains("--server"), "{refused:#}");
        picked.source = ServerSource::LoggedIn;
        token_server(&picked, &mut err)?;
        let note = String::from_utf8(err)?;
        assert!(note.contains(SERVER) && note.contains("/repo/.sekret.toml"), "{note}");
        Ok(())
    }

    #[test]
    fn context_json_has_nothing_but_ascii() -> anyhow::Result<()> {
        let mut picked = resolved();
        picked.project = Some("app\u{202e}\u{9b}\u{1f600}".into());
        let json = ascii_json(&context(&picked, Given::default(), &ProjectFile::default())?)?;
        assert!(json.is_ascii(), "{json}");
        assert!(json.contains("\\u202e") && json.contains("\\u009b") && json.contains("\\ud83d\\ude00"));
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["project"], "app\u{202e}\u{9b}\u{1f600}");
        Ok(())
    }
}
