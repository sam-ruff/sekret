mod cli;
mod prompt;
mod server;
mod settings;
mod socket_check;

use anyhow::Context;
use clap::{Parser, Subcommand};
use sekret_client::SekretApi;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sekret",
    version = sekret_core::VERSION,
    about = "Secrets management server, CLI and Kubernetes operator",
    after_help = cli::config::SETTINGS_ORDER
)]
struct Cli {
    #[command(flatten)]
    client: cli::ClientArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the API server and web interface.
    Server(Box<settings::ServerArgs>),
    /// Set up, unlock, seal and back up a server.
    #[command(subcommand)]
    Sys(cli::sys::SysCommand),
    /// Administrative tasks run on the server host.
    #[command(subcommand)]
    Admin(server::AdminCommand),
    /// Print the OpenAPI document.
    Openapi,
    /// Log in, interactively through the browser or as a machine identity.
    Login(cli::LoginArgs),
    /// Revoke and forget the saved token for this server.
    Logout,
    /// Show who the current token belongs to.
    Whoami,
    /// Print the token `sekret login` saved for this server, for another program to use. Exits 3
    /// when not logged in and 4 when the login has expired. Ignores --token and SEKRET_TOKEN.
    Token(cli::token::TokenArgs),
    /// List the projects you can see, or create one.
    Projects {
        #[command(subcommand)]
        action: Option<ProjectsAction>,
    },
    /// Read and change secrets.
    #[command(subcommand)]
    Secrets(cli::SecretsCommand),
    /// Print secrets as dotenv, JSON, YAML or shell exports.
    Export(cli::ExportArgs),
    /// Run a command with secrets in its environment.
    Run(cli::RunArgs),
    /// Show the project's default generation and rotation policy, or change it with the flags.
    Policy(cli::PolicyFlags),
    /// Load an environment's secrets into this shell, switch between environments, or unload them.
    #[command(subcommand)]
    Env(cli::EnvCommand),
    /// Print the `sekret-env` shell function; add `eval "$(sekret shell-init bash)"` to your shell's rc file.
    ShellInit {
        #[arg(value_enum, default_value = "bash")]
        shell: cli::shell::Shell,
    },
    /// List and restore environment snapshots.
    #[command(subcommand)]
    Snapshots(cli::SnapshotsCommand),
    /// Run the Kubernetes operator that syncs SekretSecret resources into Secrets.
    Operator(OperatorCommand),
}

#[derive(Debug, clap::Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct OperatorCommand {
    #[command(subcommand)]
    action: Option<OperatorAction>,
    #[command(flatten)]
    args: Option<sekret_operator::OperatorArgs>,
}

#[derive(Debug, Subcommand)]
enum ProjectsAction {
    /// List the projects you can see (the default).
    List,
    /// Create a project with the default dev, staging and prod environments, or your own.
    Create {
        slug: String,
        /// Display name; defaults to the slug.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "")]
        description: String,
        /// Environment slugs to create instead of dev, staging and prod.
        #[arg(long = "environment", value_name = "SLUG")]
        environments: Vec<String>,
    },
    /// Show per-secret access for the project and its restricted secrets, or turn it on or off.
    /// Off by default; turning it off is refused while any secret is restricted. Admins only.
    SecretAccess {
        #[arg(value_enum)]
        state: Option<cli::access::OnOff>,
    },
}

#[derive(Debug, Subcommand)]
enum OperatorAction {
    /// Print the SekretSecret CustomResourceDefinition.
    Crd,
}

async fn authenticated(args: &cli::ClientArgs) -> anyhow::Result<(cli::config::Resolved, sekret_client::HttpClient)> {
    let resolved = cli::resolve(args)?;
    let Some(token) = resolved.token.clone() else {
        anyhow::bail!(
            "not logged in to {}; run `sekret login` or set SEKRET_TOKEN",
            cli::format::one_line(&resolved.server)
        );
    };
    let api = cli::client(args, &resolved, Some(token))?;
    Ok((resolved, api))
}

async fn dispatch(cli: Cli, env_secrets: settings::EnvSecrets, sources: &settings::Sources) -> anyhow::Result<i32> {
    let mut out = std::io::stdout();
    match cli.command {
        Command::Operator(OperatorCommand {
            action: Some(OperatorAction::Crd),
            ..
        }) => {
            print!("{}", sekret_operator::crd_yaml()?);
        }
        Command::Operator(OperatorCommand { args: Some(args), .. }) => sekret_operator::run(args).await?,
        Command::Operator(_) => anyhow::bail!("--server-url or SEKRET_URL is required"),
        Command::Server(args) => server::run_server(*args, env_secrets, sources).await?,
        Command::Admin(command) => server::run_admin(command, sources).await?,
        Command::Sys(command) if command.socket().is_some() => {
            cli::sys::refuse_binary_to_terminal(&command, std::io::IsTerminal::is_terminal(&out))?;
            let (path, owner) = command
                .socket()
                .map(|(path, owner)| (path.to_path_buf(), owner.map(String::from)))
                .unwrap_or_default();
            let api = cli::host_socket_client(&path, owner.as_deref()).await?;
            return cli::sys::run(&api, command, &prompt::Terminal, &mut out).await;
        }
        Command::Sys(command) => {
            cli::sys::refuse_binary_to_terminal(&command, std::io::IsTerminal::is_terminal(&out))?;
            let api = cli::sys_client(&cli.client)?;
            return cli::sys::run(&api, command, &prompt::Terminal, &mut out).await;
        }
        Command::Openapi => println!("{}", sekret_server::openapi_json()),
        Command::Login(args) => cli::run_login(&cli.client, args).await?,
        Command::Logout => cli::run_logout(&cli.client).await?,
        Command::Token(args) => return cli::token::run(&cli.client, &args, &mut out),
        Command::Whoami => {
            let (resolved, api) = authenticated(&cli.client).await?;
            let me = api.me().await?;
            let label = if me.email.is_empty() { me.name } else { me.email };
            println!(
                "{} ({:?}) on {}",
                cli::format::one_line(&label),
                me.kind,
                cli::format::one_line(&resolved.server)
            );
        }
        Command::Projects {
            action:
                Some(ProjectsAction::Create {
                    slug,
                    name,
                    description,
                    environments,
                }),
        } => {
            let (_, api) = authenticated(&cli.client).await?;
            let environments = (!environments.is_empty()).then(|| {
                environments
                    .iter()
                    .enumerate()
                    .map(|(position, slug)| sekret_api::CreateEnvironment {
                        slug: slug.clone(),
                        name: slug.clone(),
                        position: Some(position as i64),
                    })
                    .collect()
            });
            let project = api
                .create_project(sekret_api::CreateProject {
                    name: name.unwrap_or_else(|| slug.clone()),
                    slug,
                    description,
                    environments,
                })
                .await?;
            println!(
                "created project {} ({})",
                cli::format::one_line(&project.slug),
                cli::format::one_line(&project.id)
            );
        }
        Command::Projects {
            action: Some(ProjectsAction::SecretAccess { state }),
        } => {
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::confirm_target(&resolved, state.is_some())?;
            let project = resolved
                .checked_project()?
                .ok_or_else(|| anyhow::anyhow!("no project; pass -p or set SEKRET_PROJECT"))?;
            print!("{}", cli::access::project_setting(&api, project, state).await?);
        }
        Command::Projects { .. } => {
            let (_, api) = authenticated(&cli.client).await?;
            let rows: Vec<Vec<String>> = api
                .list_projects()
                .await?
                .into_iter()
                .map(|p| vec![p.slug, p.name, p.id])
                .collect();
            print!("{}", cli::format::table(&["SLUG", "NAME", "ID"], &rows));
        }
        Command::Secrets(mut command) => {
            // Pipes and files get the value exactly; only a terminal is protected.
            if let cli::SecretsCommand::Get { raw, .. } = &mut command {
                *raw |= !std::io::IsTerminal::is_terminal(&std::io::stdout());
            }
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::confirm_target(&resolved, command.changes())?;
            cli::secrets(
                &api,
                cli::location(&resolved)?,
                command,
                &mut out,
                &mut std::io::stdin(),
            )
            .await?;
        }
        Command::Export(mut args) => {
            // Pipes and files get the values exactly; only a terminal is protected.
            args.raw |= !std::io::IsTerminal::is_terminal(&std::io::stdout());
            let (resolved, api) = authenticated(&cli.client).await?;
            let policy = cli::load_policy_confirming(&resolved, &args.allow)?;
            let at = cli::location(&resolved)?;
            cli::export(&api, at, &args, &policy, &mut out, &mut std::io::stderr()).await?;
        }
        Command::Run(args) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            let policy = cli::load_policy_confirming(&resolved, &args.allow)?;
            let at = cli::location(&resolved)?;
            return cli::run_command(&api, at, &args, &policy, &mut std::io::stderr()).await;
        }
        Command::ShellInit { shell } => print!("{}", cli::shell::init_script(shell)),
        Command::Policy(flags) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::confirm_target(&resolved, !flags.is_empty())?;
            let project = resolved
                .checked_project()?
                .ok_or_else(|| anyhow::anyhow!("no project; pass -p or set SEKRET_PROJECT"))?;
            print!("{}", cli::project_policy(&api, project, &flags).await?);
        }
        Command::Env(cli::EnvCommand::Status) => {
            let loaded = cli::shell::previously_loaded(std::env::var(cli::shell::LOADED_KEYS_VAR).ok().as_deref());
            print!(
                "{}",
                cli::env_status(
                    std::env::var("SEKRET_PROJECT").ok().as_deref(),
                    std::env::var("SEKRET_ENVIRONMENT").ok().as_deref(),
                    &loaded
                )
            );
        }
        Command::Env(cli::EnvCommand::Unload { shell }) => {
            let loaded = cli::shell::previously_loaded(std::env::var(cli::shell::LOADED_KEYS_VAR).ok().as_deref());
            print!("{}", cli::shell::unload_script(shell, &loaded));
            eprintln!("sekret: unloaded {} secrets", loaded.len());
        }
        Command::Env(cli::EnvCommand::Use {
            environment,
            shell,
            recursive,
            allow,
        }) => {
            // Printing exports to a terminal would show every value; the output is meant for eval.
            if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                anyhow::bail!(
                    "this prints shell code with secret values; run `eval \"$(sekret env use ...)\"` or `sekret-env ...` (see `sekret shell-init`)"
                );
            }
            let mut args = cli.client.clone();
            if environment.is_some() {
                args.environment = environment;
            }
            let (resolved, api) = authenticated(&args).await?;
            let previous = cli::shell::previously_loaded(std::env::var(cli::shell::LOADED_KEYS_VAR).ok().as_deref());
            let policy = cli::load_policy_confirming(&resolved, &allow)?;
            let options = cli::EnvUse {
                shell,
                recursive,
                policy: &policy,
                previous: &previous,
                project_file: resolved.project_file.as_deref(),
            };
            cli::env_use(
                &api,
                cli::location(&resolved)?,
                options,
                &mut out,
                &mut std::io::stderr(),
            )
            .await?;
        }
        Command::Snapshots(command) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::confirm_target(&resolved, command.changes())?;
            cli::snapshots(&api, cli::location(&resolved)?, command, &mut out).await?;
        }
    }
    Ok(0)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Which settings came from the environment, noted before secrets are removed from it.
    let sources = settings::Sources::process();
    // Taken while the process still has one thread, so removing them from the environment is
    // safe and nothing the server starts inherits them.
    let env_secrets = match cli.command {
        Command::Server(_) => settings::EnvSecrets::take()?,
        Command::Admin(_) => {
            settings::scrub_database_url()?;
            settings::EnvSecrets::default()
        }
        Command::Run(_) => {
            settings::scrub_env(&cli::shell::CREDENTIAL_VARS)?;
            settings::EnvSecrets::default()
        }
        _ => settings::EnvSecrets::default(),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(run(cli, env_secrets, sources))
}

async fn run(cli: Cli, env_secrets: settings::EnvSecrets, sources: settings::Sources) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("SEKRET_LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();
    let code = dispatch(cli, env_secrets, &sources).await?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
