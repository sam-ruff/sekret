mod cli;
mod prompt;
mod server;
mod settings;

use anyhow::Context;
use clap::{Parser, Subcommand};
use sekret_client::SekretApi;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sekret",
    version = sekret_core::VERSION,
    about = "Secrets management server, CLI and Kubernetes operator"
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
            resolved.server
        );
    };
    let api = cli::client(args, &resolved, Some(token))?;
    Ok((resolved, api))
}

async fn dispatch(cli: Cli, env_secrets: settings::EnvSecrets) -> anyhow::Result<i32> {
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
        Command::Server(args) => server::run_server(*args, env_secrets).await?,
        Command::Admin(command) => server::run_admin(command).await?,
        Command::Sys(command) => {
            let resolved = cli::resolve(&cli.client)?;
            let api = cli::client(&cli.client, &resolved, resolved.token.clone())?;
            return cli::sys::run(&api, command, &prompt::Terminal, &mut out).await;
        }
        Command::Openapi => println!("{}", sekret_server::openapi_json()),
        Command::Login(args) => cli::run_login(&cli.client, args).await?,
        Command::Logout => cli::run_logout(&cli.client).await?,
        Command::Whoami => {
            let (resolved, api) = authenticated(&cli.client).await?;
            let me = api.me().await?;
            let label = if me.email.is_empty() { me.name } else { me.email };
            println!("{label} ({:?}) on {}", me.kind, resolved.server);
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
            println!("created project {} ({})", project.slug, project.id);
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
        Command::Secrets(command) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::secrets(
                &api,
                cli::location(&resolved)?,
                command,
                &mut out,
                &mut std::io::stdin(),
            )
            .await?;
        }
        Command::Export(args) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::export(&api, cli::location(&resolved)?, &args, &mut out).await?;
        }
        Command::Run(args) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            return cli::run_command(&api, cli::location(&resolved)?, &args).await;
        }
        Command::ShellInit { shell } => print!("{}", cli::shell::init_script(shell)),
        Command::Policy(flags) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            let project = resolved
                .project
                .clone()
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
            cli::env_use(
                &api,
                cli::location(&resolved)?,
                shell,
                recursive,
                &previous,
                &mut out,
                &mut std::io::stderr(),
            )
            .await?;
        }
        Command::Snapshots(command) => {
            let (resolved, api) = authenticated(&cli.client).await?;
            cli::snapshots(&api, cli::location(&resolved)?, command, &mut out).await?;
        }
    }
    Ok(0)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Taken while the process still has one thread, so removing them from the environment is
    // safe and nothing the server starts inherits them.
    let env_secrets = match cli.command {
        Command::Server(_) => settings::EnvSecrets::take(),
        _ => settings::EnvSecrets::default(),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(run(cli, env_secrets))
}

async fn run(cli: Cli, env_secrets: settings::EnvSecrets) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("SEKRET_LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();
    let code = dispatch(cli, env_secrets).await?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
