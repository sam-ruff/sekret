//! Shell code for loading secrets into the calling shell. A process cannot change its parent's
//! environment, so these functions produce text for the shell to `eval`.

use std::collections::BTreeMap;

use super::format::shell_value;

/// Variable listing the keys the last `env use` exported, so the next switch can remove them.
pub const LOADED_KEYS_VAR: &str = "SEKRET_LOADED_KEYS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Sh,
    Fish,
}

impl Shell {
    fn is_fish(self) -> bool {
        self == Shell::Fish
    }
}

/// Where the loaded secrets came from; exported so later `sekret` commands default to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub project: String,
    pub environment: String,
    pub path: String,
    /// The project file in force when loading, empty when there was none.
    pub project_file: String,
}

/// What `env use` exports besides the secrets, and `env unload` removes.
const ORIGIN_VARS: [&str; 4] = [
    "SEKRET_PROJECT",
    "SEKRET_ENVIRONMENT",
    "SEKRET_PATH",
    super::config::LOADED_FILE_VAR,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub script: String,
    pub loaded: Vec<String>,
    pub skipped: Vec<Skipped>,
}

/// `^[A-Za-z_][A-Za-z0-9_]*$`
pub fn is_variable_name(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Names a shell, the dynamic linker, a runtime or a tool reads to decide what to run or where
/// to connect. Anyone who can write a secret could otherwise run code on the machine of whoever
/// loads the environment. Compared case-insensitively, since zsh ties `path` and `fpath` to their
/// upper-case forms and proxies are read in either case.
const BLOCKED_EXACT: &[&str] = &[
    "PATH",
    "ENV",
    "IFS",
    "HOME",
    "SHELL",
    "SHELLOPTS",
    "BASHOPTS",
    "ZDOTDIR",
    "CDPATH",
    "FPATH",
    "MANPATH",
    "MODULE_PATH",
    "HISTFILE",
    "TMOUT",
    "MAIL",
    "MAILPATH",
    "BROWSER",
    "VISUAL",
    "INPUTRC",
    "LESSOPEN",
    "LESSCLOSE",
    "GCONV_PATH",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "HOSTALIASES",
    "GNUPGHOME",
    "GOFLAGS",
    "GOROOT",
    "GOPATH",
    "GOENV",
    "GOTOOLCHAIN",
    "GOPROXY",
    "GONOPROXY",
    "GOSUMDB",
    "GONOSUMDB",
    "GOPRIVATE",
    "GOINSECURE",
    "GOVCS",
    "GOAUTH",
    "GOBIN",
    "GOCACHE",
    "GOCACHEPROG",
    "GOMODCACHE",
    "GOWORK",
    "GOEXPERIMENT",
    "GODEBUG",
    "CC_FOR_TARGET",
    "CXX_FOR_TARGET",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CC",
    "CXX",
    "CPP",
    "LD",
    "AR",
    "AS",
    "NM",
    "RANLIB",
    "STRIP",
    "OBJCOPY",
    "OBJDUMP",
    "FC",
    "F77",
    "YACC",
    "LEX",
    "M4",
    "RM",
    "INSTALL",
    "MAKE",
    "MAKEFILES",
    "MAKEFLAGS",
    "GNUMAKEFLAGS",
    "MFLAGS",
    "GCC_EXEC_PREFIX",
    "COMPILER_PATH",
    "LIBRARY_PATH",
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "LDLIBS",
    "NULLCMD",
    "READNULLCMD",
    "VIM",
    "VIMRUNTIME",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "BOTO_CONFIG",
    "CLOUDSDK_CONFIG",
    "AZURE_CONFIG_DIR",
    "TERRAFORM_CONFIG",
    "HGRCPATH",
    "TCLLIBPATH",
    "GUILE_LOAD_PATH",
    "GUILE_LOAD_COMPILED_PATH",
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "GHC_ENVIRONMENT",
    "FCEDIT",
    "SSLKEYLOGFILE",
    "AWS_CA_BUNDLE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "CONFIG_SITE",
    "MKDIR_P",
    "GITHUB_API_URL",
    "GITHUB_SERVER_URL",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_OUTPUT",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
    "CI_SERVER_URL",
    "CI_API_V4_URL",
    "CI_API_GRAPHQL_URL",
    "AZURE_AUTHORITY_HOST",
    "CYPRESS_INSTALL_BINARY",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "CONTAINER_SSHKEY",
    "BUILDKIT_HOST",
];

const BLOCKED_PREFIXES: &[&str] = &[
    "BASH_",
    "FISH_",
    "TERM",
    "LD_",
    "DYLD_",
    "MALLOC_",
    "XDG_",
    "GIT_",
    "SSH_",
    "GPG",
    "CARGO_",
    "RUSTC",
    "RUSTUP_",
    "PYTHON",
    "PIP_",
    "PERL",
    "RUBY",
    "GEM_",
    "BUNDLE_",
    "NODE_",
    "NPM_",
    "YARN_",
    "JAVA_",
    "_JAVA_",
    "JDK_",
    "CLASSPATH",
    "LUA_",
    "DOCKER_",
    "KUBE",
    "SSL_",
    "OPENSSL_",
    "CURL_",
    "REQUESTS_CA",
    "GTK_",
    "QT_",
    "GST_PLUGIN",
    "DOTNET_",
    "CORECLR_",
    "ERL_",
    "ELIXIR_",
    "MAVEN_",
    "GRADLE_",
    "ANSIBLE_",
    "TF_CLI_",
    "R_PROFILE",
    "R_ENVIRON",
    "R_LIBS",
    "JULIA_",
    "UV_",
    "POETRY_",
    "PHP",
    "CGO_",
    "CMAKE_",
    "NIX_",
    "CCACHE_",
    "SCCACHE_",
    "DISTCC_",
    "PKG_CONFIG",
    "LESS",
    "DENO_",
    "BUN_",
    "HELM_",
    "ELECTRON_",
    "RSYNC_",
    "SVN_",
    "CVS_",
    "VK_",
    "GIO_",
    "GDK_",
    "LIBGL_",
    "EMACS",
    "IPYTHON",
    "JUPYTER_",
    "AWS_ENDPOINT_URL",
    "KRB5",
    "CLOUDSDK_",
    "COREPACK_",
    "VAULT_",
    "BAO_",
    "CONSUL_",
    "NOMAD_",
    "BOUNDARY_",
    "ACTIONS_",
    "RUNNER_",
    "NVM_",
    "VOLTA_",
    "FNM_",
    "HOMEBREW_",
    "CONDA_",
    "MAMBA_",
    "PNPM_",
    "ASDF_",
    "PYENV_",
    "RBENV_",
    "SDKMAN_",
    "MISE_",
    "COMPOSER_",
    "PUPPETEER_",
    "PLAYWRIGHT_",
    "CONTAINERS_",
    "PODMAN_",
    "BUILDAH_",
    "RESTIC_",
    "BORG_",
    "RCLONE_",
];

/// `INIT` covers `VIMINIT` and `EXINIT`, and `RC` the rc files tools run, such as `PSQLRC`,
/// `IRBRC`, `PHPRC` and `WGETRC`. `FLAGS` covers `GNUMAKEFLAGS` and `CGO_LDFLAGS` as well as
/// `_FLAGS` names. The suffixes from `_SHELL` on name a program or interpreter to run, such as
/// autoconf's `CONFIG_SHELL` or gcloud's `CLOUDSDK_PYTHON`. The suffixes from `_HOME` on point a
/// tool at where it loads plugins, packages, settings or trusted CAs from. `_URL`, `_ADDR` and
/// `_ENDPOINT` are left alone, since most app config ends that way.
const BLOCKED_SUFFIXES: &[&str] = &[
    "PAGER",
    "EDITOR",
    "ASKPASS",
    "_COMMAND",
    "_OPTIONS",
    "_OPTS",
    "FLAGS",
    "_PROXY",
    "_HOOK",
    "_HOOKS",
    "_LAUNCHER",
    "_WRAPPER",
    "INIT",
    "RC",
    "_RSH",
    "_SSH",
    "_SHELL",
    "_SH",
    "_BASH",
    "_ZSH",
    "_PYTHON",
    "_PERL",
    "_RUBY",
    "_BIN",
    "_EXE",
    "_EXEC",
    "_EXECUTABLE",
    "_BINARY",
    "_CMD",
    "_PROG",
    "_PROGRAM",
    "_INTERPRETER",
    "_HOME",
    "_MIRROR",
    "_REGISTRY",
    "_INDEX_URL",
    "_BINARY_SITE",
    "_DOWNLOAD_HOST",
    "_CONFIG_FILE",
    "_CONFIG_PATH",
    "_CONFIG_DIR",
    "_CA_BUNDLE",
    "_CA_FILE",
    "_CA_PATH",
    "_CAFILE",
    "_CAPATH",
    "_CA_CERTS",
];

/// Names without an underscore that are plainly app config. Every other such name is held back,
/// since the settings Unix tools read are mostly single words (`CC`, `SED`, `TMPDIR`, `PGHOST`)
/// while app config is mostly not, so a name missing from the lists above fails safe.
const PLAIN_SINGLE_WORDS: &[&str] = &[
    "PORT",
    "HOST",
    "DEBUG",
    "ENVIRONMENT",
    "STAGE",
    "REGION",
    "DOMAIN",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "USERNAME",
    "APIKEY",
    "DATABASE",
    "DSN",
    "BUCKET",
    "TENANT",
    "LOGLEVEL",
    "VERBOSE",
    "TIMEOUT",
    "WORKERS",
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
];

/// `PS1`, `RPS2` and the like.
fn is_numbered_prompt(upper: &str) -> bool {
    ["PS", "RPS"].iter().any(|prefix| {
        upper
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Why a name is held back unless `--allow NAME` or `allow = [...]` names it.
pub fn blocked_reason(key: &str) -> Option<SkipReason> {
    let upper = key.to_ascii_uppercase();
    let listed = BLOCKED_EXACT.contains(&upper.as_str())
        || BLOCKED_PREFIXES.iter().any(|p| upper.starts_with(p))
        || BLOCKED_SUFFIXES.iter().any(|s| upper.ends_with(s))
        || upper.contains("PROMPT")
        || is_numbered_prompt(&upper);
    if listed {
        return Some(SkipReason::Blocked);
    }
    if !upper.contains('_') && !PLAIN_SINGLE_WORDS.contains(&upper.as_str()) {
        return Some(SkipReason::SingleWord);
    }
    None
}

/// sekret's own settings are never loaded from secrets, even when allowed.
fn is_sekret_setting(key: &str) -> bool {
    key.to_ascii_uppercase().starts_with("SEKRET_")
}

/// Why a key was not loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    InvalidName,
    SekretSetting,
    Blocked,
    SingleWord,
}

impl SkipReason {
    fn explain(self) -> &'static str {
        match self {
            SkipReason::InvalidName => "they are not valid variable names",
            SkipReason::SekretSetting => "SEKRET_* names are sekret's own settings",
            SkipReason::Blocked => {
                "they can change what programs run or where they connect; pass --allow NAME, or add the name to \
                 `allow` in .sekret.toml, to load one anyway"
            }
            SkipReason::SingleWord => {
                "names without an underscore are mostly settings programs read, such as CC or TMPDIR; pass \
                 --allow NAME, or add the name to `allow` in .sekret.toml, to load one anyway"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub key: String,
    pub reason: SkipReason,
}

/// Which secrets may become environment variables: valid names that are not sekret's own and
/// not blocked, unless explicitly allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadPolicy {
    allowed: std::collections::BTreeSet<String>,
}

impl LoadPolicy {
    /// `allowed` names unblock themselves exactly as written; sekret's own names cannot be allowed.
    pub fn new(allowed: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut set = std::collections::BTreeSet::new();
        for name in allowed {
            if !is_variable_name(&name) {
                anyhow::bail!("cannot allow {name:?}: it is not a valid variable name");
            }
            if is_sekret_setting(&name) {
                anyhow::bail!("cannot allow {name}: sekret's own SEKRET_* settings are never loaded from secrets");
            }
            set.insert(name);
        }
        Ok(Self { allowed: set })
    }

    pub fn check(&self, key: &str) -> Result<(), SkipReason> {
        if !is_variable_name(key) {
            return Err(SkipReason::InvalidName);
        }
        if is_sekret_setting(key) {
            return Err(SkipReason::SekretSetting);
        }
        if self.allowed.contains(key) {
            return Ok(());
        }
        blocked_reason(key).map_or(Ok(()), Err)
    }

    /// Splits secrets into those that may be loaded and those left out, with why.
    pub fn split(&self, vars: BTreeMap<String, String>) -> (BTreeMap<String, String>, Vec<Skipped>) {
        let mut kept = BTreeMap::new();
        let mut skipped = Vec::new();
        for (key, value) in vars {
            match self.check(&key) {
                Ok(()) => {
                    kept.insert(key, value);
                }
                Err(reason) => skipped.push(Skipped { key, reason }),
            }
        }
        (kept, skipped)
    }
}

/// One line per reason naming the skipped keys, never their values.
pub fn describe_skipped(skipped: &[Skipped]) -> Vec<String> {
    let mut by_reason: BTreeMap<SkipReason, Vec<String>> = BTreeMap::new();
    for item in skipped {
        by_reason
            .entry(item.reason)
            .or_default()
            .push(super::format::one_line(&item.key));
    }
    by_reason
        .into_iter()
        .map(|(reason, keys)| format!("sekret: skipped {} because {}", keys.join(", "), reason.explain()))
        .collect()
}

/// Credentials of the CLI and server that a child process never needs.
pub const CREDENTIAL_VARS: [&str; 4] = [
    "SEKRET_TOKEN",
    "SEKRET_CLIENT_SECRET",
    "SEKRET_UNLOCK_PASSPHRASE",
    "SEKRET_REMEMBER_SECRET",
];

fn fish_value(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn export(shell: Shell, name: &str, value: &str) -> String {
    if shell.is_fish() {
        return format!("set -gx {name} {}\n", fish_value(value));
    }
    format!("export {name}={}\n", shell_value(value))
}

fn unset(shell: Shell, names: &[String]) -> String {
    let names: Vec<&String> = names.iter().filter(|n| is_variable_name(n)).collect();
    if names.is_empty() {
        return String::new();
    }
    let joined = names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(" ");
    if shell.is_fish() {
        return format!("set -e {joined}\n");
    }
    format!("unset {joined}\n")
}

/// Keys recorded by a previous switch, read from the shell's `SEKRET_LOADED_KEYS`.
pub fn previously_loaded(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split_whitespace()
        .filter(|k| is_variable_name(k))
        .map(String::from)
        .collect()
}

/// Removes what the last switch loaded, then exports what `policy` lets through and records it.
pub fn switch_script(
    shell: Shell,
    previous: &[String],
    vars: BTreeMap<String, String>,
    policy: &LoadPolicy,
    origin: &Origin,
) -> Switch {
    let mut script = unset(shell, previous);
    let (kept, skipped) = policy.split(vars);
    let mut loaded = Vec::new();
    for (key, value) in kept {
        script.push_str(&export(shell, &key, &value));
        loaded.push(key);
    }
    script.push_str(&export(shell, "SEKRET_PROJECT", &origin.project));
    script.push_str(&export(shell, "SEKRET_ENVIRONMENT", &origin.environment));
    script.push_str(&export(shell, "SEKRET_PATH", &origin.path));
    script.push_str(&export(shell, super::config::LOADED_FILE_VAR, &origin.project_file));
    script.push_str(&export(shell, LOADED_KEYS_VAR, &loaded.join(" ")));
    Switch {
        script,
        loaded,
        skipped,
    }
}

/// Removes what the last switch loaded, and the project and environment it chose.
pub fn unload_script(shell: Shell, previous: &[String]) -> String {
    let mut names = previous.to_vec();
    names.push(LOADED_KEYS_VAR.into());
    names.extend(ORIGIN_VARS.iter().map(|n| n.to_string()));
    unset(shell, &names)
}

/// Defines `sekret-env`: `sekret-env prod` switches, `sekret-env off` unloads, bare shows status.
pub fn init_script(shell: Shell) -> String {
    if shell.is_fish() {
        return "function sekret-env --description 'Load sekret secrets into this shell'\n    \
                switch \"$argv[1]\"\n        \
                case '' status\n            command sekret env status\n        \
                case off unload\n            command sekret env unload --shell fish | source\n        \
                case '*'\n            command sekret env use --shell fish $argv | source\n    \
                end\nend\n"
            .into();
    }
    let flag = match shell {
        Shell::Zsh => "zsh",
        Shell::Sh => "sh",
        _ => "bash",
    };
    format!(
        "sekret-env() {{\n  \
         case \"${{1:-}}\" in\n    \
         ''|status) command sekret env status ;;\n    \
         off|unload) eval \"$(command sekret env unload --shell {flag})\" ;;\n    \
         *) eval \"$(command sekret env use --shell {flag} \"$@\")\" ;;\n  \
         esac\n}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::super::config::LOADED_FILE_VAR;
    use super::*;
    use anyhow::Context;

    fn is_blocked(key: &str) -> bool {
        blocked_reason(key).is_some()
    }

    fn origin(environment: &str) -> Origin {
        Origin {
            project: "app".into(),
            environment: environment.into(),
            path: "/".into(),
            project_file: "/repo/.sekret.toml".into(),
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Runs `script` in a fresh bash and prints the named variables, `-` when unset.
    fn bash_after(script: &str, names: &[&str]) -> anyhow::Result<Vec<String>> {
        let probe: String = names
            .iter()
            .map(|n| format!("printf '%s\\n' \"${{{n}-<unset>}}\"\n"))
            .collect();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("{script}\n{probe}"))
            .env_remove(LOADED_KEYS_VAR)
            .output()
            .context("bash")?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(String::from)
            .collect())
    }

    fn strict() -> LoadPolicy {
        LoadPolicy::default()
    }

    fn skipped_keys(skipped: &[Skipped]) -> Vec<&str> {
        skipped.iter().map(|s| s.key.as_str()).collect()
    }

    #[test]
    fn switching_replaces_the_previous_environment() -> anyhow::Result<()> {
        let dev = switch_script(
            Shell::Bash,
            &[],
            vars(&[("DB_URL", "postgres://dev"), ("DEV_ONLY", "x")]),
            &strict(),
            &origin("dev"),
        );
        let prod = switch_script(
            Shell::Bash,
            &dev.loaded,
            vars(&[("DB_URL", "postgres://prod")]),
            &strict(),
            &origin("prod"),
        );
        let state = bash_after(
            &format!("{}{}", dev.script, prod.script),
            &["DB_URL", "DEV_ONLY", "SEKRET_ENVIRONMENT", LOADED_KEYS_VAR],
        )?;
        assert_eq!(state, ["postgres://prod", "<unset>", "prod", "DB_URL"]);
        Ok(())
    }

    #[test]
    fn hostile_values_are_not_executed() -> anyhow::Result<()> {
        let value = "'; touch /tmp/sekret-pwned; echo '$(id) `id` \"\\ \n end";
        let switch = switch_script(
            Shell::Bash,
            &[],
            vars(&[("NASTY_VALUE", value)]),
            &strict(),
            &origin("dev"),
        );
        assert_eq!(bash_after(&switch.script, &["NASTY_VALUE"])?.join("\n"), value);
        Ok(())
    }

    #[test]
    fn keys_that_cannot_be_variables_are_skipped() {
        let switch = switch_script(
            Shell::Bash,
            &[],
            vars(&[
                ("my.key", "a"),
                ("1ABC", "b"),
                ("SEKRET_TOKEN", "c"),
                ("OK_KEY", "d"),
                ("Ä", "e"),
            ]),
            &strict(),
            &origin("dev"),
        );
        assert_eq!(switch.loaded, ["OK_KEY"]);
        assert_eq!(skipped_keys(&switch.skipped), ["1ABC", "SEKRET_TOKEN", "my.key", "Ä"]);
    }

    #[test]
    fn names_that_change_shell_or_linker_behaviour_are_skipped() {
        let hostile = vars(&[
            ("BASH_ENV", "/tmp/x"),
            ("PROMPT_COMMAND", "touch /tmp/pwned"),
            ("PS1", "$(id)"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("PATH", "/tmp"),
            ("NODE_OPTIONS", "--require /tmp/x.js"),
            ("JAVA_TOOL_OPTIONS", "-javaagent:x"),
            ("GIT_SSH_COMMAND", "sh -c id"),
            ("DATABASE_URL", "postgres://db"),
            ("PSQL_HOST", "db"),
        ]);
        let switch = switch_script(Shell::Bash, &[], hostile, &strict(), &origin("dev"));
        assert_eq!(switch.loaded, ["DATABASE_URL", "PSQL_HOST"]);
        assert!(!switch.script.contains("BASH_ENV") && !switch.script.contains("LD_PRELOAD"));
        assert!(switch.skipped.iter().all(|s| s.reason == SkipReason::Blocked));
    }

    /// Every name the round 3 audit showed getting past the old denylist, among them ones that
    /// run code (`GIT_EXTERNAL_DIFF`, `PAGER`, `EDITOR`, `GCONV_PATH`) or redirect traffic.
    const BYPASSES: &[&str] = &[
        "GIT_EXTERNAL_DIFF",
        "GIT_EDITOR",
        "GIT_PAGER",
        "GIT_SSH",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "PAGER",
        "MANPAGER",
        "SYSTEMD_PAGER",
        "EDITOR",
        "VISUAL",
        "SUDO_ASKPASS",
        "DISPLAY_COMMAND",
        "RPROMPT",
        "RPS1",
        "PS4",
        "PROMPT",
        "XDG_CONFIG_HOME",
        "XDG_DATA_DIRS",
        "SSH_AUTH_SOCK",
        "GPG_AGENT_INFO",
        "GNUPGHOME",
        "CARGO_HOME",
        "RUSTC_WRAPPER",
        "RUSTUP_TOOLCHAIN",
        "PYTHONUSERBASE",
        "PERLLIB",
        "RUBYGEMS_GEMDEPS",
        "GEM_HOME",
        "NODE_EXTRA_CA_CERTS",
        "NPM_CONFIG_PREFIX",
        "JAVA_HOME",
        "CLASSPATH",
        "DOCKER_HOST",
        "KUBECONFIG",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "HTTPS_PROXY",
        "https_proxy",
        "ftp_proxy",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "HISTFILE",
        "FPATH",
        "fpath",
        "path",
        "TMOUT",
        "MAILPATH",
        "MAIL",
        "BROWSER",
        "HOME",
        "SHELL",
        "IFS",
        "ENV",
        "BASH_ENV",
        "BASH_FUNC_x%%",
        "ZDOTDIR",
        "TERMINFO",
        "TERM",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "OPENSSL_CONF",
        "LUA_INIT",
        "COREPACK_NPM_REGISTRY",
        "COREPACK_INTEGRITY_KEYS",
        "COREPACK_HOME",
        "VAULT_ADDR",
        "CONSUL_HTTP_ADDR",
        "NOMAD_ADDR",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "GITHUB_API_URL",
        "NVM_NODEJS_ORG_MIRROR",
        "CONDA_CHANNEL_ALIAS",
        "HOMEBREW_API_DOMAIN",
        "ANT_HOME",
    ];

    #[test]
    fn the_demonstrated_bypasses_are_all_refused() {
        let policy = strict();
        for name in BYPASSES {
            assert!(policy.check(name).is_err(), "{name}");
        }
        for fine in [
            "DATABASE_URL",
            "API_KEY",
            "STRIPE_SECRET",
            "PSQL_HOST",
            "_PRIVATE",
            "REDIS_PASSWORD",
        ] {
            assert_eq!(policy.check(fine), Ok(()), "{fine}");
        }
    }

    /// Names from the round 4 audit that make editors, database shells, build tools and runtimes
    /// run code chosen by whoever wrote the secret.
    const CODE_RUNNERS: &[&str] = &[
        "VIMINIT",
        "EXINIT",
        "GVIMINIT",
        "MYVIMRC",
        "VIMRUNTIME",
        "PSQLRC",
        "MAVEN_OPTS",
        "MAVEN_ARGS",
        "GRADLE_OPTS",
        "GRADLE_USER_HOME",
        "SBT_OPTS",
        "ANT_OPTS",
        "DOTNET_STARTUP_HOOKS",
        "CORECLR_ENABLE_PROFILING",
        "CORECLR_PROFILER_PATH",
        "COR_PROFILER_PATH",
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        "ERL_AFLAGS",
        "ERL_FLAGS",
        "ERL_ZFLAGS",
        "ELIXIR_ERL_OPTIONS",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "TF_CLI_CONFIG_FILE",
        "TERRAFORM_CONFIG",
        "HGRCPATH",
        "IRBRC",
        "WGETRC",
        "NETRC",
        "ANSIBLE_CONFIG",
        "NULLCMD",
        "CFLAGS",
        "LDFLAGS",
        "R_PROFILE_USER",
        "JULIA_DEPOT_PATH",
        "UV_INDEX_URL",
        "SOME_TOOL_OPTS",
        "SOME_TOOL_FLAGS",
        "PRE_COMMIT_HOOK",
        "viminit",
    ];

    #[test]
    fn names_that_make_tools_run_code_are_refused() {
        let policy = strict();
        for name in CODE_RUNNERS {
            assert!(is_blocked(name), "{name}");
            assert_eq!(policy.check(name), Err(SkipReason::Blocked), "{name}");
        }
        for fine in ["DATABASE_URL", "PSQL_HOST", "AWS_REGION", "SENTRY_DSN", "OPTS_URL"] {
            assert_eq!(policy.check(fine), Ok(()), "{fine}");
        }
    }

    /// Remote container engines and backup or sync tools, which would send a working tree or a
    /// backup to whoever wrote the secret.
    const REMOTE_DESTINATIONS: &[&str] = &[
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "CONTAINER_SSHKEY",
        "CONTAINERS_CONF",
        "CONTAINERS_REGISTRIES_CONF",
        "PODMAN_CONNECTIONS_CONF",
        "BUILDAH_ISOLATION",
        "BUILDKIT_HOST",
        "RESTIC_REPOSITORY",
        "RESTIC_PASSWORD",
        "RESTIC_REPOSITORY_FILE",
        "BORG_REPO",
        "BORG_PASSPHRASE",
        "RCLONE_CONFIG_MYREMOTE_TYPE",
        "RCLONE_CONFIG_MYREMOTE_HOST",
        "rclone_config",
        "container_host",
    ];

    #[test]
    fn remote_engines_and_backup_destinations_are_refused() -> anyhow::Result<()> {
        let policy = strict();
        for name in REMOTE_DESTINATIONS {
            assert!(is_blocked(name), "{name}");
            assert_eq!(policy.check(name), Err(SkipReason::Blocked), "{name}");
        }
        for fine in ["CONTAINER_NAME", "BACKUP_BUCKET", "PODS_URL", "BORGES_KEY"] {
            assert_eq!(policy.check(fine), Ok(()), "{fine}");
        }
        let allowed = LoadPolicy::new(["RESTIC_REPOSITORY".to_string()])?;
        assert_eq!(allowed.check("RESTIC_REPOSITORY"), Ok(()));
        Ok(())
    }

    /// Build tool settings that run a command or swap the toolchain, from the round 5 audit.
    const BUILD_TOOL_RUNNERS: &[&str] = &[
        "GNUMAKEFLAGS",
        "MAKEFILES",
        "CGO_CFLAGS",
        "CGO_CPPFLAGS",
        "CGO_CXXFLAGS",
        "CGO_LDFLAGS",
        "CGO_ENABLED",
        "CMAKE_C_COMPILER_LAUNCHER",
        "CMAKE_CXX_COMPILER_LAUNCHER",
        "CMAKE_TOOLCHAIN_FILE",
        "SOME_LINKER_LAUNCHER",
        "RUSTC_WRAPPER",
        "SOME_WRAPPER",
        "NIX_PATH",
        "NIX_CONFIG",
        "GOPROXY",
        "GONOPROXY",
        "GOSUMDB",
        "GONOSUMDB",
        "GOPRIVATE",
        "GOINSECURE",
        "GOAUTH",
        "GOCACHEPROG",
        "GOEXPERIMENT",
        "CCACHE_PREFIX",
        "CCACHE_CONFIGPATH",
        "SCCACHE_DIR",
        "DISTCC_HOSTS",
        "GCC_EXEC_PREFIX",
        "COMPILER_PATH",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "PKG_CONFIG",
        "PKG_CONFIG_PATH",
        "LESS",
        "LESSKEY",
        "ELECTRON_RUN_AS_NODE",
        "HELM_PLUGINS",
        "AS",
        "RANLIB",
        "gnumakeflags",
    ];

    #[test]
    fn build_tool_settings_that_run_code_are_refused() {
        let policy = strict();
        for name in BUILD_TOOL_RUNNERS {
            assert!(is_blocked(name), "{name}");
            assert_eq!(policy.check(name), Err(SkipReason::Blocked), "{name}");
        }
        for fine in [
            "GOOGLE_API_KEY",
            "GO_SERVICE_URL",
            "NIXIE_COUNT",
            "CC_EMAIL",
            "FLAG_COLOUR",
        ] {
            assert_eq!(policy.check(fine), Ok(()), "{fine}");
        }
    }

    /// Autoconf, gcloud and interpreter overrides from the round 7 audit, and names in the same
    /// classes that no list names, which the structural rules catch.
    const PROGRAM_OVERRIDES: &[&str] = &[
        "CONFIG_SHELL",
        "CONFIG_SITE",
        "SED",
        "GREP",
        "EGREP",
        "FGREP",
        "AWK",
        "MKDIR_P",
        "LIBTOOL",
        "LIBTOOLIZE",
        "AUTOCONF",
        "AUTOHEADER",
        "AUTOMAKE",
        "ACLOCAL",
        "AUTOM4TE",
        "CLOUDSDK_PYTHON",
        "CLOUDSDK_PYTHON_ARGS",
        "CLOUDSDK_API_ENDPOINT_OVERRIDES_STORAGE",
        "TMPDIR",
        "PYSPARK_PYTHON",
        "CHROME_BIN",
        "SOME_TOOL_EXECUTABLE",
        "SOME_TOOL_EXE",
        "SOME_TOOL_CMD",
        "SOME_TOOL_PROGRAM",
        "SOME_TOOL_INTERPRETER",
        "SOME_TOOL_SH",
        "PERL5DB",
        "PGSERVICEFILE",
        "PGSSLROOTCERT",
        "SOMEFUTURETOOL",
        "config_shell",
        "tmpdir",
    ];

    #[test]
    fn program_overrides_and_unknown_single_words_are_refused() {
        let policy = strict();
        for name in PROGRAM_OVERRIDES {
            assert!(is_blocked(name), "{name}");
            assert!(policy.check(name).is_err(), "{name}");
        }
        assert_eq!(policy.check("CONFIG_SHELL"), Err(SkipReason::Blocked));
        assert_eq!(policy.check("CLOUDSDK_PYTHON"), Err(SkipReason::Blocked));
        assert_eq!(policy.check("TMPDIR"), Err(SkipReason::SingleWord));
        assert_eq!(policy.check("SED"), Err(SkipReason::SingleWord));
        assert_eq!(
            policy.check("CC"),
            Err(SkipReason::Blocked),
            "listed names keep their reason"
        );
    }

    /// Installers, secret stores and CI settings from the round 8 audit that fetch code from, or
    /// send the loader's own credentials to, a server the secret writer names. The `SOME_TOOL_`
    /// names are caught by the structural suffixes rather than a list.
    const CREDENTIAL_REDIRECTS: &[&str] = &[
        "COREPACK_NPM_REGISTRY",
        "COREPACK_INTEGRITY_KEYS",
        "COREPACK_HOME",
        "VAULT_ADDR",
        "BAO_ADDR",
        "CONSUL_HTTP_ADDR",
        "NOMAD_ADDR",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_URL",
        "RUNNER_TEMP",
        "GITHUB_API_URL",
        "GITHUB_SERVER_URL",
        "GITHUB_GRAPHQL_URL",
        "GITHUB_ENV",
        "CI_API_V4_URL",
        "NVM_NODEJS_ORG_MIRROR",
        "CONDA_CHANNEL_ALIAS",
        "MAMBA_ROOT_PREFIX",
        "HOMEBREW_API_DOMAIN",
        "ANT_HOME",
        "PNPM_HOME",
        "ASDF_DATA_DIR",
        "PYENV_ROOT",
        "RBENV_ROOT",
        "SDKMAN_DIR",
        "MISE_DATA_DIR",
        "COMPOSER_AUTH",
        "PUPPETEER_EXECUTABLE_PATH",
        "PLAYWRIGHT_DOWNLOAD_HOST",
        "AZURE_AUTHORITY_HOST",
        "SOME_TOOL_HOME",
        "SOME_TOOL_MIRROR",
        "SOME_TOOL_REGISTRY",
        "SOME_TOOL_INDEX_URL",
        "SOME_TOOL_EXTRA_INDEX_URL",
        "SASS_BINARY_SITE",
        "SOME_TOOL_DOWNLOAD_HOST",
        "SOME_TOOL_CONFIG_FILE",
        "SOME_TOOL_CONFIG_PATH",
        "SOME_TOOL_CONFIG_DIR",
        "SOME_TOOL_CA_BUNDLE",
        "SOME_TOOL_CA_FILE",
        "SOME_TOOL_CAFILE",
        "SOME_TOOL_CA_CERTS",
        "vault_addr",
    ];

    #[test]
    fn names_that_redirect_installers_or_credentials_are_refused() {
        let policy = strict();
        for name in CREDENTIAL_REDIRECTS {
            assert!(is_blocked(name), "{name}");
            assert_eq!(policy.check(name), Err(SkipReason::Blocked), "{name}");
        }
        for fine in [
            "DATABASE_URL",
            "API_KEY",
            "STRIPE_SECRET",
            "GITHUB_TOKEN",
            "LISTEN_ADDR",
            "REDIS_ADDR",
            "S3_ENDPOINT",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "SCHEMA_REGISTRY_URL",
            "FIREBASE_CONFIG",
            "DATABASE_CA_CERT",
            "HOMEPAGE_URL",
        ] {
            assert_eq!(policy.check(fine), Ok(()), "{fine}");
        }
    }

    #[test]
    fn ordinary_app_config_still_loads() {
        let policy = strict();
        for fine in [
            "DATABASE_URL",
            "API_KEY",
            "STRIPE_SECRET",
            "STRIPE_SECRET_KEY",
            "JWT_SECRET",
            "REDIS_URL",
            "SENTRY_DSN",
            "SMTP_HOST",
            "LOG_LEVEL",
            "S3_BUCKET",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "FEATURE_X_ENABLED",
            "SHELL_COLOUR_THEME",
            "BIN_COUNT",
            "PORT",
            "HOST",
            "DEBUG",
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PGHOST",
            "PGPASSWORD",
            "port",
        ] {
            assert_eq!(policy.check(fine), Ok(()), "{fine}");
        }
    }

    #[test]
    fn single_words_load_when_allowed_and_are_explained() -> anyhow::Result<()> {
        let policy = LoadPolicy::new(["TMPDIR".to_string(), "CONFIG_SHELL".to_string()])?;
        assert_eq!(policy.check("TMPDIR"), Ok(()));
        assert_eq!(policy.check("CONFIG_SHELL"), Ok(()));
        assert_eq!(policy.check("SED"), Err(SkipReason::SingleWord));
        let (_, skipped) = strict().split(vars(&[("SED", "/tmp/evil"), ("CONFIG_SHELL", "/tmp/evil")]));
        let lines = describe_skipped(&skipped);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].contains("CONFIG_SHELL") && lines[0].contains("--allow"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("SED") && lines[1].contains("without an underscore") && lines[1].contains("--allow"),
            "{lines:?}"
        );
        assert!(!lines.join("\n").contains("/tmp/evil"));
        Ok(())
    }

    #[test]
    fn config_shell_from_a_secret_does_not_reach_configure() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let marker = dir.path().join("pwned");
        let payload = format!("/bin/sh -c touch${{IFS}}{}", marker.display());
        let switch = switch_script(
            Shell::Bash,
            &[],
            vars(&[
                ("CONFIG_SHELL", payload.as_str()),
                ("SED", "/bin/false"),
                ("TMPDIR", "/tmp/elsewhere"),
                ("DATABASE_URL", "postgres://db"),
            ]),
            &strict(),
            &origin("dev"),
        );
        assert_eq!(switch.loaded, ["DATABASE_URL"]);
        assert!(!switch.script.contains("TMPDIR") && !switch.script.contains("touch"));
        let probe = "${CONFIG_SHELL:-true}\n";
        let state = bash_after(
            &format!("{}{probe}", switch.script),
            &["CONFIG_SHELL", "SED", "DATABASE_URL"],
        )?;
        assert_eq!(state, ["<unset>", "<unset>", "postgres://db"]);
        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn gnumakeflags_from_a_secret_is_not_exported() -> anyhow::Result<()> {
        let switch = switch_script(
            Shell::Bash,
            &[],
            vars(&[
                ("GNUMAKEFLAGS", "--eval=$(shell touch /tmp/pwned)"),
                ("CGO_CFLAGS", "-wrapper /bin/sh,-c,id"),
                ("API_KEY", "k"),
            ]),
            &strict(),
            &origin("dev"),
        );
        assert_eq!(switch.loaded, ["API_KEY"]);
        assert_eq!(skipped_keys(&switch.skipped), ["CGO_CFLAGS", "GNUMAKEFLAGS"]);
        let after = bash_after(&switch.script, &["GNUMAKEFLAGS", "CGO_CFLAGS", "API_KEY"])?;
        assert_eq!(after, ["<unset>", "<unset>", "k"]);
        Ok(())
    }

    #[test]
    fn viminit_from_a_secret_is_not_exported() -> anyhow::Result<()> {
        let switch = switch_script(
            Shell::Bash,
            &[],
            vars(&[
                ("VIMINIT", ":silent !touch /tmp/pwned"),
                ("MAVEN_OPTS", "-javaagent:/tmp/x.jar"),
            ]),
            &strict(),
            &origin("dev"),
        );
        assert!(switch.loaded.is_empty());
        assert_eq!(
            bash_after(&switch.script, &["VIMINIT", "MAVEN_OPTS"])?,
            ["<unset>", "<unset>"]
        );
        Ok(())
    }

    #[test]
    fn blocked_names_load_only_when_allowed_by_exact_name() -> anyhow::Result<()> {
        let policy = LoadPolicy::new(["GIT_PAGER".to_string(), "KUBECONFIG".to_string()])?;
        assert_eq!(policy.check("GIT_PAGER"), Ok(()));
        assert_eq!(policy.check("KUBECONFIG"), Ok(()));
        assert_eq!(policy.check("git_pager"), Err(SkipReason::Blocked), "exact name only");
        assert_eq!(policy.check("GIT_EXTERNAL_DIFF"), Err(SkipReason::Blocked));
        assert!(
            LoadPolicy::new(["SEKRET_URL".to_string()]).is_err(),
            "sekret's own names stay out"
        );
        assert!(LoadPolicy::new(["sekret_url".to_string()]).is_err());
        assert!(LoadPolicy::new(["BAD-NAME".to_string()]).is_err());
        Ok(())
    }

    #[test]
    fn skipped_keys_are_explained_by_reason_without_values() {
        let (_, skipped) = strict().split(vars(&[
            ("GIT_EXTERNAL_DIFF", "/tmp/evil"),
            ("bad.key", "v1"),
            ("SEKRET_URL", "https://evil.test"),
            ("bad\u{1b}[2Jkey", "v2"),
        ]));
        let lines = describe_skipped(&skipped);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains("bad.key") && lines[0].contains("not valid variable names"));
        assert!(lines[0].contains("badkey"), "server text is made printable: {lines:?}");
        assert!(lines[1].contains("SEKRET_URL") && lines[1].contains("sekret's own"));
        assert!(lines[2].contains("GIT_EXTERNAL_DIFF") && lines[2].contains("--allow"));
        let all = lines.join("\n");
        assert!(!all.contains("/tmp/evil") && !all.contains("evil.test") && !all.contains('\u{1b}'));
    }

    #[test]
    fn git_external_diff_from_a_secret_does_not_run() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let marker = dir.path().join("pwned");
        let switch = switch_script(
            Shell::Bash,
            &[],
            vars(&[("GIT_EXTERNAL_DIFF", &format!("touch {}", marker.display()))]),
            &strict(),
            &origin("dev"),
        );
        assert!(switch.loaded.is_empty());
        assert_eq!(bash_after(&switch.script, &["GIT_EXTERNAL_DIFF"])?, ["<unset>"]);
        Ok(())
    }

    #[test]
    fn helper_programs_proxies_and_runtime_paths_are_unsafe() {
        for name in [
            "GIT_PROXY_COMMAND",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "LESSOPEN",
            "LESSCLOSE",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "NODE_PATH",
            "NODE_OPTIONS",
            "RUBYLIB",
            "RUBYOPT",
            "PERL5OPT",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "NO_PROXY",
            "BASH_ENV",
            "ENV",
            "PROMPT_COMMAND",
        ] {
            assert!(is_blocked(name), "{name}");
            assert_eq!(strict().check(name), Err(SkipReason::Blocked), "{name}");
        }
        assert_eq!(strict().check("SEKRET_URL"), Err(SkipReason::SekretSetting));
        assert_eq!(strict().check("bad.key"), Err(SkipReason::InvalidName));
        let (kept, skipped) = strict().split(vars(&[("DB_URL", "1"), ("SEKRET_TOKEN", "x"), ("HTTPS_PROXY", "p")]));
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["DB_URL"]);
        assert_eq!(skipped_keys(&skipped), ["HTTPS_PROXY", "SEKRET_TOKEN"]);
    }

    #[test]
    fn remote_shells_module_paths_and_leaky_settings_are_blocked() {
        for name in [
            "RSYNC_RSH",
            "RSYNC_CONNECT_PROG",
            "SVN_SSH",
            "CVS_RSH",
            "FCEDIT",
            "fcedit",
            "GIO_EXTRA_MODULES",
            "GDK_PIXBUF_MODULE_FILE",
            "LIBGL_DRIVERS_PATH",
            "VK_LAYER_PATH",
            "VK_ADD_LAYER_PATH",
            "VK_ICD_FILENAMES",
            "EMACSLOADPATH",
            "IPYTHONDIR",
            "JUPYTER_CONFIG_DIR",
            "SSLKEYLOGFILE",
            "AWS_ENDPOINT_URL",
            "AWS_ENDPOINT_URL_S3",
            "AWS_CA_BUNDLE",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "DBUS_SESSION_BUS_ADDRESS",
            "KRB5_CONFIG",
            "KRB5CCNAME",
            "SOME_TOOL_RSH",
            "SOME_TOOL_SSH",
        ] {
            assert!(is_blocked(name), "{name}");
            assert_eq!(strict().check(name), Err(SkipReason::Blocked), "{name}");
        }
        for name in ["AWS_REGION", "AWS_ACCESS_KEY_ID", "DATABASE_URL", "CREDIT_LIMIT"] {
            assert!(!is_blocked(name), "{name}");
        }
    }

    #[test]
    fn unload_removes_only_what_was_loaded() -> anyhow::Result<()> {
        let load = switch_script(Shell::Bash, &[], vars(&[("DB_URL", "1")]), &strict(), &origin("dev"));
        let unload = unload_script(Shell::Bash, &previously_loaded(Some("DB_URL")));
        let loaded = bash_after(&load.script, &["SEKRET_PROJECT", LOADED_FILE_VAR])?;
        assert_eq!(loaded, ["app", "/repo/.sekret.toml"]);
        let state = bash_after(
            &format!("KEEP=me\n{}{unload}", load.script),
            &[
                "DB_URL",
                "KEEP",
                LOADED_KEYS_VAR,
                "SEKRET_PROJECT",
                "SEKRET_ENVIRONMENT",
                "SEKRET_PATH",
                LOADED_FILE_VAR,
            ],
        )?;
        assert_eq!(
            state,
            ["<unset>", "me", "<unset>", "<unset>", "<unset>", "<unset>", "<unset>"],
            "unloading also forgets the project and environment, so another folder's file applies"
        );
        Ok(())
    }

    #[test]
    fn previously_loaded_ignores_junk() {
        assert_eq!(previously_loaded(Some("A  B $(id) C")), ["A", "B", "C"]);
        assert!(previously_loaded(None).is_empty());
    }

    #[test]
    fn fish_output_uses_set() {
        let switch = switch_script(
            Shell::Fish,
            &["OLD".into()],
            vars(&[("APP_NOTE", "it's \\")]),
            &strict(),
            &origin("dev"),
        );
        assert!(switch.script.starts_with("set -e OLD\n"));
        assert!(switch.script.contains("set -gx APP_NOTE 'it\\'s \\\\'\n"));
        assert!(init_script(Shell::Fish).contains("| source"));
    }

    #[test]
    fn bash_init_defines_a_working_function() -> anyhow::Result<()> {
        let script = format!(
            "{}\ntype sekret-env >/dev/null && echo defined",
            init_script(Shell::Bash)
        );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .output()
            .context("bash")?;
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "defined");
        Ok(())
    }
}
