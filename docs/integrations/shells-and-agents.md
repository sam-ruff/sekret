# Shells and AI agents

A program cannot change the environment of the shell that started it, so `sekret env use` prints shell code and the shell runs it. `eval "$(sekret env use prod)"` loads the project's `prod` secrets into the current shell, and the next `env use` removes the keys the last one loaded before adding the new ones, so nothing from `dev` lingers in a `prod` shell.

## In your own shell

Add one line to your shell's start-up file to get a `sekret-env` command:

=== "bash"

    ```sh
    echo 'eval "$(sekret shell-init bash)"' >> ~/.bashrc
    ```

=== "zsh"

    ```sh
    echo 'eval "$(sekret shell-init zsh)"' >> ~/.zshrc
    ```

=== "fish"

    ```sh
    echo 'sekret shell-init fish | source' >> ~/.config/fish/config.fish
    ```

```sh
sekret-env dev        # load dev
sekret-env prod       # swap to prod
sekret-env            # show what is loaded, names only
sekret-env off        # unload
```

The project comes from `-p`, `SEKRET_PROJECT` or `.sekret.toml`, so `sekret-env` in a repository with a `.sekret.toml` loads that repository's project.

`sekret-env` leaves `SEKRET_PROJECT` and `SEKRET_ENVIRONMENT` set in the shell, so later `sekret` commands use the same place, and records which `.sekret.toml` was in force in `SEKRET_LOADED_FILE`. If you then move into another repository whose `.sekret.toml` names a different project or environment, sekret refuses to use the shell's values there instead of quietly loading the first repository's secrets, which might be production ones. Run `sekret-env off`, which also clears those variables, to use the new folder's file, or pass `-p` and `-e`. Values you set yourself, or that CI sets, are not checked and still win over the file.

!!! warning "Loading secrets runs code chosen by whoever can write them"

    Environment variables steer what programs do. A secret named `GNUMAKEFLAGS`, `NODE_OPTIONS` or `LD_PRELOAD` turns the next `make`, `node` or almost any program into a command of the secret writer's choosing. So loading an environment's secrets into a shell, or running a command with `sekret run`, gives everyone who can write secrets in that environment a way to run code as you. sekret blocks the names it knows are dangerous, but no list can cover every program and every setting it reads, so the list only reduces this risk. Only load secrets from environments whose writers you would trust with a shell on your machine.

Anyone who can write a secret could run code on your machine, or see your traffic, if a secret's name were one a shell, the dynamic linker or a program acts on. So only names made of letters, digits and underscores, not starting with a digit, are loaded, and of those the following are blocked unless you allow them. Names are compared without regard to case.

- Names without an underscore, apart from a few that are plainly app settings: `PORT`, `HOST`, `DEBUG`, `ENVIRONMENT`, `STAGE`, `REGION`, `DOMAIN`, `SECRET`, `TOKEN`, `PASSWORD`, `USERNAME`, `APIKEY`, `DATABASE`, `DSN`, `BUCKET`, `TENANT`, `LOGLEVEL`, `VERBOSE`, `TIMEOUT`, `WORKERS`, `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` and `PGDATABASE`. The settings Unix tools read are nearly all single words, such as `CC`, `SED`, `AWK`, `TMPDIR` or `PERL5DB`, while app settings such as `DATABASE_URL`, `API_KEY` or `STRIPE_SECRET` nearly all have an underscore. Holding back every other single word means a tool setting nobody has listed yet is left out rather than loaded.
- Names ending in `PAGER`, `EDITOR`, `ASKPASS`, `_COMMAND`, `_OPTIONS`, `_OPTS`, `FLAGS` (such as `CGO_LDFLAGS` or `GNUMAKEFLAGS`), `_PROXY`, `_HOOK`, `_HOOKS`, `_LAUNCHER` (such as `CMAKE_C_COMPILER_LAUNCHER`), `_WRAPPER`, `INIT` (such as `VIMINIT`), `RC` (such as `PSQLRC` or `IRBRC`), `_RSH` or `_SSH`, and names containing `PROMPT`.
- Names ending in a word that names a program to run: `_SHELL` (such as autoconf's `CONFIG_SHELL`), `_SH`, `_BASH`, `_ZSH`, `_PYTHON` (such as `CLOUDSDK_PYTHON` or `PYSPARK_PYTHON`), `_PERL`, `_RUBY`, `_BIN` (such as `CHROME_BIN`), `_EXE`, `_EXEC`, `_EXECUTABLE`, `_BINARY`, `_CMD`, `_PROG`, `_PROGRAM` or `_INTERPRETER`.
- Names ending in a word that points a tool at where it loads code, packages, settings or trusted certificates from: `_HOME` (such as `ANT_HOME`), `_MIRROR` (such as `NVM_NODEJS_ORG_MIRROR`), `_REGISTRY`, `_INDEX_URL`, `_BINARY_SITE`, `_DOWNLOAD_HOST`, `_CONFIG_FILE`, `_CONFIG_PATH`, `_CONFIG_DIR`, `_CA_BUNDLE`, `_CA_FILE`, `_CA_PATH`, `_CAFILE`, `_CAPATH` or `_CA_CERTS`. Names ending in `_URL`, `_ADDR` or `_ENDPOINT` are not blocked as a group, since most app settings end that way, so the tools that read such names are blocked by prefix or by name instead.
- The prompt variables `PS1` to `PS4`, `RPS1` and the like.
- Names starting with `BASH_`, `FISH_`, `TERM`, `LD_`, `DYLD_`, `MALLOC_`, `XDG_`, `GIT_`, `SSH_`, `GPG`, `CARGO_`, `RUSTC`, `RUSTUP_`, `PYTHON`, `PIP_`, `UV_`, `POETRY_`, `PERL`, `RUBY`, `GEM_`, `BUNDLE_`, `NODE_`, `NPM_`, `YARN_`, `DENO_`, `BUN_`, `ELECTRON_`, `JAVA_`, `_JAVA_`, `JDK_`, `CLASSPATH`, `MAVEN_`, `GRADLE_`, `DOTNET_`, `CORECLR_`, `ERL_`, `ELIXIR_`, `PHP`, `R_PROFILE`, `R_ENVIRON`, `R_LIBS`, `JULIA_`, `LUA_`, `ANSIBLE_`, `TF_CLI_`, `HELM_`, `DOCKER_`, `CONTAINERS_`, `PODMAN_`, `BUILDAH_`, `KUBE`, `NIX_`, `CGO_`, `CMAKE_`, `CCACHE_`, `SCCACHE_`, `DISTCC_`, `PKG_CONFIG`, `LESS`, `SSL_`, `OPENSSL_`, `CURL_`, `REQUESTS_CA`, `GTK_`, `QT_`, `GST_PLUGIN`, `GIO_`, `GDK_`, `LIBGL_`, `VK_`, `EMACS`, `IPYTHON`, `JUPYTER_`, `RSYNC_`, `SVN_`, `CVS_`, `KRB5`, `CLOUDSDK_`, `AWS_ENDPOINT_URL`, `COREPACK_`, `NVM_`, `VOLTA_`, `FNM_`, `PNPM_`, `HOMEBREW_`, `CONDA_`, `MAMBA_`, `ASDF_`, `PYENV_`, `RBENV_`, `SDKMAN_`, `MISE_`, `COMPOSER_`, `PUPPETEER_`, `PLAYWRIGHT_`, the backup and sync settings `RESTIC_`, `BORG_` and `RCLONE_`, the secret store and scheduler settings `VAULT_`, `BAO_`, `CONSUL_`, `NOMAD_` and `BOUNDARY_`, or the GitHub Actions runner settings `ACTIONS_` and `RUNNER_`.
- CI and cloud settings that say where the job's own tokens go: `GITHUB_API_URL`, `GITHUB_SERVER_URL`, `GITHUB_GRAPHQL_URL`, `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`, `GITHUB_STEP_SUMMARY`, GitLab's `CI_SERVER_URL`, `CI_API_V4_URL` and `CI_API_GRAPHQL_URL`, `AZURE_AUTHORITY_HOST` and `CYPRESS_INSTALL_BINARY`.
- Remote container engines, which would send a build context to another machine: `CONTAINER_HOST`, `CONTAINER_CONNECTION`, `CONTAINER_SSHKEY` and `BUILDKIT_HOST`.
- `PATH`, `HOME`, `SHELL`, `ENV`, `IFS`, `SHELLOPTS`, `BASHOPTS`, `ZDOTDIR`, `CDPATH`, `FPATH`, `MANPATH`, `MODULE_PATH`, `HISTFILE`, `TMOUT`, `MAIL`, `MAILPATH`, `BROWSER`, `VISUAL`, `INPUTRC`, `NULLCMD`, `READNULLCMD`, `VIM`, `VIMRUNTIME`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `GNUPGHOME`, `RUSTFLAGS`, `RUSTDOCFLAGS`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `BOTO_CONFIG`, `CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`, `TERRAFORM_CONFIG`, `HGRCPATH`, `TCLLIBPATH`, `GUILE_LOAD_PATH`, `GUILE_LOAD_COMPILED_PATH`, `COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH`, `GHC_ENVIRONMENT`, `FCEDIT`, `SSLKEYLOGFILE`, `AWS_CA_BUNDLE`, `DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, and autoconf's `CONFIG_SITE` and `MKDIR_P`.
- Go settings that change the toolchain or where modules come from: `GOFLAGS`, `GOROOT`, `GOPATH`, `GOENV`, `GOTOOLCHAIN`, `GOPROXY`, `GONOPROXY`, `GOSUMDB`, `GONOSUMDB`, `GOPRIVATE`, `GOINSECURE`, `GOVCS`, `GOAUTH`, `GOBIN`, `GOCACHE`, `GOCACHEPROG`, `GOMODCACHE`, `GOWORK`, `GOEXPERIMENT`, `GODEBUG`, `CC_FOR_TARGET` and `CXX_FOR_TARGET`.
- Compiler and make settings: `CC`, `CXX`, `CPP`, `LD`, `AR`, `AS`, `NM`, `RANLIB`, `STRIP`, `OBJCOPY`, `OBJDUMP`, `FC`, `F77`, `YACC`, `LEX`, `M4`, `RM`, `INSTALL`, `MAKE`, `MAKEFILES`, `MAKEFLAGS`, `MFLAGS`, `LDLIBS`, `GCC_EXEC_PREFIX`, `COMPILER_PATH`, `LIBRARY_PATH`, `CPATH`, `C_INCLUDE_PATH`, `CPLUS_INCLUDE_PATH` and `OBJC_INCLUDE_PATH`.

These rules catch some ordinary names too, such as `FEATURE_FLAGS`, `IMAGE_SRC` or a one-word name like `GREETING`. Allow those by name, or rename the secret with an underscore.

To load a blocked name, name it exactly with `--allow NAME` on `sekret env use`, `sekret run` or `sekret export`, or add it to `allow = [...]` in `.sekret.toml`. A `.sekret.toml` comes with the repository, so its `allow` list does nothing until you confirm it: the first time, sekret shows the file, the names and the server, project, environment and folder they would load from, and asks at the terminal. Your answer is saved beside your logins, for that file, that exact list and that place. Any change to the list asks again, and so does loading from somewhere else, so a commit that points the file at a project more people can write to cannot reuse your yes. Without a terminal, the names are left out with a note. Only allow a name if you trust everyone who can write secrets in that environment. Keys starting with `SEKRET_`, and `HOME` and `XDG_CONFIG_HOME`, which locate sekret's user config and so decide which server it trusts, are never loaded, even when allowed. `sekret run` and `sekret export --format dotenv` or `shell` follow the same rules. Each skipped key is named on standard error with the reason, never its value.

The project and environment a `.sekret.toml` picks are confirmed the same way: the first `sekret-env`, `sekret run` or `sekret export` that loads from them, or `secrets set`, `delete`, `rollback`, `generate`, a policy change or `snapshots restore` that changes something there, asks at the terminal, and a script or agent without one is refused until it passes `-p` and `-e` itself. Commands that only read, such as `secrets list`, name the file on standard error instead. See the [CLI reference](../cli.md).

`sekret env use` refuses to print to a terminal, since its output contains every value. Run it inside `eval`, or through `sekret-env`.

## For AI coding agents

The repository ships a skill for Claude Code in `integrations/claude/skills/sekret`. Link it into `~/.claude/skills/` and agents learn to check the login with `sekret whoami`, use `sekret run` for single commands, load and use secrets within one shell call (each tool call starts a fresh shell), never print values, and confirm with you before touching production.

```sh
ln -s "$PWD/integrations/claude/skills/sekret" ~/.claude/skills/sekret
```

Logging in needs a person, because the browser approval cannot be done by the agent. Run `sekret login` yourself, or give the agent a machine identity's token through `SEKRET_TOKEN`.
