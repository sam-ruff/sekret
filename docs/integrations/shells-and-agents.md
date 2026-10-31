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

Anyone who can write a secret could run code on your machine, or see your traffic, if a secret's name were one a shell, the dynamic linker or a program acts on. So only names made of letters, digits and underscores, not starting with a digit, are loaded, and of those the following are blocked unless you allow them. Names are compared without regard to case.

- Names ending in `PAGER`, `EDITOR`, `ASKPASS`, `_COMMAND`, `_OPTIONS` or `_PROXY`, and names containing `PROMPT`.
- The prompt variables `PS1` to `PS4`, `RPS1` and the like.
- Names starting with `BASH_`, `FISH_`, `TERM`, `LD_`, `DYLD_`, `MALLOC_`, `XDG_`, `GIT_`, `SSH_`, `GPG`, `CARGO_`, `RUSTC`, `RUSTUP_`, `PYTHON`, `PIP_`, `PERL`, `RUBY`, `GEM_`, `BUNDLE_`, `NODE_`, `NPM_`, `YARN_`, `JAVA_`, `_JAVA_`, `JDK_`, `CLASSPATH`, `LUA_`, `DOCKER_`, `KUBE`, `SSL_`, `OPENSSL_`, `CURL_`, `REQUESTS_CA`, `GTK_`, `QT_` or `GST_PLUGIN`.
- `PATH`, `HOME`, `SHELL`, `ENV`, `IFS`, `SHELLOPTS`, `BASHOPTS`, `ZDOTDIR`, `CDPATH`, `FPATH`, `MANPATH`, `MODULE_PATH`, `HISTFILE`, `TMOUT`, `MAIL`, `MAILPATH`, `BROWSER`, `VISUAL`, `INPUTRC`, `LESSOPEN`, `LESSCLOSE`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `GNUPGHOME`, `GOFLAGS`, `GOROOT`, `GOPATH`, `GOENV`, `GOTOOLCHAIN`, `RUSTFLAGS`, `RUSTDOCFLAGS`, `CC`, `CXX`, `CPP`, `LD`, `AR`, `MAKE`, `MAKEFLAGS` and `MFLAGS`.

To load a blocked name, name it exactly with `--allow NAME` on `sekret env use`, `sekret run` or `sekret export`, or add it to `allow = [...]` in `.sekret.toml`. Only allow a name if you trust everyone who can write secrets in that environment, and remember that a `.sekret.toml` comes with the repository: check its `allow` list in a repository you did not write. Keys starting with `SEKRET_` are never loaded, even when allowed. `sekret run` and `sekret export --format dotenv` or `shell` follow the same rules. Each skipped key is named on standard error with the reason, never its value.

`sekret env use` refuses to print to a terminal, since its output contains every value. Run it inside `eval`, or through `sekret-env`.

## For AI coding agents

The repository ships a skill for Claude Code in `integrations/claude/skills/sekret`. Link it into `~/.claude/skills/` and agents learn to check the login with `sekret whoami`, use `sekret run` for single commands, load and use secrets within one shell call (each tool call starts a fresh shell), never print values, and confirm with you before touching production.

```sh
ln -s "$PWD/integrations/claude/skills/sekret" ~/.claude/skills/sekret
```

Logging in needs a person, because the browser approval cannot be done by the agent. Run `sekret login` yourself, or give the agent a machine identity's token through `SEKRET_TOKEN`.
