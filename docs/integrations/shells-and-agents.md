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

Some names are never loaded, because a shell, the dynamic linker or a program would act on them: `PATH`, `LD_*`, `BASH_ENV`, `PROMPT_COMMAND`, the prompt variables `PS*`, names ending in `_OPTIONS`, helper commands such as `GIT_ASKPASS` and `LESSOPEN`, proxy settings such as `HTTPS_PROXY`, and a few more. Anyone who can write a secret could otherwise run code on your machine, or see your traffic, when you load the environment. `sekret run` and `sekret export --format dotenv` or `shell` leave out the same names, as well as keys starting with `SEKRET_`. Keys that are not valid variable names, such as `my.key`, are skipped too. Each of them names what it skipped on standard error.

`sekret env use` refuses to print to a terminal, since its output contains every value. Run it inside `eval`, or through `sekret-env`.

## For AI coding agents

The repository ships a skill for Claude Code in `integrations/claude/skills/sekret`. Link it into `~/.claude/skills/` and agents learn to check the login with `sekret whoami`, use `sekret run` for single commands, load and use secrets within one shell call (each tool call starts a fresh shell), never print values, and confirm with you before touching production.

```sh
ln -s "$PWD/integrations/claude/skills/sekret" ~/.claude/skills/sekret
```

Logging in needs a person, because the browser approval cannot be done by the agent. Run `sekret login` yourself, or give the agent a machine identity's token through `SEKRET_TOKEN`.
