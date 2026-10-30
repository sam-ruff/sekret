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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub script: String,
    pub loaded: Vec<String>,
    /// Keys left out because they are not valid variable names or would clash with sekret's own.
    pub skipped: Vec<String>,
}

pub fn is_variable_name(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Names that change how a shell, the dynamic linker or a runtime behaves. Anyone who can write a
/// secret could otherwise run code on the machine of whoever loads the environment.
pub fn is_unsafe_name(key: &str) -> bool {
    const EXACT: [&str; 14] = [
        "PATH",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "IFS",
        "SHELLOPTS",
        "BASHOPTS",
        "ZDOTDIR",
        "HOME",
        "SHELL",
        "CDPATH",
        "PYTHONSTARTUP",
        "PERL5OPT",
        "RUBYOPT",
    ];
    const PREFIXES: [&str; 7] = ["LD_", "DYLD_", "PS", "BASH_FUNC_", "fish_", "PYTHONPATH", "PERL5LIB"];
    let upper = key.to_ascii_uppercase();
    EXACT.contains(&upper.as_str())
        || PREFIXES
            .iter()
            .any(|p| key.starts_with(p) || upper.starts_with(&p.to_ascii_uppercase()))
        || upper.ends_with("_OPTIONS")
        || upper == "GIT_SSH_COMMAND"
        || upper.starts_with("GIT_CONFIG")
}

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

/// Removes what the last switch loaded, then exports `vars` and records them.
pub fn switch_script(shell: Shell, previous: &[String], vars: &BTreeMap<String, String>, origin: &Origin) -> Switch {
    let mut script = unset(shell, previous);
    let mut loaded = Vec::new();
    let mut skipped = Vec::new();
    for (key, value) in vars {
        if !is_variable_name(key) || key.starts_with("SEKRET_") || is_unsafe_name(key) {
            skipped.push(key.clone());
            continue;
        }
        script.push_str(&export(shell, key, value));
        loaded.push(key.clone());
    }
    script.push_str(&export(shell, "SEKRET_PROJECT", &origin.project));
    script.push_str(&export(shell, "SEKRET_ENVIRONMENT", &origin.environment));
    script.push_str(&export(shell, "SEKRET_PATH", &origin.path));
    script.push_str(&export(shell, LOADED_KEYS_VAR, &loaded.join(" ")));
    Switch {
        script,
        loaded,
        skipped,
    }
}

/// Removes what the last switch loaded.
pub fn unload_script(shell: Shell, previous: &[String]) -> String {
    let mut names = previous.to_vec();
    names.push(LOADED_KEYS_VAR.into());
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
    use super::*;

    fn origin(environment: &str) -> Origin {
        Origin {
            project: "app".into(),
            environment: environment.into(),
            path: "/".into(),
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Runs `script` in a fresh bash and prints the named variables, `-` when unset.
    fn bash_after(script: &str, names: &[&str]) -> Vec<String> {
        let probe: String = names
            .iter()
            .map(|n| format!("printf '%s\\n' \"${{{n}-<unset>}}\"\n"))
            .collect();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("{script}\n{probe}"))
            .env_remove(LOADED_KEYS_VAR)
            .output()
            .expect("bash");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn switching_replaces_the_previous_environment() {
        let dev = switch_script(
            Shell::Bash,
            &[],
            &vars(&[("DB_URL", "postgres://dev"), ("DEV_ONLY", "x")]),
            &origin("dev"),
        );
        let prod = switch_script(
            Shell::Bash,
            &dev.loaded,
            &vars(&[("DB_URL", "postgres://prod")]),
            &origin("prod"),
        );
        let state = bash_after(
            &format!("{}{}", dev.script, prod.script),
            &["DB_URL", "DEV_ONLY", "SEKRET_ENVIRONMENT", LOADED_KEYS_VAR],
        );
        assert_eq!(state, ["postgres://prod", "<unset>", "prod", "DB_URL"]);
    }

    #[test]
    fn hostile_values_are_not_executed() {
        let value = "'; touch /tmp/sekret-pwned; echo '$(id) `id` \"\\ \n end";
        let switch = switch_script(Shell::Bash, &[], &vars(&[("NASTY", value)]), &origin("dev"));
        assert_eq!(bash_after(&switch.script, &["NASTY"]).join("\n"), value);
    }

    #[test]
    fn keys_that_cannot_be_variables_are_skipped() {
        let switch = switch_script(
            Shell::Bash,
            &[],
            &vars(&[("my.key", "a"), ("1ABC", "b"), ("SEKRET_TOKEN", "c"), ("OK_KEY", "d")]),
            &origin("dev"),
        );
        assert_eq!(switch.loaded, ["OK_KEY"]);
        assert_eq!(switch.skipped, ["1ABC", "SEKRET_TOKEN", "my.key"]);
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
        let switch = switch_script(Shell::Bash, &[], &hostile, &origin("dev"));
        assert_eq!(switch.loaded, ["DATABASE_URL"]);
        assert!(!switch.script.contains("BASH_ENV") && !switch.script.contains("LD_PRELOAD"));
        assert!(
            switch.skipped.contains(&"PSQL_HOST".to_string()),
            "PS* is treated as a prompt variable"
        );
    }

    #[test]
    fn unload_removes_only_what_was_loaded() {
        let load = switch_script(Shell::Bash, &[], &vars(&[("A", "1")]), &origin("dev"));
        let unload = unload_script(Shell::Bash, &previously_loaded(Some("A")));
        let state = bash_after(
            &format!("KEEP=me\n{}{unload}", load.script),
            &["A", "KEEP", LOADED_KEYS_VAR],
        );
        assert_eq!(state, ["<unset>", "me", "<unset>"]);
    }

    #[test]
    fn previously_loaded_ignores_junk() {
        assert_eq!(previously_loaded(Some("A  B $(id) C")), ["A", "B", "C"]);
        assert!(previously_loaded(None).is_empty());
    }

    #[test]
    fn fish_output_uses_set() {
        let switch = switch_script(Shell::Fish, &["OLD".into()], &vars(&[("A", "it's \\")]), &origin("dev"));
        assert!(switch.script.starts_with("set -e OLD\n"));
        assert!(switch.script.contains("set -gx A 'it\\'s \\\\'\n"));
        assert!(init_script(Shell::Fish).contains("| source"));
    }

    #[test]
    fn bash_init_defines_a_working_function() {
        let script = format!(
            "{}\ntype sekret-env >/dev/null && echo defined",
            init_script(Shell::Bash)
        );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .output()
            .expect("bash");
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "defined");
    }
}
