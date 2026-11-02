//! The user config at `$XDG_CONFIG_HOME/sekret/config.toml`, on the real binary: where it sits in
//! the order of flags, environment variables and the project file, for the server and the CA file.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::Context;

const BIN: &str = env!("CARGO_BIN_EXE_sekret");

fn run(args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Output> {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .current_dir(dir.join("work"));
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().context("run sekret")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A home with a private config directory and an empty working directory.
fn home() -> anyhow::Result<tempfile::TempDir> {
    let dir = tempfile::tempdir().context("dir")?;
    let config = dir.path().join("config").join("sekret");
    std::fs::create_dir_all(&config).context("config dir")?;
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    std::fs::create_dir(dir.path().join("work")).context("work dir")?;
    Ok(dir)
}

fn write_user_config(dir: &Path, text: &str) -> anyhow::Result<()> {
    let path = dir.join("config").join("sekret").join("config.toml");
    std::fs::write(&path, text).context("user config")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")
}

/// `whoami` without a token names the server it resolved and contacts nothing.
fn chosen_server(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<String> {
    let mut all = vec!["whoami"];
    all.extend_from_slice(args);
    let output = run(&all, env, dir)?;
    let text = stderr(&output);
    anyhow::ensure!(!output.status.success(), "whoami succeeded without a token: {text}");
    let server = text
        .split("not logged in to ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .with_context(|| format!("no server named in: {text}"))?;
    Ok(server.to_string())
}

#[test]
fn the_server_is_taken_from_flag_then_environment_then_project_file_then_user_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\n")?;
    assert_eq!(chosen_server(home, &[], &[])?, "https://user.test");

    std::fs::write(home.join("work/.sekret.toml"), "server = \"https://file.test\"\n").context("project file")?;
    assert_eq!(chosen_server(home, &[], &[])?, "https://file.test");

    let env = [("SEKRET_URL", "https://env.test")];
    assert_eq!(chosen_server(home, &[], &env)?, "https://env.test");
    assert_eq!(
        chosen_server(home, &["--server", "https://flag.test"], &env)?,
        "https://flag.test"
    );
    Ok(())
}

/// With a token in the environment, `whoami` builds a client, which reads the CA file first. Each
/// path below does not exist, so the error names the one that was chosen and nothing is sent.
fn chosen_ca(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<String> {
    let mut all = vec!["whoami"];
    all.extend_from_slice(args);
    let mut env = env.to_vec();
    env.push(("SEKRET_TOKEN", "skt_test"));
    let output = run(&all, &env, dir)?;
    let text = stderr(&output);
    anyhow::ensure!(text.contains("reading CA file"), "the CA file was not read: {text}");
    ["flag.pem", "env.pem", "user.pem"]
        .into_iter()
        .find(|name| text.contains(name))
        .map(String::from)
        .with_context(|| format!("no CA named in: {text}"))
}

#[test]
fn the_ca_file_is_taken_from_flag_then_environment_then_user_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"/absent/user.pem\"\n")?;
    assert_eq!(chosen_ca(home, &[], &[])?, "user.pem");

    // A project file sets no CA, so the user's still applies to the server it names, once that
    // server is confirmed.
    std::fs::write(home.join("work/.sekret.toml"), "server = \"https://file.test\"\n").context("project file")?;
    let confirmed = [("SEKRET_URL", "https://file.test")];
    assert_eq!(chosen_ca(home, &[], &confirmed)?, "user.pem");

    let env = [
        ("SEKRET_URL", "https://file.test"),
        ("SEKRET_CA_FILE", "/absent/env.pem"),
    ];
    assert_eq!(chosen_ca(home, &[], &env)?, "env.pem");
    assert_eq!(chosen_ca(home, &["--ca-file", "/absent/flag.pem"], &env)?, "flag.pem");
    Ok(())
}

#[test]
fn a_relative_ca_file_is_found_beside_the_user_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"user.pem\"\n")?;
    let output = run(&["whoami"], &[("SEKRET_TOKEN", "skt_test")], home)?;
    let expected = home.join("config/sekret/user.pem");
    assert!(
        stderr(&output).contains(&expected.display().to_string()),
        "{}",
        stderr(&output)
    );
    Ok(())
}

#[test]
fn the_user_config_server_receives_the_environment_token_but_a_project_file_server_does_not() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"/absent/user.pem\"\n")?;
    let env = [("SEKRET_TOKEN", "skt_test")];
    // Reaching the CA file means the token was accepted for this server.
    assert!(stderr(&run(&["whoami"], &env, home)?).contains("reading CA file"));

    std::fs::write(home.join("work/.sekret.toml"), "server = \"https://file.test\"\n").context("project file")?;
    let text = stderr(&run(&["whoami"], &env, home)?);
    assert!(text.contains("is not sent to it"), "{text}");
    assert!(!text.contains("reading CA file"), "{text}");
    Ok(())
}

#[test]
fn sys_commands_trust_a_user_config_server_unless_a_project_file_names_another() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"/absent/user.pem\"\n")?;
    // Reaching the CA file means the command went on to contact the server.
    let text = stderr(&run(&["sys", "status"], &[], home)?);
    assert!(text.contains("reading CA file"), "{text}");

    std::fs::write(home.join("work/.sekret.toml"), "server = \"https://user.test/\"\n").context("same server")?;
    let text = stderr(&run(&["sys", "status"], &[("SEKRET_TOKEN", "skt_test")], home)?);
    assert!(
        text.contains("reading CA file"),
        "a project file agreeing keeps it trusted: {text}"
    );

    std::fs::write(home.join("work/.sekret.toml"), "server = \"https://file.test\"\n").context("other server")?;
    let text = stderr(&run(&["sys", "status"], &[], home)?);
    assert!(text.contains("comes only from .sekret.toml"), "{text}");
    assert!(!text.contains("reading CA file"), "{text}");
    Ok(())
}

#[test]
fn an_empty_variable_falls_through_to_the_user_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"/absent/user.pem\"\n")?;
    let env = [("SEKRET_URL", "")];
    assert_eq!(chosen_server(home, &[], &env)?, "https://user.test");
    assert_eq!(chosen_ca(home, &[], &env)?, "user.pem");
    // An empty CA variable is an error rather than a silent fallback.
    let output = run(&["whoami"], &[("SEKRET_CA_FILE", "")], home)?;
    assert!(
        !output.status.success() && stderr(&output).contains("--ca-file"),
        "{}",
        stderr(&output)
    );
    Ok(())
}

#[test]
fn a_secret_typed_into_the_user_config_is_not_printed() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "token = \"skt_SUPERSECRET\"\n")?;
    let output = run(&["whoami"], &[], home)?;
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("line 1") && !text.contains("SUPERSECRET"), "{text}");
    Ok(())
}

#[test]
fn a_user_config_others_can_change_stops_the_command() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\n")?;
    let path = home.join("config/sekret/config.toml");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
    let output = run(&["whoami"], &[("SEKRET_URL", "https://env.test")], home)?;
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("other users can change it"),
        "{}",
        stderr(&output)
    );
    Ok(())
}

#[test]
fn an_unknown_key_in_the_user_config_is_an_error() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nenvironment = \"prod\"\n")?;
    let output = run(&["whoami"], &[], home)?;
    assert!(!output.status.success());
    assert!(stderr(&output).contains("line 2"), "{}", stderr(&output));
    Ok(())
}

#[test]
fn a_broken_user_config_stops_even_a_command_given_its_server() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    let path = home.join("config/sekret/config.toml");
    for (what, make) in [("a FIFO", "fifo"), ("a directory", "dir"), ("an oversize file", "big")] {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&path);
        match make {
            "fifo" => {
                let status = Command::new("mkfifo").arg(&path).status().context("mkfifo")?;
                anyhow::ensure!(status.success(), "mkfifo failed");
            }
            "dir" => std::fs::create_dir(&path).context("mkdir")?,
            _ => write_user_config(home, &format!("# {}\n", "x".repeat(2 << 20)))?,
        }
        let output = run(&["whoami", "--server", "https://flag.test"], &[], home)?;
        assert!(!output.status.success(), "{what}");
        assert!(
            !stderr(&output).contains("not logged in"),
            "{what}: {}",
            stderr(&output)
        );
    }
    Ok(())
}

#[test]
fn a_ca_file_others_can_change_is_not_trusted() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"root.pem\"\n")?;
    let ca = home.join("config/sekret/root.pem");
    std::fs::write(&ca, "not a certificate").context("ca")?;
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
    let text = stderr(&run(&["whoami"], &[("SEKRET_TOKEN", "skt_test")], home)?);
    assert!(text.contains("other users can change it"), "{text}");
    Ok(())
}

#[test]
fn a_relative_home_never_reads_a_config_from_the_current_directory() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    // A cloned repository carrying what would be ./.config/sekret/config.toml.
    let planted = home.join("work/.config/sekret");
    std::fs::create_dir_all(&planted).context("planted dir")?;
    std::fs::write(
        planted.join("config.toml"),
        "server = \"https://evil.test\"\nca_file = \"/absent/user.pem\"\n",
    )
    .context("planted config")?;
    for relative in ["", "."] {
        let env = [
            ("HOME", relative),
            ("XDG_CONFIG_HOME", ""),
            ("SEKRET_TOKEN", "skt_test"),
        ];
        let text = stderr(&run(&["whoami"], &env, home)?);
        assert!(text.contains("HOME is not an absolute path"), "{relative:?}: {text}");
        assert!(!text.contains("reading CA file"), "{relative:?}: {text}");
    }
    Ok(())
}

/// Grants `uid` read and write on a 0600 file by writing the access ACL xattr directly, as
/// `setfacl -m u:<uid>:rw` would, so the test needs no `acl` package.
#[cfg(target_os = "linux")]
fn grant_user_rw(path: &std::path::Path, uid: u32) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    const UNDEFINED: u32 = u32::MAX;
    // posix_acl_xattr: a version header, then (tag, perm, id) entries sorted by tag.
    let entries: [(u16, u16, u32); 5] = [
        (0x01, 6, UNDEFINED), // owner
        (0x02, 6, uid),       // named user
        (0x04, 0, UNDEFINED), // owning group
        (0x10, 6, UNDEFINED), // mask
        (0x20, 0, UNDEFINED), // other
    ];
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        acl.extend(tag.to_le_bytes());
        acl.extend(perm.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).context("path")?;
    // SAFETY: both strings are NUL-terminated and the value pointer and length describe `acl`.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    anyhow::ensure!(result == 0, "setxattr: {}", std::io::Error::last_os_error());
    Ok(())
}

/// Needs a filesystem with POSIX ACLs.
#[cfg(target_os = "linux")]
#[test]
fn an_acl_granting_another_user_write_is_refused() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\n")?;
    let path = home.join("config/sekret/config.toml");
    grant_user_rw(&path, 65534)?;
    let output = run(&["whoami"], &[], home)?;
    assert!(
        stderr(&output).contains("other users can change it"),
        "{}",
        stderr(&output)
    );
    Ok(())
}

#[test]
fn a_home_that_cannot_be_entered_is_an_error_not_an_absent_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\n")?;
    let locked = home.join("config");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).context("chmod")?;
    let output = run(&["whoami"], &[("SEKRET_URL", "https://env.test")], home);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    let output = output?;
    // Root can enter any directory, so the check only means something for other users.
    if running_as_root()? {
        return Ok(());
    }
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("reading the user config"),
        "{}",
        stderr(&output)
    );
    Ok(())
}

fn running_as_root() -> anyhow::Result<bool> {
    let output = Command::new("id").arg("-u").output().context("id -u")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "0")
}

#[test]
fn an_empty_server_flag_still_honours_sekret_url() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\n")?;
    let env = [("SEKRET_URL", "https://env.test")];
    assert_eq!(chosen_server(home, &["--server", ""], &env)?, "https://env.test");
    Ok(())
}

#[test]
fn naming_both_server_and_ca_skips_the_user_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "not toml at all")?;
    let output = run(&["whoami", "--server", "https://flag.test"], &[], home)?;
    assert!(stderr(&output).contains("line 1"), "{}", stderr(&output));
    let args = ["--server", "https://flag.test", "--ca-file", "/absent/flag.pem"];
    assert_eq!(chosen_server(home, &args, &[])?, "https://flag.test");
    Ok(())
}

#[test]
fn empty_flags_fall_through_like_empty_variables() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\n")?;
    assert_eq!(chosen_server(home, &["--server", ""], &[])?, "https://user.test");
    assert_eq!(chosen_server(home, &["--token", ""], &[])?, "https://user.test");
    Ok(())
}

#[test]
fn the_help_states_the_order() -> anyhow::Result<()> {
    let dir = home()?;
    let output = run(&["--help"], &[], dir.path())?;
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("Settings are taken from the first of these that sets them"),
        "{text}"
    );
    let login = run(&["login", "--help"], &[], dir.path())?;
    let text = String::from_utf8_lossy(&login.stdout);
    assert!(
        text.contains("then `server` in the user config ($XDG_CONFIG_HOME/sekret/config.toml")
            && text.contains("then `ca_file` in the user config"),
        "{text}"
    );
    Ok(())
}

#[test]
fn an_empty_ca_flag_or_variable_is_an_error_not_a_fallback() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"/absent/user.pem\"\n")?;
    let flag = run(&["whoami", "--ca-file", ""], &[("SEKRET_TOKEN", "skt_test")], home)?;
    let env = run(
        &["whoami"],
        &[("SEKRET_TOKEN", "skt_test"), ("SEKRET_CA_FILE", "")],
        home,
    )?;
    for output in [flag, env] {
        let text = stderr(&output);
        assert!(!output.status.success(), "{text}");
        assert!(!text.contains("user.pem"), "{text}");
    }
    Ok(())
}

#[test]
fn a_relative_ca_file_is_read_from_the_real_directory_behind_a_symlinked_config() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    let real = home.join("dotfiles");
    std::fs::create_dir(&real).context("dotfiles")?;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    std::fs::write(
        real.join("config.toml"),
        "server = \"https://user.test\"\nca_file = \"root.pem\"\n",
    )
    .context("config")?;
    std::fs::set_permissions(real.join("config.toml"), std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    std::fs::remove_dir(home.join("config/sekret")).context("rmdir")?;
    std::os::unix::fs::symlink(&real, home.join("config/sekret")).context("link")?;
    let output = run(&["whoami"], &[("SEKRET_TOKEN", "skt_test")], home)?;
    let expected = std::fs::canonicalize(&real).context("canonical")?.join("root.pem");
    assert!(
        stderr(&output).contains(&expected.display().to_string()),
        "{}",
        stderr(&output)
    );
    Ok(())
}

#[test]
fn a_ca_file_holding_no_certificates_is_refused() -> anyhow::Result<()> {
    let dir = home()?;
    let home = dir.path();
    write_user_config(home, "server = \"https://user.test\"\nca_file = \"config.toml\"\n")?;
    let text = stderr(&run(&["whoami"], &[("SEKRET_TOKEN", "skt_test")], home)?);
    assert!(text.contains("holds no PEM certificates"), "{text}");
    Ok(())
}
