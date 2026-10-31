//! Asking for setup codes and passphrases, or reading them from files for scripts.

use std::io::{BufRead, Read, Write};
use std::path::Path;

use anyhow::{Context, bail};
use sekret_core::seal::{trim_input, validate_passphrase};
use sekret_server::files::{SECRET_FILE_LIMIT, read_limited};
use zeroize::Zeroizing;

/// Interactive questions, injected so commands can be tested without a terminal.
pub trait Prompter {
    /// Asks without echoing the answer.
    fn secret(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>>;
    fn line(&self, prompt: &str) -> anyhow::Result<String>;
}

pub struct Terminal;

impl Prompter for Terminal {
    fn secret(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .context("no terminal to ask on; pass --passphrase-file instead")
    }

    fn line(&self, prompt: &str) -> anyhow::Result<String> {
        let mut stderr = std::io::stderr();
        write!(stderr, "{prompt}").context("prompt")?;
        stderr.flush().context("prompt")?;
        let mut answer = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut answer)
            .context("reading the answer")?;
        Ok(answer.trim().to_string())
    }
}

/// The first line of stdin, at most 4 KiB.
pub fn read_stdin_line() -> anyhow::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(SECRET_FILE_LIMIT + 1)
        .read_line(&mut line)
        .context("reading stdin")?;
    if line.len() as u64 > SECRET_FILE_LIMIT {
        bail!("the input is longer than {SECRET_FILE_LIMIT} bytes");
    }
    Ok(line)
}

/// A secret file of at most 4 KiB, following symlinks.
pub fn read_text_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let bytes = read_limited(path, SECRET_FILE_LIMIT).with_context(|| format!("reading {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    Ok(Zeroizing::new(text.to_string()))
}

/// Reads a passphrase from a file, `-` for the first line of stdin, or asks. Every source drops
/// a leading byte order mark and one trailing line ending, and nothing else.
pub fn read_passphrase(
    file: Option<&Path>,
    prompt: &str,
    prompter: &dyn Prompter,
) -> anyhow::Result<Zeroizing<String>> {
    let text = match file {
        None => prompter.secret(prompt)?,
        Some(path) if path == Path::new("-") => read_stdin_line()?,
        Some(path) => read_text_file(path)?,
    };
    let passphrase = Zeroizing::new(trim_input(&text).to_string());
    if passphrase.is_empty() {
        bail!("the passphrase is empty");
    }
    Ok(passphrase)
}

/// A new passphrase: from a file, or asked for twice. It must be strong enough.
pub fn read_new_passphrase(file: Option<&Path>, prompter: &dyn Prompter) -> anyhow::Result<Zeroizing<String>> {
    let passphrase = read_passphrase(file, "New passphrase: ", prompter)?;
    if file.is_none() {
        let again = prompter.secret("Repeat it: ")?;
        if *again != *passphrase {
            bail!("the passphrases do not match");
        }
    }
    validate_passphrase(&passphrase)?;
    Ok(passphrase)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Answers questions from a script, in order.
    pub struct Scripted(pub RefCell<VecDeque<String>>);

    impl Scripted {
        pub fn new(answers: &[&str]) -> Self {
            Self(RefCell::new(answers.iter().map(|a| a.to_string()).collect()))
        }

        fn next(&self) -> anyhow::Result<String> {
            self.0.borrow_mut().pop_front().context("no scripted answer left")
        }
    }

    impl Prompter for Scripted {
        fn secret(&self, _prompt: &str) -> anyhow::Result<Zeroizing<String>> {
            self.next().map(Zeroizing::new)
        }

        fn line(&self, _prompt: &str) -> anyhow::Result<String> {
            self.next()
        }
    }

    #[test]
    fn new_passphrases_are_asked_twice_and_checked() -> anyhow::Result<()> {
        let ok = Scripted::new(&["violet tractor sings beneath", "violet tractor sings beneath"]);
        assert_eq!(read_new_passphrase(None, &ok)?.as_str(), "violet tractor sings beneath");
        let mismatch = Scripted::new(&["violet tractor sings beneath", "violet tractor sings"]);
        assert!(read_new_passphrase(None, &mismatch).is_err());
        let weak = Scripted::new(&["password1234", "password1234"]);
        assert!(read_new_passphrase(None, &weak).is_err());
        Ok(())
    }

    #[test]
    fn passphrase_files_drop_only_the_line_ending() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("pass");
        std::fs::write(&path, "  spaced passphrase here \r\n").context("write")?;
        let read = read_passphrase(Some(&path), "", &Scripted::new(&[]))?;
        assert_eq!(read.as_str(), "  spaced passphrase here ");
        std::fs::write(&path, "\n").context("write")?;
        assert!(read_passphrase(Some(&path), "", &Scripted::new(&[])).is_err());
        // Only one line ending goes, the same as from the environment or the API.
        std::fs::write(&path, "two endings\n\n").context("write")?;
        assert_eq!(
            read_passphrase(Some(&path), "", &Scripted::new(&[]))?.as_str(),
            "two endings\n"
        );
        let prompted = read_passphrase(None, "", &Scripted::new(&["typed\n"]))?;
        assert_eq!(prompted.as_str(), "typed");
        std::fs::write(&path, "\u{feff}saved by notepad\r\n").context("write")?;
        assert_eq!(
            read_passphrase(Some(&path), "", &Scripted::new(&[]))?.as_str(),
            "saved by notepad"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_files_are_bounded_and_regular() -> anyhow::Result<()> {
        assert!(read_passphrase(Some(Path::new("/dev/zero")), "", &Scripted::new(&[])).is_err());
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("big");
        std::fs::write(&path, "a".repeat(5000)).context("write")?;
        assert!(read_passphrase(Some(&path), "", &Scripted::new(&[])).is_err());
        Ok(())
    }

    #[test]
    fn new_passphrases_with_control_characters_are_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("pass");
        std::fs::write(&path, "violet tractor\tsings beneath\n").context("write")?;
        assert!(read_new_passphrase(Some(&path), &Scripted::new(&[])).is_err());
        Ok(())
    }
}
