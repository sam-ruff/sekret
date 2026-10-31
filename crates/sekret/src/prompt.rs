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
    let text = read_passphrase_for_api(file, prompt, prompter)?;
    Ok(Zeroizing::new(trim_input(&text).to_string()))
}

/// The passphrase exactly as read, for sending to the API, which drops the byte order mark and
/// line ending itself. Trimming here too would trim twice, so a passphrase file ending in two
/// line endings would open the wrap online but not offline.
pub fn read_passphrase_for_api(
    file: Option<&Path>,
    prompt: &str,
    prompter: &dyn Prompter,
) -> anyhow::Result<Zeroizing<String>> {
    let text = match file {
        None => prompter.secret(prompt)?,
        Some(path) if path == Path::new("-") => read_stdin_line()?,
        Some(path) => read_text_file(path)?,
    };
    if trim_input(&text).is_empty() {
        bail!("the passphrase is empty");
    }
    Ok(text)
}

/// A new passphrase: from a file, or asked for twice. It must be strong enough.
pub fn read_new_passphrase(file: Option<&Path>, prompter: &dyn Prompter) -> anyhow::Result<Zeroizing<String>> {
    let text = read_new_passphrase_for_api(file, prompter)?;
    Ok(Zeroizing::new(trim_input(&text).to_string()))
}

/// [`read_new_passphrase`], untrimmed for the API; the checks apply to the trimmed form the
/// server will use.
pub fn read_new_passphrase_for_api(file: Option<&Path>, prompter: &dyn Prompter) -> anyhow::Result<Zeroizing<String>> {
    let text = read_passphrase_for_api(file, "New passphrase: ", prompter)?;
    let passphrase = trim_input(&text);
    if file.is_none() {
        let again = prompter.secret("Repeat it: ")?;
        if trim_input(&again) != passphrase {
            bail!("the passphrases do not match");
        }
    }
    validate_passphrase(passphrase)?;
    Ok(text)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Answers questions from a script, in order, and records what was asked.
    pub struct Scripted {
        answers: RefCell<VecDeque<String>>,
        asked: RefCell<Vec<String>>,
    }

    impl Scripted {
        pub fn new(answers: &[&str]) -> Self {
            Self {
                answers: RefCell::new(answers.iter().map(|a| a.to_string()).collect()),
                asked: RefCell::new(Vec::new()),
            }
        }

        pub fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }

        fn next(&self, prompt: &str) -> anyhow::Result<String> {
            self.asked.borrow_mut().push(prompt.to_string());
            self.answers.borrow_mut().pop_front().context("no scripted answer left")
        }
    }

    impl Prompter for Scripted {
        fn secret(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
            self.next(prompt).map(Zeroizing::new)
        }

        fn line(&self, prompt: &str) -> anyhow::Result<String> {
            self.next(prompt)
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

    /// The API trims what it is sent, so the CLI sends what it read; trimming on both sides
    /// dropped two line endings online but one offline.
    #[test]
    fn passphrases_for_the_api_are_trimmed_once_by_the_server() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("pass");
        for content in ["two endings\n\n", "\u{feff}saved by notepad\r\n", "plain"] {
            std::fs::write(&path, content).context("write")?;
            let sent = read_passphrase_for_api(Some(&path), "", &Scripted::new(&[]))?;
            assert_eq!(sent.as_str(), content, "sent exactly as read");
            let offline = read_passphrase(Some(&path), "", &Scripted::new(&[]))?;
            assert_eq!(trim_input(&sent), offline.as_str(), "{content:?}");
        }
        std::fs::write(&path, "\u{feff}\n").context("write")?;
        assert!(read_passphrase_for_api(Some(&path), "", &Scripted::new(&[])).is_err());
        std::fs::write(&path, "violet tractor sings beneath\n").context("write")?;
        let new = read_new_passphrase_for_api(Some(&path), &Scripted::new(&[]))?;
        assert_eq!(new.as_str(), "violet tractor sings beneath\n");
        let typed = Scripted::new(&["violet tractor sings beneath", "violet tractor sings beneath"]);
        assert_eq!(
            read_new_passphrase_for_api(None, &typed)?.as_str(),
            "violet tractor sings beneath"
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
