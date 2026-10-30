use std::collections::BTreeMap;

use anyhow::bail;
use sekret_api::RawSecret;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    Dotenv,
    Json,
    Yaml,
    Shell,
}

/// Flattens secrets to key/value, refusing silent overwrites when folders share a key.
pub fn flatten(secrets: &[RawSecret]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for secret in secrets {
        if out.insert(secret.key.clone(), secret.value.clone()).is_some() {
            bail!(
                "{} exists in more than one folder; narrow --path or drop --recursive",
                secret.key
            );
        }
    }
    Ok(out)
}

/// Double-quoted, with `$` and backticks escaped so `source .env` cannot expand or run anything.
fn dotenv_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            '`' => escaped.push_str("\\`"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            other => escaped.push(other),
        }
    }
    format!("\"{escaped}\"")
}

fn unescape_double_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

pub fn shell_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn render(secrets: &BTreeMap<String, String>, format: ExportFormat) -> anyhow::Result<String> {
    let text = match format {
        ExportFormat::Dotenv => secrets
            .iter()
            .map(|(k, v)| format!("{k}={}\n", dotenv_value(v)))
            .collect(),
        // Output meant for `source`, so names a shell would act on are left out.
        ExportFormat::Shell => secrets
            .iter()
            .filter(|(k, _)| !super::shell::is_unsafe_name(k) && super::shell::is_variable_name(k))
            .map(|(k, v)| format!("export {k}={}\n", shell_value(v)))
            .collect(),
        // JSON strings are valid YAML scalars, which sidesteps YAML's quoting rules.
        ExportFormat::Yaml => secrets
            .iter()
            .map(|(k, v)| Ok(format!("{k}: {}\n", serde_json::to_string(v)?)))
            .collect::<anyhow::Result<String>>()?,
        ExportFormat::Json => format!("{}\n", serde_json::to_string_pretty(secrets)?),
    };
    Ok(text)
}

/// Parses `.env` text: `KEY=value`, optional `export`, quotes and `#` comments.
pub fn parse_dotenv(text: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            bail!("line {} is not KEY=value", number + 1);
        };
        let value = value.trim();
        let value = if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            unescape_double_quoted(inner)
        } else if let Some(inner) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
            inner.to_string()
        } else {
            value.split(" #").next().unwrap_or_default().trim().to_string()
        };
        out.push((key.trim().to_string(), value));
    }
    Ok(out)
}

/// Unix seconds as `YYYY-MM-DD HH:MM UTC`, using the proleptic Gregorian calendar.
pub fn timestamp(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// Pads columns so plain-text tables line up.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }
    let line = |cells: Vec<String>| {
        let padded: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = widths[i]))
            .collect();
        format!("{}\n", padded.join("  ").trim_end())
    };
    let mut out = line(headers.iter().map(|h| h.to_string()).collect());
    for row in rows {
        out.push_str(&line(row.clone()));
    }
    out
}

/// A unified-style line diff: unchanged lines start with two spaces, removed with `- `, added with `+ `.
pub fn line_diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    // The table below is old x new lines; past this a plain replace is shown instead.
    if a.len().saturating_mul(b.len()) > 4_000_000 {
        let removed = a.iter().map(|l| format!("- {l}\n"));
        let added = b.iter().map(|l| format!("+ {l}\n"));
        return removed.chain(added).collect();
    }
    // Longest common subsequence lengths, filled from the end.
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = String::new();
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            out.push_str(&format!("  {}\n", a[i]));
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn timestamps_are_utc_dates() {
        assert_eq!(timestamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(timestamp(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(timestamp(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(timestamp(-86_400), "1969-12-31 00:00 UTC");
    }

    #[test]
    fn line_diff_marks_changes() {
        assert_eq!(line_diff("a\nb\nc", "a\nx\nc"), "  a\n- b\n+ x\n  c\n");
        assert_eq!(line_diff("", "new"), "+ new\n");
        assert_eq!(line_diff("same", "same"), "  same\n");
        let huge = "x\n".repeat(3000);
        assert_eq!(line_diff(&huge, &huge).lines().count(), 6000, "large inputs fall back");
    }

    fn secrets() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("A".to_string(), "plain".to_string()),
            ("B".to_string(), "it's \"quoted\"\nline2 $HOME `id` \\n".to_string()),
        ])
    }

    #[test]
    fn dotenv_round_trips() -> anyhow::Result<()> {
        let text = render(&secrets(), ExportFormat::Dotenv).context("render")?;
        let parsed: BTreeMap<String, String> = parse_dotenv(&text).context("parse")?.into_iter().collect();
        assert_eq!(parsed, secrets());
        Ok(())
    }

    #[test]
    fn sourced_dotenv_does_not_expand() -> anyhow::Result<()> {
        let text = render(&secrets(), ExportFormat::Dotenv).context("render")?;
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{text}\nprintf '%s' \"$B\""))
            .output()
            .context("sh")?;
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "it's \"quoted\"\\nline2 $HOME `id` \\n",
            "the shell sees escapes literally but runs nothing"
        );
        Ok(())
    }

    #[test]
    fn shell_quoting_is_safe() -> anyhow::Result<()> {
        let text = render(&secrets(), ExportFormat::Shell).context("render")?;
        assert!(text.contains("export A='plain'"));
        assert!(text.contains("'it'\\''s"));
        Ok(())
    }

    #[test]
    fn json_and_yaml() -> anyhow::Result<()> {
        let json = render(&secrets(), ExportFormat::Json).context("json")?;
        let back: BTreeMap<String, String> = serde_json::from_str(&json).context("parse")?;
        assert_eq!(back, secrets());
        let yaml = render(&secrets(), ExportFormat::Yaml).context("yaml")?;
        assert!(yaml.starts_with("A: \"plain\"\n"));
        assert!(yaml.contains("\\n"));
        Ok(())
    }

    #[test]
    fn parse_dotenv_variants() -> anyhow::Result<()> {
        let parsed = parse_dotenv("# comment\nexport A=1\nB = 'two words'\nC=three # trailing\n\nD=\"x=y\"\n")
            .context("parse")?;
        assert_eq!(
            parsed,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "three".into()),
                ("D".into(), "x=y".into())
            ]
        );
        assert!(parse_dotenv("NOEQUALS").is_err());
        Ok(())
    }

    #[test]
    fn flatten_rejects_collisions() {
        let make = |path: &str| RawSecret {
            path: path.into(),
            key: "K".into(),
            value: "v".into(),
        };
        assert!(flatten(&[make("/")]).is_ok());
        assert!(flatten(&[make("/"), make("/a")]).is_err());
    }

    #[test]
    fn tables_align() {
        let out = table(
            &["KEY", "VERSION"],
            &[vec!["LONG_NAME".into(), "1".into()], vec!["A".into(), "12".into()]],
        );
        assert_eq!(out, "KEY        VERSION\nLONG_NAME  1\nA          12\n");
    }
}
