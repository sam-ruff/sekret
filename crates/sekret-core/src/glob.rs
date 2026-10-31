/// Glob matching for secret paths and token claims.
///
/// `*` matches any run of characters except `separator` (or anything when there is none),
/// `**` matches anything including the separator, and `?` matches one non-separator character.
/// A trailing `/**` also matches the folder itself, so `/a/**` covers `/a`.
/// Runs in O(pattern x text) time and O(text) memory, with no recursion.
pub fn glob_match(pattern: &str, text: &str, separator: Option<char>) -> bool {
    let text: Vec<char> = text.chars().collect();
    if let Some(folder) = trailing_segments_parent(pattern, separator)
        && matches(folder, &text, separator)
    {
        return true;
    }
    matches(pattern, &text, separator)
}

/// The pattern without its trailing `<separator>**`, when it ends that way.
fn trailing_segments_parent(pattern: &str, separator: Option<char>) -> Option<&str> {
    let separator = separator?;
    let stars = pattern.len() - pattern.trim_end_matches('*').len();
    if stars < 2 {
        return None;
    }
    pattern[..pattern.len() - stars].strip_suffix(separator)
}

fn matches(pattern: &str, text: &[char], separator: Option<char>) -> bool {
    let mut reach = vec![false; text.len() + 1];
    reach[0] = true;
    for token in tokens(pattern, separator) {
        reach = advance(&reach, text, token, separator);
        if !reach.iter().any(|r| *r) {
            return false;
        }
    }
    reach[text.len()]
}

/// Longest pattern accepted when a glob is saved.
pub const MAX_GLOB_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Literal(char),
    One,
    Star {
        crosses: bool,
    },
    /// `**/` after a separator: nothing at all, or any run ending in a separator, so `/a/**/b`
    /// also covers `/a/b`.
    Segments,
}

fn tokens(pattern: &str, separator: Option<char>) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                let start = i;
                while i < chars.len() && chars[i] == '*' {
                    i += 1;
                }
                let double = i - start >= 2;
                let after_separator = start > 0 && separator.is_some_and(|s| chars[start - 1] == s);
                let before_separator = separator.is_some_and(|s| chars.get(i) == Some(&s));
                if double && after_separator && before_separator {
                    out.push(Token::Segments);
                    i += 1;
                    continue;
                }
                out.push(Token::Star {
                    crosses: double || separator.is_none(),
                });
                continue;
            }
            '?' => out.push(Token::One),
            c => out.push(Token::Literal(c)),
        }
        i += 1;
    }
    out
}

fn advance(reach: &[bool], text: &[char], token: Token, separator: Option<char>) -> Vec<bool> {
    let is_separator = |c: char| separator == Some(c);
    let mut next = vec![false; reach.len()];
    match token {
        Token::Literal(c) => {
            for i in 0..text.len() {
                next[i + 1] = reach[i] && text[i] == c;
            }
        }
        Token::One => {
            for i in 0..text.len() {
                next[i + 1] = reach[i] && !is_separator(text[i]);
            }
        }
        Token::Star { crosses } => {
            let mut running = false;
            for j in 0..reach.len() {
                if j > 0 && !crosses && is_separator(text[j - 1]) {
                    running = false;
                }
                running |= reach[j];
                next[j] = running;
            }
        }
        Token::Segments => {
            let mut seen = false;
            for j in 0..reach.len() {
                next[j] = reach[j] || (seen && is_separator(text[j - 1]));
                seen |= reach[j];
            }
        }
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str, t: &str) -> bool {
        glob_match(p, t, Some('/'))
    }

    #[test]
    fn literal_and_single_star() {
        assert!(path("/app", "/app"));
        assert!(!path("/app", "/apps"));
        assert!(path("/app/*", "/app/db"));
        assert!(!path("/app/*", "/app/db/primary"));
        assert!(path("/*", "/anything"));
        assert!(path("*", ""));
        assert!(!path("", "x"));
        assert!(path("", ""));
    }

    #[test]
    fn double_star_crosses_separators() {
        assert!(path("/app/**", "/app/db/primary"));
        assert!(path("/**", "/"));
        assert!(path("/**", "/x/y/z"));
        assert!(path("/app/**/creds", "/app/creds"));
        assert!(path("/app/**/creds", "/app/a/b/creds"));
        assert!(!path("/app/**/creds", "/app/a/b/notcreds"));
        assert!(!path("/app/**", "/other/db"));
        assert!(path("/app**", "/app/x/y"));
    }

    #[test]
    fn trailing_double_star_covers_the_folder_itself() {
        let cases: &[(&str, &str, bool)] = &[
            ("/a/**", "/a", true),
            ("/a/**", "/a/", true),
            ("/a/**", "/a/b", true),
            ("/a/**", "/a/b/c", true),
            ("/a/**", "/ab", false),
            ("/a/**", "/", false),
            ("/a/**", "/b/a", false),
            ("/a/***", "/a", true),
            ("/a/b/**", "/a/b", true),
            ("/a/b/**", "/a", false),
            ("/a/*/**", "/a/x", true),
            ("/a/*/**", "/a", false),
            ("/**", "/", true),
            ("/**", "/x", true),
            ("/a**", "/a", true),
            ("/a**", "/ab", true),
            ("/a/*", "/a", false),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(path(pattern, text), *expected, "{pattern} against {text}");
        }
    }

    #[test]
    fn trailing_double_star_without_separator_is_unchanged() {
        assert!(!glob_match("a/**", "a", None));
        assert!(glob_match("a/**", "a/b", None));
    }

    #[test]
    fn question_mark() {
        assert!(path("/env?", "/env1"));
        assert!(!path("/env?", "/env/"));
    }

    #[test]
    fn claims_without_separator() {
        assert!(glob_match(
            "repo:sam-ruff/*:ref:refs/heads/main",
            "repo:sam-ruff/sekret:ref:refs/heads/main",
            None
        ));
        assert!(!glob_match(
            "repo:sam-ruff/*:ref:refs/heads/main",
            "repo:evil/sekret:ref:refs/heads/main",
            None
        ));
        assert!(!glob_match(
            "system:serviceaccount:prod:*",
            "system:serviceaccount:dev:app",
            None
        ));
        assert!(glob_match("DB_*", "DB_PASS", None));
        assert!(!glob_match("DB_*", "API_KEY", None));
    }

    #[test]
    fn pathological_patterns_terminate() {
        let pattern = "*a".repeat(30);
        let text = "a".repeat(60) + "b";
        assert!(!glob_match(&pattern, &text, None));
        let stars = "**".repeat(500_000);
        assert!(glob_match(&stars, "anything/at/all", Some('/')));
        let segments = "/**".repeat(100_000) + "/x";
        assert!(glob_match(&segments, "/a/b/x", Some('/')));
    }
}
