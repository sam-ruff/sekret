use std::cell::RefCell;
use std::collections::HashMap;

/// Glob matching for secret paths and token claims.
///
/// `*` matches any run of characters except `separator` (or anything when there is none),
/// `**` matches anything including the separator, and `?` matches one non-separator character.
/// A trailing `/**` also matches the folder itself, so `/a/**` covers `/a`.
/// Runs in O(pattern x text / 64) time and O(text) memory, with no recursion.
pub fn glob_match(pattern: &str, text: &str, separator: Option<char>) -> bool {
    if pattern.len() > MAX_CACHED_LEN || text.len() > MAX_CACHED_LEN {
        return Glob::new(pattern, separator).is_match(text);
    }
    COMPILED.with(|cache| match cache.try_borrow_mut() {
        Ok(mut cache) => cache.is_match(pattern, text, separator),
        Err(_) => Glob::new(pattern, separator).is_match(text),
    })
}

/// Longest pattern accepted when a glob is saved.
pub const MAX_GLOB_LEN: usize = 256;

/// Compiled patterns kept per thread, so a pattern is parsed once however often it is checked.
const MAX_CACHED: usize = 1024;
const MAX_CACHED_LEN: usize = 1024;

thread_local! {
    static COMPILED: RefCell<Cache> = RefCell::new(Cache::default());
}

#[derive(Default)]
struct Cache {
    by_separator: HashMap<Option<char>, HashMap<String, Cached>>,
    size: usize,
}

/// A compiled pattern and its last answer: listing one folder checks the same path many times.
struct Cached {
    glob: Glob,
    last: Option<(String, bool)>,
}

impl Cache {
    fn is_match(&mut self, pattern: &str, text: &str, separator: Option<char>) -> bool {
        let known = self
            .by_separator
            .get(&separator)
            .is_some_and(|patterns| patterns.contains_key(pattern));
        if !known && self.size >= MAX_CACHED {
            self.by_separator.clear();
            self.size = 0;
        }
        let patterns = self.by_separator.entry(separator).or_default();
        if !known {
            patterns.insert(
                pattern.to_string(),
                Cached {
                    glob: Glob::new(pattern, separator),
                    last: None,
                },
            );
            self.size += 1;
        }
        let Some(cached) = patterns.get_mut(pattern) else {
            return Glob::new(pattern, separator).is_match(text);
        };
        if let Some((last, hit)) = &cached.last
            && last == text
        {
            return *hit;
        }
        let hit = cached.glob.is_match(text);
        cached.last = Some((text.to_string(), hit));
        hit
    }
}

/// A parsed pattern, ready to match many texts.
#[derive(Debug, Clone)]
pub struct Glob {
    tokens: Vec<Token>,
    /// The pattern without its trailing `/**`, which also matches.
    folder: Option<Vec<Token>>,
    separator: Option<char>,
    /// Every literal character in the pattern, sorted.
    literals: Vec<char>,
}

impl Glob {
    pub fn new(pattern: &str, separator: Option<char>) -> Self {
        let tokens = tokens(pattern, separator);
        let folder = trailing_segments_parent(pattern, separator).map(|folder| self::tokens(folder, separator));
        let mut literals: Vec<char> = tokens
            .iter()
            .chain(folder.iter().flatten())
            .filter_map(|t| match t {
                Token::Literal(c) => Some(*c),
                _ => None,
            })
            .collect();
        literals.sort_unstable();
        literals.dedup();
        Self {
            tokens,
            folder,
            separator,
            literals,
        }
    }

    pub fn is_match(&self, text: &str) -> bool {
        let text = Text::new(text, &self.literals, self.separator);
        if let Some(folder) = &self.folder
            && text.matches(folder, &self.literals)
        {
            return true;
        }
        text.matches(&self.tokens, &self.literals)
    }
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

/// A text as bit sets over its positions, where position `j` is the point before character `j`
/// and position `len` is the end. Matching keeps the set of positions the pattern so far can
/// reach, and each token moves the whole set at once, 64 positions per step.
struct Text {
    len: usize,
    /// Positions `0..=len`.
    valid: Vec<u64>,
    /// Positions holding a character other than the separator.
    ordinary: Vec<u64>,
    /// Positions just after a separator, where a single `*` cannot carry on.
    after_separator: Vec<u64>,
    /// For each literal in the pattern, the positions holding it.
    literal_at: Vec<Vec<u64>>,
}

impl Text {
    fn new(text: &str, literals: &[char], separator: Option<char>) -> Self {
        let len = text.chars().count();
        let words = (len + 1).div_ceil(64);
        let mut valid = vec![0; words];
        let mut ordinary = vec![0; words];
        let mut separators = vec![0; words];
        let mut literal_at = vec![vec![0; words]; literals.len()];
        set(&mut valid, len);
        for (i, c) in text.chars().enumerate() {
            set(&mut valid, i);
            if separator == Some(c) {
                set(&mut separators, i);
            } else {
                set(&mut ordinary, i);
            }
            if let Ok(at) = literals.binary_search(&c)
                && let Some(bits) = literal_at.get_mut(at)
            {
                set(bits, i);
            }
        }
        shift_up(&mut separators);
        Self {
            len,
            valid,
            ordinary,
            after_separator: separators,
            literal_at,
        }
    }

    fn matches(&self, tokens: &[Token], literals: &[char]) -> bool {
        let mut reach = vec![0u64; self.valid.len()];
        set(&mut reach, 0);
        for token in tokens {
            match *token {
                Token::Literal(c) => {
                    let Some(at) = literals.binary_search(&c).ok().and_then(|at| self.literal_at.get(at)) else {
                        return false;
                    };
                    intersect(&mut reach, at);
                    shift_up(&mut reach);
                }
                Token::One => {
                    intersect(&mut reach, &self.ordinary);
                    shift_up(&mut reach);
                }
                Token::Star { crosses: true } => {
                    let Some(first) = lowest(&reach) else {
                        return false;
                    };
                    for (w, word) in reach.iter_mut().enumerate() {
                        *word = self.valid[w] & from(first, w);
                    }
                }
                Token::Star { crosses: false } => self.run_to_separator(&mut reach),
                Token::Segments => {
                    let Some(first) = lowest(&reach) else {
                        return false;
                    };
                    for (w, word) in reach.iter_mut().enumerate() {
                        *word |= self.after_separator[w] & from(first + 1, w);
                    }
                }
            }
            if reach.iter().all(|w| *w == 0) {
                return false;
            }
        }
        is_set(&reach, self.len)
    }

    /// Extends each reached position forward until just before the next position that follows a
    /// separator. Within a word this is the carry chain of an addition, so it takes one step.
    fn run_to_separator(&self, reach: &mut [u64]) {
        let mut carry = 0u64;
        for (w, word) in reach.iter_mut().enumerate() {
            let carries_on = self.valid[w] & !self.after_separator[w];
            let start = *word | (carry & carries_on & 1);
            let run = carries_on | start;
            let filled = ((run.wrapping_add(start) ^ run) & run) | start;
            carry = filled >> 63;
            *word = filled & self.valid[w];
        }
    }
}

fn set(bits: &mut [u64], at: usize) {
    if let Some(word) = bits.get_mut(at / 64) {
        *word |= 1 << (at % 64);
    }
}

fn is_set(bits: &[u64], at: usize) -> bool {
    bits.get(at / 64).is_some_and(|word| word & (1 << (at % 64)) != 0)
}

fn intersect(bits: &mut [u64], with: &[u64]) {
    for (word, other) in bits.iter_mut().zip(with) {
        *word &= other;
    }
}

/// Moves every position up by one.
fn shift_up(bits: &mut [u64]) {
    let mut carry = 0;
    for word in bits.iter_mut() {
        let next = *word >> 63;
        *word = (*word << 1) | carry;
        carry = next;
    }
}

fn lowest(bits: &[u64]) -> Option<usize> {
    bits.iter()
        .enumerate()
        .find(|(_, w)| **w != 0)
        .map(|(i, w)| i * 64 + w.trailing_zeros() as usize)
}

/// The bits of word `w` at positions `start` and above.
fn from(start: usize, w: usize) -> u64 {
    let base = w * 64;
    if start <= base {
        return u64::MAX;
    }
    if start >= base + 64 {
        return 0;
    }
    u64::MAX << (start - base)
}

fn wildcard_or(c: char, plain: impl Fn(char) -> bool) -> bool {
    matches!(c, '*' | '?') || plain(c)
}

/// Whether a folder pattern is shaped so it can match a stored folder path, which is always
/// `/` or `/a/b` with segments of letters, digits, `_`, `-` and `.`.
pub fn path_pattern_can_match(pattern: &str) -> bool {
    let Some(rest) = pattern.strip_prefix('/') else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    rest.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .chars()
                .all(|c| wildcard_or(c, |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    })
}

/// Whether a key pattern is shaped so it can match a secret key, which starts with a letter or
/// `_` and holds only letters, digits, `_`, `-` and `.`.
pub fn key_pattern_can_match(pattern: &str) -> bool {
    let mut chars = pattern.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    wildcard_or(first, |c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| wildcard_or(c, |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn patterns_that_can_never_match_are_recognised() {
        for good in [
            "/",
            "/**",
            "/payments",
            "/payments/**",
            "/a/*/b",
            "/app.v2/?x",
            "/**/db",
        ] {
            assert!(path_pattern_can_match(good), "{good}");
        }
        for bad in [
            "",
            "payments/**",
            "/payments/",
            "/payments//**",
            "//",
            "/a/./b",
            "/a/../b",
            "/a/..",
            "/a b",
            "/pay$ments",
        ] {
            assert!(!path_pattern_can_match(bad), "{bad}");
        }
        for good in ["DB_*", "*", "_X", "?ATH", "stripe.key-1"] {
            assert!(key_pattern_can_match(good), "{good}");
        }
        for bad in ["", "1DB", "-X", "DB KEY", "DB/*", "DB$"] {
            assert!(!key_pattern_can_match(bad), "{bad}");
        }
    }

    proptest! {
        /// Every folder path the store can hold is matched by a pattern spelling it out, and that
        /// pattern passes the shape check.
        #[test]
        fn stored_paths_pass_as_patterns(segments in prop::collection::vec("[a-zA-Z0-9_.-]{1,8}", 0..5)) {
            prop_assume!(segments.iter().all(|s| s != "." && s != ".."));
            let path = format!("/{}", segments.join("/"));
            prop_assert!(path_pattern_can_match(&path));
            prop_assert!(glob_match(&path, &path, Some('/')));
        }
    }

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

    #[test]
    fn a_cached_answer_is_only_reused_for_the_same_text() {
        for _ in 0..3 {
            assert!(path("/app/*", "/app/db"));
            assert!(!path("/app/*", "/app/db/x"));
            assert!(
                glob_match("/app/*", "/app/db/x", None),
                "the separator is part of the key"
            );
        }
    }

    #[test]
    fn the_cache_stays_correct_when_it_overflows() {
        for i in 0..(MAX_CACHED * 2) {
            let pattern = format!("/p{i}/*");
            assert!(path(&pattern, &format!("/p{i}/x")));
            assert!(!path(&pattern, "/q/x"));
        }
        COMPILED.with(|cache| {
            let size = cache.try_borrow().map(|c| c.size).unwrap_or(usize::MAX);
            assert!(size <= MAX_CACHED, "{size}");
        });
    }

    /// The worst saved pattern against the longest folder path took about 86 µs with the old
    /// position-by-position matcher. Counting word steps keeps this independent of machine speed.
    #[test]
    fn the_worst_saved_pattern_is_cheap() {
        let pattern = format!("/{}Z", "*x".repeat((MAX_GLOB_LEN - 2) / 2));
        let text = format!("/{}", "x".repeat(511));
        let glob = Glob::new(&pattern, Some('/'));
        let compiled = Text::new(&text, &glob.literals, Some('/'));
        let word_steps = glob.tokens.len() * compiled.valid.len();
        assert!(word_steps < 4_000, "{word_steps}");
        assert!(!glob.is_match(&text));
    }

    /// The matcher this one replaced, kept to check the two agree.
    fn reference(pattern: &str, text: &str, separator: Option<char>) -> bool {
        let text: Vec<char> = text.chars().collect();
        let run = |pattern: &str| {
            let mut reach = vec![false; text.len() + 1];
            reach[0] = true;
            for token in tokens(pattern, separator) {
                reach = advance(&reach, &text, token, separator);
            }
            reach[text.len()]
        };
        trailing_segments_parent(pattern, separator).is_some_and(run) || run(pattern)
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

    fn alphabet(max: usize, pattern: bool) -> impl Strategy<Value = String> {
        let chars: Vec<char> = if pattern {
            vec!['a', 'b', '/', '*', '?', 'é']
        } else {
            vec!['a', 'b', '/', 'é']
        };
        prop::collection::vec(prop::sample::select(chars), 0..max).prop_map(|c| c.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        #[test]
        fn agrees_with_the_reference_on_short_texts(pattern in alphabet(12, true), text in alphabet(16, false), slash in any::<bool>()) {
            let separator = slash.then_some('/');
            prop_assert_eq!(Glob::new(&pattern, separator).is_match(&text), reference(&pattern, &text, separator));
            prop_assert_eq!(glob_match(&pattern, &text, separator), reference(&pattern, &text, separator));
        }

        #[test]
        fn agrees_with_the_reference_across_word_boundaries(pattern in alphabet(24, true), text in alphabet(200, false), slash in any::<bool>()) {
            let separator = slash.then_some('/');
            prop_assert_eq!(Glob::new(&pattern, separator).is_match(&text), reference(&pattern, &text, separator));
        }
    }
}
