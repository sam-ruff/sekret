#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error(
        "secret key must start with a letter or underscore and contain only letters, digits, '_', '-' or '.' (max 256)"
    )]
    SecretKey,
    #[error("path must be absolute and made of segments using letters, digits, '_', '-' or '.'")]
    Path,
    #[error("slug must be 1-64 lowercase letters, digits or '-'")]
    Slug,
    #[error("name must be 1-128 printable characters")]
    Name,
    #[error("secret value is too large")]
    ValueTooLarge,
    #[error(
        "at most {MAX_GLOBS} patterns of at most {} characters each",
        crate::glob::MAX_GLOB_LEN
    )]
    Globs,
    #[error("comment must be at most {MAX_COMMENT_CHARS} characters")]
    Comment,
    #[error("description must be at most {MAX_DESCRIPTION_CHARS} characters")]
    Description,
}

pub const MAX_GLOBS: usize = 50;
pub const MAX_COMMENT_CHARS: usize = 1024;
pub const MAX_DESCRIPTION_CHARS: usize = 4096;

/// A version comment, kept with every version of a secret.
pub fn comment(value: &str) -> Result<(), ValidationError> {
    if value.chars().count() > MAX_COMMENT_CHARS {
        return Err(ValidationError::Comment);
    }
    Ok(())
}

/// A free-text description of a project, role, identity or credential.
pub fn description(value: &str) -> Result<(), ValidationError> {
    if value.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(ValidationError::Description);
    }
    Ok(())
}

/// Bounds a list of saved glob patterns so matching stays cheap.
pub fn globs(patterns: &[String]) -> Result<(), ValidationError> {
    let too_long = patterns.iter().any(|p| p.chars().count() > crate::glob::MAX_GLOB_LEN);
    if patterns.len() > MAX_GLOBS || too_long {
        return Err(ValidationError::Globs);
    }
    Ok(())
}

pub const MAX_VALUE_BYTES: usize = 64 * 1024;

pub fn secret_key(key: &str) -> Result<(), ValidationError> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(ValidationError::SecretKey);
    };
    if key.len() > 256 || !(first.is_ascii_alphabetic() || first == '_') {
        return Err(ValidationError::SecretKey);
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return Err(ValidationError::SecretKey);
    }
    Ok(())
}

pub fn secret_value(value: &str) -> Result<(), ValidationError> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(ValidationError::ValueTooLarge);
    }
    Ok(())
}

/// Normalises a folder path to `/a/b` form, rejecting traversal and odd characters.
pub fn folder_path(path: &str) -> Result<String, ValidationError> {
    if !path.starts_with('/') || path.len() > 512 {
        return Err(ValidationError::Path);
    }
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for segment in &segments {
        let valid_chars = segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !valid_chars || *segment == "." || *segment == ".." {
            return Err(ValidationError::Path);
        }
    }
    Ok(format!("/{}", segments.join("/")))
}

/// The textual UUID form, which slugs may not take because ids and slugs share lookups.
fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

pub fn slug(value: &str) -> Result<(), ValidationError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && !looks_like_uuid(value)
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        return Err(ValidationError::Slug);
    }
    Ok(())
}

pub fn name(value: &str) -> Result<(), ValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 128 || trimmed.chars().any(char::is_control) {
        return Err(ValidationError::Name);
    }
    Ok(())
}

/// True when `path` is `folder` or sits beneath it.
pub fn path_within(path: &str, folder: &str) -> bool {
    folder == "/" || path == folder || path.strip_prefix(folder).is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_keys() {
        assert!(secret_key("DATABASE_URL").is_ok());
        assert!(secret_key("_private.key-1").is_ok());
        assert!(secret_key("").is_err());
        assert!(secret_key("1ABC").is_err());
        assert!(secret_key("A B").is_err());
        assert!(secret_key("A=B").is_err());
        assert!(secret_key(&"A".repeat(257)).is_err());
    }

    #[test]
    fn folder_paths_normalise_and_reject_traversal() {
        assert_eq!(folder_path("/").as_deref(), Ok("/"));
        assert_eq!(folder_path("/app//db/").as_deref(), Ok("/app/db"));
        assert!(folder_path("app").is_err());
        assert!(folder_path("/app/../etc").is_err());
        assert!(folder_path("/app/./x").is_err());
        assert!(folder_path("/app/$x").is_err());
    }

    #[test]
    fn slugs_and_names() {
        assert!(slug("prod").is_ok());
        assert!(slug("my-app-2").is_ok());
        assert!(slug("Prod").is_err());
        assert!(slug("-x").is_err());
        assert!(slug("0192f3a4-5b6c-7d8e-9f01-23456789abcd").is_err());
        assert!(slug("0192f3a4-5b6c-7d8e-9f01-23456789abcz").is_ok());
        assert!(slug("").is_err());
        assert!(name("My project").is_ok());
        assert!(name("   ").is_err());
        assert!(name("bad\nname").is_err());
    }

    #[test]
    fn path_containment() {
        assert!(path_within("/app/db", "/app"));
        assert!(path_within("/app", "/app"));
        assert!(path_within("/anything", "/"));
        assert!(!path_within("/apps", "/app"));
    }

    #[test]
    fn comments_and_descriptions_are_bounded() {
        assert!(comment(&"é".repeat(MAX_COMMENT_CHARS)).is_ok());
        assert_eq!(
            comment(&"x".repeat(MAX_COMMENT_CHARS + 1)),
            Err(ValidationError::Comment)
        );
        assert!(description(&"x".repeat(MAX_DESCRIPTION_CHARS)).is_ok());
        assert_eq!(
            description(&"x".repeat(MAX_DESCRIPTION_CHARS + 1)),
            Err(ValidationError::Description)
        );
    }

    #[test]
    fn value_size_limit() {
        assert!(secret_value(&"x".repeat(MAX_VALUE_BYTES)).is_ok());
        assert!(secret_value(&"x".repeat(MAX_VALUE_BYTES + 1)).is_err());
    }
}
