use std::collections::{BTreeMap, BTreeSet};

use sekret_api::RawSecret;
use sha2::{Digest, Sha256};

/// Secret data keyed by name. Values are never logged or put in errors.
pub type SecretData = BTreeMap<String, Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentError {
    #[error("key {key} exists at more than one path ({}); narrow the path or disable recursive", paths.join(", "))]
    DuplicateKey { key: String, paths: Vec<String> },
    #[error("requested keys were not found: {}", .0.join(", "))]
    KeysNotFound(Vec<String>),
    #[error("key {0:?} is not a valid Secret key (allowed: letters, digits, '-', '_' and '.')")]
    InvalidKey(String),
}

/// Builds Secret data from fetched secrets, ignoring their folder paths.
pub fn build_data(secrets: Vec<RawSecret>, keys: Option<&[String]>) -> Result<SecretData, ContentError> {
    let wanted: Option<BTreeSet<&str>> = keys.map(|keys| keys.iter().map(String::as_str).collect());
    let mut data = SecretData::new();
    let mut seen_at: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for secret in secrets {
        if wanted.as_ref().is_some_and(|w| !w.contains(secret.key.as_str())) {
            continue;
        }
        seen_at.entry(secret.key.clone()).or_default().push(secret.path);
        data.insert(secret.key, secret.value.into_bytes());
    }
    if let Some((key, paths)) = seen_at.into_iter().find(|(_, paths)| paths.len() > 1) {
        return Err(ContentError::DuplicateKey { key, paths });
    }
    if let Some(wanted) = wanted {
        let missing: Vec<String> = wanted
            .into_iter()
            .filter(|k| !data.contains_key(*k))
            .map(String::from)
            .collect();
        if !missing.is_empty() {
            return Err(ContentError::KeysNotFound(missing));
        }
    }
    if let Some(bad) = data.keys().find(|k| !is_valid_key(k)) {
        return Err(ContentError::InvalidKey(bad.clone()));
    }
    Ok(data)
}

fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 253
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// SHA-256 over the sorted key/value pairs, length-prefixed so pairs cannot run together.
pub fn content_hash(data: &SecretData) -> String {
    let mut hasher = Sha256::new();
    for (key, value) in data {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(path: &str, key: &str, value: &str) -> RawSecret {
        RawSecret {
            path: path.into(),
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn ignores_paths_when_mapping_keys() {
        let data = build_data(vec![raw("/", "A", "1"), raw("/db", "B", "2")], None).expect("data");
        assert_eq!(data.get("A"), Some(&b"1".to_vec()));
        assert_eq!(data.get("B"), Some(&b"2".to_vec()));
    }

    #[test]
    fn keys_filter_keeps_only_requested_keys() {
        let keys = vec!["B".to_string()];
        let data = build_data(vec![raw("/", "A", "1"), raw("/", "B", "2")], Some(&keys)).expect("data");
        assert_eq!(data.keys().collect::<Vec<_>>(), vec!["B"]);
    }

    #[test]
    fn keys_filter_reports_missing_keys_by_name() {
        let keys = vec!["A".to_string(), "MISSING".to_string()];
        let error = build_data(vec![raw("/", "A", "1")], Some(&keys)).expect_err("missing");
        assert_eq!(error, ContentError::KeysNotFound(vec!["MISSING".into()]));
    }

    #[test]
    fn duplicate_keys_across_paths_fail_without_values() {
        let error = build_data(vec![raw("/a", "DUP", "first"), raw("/b", "DUP", "second")], None).expect_err("dup");
        assert_eq!(
            error,
            ContentError::DuplicateKey {
                key: "DUP".into(),
                paths: vec!["/a".into(), "/b".into()]
            }
        );
        let message = error.to_string();
        assert!(!message.contains("first") && !message.contains("second"), "{message}");
    }

    #[test]
    fn duplicates_outside_the_filter_are_ignored() {
        let keys = vec!["A".to_string()];
        let secrets = vec![raw("/", "A", "1"), raw("/a", "DUP", "x"), raw("/b", "DUP", "y")];
        assert!(build_data(secrets, Some(&keys)).is_ok());
    }

    #[test]
    fn rejects_keys_kubernetes_would_refuse() {
        let error = build_data(vec![raw("/", "BAD KEY", "1")], None).expect_err("invalid");
        assert_eq!(error, ContentError::InvalidKey("BAD KEY".into()));
    }

    #[test]
    fn hash_is_stable_and_sensitive_to_content() {
        let a = build_data(vec![raw("/", "A", "1"), raw("/", "B", "2")], None).expect("a");
        let b = build_data(vec![raw("/", "B", "2"), raw("/", "A", "1")], None).expect("b");
        assert_eq!(content_hash(&a), content_hash(&b));
        let c = build_data(vec![raw("/", "A", "12"), raw("/", "B", "")], None).expect("c");
        assert_ne!(content_hash(&a), content_hash(&c));
    }
}
