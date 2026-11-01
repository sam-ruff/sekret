use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::glob::glob_match;

/// Constraints a verified token's claims must satisfy before a machine identity may log in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ClaimBindings {
    /// At least one must match `aud`.
    pub audiences: Vec<String>,
    /// Globs matched against `sub`.
    pub subjects: Vec<String>,
    /// Claim name (or JSON pointer starting with `/`) to globs; every entry must match.
    pub claims: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("at least one bound audience is required")]
    NoAudience,
    #[error("a bound subject or bound claim is required so arbitrary tokens from the issuer are not accepted")]
    Unbounded,
    #[error(
        "subject and claim patterns need at least one literal character; a pattern of only wildcards matches any token"
    )]
    Wildcard,
    #[error("token audience is not bound")]
    Audience,
    #[error("token subject is not bound")]
    Subject,
    #[error("claim {0} does not match its binding")]
    Claim(String),
    #[error("bindings are too large: at most 50 patterns per list of at most 256 characters each")]
    TooLarge,
}

impl ClaimBindings {
    pub fn validate(&self) -> Result<(), BindingError> {
        if self.audiences.iter().all(|a| a.trim().is_empty()) {
            return Err(BindingError::NoAudience);
        }
        if self.subjects.is_empty() && self.claims.values().all(Vec::is_empty) {
            return Err(BindingError::Unbounded);
        }
        let lists = [&self.audiences, &self.subjects]
            .into_iter()
            .chain(self.claims.values());
        if self.claims.len() > crate::validate::MAX_GLOBS
            || lists.into_iter().any(|l| crate::validate::globs(l).is_err())
        {
            return Err(BindingError::TooLarge);
        }
        // A pattern of wildcards alone matches every token, so it bounds nothing.
        let mut patterns = self.subjects.iter().chain(self.claims.values().flatten());
        if patterns.any(|p| only_wildcards(p)) {
            return Err(BindingError::Wildcard);
        }
        Ok(())
    }

    pub fn check(&self, claims: &Value) -> Result<(), BindingError> {
        self.validate()?;
        let audiences = string_values(claims.get("aud"));
        if !audiences.iter().any(|a| self.audiences.contains(a)) {
            return Err(BindingError::Audience);
        }
        if !self.subjects.is_empty() {
            let subject = claims.get("sub").and_then(Value::as_str).unwrap_or_default();
            if !self.subjects.iter().any(|g| glob_match(g, subject, None)) {
                return Err(BindingError::Subject);
            }
        }
        for (name, globs) in &self.claims {
            if globs.is_empty() {
                continue;
            }
            let value = if name.starts_with('/') {
                claims.pointer(name)
            } else {
                claims.get(name)
            };
            let values = string_values(value);
            let matched = values.iter().any(|v| globs.iter().any(|g| glob_match(g, v, None)));
            if !matched {
                return Err(BindingError::Claim(name.clone()));
            }
        }
        Ok(())
    }
}

fn only_wildcards(pattern: &str) -> bool {
    pattern.chars().all(|c| matches!(c, '*' | '?'))
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Bool(b)) => vec![b.to_string()],
        Some(Value::Number(n)) => vec![n.to_string()],
        Some(Value::Array(items)) => items.iter().flat_map(|i| string_values(Some(i))).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn github() -> ClaimBindings {
        ClaimBindings {
            audiences: vec!["sekret".into()],
            subjects: vec!["repo:sam-ruff/*:ref:refs/heads/main".into()],
            claims: BTreeMap::from([("repository_owner".into(), vec!["sam-ruff".into()])]),
        }
    }

    #[test]
    fn matching_token_passes() {
        let claims =
            json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"});
        assert_eq!(github().check(&claims), Ok(()));
    }

    #[test]
    fn audience_array_is_supported() {
        let claims = json!({"aud": ["other", "sekret"], "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"});
        assert_eq!(github().check(&claims), Ok(()));
    }

    #[test]
    fn mismatches_are_rejected() {
        let base =
            json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"});
        let mut wrong_aud = base.clone();
        wrong_aud["aud"] = json!("someone-else");
        assert_eq!(github().check(&wrong_aud), Err(BindingError::Audience));
        let mut wrong_branch = base.clone();
        wrong_branch["sub"] = json!("repo:sam-ruff/app:ref:refs/heads/feature");
        assert_eq!(github().check(&wrong_branch), Err(BindingError::Subject));
        let mut wrong_owner = base;
        wrong_owner["repository_owner"] = json!("evil");
        assert_eq!(
            github().check(&wrong_owner),
            Err(BindingError::Claim("repository_owner".into()))
        );
        assert_eq!(github().check(&json!({"sub": "x"})), Err(BindingError::Audience));
    }

    #[test]
    fn oversized_bindings_are_refused() {
        let mut long = github();
        long.subjects = vec!["*".repeat(257)];
        assert_eq!(long.validate(), Err(BindingError::TooLarge));
        let mut many = github();
        many.subjects = vec!["a".into(); 51];
        assert_eq!(many.validate(), Err(BindingError::TooLarge));
    }

    #[test]
    fn nested_claims_via_pointer() {
        let bindings = ClaimBindings {
            audiences: vec!["sekret".into()],
            subjects: vec![],
            claims: BTreeMap::from([("/kubernetes.io/namespace".into(), vec!["apps".into()])]),
        };
        let claims = json!({"aud": ["sekret"], "kubernetes.io": {"namespace": "apps"}});
        assert_eq!(bindings.check(&claims), Ok(()));
        let other = json!({"aud": ["sekret"], "kubernetes.io": {"namespace": "kube-system"}});
        assert!(bindings.check(&other).is_err());
    }

    #[test]
    fn unbounded_configurations_are_refused() {
        assert_eq!(ClaimBindings::default().validate(), Err(BindingError::NoAudience));
        let only_aud = ClaimBindings {
            audiences: vec!["a".into()],
            ..Default::default()
        };
        assert_eq!(only_aud.validate(), Err(BindingError::Unbounded));
    }

    #[test]
    fn wildcard_only_patterns_do_not_count_as_bounds() {
        for pattern in ["*", "**", "?", "*?*", ""] {
            let any_subject = ClaimBindings {
                subjects: vec![pattern.into()],
                ..github()
            };
            assert_eq!(any_subject.validate(), Err(BindingError::Wildcard), "{pattern:?}");
            let any_claim = ClaimBindings {
                claims: BTreeMap::from([("sub".into(), vec![pattern.into()])]),
                ..github()
            };
            assert_eq!(any_claim.validate(), Err(BindingError::Wildcard), "{pattern:?}");
        }
        let claims = json!({"aud": "sekret", "sub": "repo:anyone/app:ref:refs/heads/main"});
        let saved_before = ClaimBindings {
            subjects: vec!["*".into()],
            claims: BTreeMap::new(),
            ..github()
        };
        assert_eq!(
            saved_before.check(&claims),
            Err(BindingError::Wildcard),
            "a binding saved before the check refuses logins"
        );
        assert_eq!(github().validate(), Ok(()), "a pattern with a literal part is fine");
    }
}
