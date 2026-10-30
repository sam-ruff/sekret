//! Generated secret values and when to rotate them.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, fill_random};

pub const MIN_LENGTH: u32 = 8;
pub const MAX_LENGTH: u32 = 512;
pub const MAX_ROTATION_DAYS: u32 = 3650;
const DAY: i64 = 24 * 3600;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Charset {
    /// Letters and digits.
    #[default]
    Alphanumeric,
    /// Letters, digits and punctuation that is safe to paste into most configuration files.
    Symbols,
    /// Lowercase hexadecimal.
    Hex,
    /// URL-safe base64 alphabet.
    Base64url,
    /// Digits only, such as PINs.
    Numeric,
}

impl Charset {
    fn alphabet(self) -> &'static [u8] {
        match self {
            Charset::Alphanumeric => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            Charset::Symbols => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%+,-.:=@^_~",
            Charset::Hex => b"0123456789abcdef",
            Charset::Base64url => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            Charset::Numeric => b"0123456789",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Generator {
    pub length: u32,
    #[serde(default)]
    pub charset: Charset,
}

impl Default for Generator {
    fn default() -> Self {
        Self {
            length: 32,
            charset: Charset::Alphanumeric,
        }
    }
}

/// How a secret's value is produced and refreshed. Both parts off is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretPolicy {
    /// How sekret generates the value; `None` uses the default (32 alphanumeric) when asked to generate.
    #[serde(default)]
    pub generator: Option<Generator>,
    /// Days between automatic rotations; `None` turns rotation off.
    #[serde(default)]
    pub rotation_days: Option<u32>,
}

/// A secret's own setting: follow the project, or use `policy` (which may switch everything off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum PolicyOverride {
    Inherit,
    Custom(SecretPolicy),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("length must be between {MIN_LENGTH} and {MAX_LENGTH}")]
    Length,
    #[error("rotation must be between 1 and {MAX_ROTATION_DAYS} days")]
    Rotation,
}

impl SecretPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self
            .generator
            .is_some_and(|g| !(MIN_LENGTH..=MAX_LENGTH).contains(&g.length))
        {
            return Err(PolicyError::Length);
        }
        if self.rotation_days.is_some_and(|d| d == 0 || d > MAX_ROTATION_DAYS) {
            return Err(PolicyError::Rotation);
        }
        Ok(())
    }

    pub fn generator_or_default(&self) -> Generator {
        self.generator.unwrap_or_default()
    }
}

/// The policy that applies to one secret.
pub fn effective(project: SecretPolicy, secret: Option<PolicyOverride>) -> SecretPolicy {
    match secret {
        Some(PolicyOverride::Custom(policy)) => policy,
        Some(PolicyOverride::Inherit) | None => project,
    }
}

/// When the current value is due to be replaced. Only values sekret generated itself are ever
/// rotated automatically, so pasted credentials from elsewhere are never overwritten.
pub fn next_rotation(policy: &SecretPolicy, generated: bool, version_created_at: i64) -> Option<i64> {
    let days = policy.rotation_days?;
    if !generated {
        return None;
    }
    Some(version_created_at + i64::from(days) * DAY)
}

pub fn is_due(policy: &SecretPolicy, generated: bool, version_created_at: i64, now: i64) -> bool {
    next_rotation(policy, generated, version_created_at).is_some_and(|at| at <= now)
}

/// A uniformly random value; bytes that would bias the alphabet are drawn again.
pub fn generate(generator: Generator) -> Result<Zeroizing<String>, CryptoError> {
    let alphabet = generator.charset.alphabet();
    let len = alphabet.len();
    // The largest multiple of the alphabet size that fits in a byte.
    let limit = 256 - (256 % len);
    let mut out = Zeroizing::new(String::with_capacity(generator.length as usize));
    let mut buf = Zeroizing::new([0u8; 64]);
    while out.len() < generator.length as usize {
        fill_random(&mut *buf)?;
        for &byte in buf.iter() {
            if out.len() == generator.length as usize {
                break;
            }
            if (byte as usize) < limit {
                out.push(alphabet[byte as usize % len] as char);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_values_use_the_alphabet_and_length() {
        for charset in [
            Charset::Alphanumeric,
            Charset::Symbols,
            Charset::Hex,
            Charset::Base64url,
            Charset::Numeric,
        ] {
            let value = generate(Generator { length: 200, charset }).expect("generate");
            assert_eq!(value.len(), 200);
            assert!(value.bytes().all(|b| charset.alphabet().contains(&b)), "{charset:?}");
        }
        let a = generate(Generator::default()).expect("a");
        let b = generate(Generator::default()).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn every_character_turns_up() {
        let value = generate(Generator {
            length: 4000,
            charset: Charset::Hex,
        })
        .expect("generate");
        for c in Charset::Hex.alphabet() {
            assert!(value.as_bytes().contains(c), "{}", *c as char);
        }
    }

    #[test]
    fn secrets_inherit_or_override_the_project() {
        let project = SecretPolicy {
            generator: Some(Generator::default()),
            rotation_days: Some(30),
        };
        assert_eq!(effective(project, None), project);
        assert_eq!(effective(project, Some(PolicyOverride::Inherit)), project);
        let off = SecretPolicy::default();
        assert_eq!(effective(project, Some(PolicyOverride::Custom(off))), off);
    }

    #[test]
    fn only_generated_values_rotate() {
        let policy = SecretPolicy {
            generator: None,
            rotation_days: Some(1),
        };
        assert_eq!(next_rotation(&policy, true, 100), Some(100 + DAY));
        assert!(is_due(&policy, true, 0, DAY));
        assert!(!is_due(&policy, true, 0, DAY - 1));
        assert!(!is_due(&policy, false, 0, DAY * 100), "pasted values are left alone");
        assert!(!is_due(&SecretPolicy::default(), true, 0, DAY * 100), "off by default");
    }

    #[test]
    fn policies_are_bounded() {
        let long = SecretPolicy {
            generator: Some(Generator {
                length: MAX_LENGTH + 1,
                charset: Charset::Hex,
            }),
            rotation_days: None,
        };
        assert_eq!(long.validate(), Err(PolicyError::Length));
        let never = SecretPolicy {
            generator: None,
            rotation_days: Some(0),
        };
        assert_eq!(never.validate(), Err(PolicyError::Rotation));
        assert!(SecretPolicy::default().validate().is_ok());
    }

    #[test]
    fn overrides_round_trip_as_tagged_json() {
        let custom = PolicyOverride::Custom(SecretPolicy {
            generator: Some(Generator {
                length: 16,
                charset: Charset::Numeric,
            }),
            rotation_days: Some(7),
        });
        let json = serde_json::to_value(custom).expect("json");
        assert_eq!(json["mode"], "custom");
        assert_eq!(json["generator"]["charset"], "numeric");
        assert_eq!(serde_json::from_value::<PolicyOverride>(json).expect("parse"), custom);
        assert_eq!(
            serde_json::from_value::<PolicyOverride>(serde_json::json!({"mode": "inherit"})).expect("inherit"),
            PolicyOverride::Inherit
        );
    }
}
