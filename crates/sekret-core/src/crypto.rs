use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const BLOB_VERSION: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("key must be 32 bytes, raw, base64 or hex encoded")]
    InvalidKey,
    #[error("ciphertext is malformed")]
    Malformed,
    #[error("decryption failed")]
    Decrypt,
    #[error("system random source failed")]
    Random,
    #[error("key derivation failed")]
    Kdf,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; KEY_LEN]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; KEY_LEN]);

fn key_from_material(material: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    if material.len() == KEY_LEN {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(material);
        return Ok(key);
    }
    let text = std::str::from_utf8(material).map_err(|_| CryptoError::InvalidKey)?;
    let text = text.trim();
    // 64 hex characters are also valid base64, so hex has to be tried first.
    let decoded = Zeroizing::new(
        hex::decode(text)
            .or_else(|_| STANDARD.decode(text))
            .map_err(|_| CryptoError::InvalidKey)?,
    );
    if decoded.len() != KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Base64 of a 32-byte key plus `\n`, in a buffer sized up front so no copy is ever left behind
/// by a reallocation.
pub(crate) fn key_text(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(KEY_TEXT_LEN));
    STANDARD.encode_string(key, &mut text);
    text.push('\n');
    text
}

/// 44 base64 characters and a newline.
const KEY_TEXT_LEN: usize = 45;

impl RootKey {
    /// Accepts 32 raw bytes, or base64 / hex text with surrounding whitespace.
    pub fn parse(material: &[u8]) -> Result<Self, CryptoError> {
        key_from_material(material).map(Self)
    }

    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; KEY_LEN];
        fill_random(&mut key)?;
        Ok(Self(key))
    }

    /// Short identifier used to detect a server started with the wrong root key.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0);
        hex::encode(&digest[..8])
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        let mut text = key_text(&self.0);
        text.pop();
        text
    }

    /// The key as written to a key file: base64 and a newline.
    pub fn to_key_file_text(&self) -> Zeroizing<String> {
        key_text(&self.0)
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl DataKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; KEY_LEN];
        fill_random(&mut key)?;
        Ok(Self(key))
    }
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

pub(crate) fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| CryptoError::Malformed)?;
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Decrypt)?;
    let mut blob = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    blob.push(BLOB_VERSION);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub(crate) fn open(key: &[u8; KEY_LEN], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let Some((&version, rest)) = blob.split_first() else {
        return Err(CryptoError::Malformed);
    };
    if version != BLOB_VERSION || rest.len() < NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| CryptoError::Malformed)?;
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

fn data_key_aad(project_id: &str) -> Vec<u8> {
    format!("sekret:dek:v1:{project_id}").into_bytes()
}

pub fn wrap_data_key(root: &RootKey, data_key: &DataKey, project_id: &str) -> Result<Vec<u8>, CryptoError> {
    seal(&root.0, &data_key.0, &data_key_aad(project_id))
}

pub fn unwrap_data_key(root: &RootKey, wrapped: &[u8], project_id: &str) -> Result<DataKey, CryptoError> {
    let plain = open(&root.0, wrapped, &data_key_aad(project_id))?;
    if plain.len() != KEY_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plain);
    Ok(DataKey(key))
}

/// Binds a ciphertext to the exact row it was written for.
#[derive(Debug, Clone, Copy)]
pub struct ValueContext<'a> {
    pub project_id: &'a str,
    pub secret_id: &'a str,
    pub version: i64,
}

impl ValueContext<'_> {
    fn aad(&self) -> Vec<u8> {
        format!(
            "sekret:value:v1:{}:{}:{}",
            self.project_id, self.secret_id, self.version
        )
        .into_bytes()
    }
}

pub fn encrypt_value(key: &DataKey, plaintext: &str, ctx: ValueContext<'_>) -> Result<Vec<u8>, CryptoError> {
    seal(&key.0, plaintext.as_bytes(), &ctx.aad())
}

pub fn decrypt_value(key: &DataKey, blob: &[u8], ctx: ValueContext<'_>) -> Result<Zeroizing<String>, CryptoError> {
    let mut plain = open(&key.0, blob, &ctx.aad())?;
    let bytes = std::mem::take(&mut *plain);
    String::from_utf8(bytes).map(Zeroizing::new).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        CryptoError::Malformed
    })
}

fn credential_aad(context: &str) -> Vec<u8> {
    format!("sekret:credential:v1:{context}").into_bytes()
}

/// Encrypts a stored credential directly under the root key, bound to `context`, as base64.
pub fn seal_credential(root: &RootKey, plaintext: &str, context: &str) -> Result<String, CryptoError> {
    Ok(STANDARD.encode(seal(&root.0, plaintext.as_bytes(), &credential_aad(context))?))
}

pub fn open_credential(root: &RootKey, sealed: &str, context: &str) -> Result<Zeroizing<String>, CryptoError> {
    let blob = STANDARD.decode(sealed).map_err(|_| CryptoError::Malformed)?;
    let mut plain = open(&root.0, &blob, &credential_aad(context))?;
    let bytes = std::mem::take(&mut *plain);
    String::from_utf8(bytes).map(Zeroizing::new).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        CryptoError::Malformed
    })
}

/// Generates an opaque credential such as `skt_<43 chars>`.
pub fn generate_token(prefix: &str) -> Result<Zeroizing<String>, CryptoError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill_random(&mut *bytes)?;
    Ok(Zeroizing::new(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(*bytes))))
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn ctx<'a>(secret_id: &'a str, version: i64) -> ValueContext<'a> {
        ValueContext {
            project_id: "p1",
            secret_id,
            version,
        }
    }

    #[test]
    fn credentials_are_bound_to_root_and_context() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let sealed = seal_credential(&root, "reviewer-jwt", "identity:i1:kubernetes").context("seal")?;
        assert!(!sealed.contains("reviewer-jwt"));
        assert_eq!(
            open_credential(&root, &sealed, "identity:i1:kubernetes")
                .context("open")?
                .as_str(),
            "reviewer-jwt"
        );
        assert_eq!(
            open_credential(&root, &sealed, "identity:i2:kubernetes").err(),
            Some(CryptoError::Decrypt)
        );
        let other = RootKey::generate().context("root")?;
        assert_eq!(
            open_credential(&other, &sealed, "identity:i1:kubernetes").err(),
            Some(CryptoError::Decrypt)
        );
        assert_eq!(
            open_credential(&root, "not base64!", "identity:i1:kubernetes").err(),
            Some(CryptoError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn value_round_trip() -> anyhow::Result<()> {
        let key = DataKey::generate().context("key")?;
        let blob = encrypt_value(&key, "hunter2", ctx("s1", 1)).context("encrypt")?;
        assert_eq!(
            decrypt_value(&key, &blob, ctx("s1", 1)).context("decrypt")?.as_str(),
            "hunter2"
        );
        Ok(())
    }

    #[test]
    fn ciphertext_cannot_move_between_rows_or_versions() -> anyhow::Result<()> {
        let key = DataKey::generate().context("key")?;
        let blob = encrypt_value(&key, "v", ctx("s1", 1)).context("encrypt")?;
        assert_eq!(
            decrypt_value(&key, &blob, ctx("s2", 1)).err(),
            Some(CryptoError::Decrypt)
        );
        assert_eq!(
            decrypt_value(&key, &blob, ctx("s1", 2)).err(),
            Some(CryptoError::Decrypt)
        );
        Ok(())
    }

    #[test]
    fn tampering_is_detected() -> anyhow::Result<()> {
        let key = DataKey::generate().context("key")?;
        let mut blob = encrypt_value(&key, "value", ctx("s1", 1)).context("encrypt")?;
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert_eq!(
            decrypt_value(&key, &blob, ctx("s1", 1)).err(),
            Some(CryptoError::Decrypt)
        );
        assert_eq!(
            decrypt_value(&key, &[], ctx("s1", 1)).err(),
            Some(CryptoError::Malformed)
        );
        assert_eq!(
            decrypt_value(&key, &[9, 1, 2], ctx("s1", 1)).err(),
            Some(CryptoError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn nonces_are_unique() -> anyhow::Result<()> {
        let key = DataKey::generate().context("key")?;
        let a = encrypt_value(&key, "same", ctx("s1", 1)).context("encrypt")?;
        let b = encrypt_value(&key, "same", ctx("s1", 1)).context("encrypt")?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn data_key_wrapping_is_bound_to_project() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let dk = DataKey::generate().context("dk")?;
        let wrapped = wrap_data_key(&root, &dk, "p1").context("wrap")?;
        assert!(unwrap_data_key(&root, &wrapped, "p1").is_ok());
        assert!(unwrap_data_key(&root, &wrapped, "p2").is_err());
        let other_root = RootKey::generate().context("root")?;
        assert!(unwrap_data_key(&other_root, &wrapped, "p1").is_err());
        Ok(())
    }

    #[test]
    fn root_key_parses_raw_base64_and_hex() -> anyhow::Result<()> {
        let raw = [7u8; 32];
        let a = RootKey::parse(&raw).context("raw")?;
        let b = RootKey::parse(format!("{}\n", STANDARD.encode(raw)).as_bytes()).context("b64")?;
        let c = RootKey::parse(hex::encode(raw).as_bytes()).context("hex")?;
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint(), c.fingerprint());
        assert!(RootKey::parse(b"too short").is_err());
        Ok(())
    }

    #[test]
    fn tokens_are_prefixed_random_and_hash_stably() -> anyhow::Result<()> {
        let a = generate_token("skt_").context("token")?;
        let b = generate_token("skt_").context("token")?;
        assert!(a.starts_with("skt_"));
        assert_ne!(*a, *b);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_eq!(hash_token(&a).len(), 64);
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        Ok(())
    }
}
