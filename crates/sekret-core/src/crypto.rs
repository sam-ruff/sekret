use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const BLOB_VERSION: u8 = 1;
const FINGERPRINT_HEX_LEN: usize = 16;
const PIN_INFO: &[u8] = b"sekret/fingerprint/v1";
const INTEGRITY_KEY_AAD: &[u8] = b"sekret:integrity-key:v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("key must be 32 random bytes, raw, base64 or hex encoded; a 32-character password is not a key")]
    InvalidKey,
    #[error("ciphertext is malformed")]
    Malformed,
    #[error("decryption failed")]
    Decrypt,
    #[error("system random source failed")]
    Random,
    #[error("key derivation failed")]
    Kdf,
    #[error("the seal configuration epoch has reached its limit, which only tampering with the epoch marks can cause")]
    EpochExhausted,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; KEY_LEN]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; KEY_LEN]);

/// Whether 32 bytes of key material are printable text, such as a password, rather than raw
/// random bytes. Random bytes are all printable about once in 10^14.
fn printable_text(material: &[u8]) -> bool {
    material.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
}

/// Decodes key material straight into `out`, so no stray copy of the key is left on the stack.
/// Raw material must be exactly 32 bytes that are not printable text.
pub(crate) fn fill_from_material(material: &[u8], out: &mut [u8; KEY_LEN]) -> Result<(), CryptoError> {
    if material.len() == KEY_LEN {
        if printable_text(material) {
            return Err(CryptoError::InvalidKey);
        }
        out.copy_from_slice(material);
        return Ok(());
    }
    let text = std::str::from_utf8(material).map_err(|_| CryptoError::InvalidKey)?;
    let decoded = decode_key_text(text.trim(), &[&STANDARD]).ok_or(CryptoError::InvalidKey)?;
    if decoded.len() != KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    out.copy_from_slice(&decoded);
    Ok(())
}

/// Hex, or else base64 under the first of `engines` that accepts it, decoded into a buffer
/// allocated once at its final size, so no partly filled copy is freed without being zeroed.
pub(crate) fn decode_key_text(text: &str, engines: &[&base64::engine::GeneralPurpose]) -> Option<Zeroizing<Vec<u8>>> {
    // Hex text is also valid base64, so hex has to be tried first.
    if text.len().is_multiple_of(2) {
        let mut out = Zeroizing::new(vec![0u8; text.len() / 2]);
        if hex::decode_to_slice(text, &mut out).is_ok() {
            return Some(out);
        }
    }
    let mut out = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(text.len())]);
    for engine in engines {
        if let Ok(written) = engine.decode_slice(text, &mut out) {
            // Shortening keeps the allocation, which is zeroed in full on drop.
            out.truncate(written);
            return Some(out);
        }
    }
    None
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
        let mut key = Self([0u8; KEY_LEN]);
        fill_from_material(material, &mut key.0)?;
        Ok(key)
    }

    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Self([0u8; KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
    }

    /// Short identifier used to detect a server started with the wrong root key.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0);
        hex::encode(&digest[..8])
    }

    /// A full-length identifier derived from the key, recorded in the epoch marks, where a short
    /// fingerprint could be matched by searching for another key.
    pub fn pin(&self) -> Result<String, CryptoError> {
        let mut out = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(PIN_INFO, &mut out)
            .map_err(|_| CryptoError::Kdf)?;
        Ok(hex::encode(out))
    }

    /// Whether `recorded`, a pin or a fingerprint from before pins, names this key.
    pub fn is_named_by(&self, recorded: &str) -> bool {
        match recorded.len() {
            FINGERPRINT_HEX_LEN => constant_time_eq(recorded.as_bytes(), self.fingerprint().as_bytes()),
            _ => self
                .pin()
                .is_ok_and(|pin| constant_time_eq(recorded.as_bytes(), pin.as_bytes())),
        }
    }

    /// Whether `recorded` names this key by its full-length pin. A short fingerprint from before
    /// pins does not count, since another key with the same 64 bits can be searched for.
    pub fn is_pinned_by(&self, recorded: &str) -> bool {
        recorded.len() != FINGERPRINT_HEX_LEN && self.is_named_by(recorded)
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

    /// Copies exactly [`KEY_LEN`] bytes into a new key, filled in place.
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut key = Self([0u8; KEY_LEN]);
        key.0.copy_from_slice(bytes);
        Ok(key)
    }
}

impl DataKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Self([0u8; KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
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
    let mut key = DataKey([0u8; KEY_LEN]);
    key.0.copy_from_slice(&plain);
    Ok(key)
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

/// How tokens and client secrets were stored before [`IntegrityKey`]; still used for CLI device
/// codes, whose approval is authenticated separately.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Authenticates the rows that grant access, so someone who can write the database but does not
/// hold the root key cannot add a credential or move one to another principal. It is random and
/// kept wrapped under the root key, so replacing the root key keeps every credential working.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IntegrityKey([u8; KEY_LEN]);

impl IntegrityKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Self([0u8; KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
    }

    /// The key sealed under `root`, as base64.
    pub fn wrap(&self, root: &RootKey) -> Result<String, CryptoError> {
        Ok(STANDARD.encode(seal(&root.0, &self.0, INTEGRITY_KEY_AAD)?))
    }

    pub fn unwrap(root: &RootKey, wrapped: &str) -> Result<Self, CryptoError> {
        let blob = STANDARD.decode(wrapped).map_err(|_| CryptoError::Malformed)?;
        let plain = open(&root.0, &blob, INTEGRITY_KEY_AAD)?;
        if plain.len() != KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut key = Self([0u8; KEY_LEN]);
        key.0.copy_from_slice(&plain);
        Ok(key)
    }

    fn hmac(&self, purpose: &str, fields: &[&[u8]]) -> Result<Hmac<Sha256>, CryptoError> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&self.0).map_err(|_| CryptoError::InvalidKey)?;
        for field in std::iter::once(purpose.as_bytes()).chain(fields.iter().copied()) {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        Ok(mac)
    }

    /// What a bearer secret is stored and found under: the same for the same secret, and
    /// impossible to compute without this key.
    pub fn lookup(&self, purpose: &str, secret: &str) -> Result<String, CryptoError> {
        Ok(hex::encode(
            self.hmac(purpose, &[secret.as_bytes()])?.finalize().into_bytes(),
        ))
    }

    /// Authenticates `fields`, which are length-prefixed, under `purpose`, as hex.
    pub fn mac(&self, purpose: &str, fields: &[&[u8]]) -> Result<String, CryptoError> {
        Ok(hex::encode(self.hmac(purpose, fields)?.finalize().into_bytes()))
    }

    /// Checks a MAC from [`IntegrityKey::mac`] in constant time.
    pub fn verify(&self, purpose: &str, fields: &[&[u8]], mac: &str) -> bool {
        let Ok(expected) = hex::decode(mac) else {
            return false;
        };
        self.hmac(purpose, fields)
            .is_ok_and(|hmac| hmac.verify_slice(&expected).is_ok())
    }
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
    fn a_32_character_password_is_not_a_raw_key() -> anyhow::Result<()> {
        let password = b"correct horse battery staple 123";
        assert_eq!(password.len(), KEY_LEN);
        assert_eq!(RootKey::parse(password).err(), Some(CryptoError::InvalidKey));
        assert_eq!(RootKey::parse(&[b'a'; 32]).err(), Some(CryptoError::InvalidKey));
        let mut raw = [b'a'; 32];
        raw[5] = 0xfe;
        RootKey::parse(&raw).context("one byte outside text makes it raw")?;
        // The same text as base64 is a real key, so encoded keys are unaffected.
        RootKey::parse(STANDARD.encode(password).as_bytes()).context("base64")?;
        Ok(())
    }

    #[test]
    fn pins_are_full_length_and_name_only_their_key() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let other = RootKey::generate().context("root")?;
        let pin = root.pin().context("pin")?;
        assert_eq!(pin.len(), 64);
        assert_eq!(pin, root.pin().context("pin")?);
        assert!(!pin.starts_with(&root.fingerprint()), "not the fingerprint lengthened");
        assert!(root.is_named_by(&pin));
        assert!(root.is_named_by(&root.fingerprint()), "marks from before pins");
        assert!(!other.is_named_by(&pin));
        assert!(!other.is_named_by(&root.fingerprint()));
        assert!(!root.is_named_by(&pin[..32]));
        assert!(root.is_pinned_by(&pin));
        assert!(!root.is_pinned_by(&root.fingerprint()), "64 bits pin nothing");
        assert!(!other.is_pinned_by(&pin));
        Ok(())
    }

    #[test]
    fn integrity_keys_wrap_under_the_root_and_authenticate_fields() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let key = IntegrityKey::generate().context("key")?;
        let wrapped = key.wrap(&root).context("wrap")?;
        let opened = IntegrityKey::unwrap(&root, &wrapped).context("unwrap")?;
        assert_eq!(
            key.lookup("t", "skt_x").context("lookup")?,
            opened.lookup("t", "skt_x").context("lookup")?
        );
        let other_root = RootKey::generate().context("root")?;
        assert_eq!(
            IntegrityKey::unwrap(&other_root, &wrapped).err(),
            Some(CryptoError::Decrypt)
        );
        assert_eq!(IntegrityKey::unwrap(&root, "%%").err(), Some(CryptoError::Malformed));

        let lookup = key.lookup("token", "skt_x").context("lookup")?;
        assert_eq!(lookup.len(), 64);
        assert_ne!(lookup, hash_token("skt_x"), "not computable without the key");
        assert_ne!(lookup, key.lookup("client-secret", "skt_x").context("lookup")?);
        let stranger = IntegrityKey::generate().context("key")?;
        assert_ne!(lookup, stranger.lookup("token", "skt_x").context("lookup")?);

        let mac = key.mac("row", &[b"ab", b"c"]).context("mac")?;
        assert!(key.verify("row", &[b"ab", b"c"], &mac));
        assert!(!key.verify("row", &[b"a", b"bc"], &mac), "fields are length-prefixed");
        assert!(!key.verify("other", &[b"ab", b"c"], &mac));
        assert!(!stranger.verify("row", &[b"ab", b"c"], &mac));
        assert!(!key.verify("row", &[b"ab", b"c"], "not hex"));
        assert!(!key.verify("row", &[b"ab", b"c"], &mac[..62]));
        Ok(())
    }

    #[test]
    fn key_text_decodes_into_a_buffer_of_its_final_size() -> anyhow::Result<()> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let raw: Vec<u8> = (0u8..48).map(|b| b.wrapping_mul(37)).collect();
        for text in [hex::encode(&raw), STANDARD.encode(&raw), URL_SAFE_NO_PAD.encode(&raw)] {
            let decoded = decode_key_text(&text, &[&STANDARD, &URL_SAFE_NO_PAD]).context("decode")?;
            assert_eq!(decoded.as_slice(), raw.as_slice(), "{text}");
            assert_eq!(decoded.capacity(), raw.len(), "never grown: {text}");
        }
        // Unpadded base64 is refused unless an engine accepts it.
        assert!(decode_key_text(&URL_SAFE_NO_PAD.encode([0xfbu8; 31]), &[&STANDARD]).is_none());
        assert!(decode_key_text("not a key!", &[&STANDARD]).is_none());
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
