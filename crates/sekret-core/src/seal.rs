//! Protecting the root key at rest: passphrase wrapping, remembered unlocks, setup codes and backups.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use icu_properties::props::{BinaryProperty, DefaultIgnorableCodePoint, EnumeratedProperty, GeneralCategory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use utoipa::ToSchema;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    CryptoError, KEY_LEN, RootKey, constant_time_eq, fill_from_material, fill_random, key_text, open, seal,
};

pub const MIN_PASSPHRASE_LEN: usize = 12;
/// Longer passphrases are refused before any key derivation runs.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;
pub const MAX_SETUP_CODE_BYTES: usize = 64;
pub const MIN_REMEMBER_SECRET_LEN: usize = 32;
pub const BACKUP_MAGIC: &[u8; 4] = b"SKB1";
/// Largest backup accepted or produced, whole file.
pub const MAX_BACKUP_LEN: usize = 1 << 30;

const ROOT_KEY_AAD: &[u8] = b"sekret/root-key/v1";
const REMEMBER_AAD: &[u8] = b"sekret/remember/v1";
const REMEMBER_V2_AAD: &[u8] = b"sekret/remember/v2";
const REMEMBER_V2_INFO: &[u8] = b"sekret/remember/v2";
const SEAL_CONFIG_INFO: &[u8] = b"sekret/seal-config/v1";
const BACKUP_INFO: &[u8] = b"sekret/backup/v1";
/// Argon2 memory floor in KiB, and iteration floor, for stored parameters.
const MIN_KDF_MEMORY: u32 = 64 * 1024;
const MIN_KDF_ITERATIONS: u32 = 3;
/// Ceilings for stored or backup parameters, so a crafted file cannot tie the server up for long.
const MAX_KDF_MEMORY: u32 = 512 * 1024;
const MAX_KDF_ITERATIONS: u32 = 10;
const MAX_KDF_LANES: u32 = 16;
const BOM: char = '\u{feff}';
const SALT_LEN: usize = 16;
const MAX_HEADER_LEN: usize = 64 * 1024;
const SETUP_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
const SETUP_GROUPS: usize = 3;
const SETUP_GROUP_LEN: usize = 4;

/// Whether the server can reach its secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SealState {
    /// First boot: no root key exists yet.
    Uninitialised,
    /// The root key is not in memory; only status and unseal respond.
    Sealed,
    Unsealed,
}

/// How the root key is kept between restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SealMode {
    /// Wrapped under a passphrase in the database; the server starts sealed.
    Passphrase,
    /// Read from a file on every start; the server is never sealed.
    KeyFile,
}

impl SealMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SealMode::Passphrase => "passphrase",
            SealMode::KeyFile => "key-file",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "passphrase" => Some(SealMode::Passphrase),
            "key-file" => Some(SealMode::KeyFile),
            _ => None,
        }
    }
}

/// How a passphrase-mode server gets unlocked after it starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockPolicy {
    /// Someone unlocks it by hand after every start.
    #[default]
    Manual,
    /// Unlocked by hand once, then from a device key file on later starts.
    Remember,
    /// Unlocked at start from a passphrase file or environment variable.
    PassphraseFile,
}

impl UnlockPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            UnlockPolicy::Manual => "manual",
            UnlockPolicy::Remember => "remember",
            UnlockPolicy::PassphraseFile => "passphrase-file",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "manual" => Some(UnlockPolicy::Manual),
            "remember" => Some(UnlockPolicy::Remember),
            "passphrase-file" => Some(UnlockPolicy::PassphraseFile),
            _ => None,
        }
    }
}

/// How the root key got into memory this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum UnsealedBy {
    /// Someone entered the passphrase.
    Passphrase,
    /// The remember file and the database wrap.
    Remember,
    /// A root key file, which also overrides passphrase mode.
    KeyFile,
    /// The passphrase file or environment variable read at start.
    PassphraseFile,
}

/// Argon2id cost: memory in KiB, iterations and parallelism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    /// The wrap was made from the NFKC form of the passphrase, so no other form is ever tried.
    /// Left out when false, so wraps made before it existed are stored and signed as they were.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub normalised: bool,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: 256 * 1024,
            t: 3,
            p: 1,
            normalised: true,
        }
    }
}

impl KdfParams {
    /// The weakest parameters a stored wrap may use.
    pub const FLOOR: KdfParams = KdfParams {
        m: MIN_KDF_MEMORY,
        t: MIN_KDF_ITERATIONS,
        p: 1,
        normalised: true,
    };

    /// Argon2id at the given cost, for a new NFKC wrap.
    pub const fn new(m: u32, t: u32, p: u32) -> Self {
        Self {
            m,
            t,
            p,
            normalised: true,
        }
    }

    /// Cheaper than today's default, so the wrap should be redone at the next chance.
    pub fn needs_upgrade(self) -> bool {
        let current = Self::default();
        self.m < current.m || self.t < current.t
    }

    /// Parameters read from a database or a backup are bounded on both sides: a crafted file can
    /// neither exhaust memory nor make the passphrase cheap to guess.
    fn argon2(self) -> Result<Argon2<'static>, CryptoError> {
        if self.m > MAX_KDF_MEMORY || self.t > MAX_KDF_ITERATIONS || self.p > MAX_KDF_LANES {
            return Err(CryptoError::Kdf);
        }
        if self.m < MIN_KDF_MEMORY || self.t < MIN_KDF_ITERATIONS {
            return Err(CryptoError::Kdf);
        }
        let params = Params::new(self.m, self.t, self.p, Some(KEY_LEN)).map_err(|_| CryptoError::Kdf)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// The root key encrypted under a key derived from a passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedRootKey {
    pub salt: Vec<u8>,
    pub params: KdfParams,
    pub ciphertext: Vec<u8>,
}

/// zxcvbn's verdict on a passphrase, from 0 (guessable) to 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PassphraseStrength {
    pub score: u8,
    /// Long enough, free of control characters and scores 4.
    pub acceptable: bool,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

impl std::fmt::Display for PassphraseStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the passphrase is too weak")?;
        if let Some(warning) = &self.warning {
            write!(f, ": {}", warning.trim_end_matches('.'))?;
        }
        for suggestion in &self.suggestions {
            write!(f, ". {}", suggestion.trim_end_matches('.'))?;
        }
        Ok(())
    }
}

pub const MIN_PASSPHRASE_SCORE: u8 = 4;

/// Drops one trailing `\r\n` or `\n`, the way every passphrase and secret source is read.
pub fn strip_line_ending(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

/// Drops a leading byte order mark, which some editors add, then one trailing line ending. Every
/// passphrase source goes through this: files, the environment, stdin, prompts and JSON.
pub fn trim_input(text: &str) -> &str {
    strip_line_ending(text.strip_prefix(BOM).unwrap_or(text))
}

/// Characters below 0x20 and DEL, which no prompt can reproduce reliably.
pub fn has_control_characters(text: &str) -> bool {
    text.chars().any(|c| u32::from(c) < 0x20 || c == '\u{7f}')
}

/// Characters that cannot be typed back reliably: controls (C0, C1 and DEL), format characters,
/// every space but U+0020, line and paragraph separators, default-ignorable code points such as
/// variation selectors and the Hangul filler, private-use and unassigned code points.
pub fn is_forbidden_char(c: char) -> bool {
    if c == ' ' {
        return false;
    }
    // The Braille blank is a symbol to Unicode, but shows as a space.
    if c == '\u{2800}' || DefaultIgnorableCodePoint::for_char(c) {
        return true;
    }
    matches!(
        GeneralCategory::for_char(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::SpaceSeparator
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::PrivateUse
            | GeneralCategory::Surrogate
            | GeneralCategory::Unassigned
    )
}

pub fn has_forbidden_characters(text: &str) -> bool {
    text.chars().any(is_forbidden_char)
}

/// The NFC form, which wraps made before NFKC used. NFC grows UTF-8 at most threefold, so the
/// buffer never reallocates.
pub fn nfc(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len().saturating_mul(3)));
    for c in text.nfc() {
        out.push(c);
    }
    out
}

/// The NFKC form, so the same passphrase typed with composed or decomposed accents, full-width
/// letters or ligatures opens the same wrap. Collected through a sized buffer that is zeroed.
pub fn nfkc(text: &str) -> Zeroizing<String> {
    // NFKC can grow text far more than NFC (one ligature becomes several letters), so the
    // buffer is sized by counting first rather than guessing.
    let len: usize = text.nfkc().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for c in text.nfkc() {
        out.push(c);
    }
    out
}

fn refused(score: u8, warning: &str, suggestion: &str) -> PassphraseStrength {
    PassphraseStrength {
        score,
        acceptable: false,
        warning: Some(warning.into()),
        suggestions: vec![suggestion.into()],
    }
}

pub fn passphrase_strength(passphrase: &str) -> PassphraseStrength {
    // zxcvbn's cost grows quickly with length, so oversized input never reaches it.
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return refused(
            0,
            &format!("Use at most {MAX_PASSPHRASE_BYTES} bytes."),
            "Use a shorter passphrase.",
        );
    }
    if has_forbidden_characters(passphrase) {
        return refused(
            0,
            "Remove tabs, line breaks, non-breaking spaces and other invisible characters.",
            "Use letters, digits, spaces and punctuation only.",
        );
    }
    let passphrase = nfkc(passphrase);
    let passphrase = passphrase.as_str();
    let entropy = zxcvbn::zxcvbn(passphrase, &["sekret"]);
    let score = u8::from(entropy.score());
    let long_enough = passphrase.chars().count() >= MIN_PASSPHRASE_LEN;
    let mut warning = entropy.feedback().and_then(|f| f.warning()).map(|w| w.to_string());
    let mut suggestions: Vec<String> = entropy
        .feedback()
        .map(|f| f.suggestions().iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    if !long_enough {
        warning.get_or_insert_with(|| format!("Use at least {MIN_PASSPHRASE_LEN} characters."));
        suggestions.insert(0, "Use a few words, avoid common phrases.".into());
        suggestions.dedup();
    } else if score < MIN_PASSPHRASE_SCORE && warning.is_none() && suggestions.is_empty() {
        suggestions.push("Add another word or two.".into());
    }
    PassphraseStrength {
        score,
        acceptable: long_enough && score >= MIN_PASSPHRASE_SCORE,
        warning,
        suggestions,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PassphraseError {
    #[error("{0}")]
    Weak(PassphraseStrength),
}

impl PassphraseError {
    pub fn strength(&self) -> &PassphraseStrength {
        match self {
            PassphraseError::Weak(strength) => strength,
        }
    }
}

/// At least [`MIN_PASSPHRASE_LEN`] characters, no control characters and a zxcvbn score of
/// [`MIN_PASSPHRASE_SCORE`].
pub fn validate_passphrase(passphrase: &str) -> Result<(), PassphraseError> {
    let strength = passphrase_strength(passphrase);
    if !strength.acceptable {
        return Err(PassphraseError::Weak(strength));
    }
    Ok(())
}

fn derive_kek(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    params
        .argon2()?
        .hash_password_into(passphrase.as_bytes(), salt, &mut *kek)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(kek)
}

pub fn wrap_root_key(root: &RootKey, passphrase: &str) -> Result<WrappedRootKey, CryptoError> {
    wrap_root_key_with(root, passphrase, KdfParams::default())
}

/// Wraps under the NFKC form of `passphrase`.
pub fn wrap_root_key_with(root: &RootKey, passphrase: &str, params: KdfParams) -> Result<WrappedRootKey, CryptoError> {
    let params = KdfParams {
        normalised: true,
        ..params
    };
    let mut salt = vec![0u8; SALT_LEN];
    fill_random(&mut salt)?;
    let kek = derive_kek(&nfkc(passphrase), &salt, params)?;
    let ciphertext = seal(&kek, root.bytes(), ROOT_KEY_AAD)?;
    Ok(WrappedRootKey {
        salt,
        params,
        ciphertext,
    })
}

/// A root key opened with a passphrase.
pub struct Unwrapped {
    pub root: RootKey,
    /// The wrap was made from an older form of the passphrase (NFC, or as typed), or does not
    /// record which form it used, so it should be made again.
    pub needs_rewrap: bool,
}

/// Fails with [`CryptoError::Decrypt`] when the passphrase is wrong or the wrap was altered.
pub fn unwrap_root_key(wrapped: &WrappedRootKey, passphrase: &str) -> Result<RootKey, CryptoError> {
    unwrap_root_key_checked(wrapped, passphrase).map(|u| u.root)
}

/// The most derivations one unwrap can cost: one per distinct form of the passphrase.
pub const MAX_UNWRAP_DERIVATIONS: usize = 3;

/// The forms of `passphrase` to try against `wrapped`, in order, with whether a match means the
/// wrap should be made again. A wrap that records its form gets exactly one; an older one also
/// gets the NFC form and the passphrase as typed, each only when it differs from those before.
fn passphrase_forms(wrapped: &WrappedRootKey, passphrase: &str) -> Vec<(Zeroizing<String>, bool)> {
    let compatible = nfkc(passphrase);
    if wrapped.params.normalised {
        return vec![(compatible, false)];
    }
    let mut forms = Vec::with_capacity(MAX_UNWRAP_DERIVATIONS);
    forms.push((compatible, true));
    for form in [nfc(passphrase), Zeroizing::new(passphrase.to_string())] {
        if forms.iter().all(|(tried, _)| tried.as_str() != form.as_str()) {
            forms.push((form, true));
        }
    }
    forms
}

/// Derives once per form from [`passphrase_forms`], so a passphrase whose normalised forms are
/// all the same costs one derivation, and none costs more than [`MAX_UNWRAP_DERIVATIONS`].
pub fn unwrap_root_key_checked(wrapped: &WrappedRootKey, passphrase: &str) -> Result<Unwrapped, CryptoError> {
    for (form, needs_rewrap) in passphrase_forms(wrapped, passphrase) {
        match open_with_passphrase(wrapped, &form) {
            Ok(root) => return Ok(Unwrapped { root, needs_rewrap }),
            Err(CryptoError::Decrypt) => {}
            Err(error) => return Err(error),
        }
    }
    Err(CryptoError::Decrypt)
}

fn open_with_passphrase(wrapped: &WrappedRootKey, passphrase: &str) -> Result<RootKey, CryptoError> {
    let kek = derive_kek(passphrase, &wrapped.salt, wrapped.params)?;
    root_from_plain(&open(&kek, &wrapped.ciphertext, ROOT_KEY_AAD)?)
}

fn root_from_plain(plain: &[u8]) -> Result<RootKey, CryptoError> {
    RootKey::from_slice(plain)
}

/// A per-host key kept in a file, under which the root key is remembered in the database.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceKey([u8; KEY_LEN]);

impl DeviceKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Self([0u8; KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
    }

    /// Accepts the same encodings as a root key file.
    pub fn parse(material: &[u8]) -> Result<Self, CryptoError> {
        let mut key = Self([0u8; KEY_LEN]);
        fill_from_material(material, &mut key.0)?;
        Ok(key)
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        let mut text = key_text(&self.0);
        text.pop();
        text
    }

    /// The key as written to the remember file: base64 and a newline.
    pub fn to_key_file_text(&self) -> Zeroizing<String> {
        key_text(&self.0)
    }

    /// Whether a file of `len` bytes could hold a device key in one of its encodings.
    pub fn plausible_file_len(len: u64) -> bool {
        // Raw, then base64 and hex, each with an optional `\n` or `\r\n`.
        [32, 44, 45, 46, 64, 65, 66].contains(&len)
    }
}

/// A deployment secret mixed into the remember key, so the disk alone cannot unlock.
#[derive(Clone)]
pub struct RememberSecret(Zeroizing<String>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RememberSecretError {
    #[error("the remember secret must be at least {MIN_REMEMBER_SECRET_LEN} characters")]
    TooShort,
    #[error("the remember secret must not contain control characters")]
    ControlCharacters,
    #[error(
        "the remember secret is too easy to guess; use 32 random bytes, base64 or hex encoded, such as the output \
         of `openssl rand -base64 32`"
    )]
    Guessable,
}

/// Fewer distinct bytes than this in a decoded key means it was not drawn at random.
const MIN_DISTINCT_KEY_BYTES: usize = 16;

/// Consecutive key bytes stepping by the same amount this many times means a pattern, not chance.
const MAX_KEY_STEP_RUN: usize = 4;
/// The same for the characters of the encoded text, such as `ABCDEFGHI`. Higher, as hex has only
/// 16 characters to step through.
const MAX_TEXT_STEP_RUN: usize = 8;

/// Whether `values` has `limit` steps in a row of the same size.
fn has_step_run(values: &[u8], limit: usize) -> bool {
    let mut run = 0;
    let mut previous_step = None;
    for pair in values.windows(2) {
        let step = pair[1].wrapping_sub(pair[0]);
        run = if previous_step == Some(step) { run + 1 } else { 0 };
        if run + 1 >= limit {
            return true;
        }
        previous_step = Some(step);
    }
    false
}

/// The bytes `text` decodes to as hex or base64, when that is at least [`KEY_LEN`] of them.
fn decoded_key(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    hex::decode(text)
        .ok()
        .or_else(|| {
            [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|engine| engine.decode(text).ok())
        })
        .map(Zeroizing::new)
        .filter(|bytes| bytes.len() >= KEY_LEN)
}

/// Whether an encoded key could have been drawn at random: enough distinct byte values, no run
/// stepping by a fixed amount in the bytes or the text, and not printable text underneath.
fn looks_random(text: &str, bytes: &[u8]) -> bool {
    let mut seen = [false; 256];
    for byte in bytes {
        seen[usize::from(*byte)] = true;
    }
    seen.iter().filter(|s| **s).count() >= MIN_DISTINCT_KEY_BYTES
        && !has_step_run(bytes, MAX_KEY_STEP_RUN)
        && !has_step_run(text.as_bytes(), MAX_TEXT_STEP_RUN)
        && !bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
}

fn scores_as_passphrase(text: &str) -> bool {
    text.len() <= MAX_PASSPHRASE_BYTES && u8::from(zxcvbn::zxcvbn(text, &["sekret"]).score()) >= MIN_PASSPHRASE_SCORE
}

impl RememberSecret {
    /// Drops one trailing line ending, then checks length, characters and that it cannot be
    /// guessed: text with the score a passphrase needs and, when it decodes to a key, key bytes
    /// with no obvious pattern. A key too long to score is judged on its bytes alone.
    pub fn new(text: &str) -> Result<Self, RememberSecretError> {
        let text = trim_input(text);
        if has_control_characters(text) {
            return Err(RememberSecretError::ControlCharacters);
        }
        if text.chars().count() < MIN_REMEMBER_SECRET_LEN {
            return Err(RememberSecretError::TooShort);
        }
        let strong = match decoded_key(text) {
            Some(bytes) => {
                looks_random(text, &bytes) && (text.len() > MAX_PASSPHRASE_BYTES || scores_as_passphrase(text))
            }
            None => scores_as_passphrase(text),
        };
        if !strong {
            return Err(RememberSecretError::Guessable);
        }
        Ok(Self(Zeroizing::new(text.to_string())))
    }
}

impl std::fmt::Debug for RememberSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RememberSecret(redacted)")
    }
}

/// The key and AAD the remembered wrap uses: the device key alone, or mixed with the secret.
fn remember_key(
    device: &DeviceKey,
    secret: Option<&RememberSecret>,
) -> Result<(Zeroizing<[u8; KEY_LEN]>, &'static [u8]), CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let Some(secret) = secret else {
        key.copy_from_slice(&device.0);
        return Ok((key, REMEMBER_AAD));
    };
    let mut material = Zeroizing::new(Vec::with_capacity(KEY_LEN + secret.0.len()));
    material.extend_from_slice(&device.0);
    material.extend_from_slice(secret.0.as_bytes());
    Hkdf::<Sha256>::new(None, &material)
        .expand(REMEMBER_V2_INFO, &mut *key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok((key, REMEMBER_V2_AAD))
}

pub fn remember_root_key(
    root: &RootKey,
    device: &DeviceKey,
    secret: Option<&RememberSecret>,
) -> Result<Vec<u8>, CryptoError> {
    let (key, aad) = remember_key(device, secret)?;
    seal(&key, root.bytes(), aad)
}

/// Fails with [`CryptoError::Decrypt`] for another server's device key, the wrong remember
/// secret or an altered wrap.
pub fn recall_root_key(
    remembered: &[u8],
    device: &DeviceKey,
    secret: Option<&RememberSecret>,
) -> Result<RootKey, CryptoError> {
    let (key, aad) = remember_key(device, secret)?;
    root_from_plain(&open(&key, remembered, aad)?)
}

/// Facts about the seal configuration that only ever move one way, signed with it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealFlags {
    /// Reviewer tokens sealed before they were bound to their cluster have been moved, so a
    /// token in the old format is never accepted or moved again.
    pub reviewer_tokens_migrated: bool,
    /// The remembered wrap was made with a remember secret, so one without it is never written
    /// in its place. Only forgetting the unlock clears it.
    pub remember_secret: bool,
    /// The wrap's passphrase form marker is part of the signed message. Configurations signed
    /// before this leave it out.
    pub wrap_form_signed: bool,
}

impl SealFlags {
    const REVIEWER_TOKENS_MIGRATED: i64 = 1;
    const REMEMBER_SECRET: i64 = 2;
    const WRAP_FORM_SIGNED: i64 = 4;

    /// The flags as stored in the database.
    pub fn bits(self) -> i64 {
        let mut bits = 0;
        if self.reviewer_tokens_migrated {
            bits |= Self::REVIEWER_TOKENS_MIGRATED;
        }
        if self.remember_secret {
            bits |= Self::REMEMBER_SECRET;
        }
        if self.wrap_form_signed {
            bits |= Self::WRAP_FORM_SIGNED;
        }
        bits
    }

    /// Unknown bits are refused, so a flag this version does not understand is never dropped.
    pub fn from_bits(bits: i64) -> Option<Self> {
        let known = Self::REVIEWER_TOKENS_MIGRATED | Self::REMEMBER_SECRET | Self::WRAP_FORM_SIGNED;
        if bits & !known != 0 {
            return None;
        }
        Some(Self {
            reviewer_tokens_migrated: bits & Self::REVIEWER_TOKENS_MIGRATED != 0,
            remember_secret: bits & Self::REMEMBER_SECRET != 0,
            wrap_form_signed: bits & Self::WRAP_FORM_SIGNED != 0,
        })
    }
}

/// Everything about the seal configuration that a database writer must not be able to change
/// without the root key.
#[derive(Debug, Clone, Copy)]
pub struct SealBinding<'a> {
    pub mode: SealMode,
    pub policy: UnlockPolicy,
    pub fingerprint: &'a str,
    /// Goes up with every change to the configuration.
    pub epoch: i64,
    pub wrapped: Option<&'a WrappedRootKey>,
    pub remembered: Option<&'a [u8]>,
    pub flags: SealFlags,
}

fn push_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u64).to_be_bytes());
    message.extend_from_slice(field);
}

fn optional_digest(field: Option<Vec<u8>>) -> Vec<u8> {
    match field {
        Some(bytes) => {
            let mut out = vec![1];
            out.extend_from_slice(&Sha256::digest(&bytes));
            out
        }
        None => vec![0],
    }
}

impl SealBinding<'_> {
    fn message(&self) -> Result<Vec<u8>, CryptoError> {
        let wrap = self
            .wrapped
            .map(|w| {
                // Configurations signed before the flag left the marker out, and still verify.
                let signed = KdfParams {
                    normalised: w.params.normalised && self.flags.wrap_form_signed,
                    ..w.params
                };
                let params = serde_json::to_vec(&signed).map_err(|_| CryptoError::Malformed)?;
                let mut bytes = Vec::new();
                push_field(&mut bytes, &w.salt);
                push_field(&mut bytes, &params);
                push_field(&mut bytes, &w.ciphertext);
                Ok(bytes)
            })
            .transpose()?;
        let mut message = Vec::new();
        push_field(&mut message, self.mode.as_str().as_bytes());
        push_field(&mut message, self.policy.as_str().as_bytes());
        push_field(&mut message, self.fingerprint.as_bytes());
        push_field(&mut message, &self.epoch.to_be_bytes());
        push_field(&mut message, &optional_digest(wrap));
        push_field(&mut message, &optional_digest(self.remembered.map(<[u8]>::to_vec)));
        // Appended only when set, so configurations signed before flags existed still verify,
        // and clearing a flag changes the message.
        let bits = self.flags.bits();
        if bits != 0 {
            push_field(&mut message, b"flags");
            push_field(&mut message, &bits.to_be_bytes());
        }
        Ok(message)
    }
}

fn seal_config_hmac(root: &RootKey, binding: &SealBinding<'_>) -> Result<Hmac<Sha256>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, root.bytes())
        .expand(SEAL_CONFIG_INFO, &mut *key)
        .map_err(|_| CryptoError::Kdf)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key).map_err(|_| CryptoError::InvalidKey)?;
    mac.update(&binding.message()?);
    Ok(mac)
}

/// Authenticates the seal configuration under a key derived from the root key.
pub fn seal_config_mac(root: &RootKey, binding: &SealBinding<'_>) -> Result<Vec<u8>, CryptoError> {
    Ok(seal_config_hmac(root, binding)?.finalize().into_bytes().to_vec())
}

/// Fails with [`CryptoError::Decrypt`] when any bound field was changed, in constant time.
pub fn verify_seal_config(root: &RootKey, binding: &SealBinding<'_>, mac: &[u8]) -> Result<(), CryptoError> {
    seal_config_hmac(root, binding)?
        .verify_slice(mac)
        .map_err(|_| CryptoError::Decrypt)
}

/// A one-time code such as `ABCD-EFGH-JKMN`, shown in the log on an uninitialised server.
pub fn generate_setup_code() -> Result<Zeroizing<String>, CryptoError> {
    let mut code = Zeroizing::new(String::with_capacity(SETUP_GROUPS * (SETUP_GROUP_LEN + 1)));
    let mut chars = 0;
    // Rejection sampling keeps every character equally likely.
    let limit = (256 / SETUP_ALPHABET.len() * SETUP_ALPHABET.len()) as u8;
    while chars < SETUP_GROUPS * SETUP_GROUP_LEN {
        let mut byte = [0u8; 1];
        fill_random(&mut byte)?;
        if byte[0] >= limit {
            continue;
        }
        if chars > 0 && chars % SETUP_GROUP_LEN == 0 {
            code.push('-');
        }
        code.push(char::from(SETUP_ALPHABET[usize::from(byte[0]) % SETUP_ALPHABET.len()]));
        chars += 1;
    }
    Ok(code)
}

fn normalise_code(code: &str) -> Zeroizing<String> {
    Zeroizing::new(
        code.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    )
}

/// Compares in constant time, ignoring case, spaces and dashes. Oversized input never matches.
pub fn setup_code_matches(expected: &str, given: &str) -> bool {
    if given.len() > MAX_SETUP_CODE_BYTES {
        return false;
    }
    constant_time_eq(normalise_code(expected).as_bytes(), normalise_code(given).as_bytes())
}

/// The plain-text part of a `.skb` backup, authenticated as the AAD of the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupHeader {
    pub mode: SealMode,
    pub wrapped_root_key: Option<String>,
    pub kdf_salt: Option<String>,
    pub kdf_params: Option<KdfParams>,
    pub root_fingerprint: String,
    pub created_at: i64,
    /// The sekret version that wrote the backup.
    pub version: String,
}

impl BackupHeader {
    pub fn new(
        mode: SealMode,
        wrapped: Option<&WrappedRootKey>,
        root: &RootKey,
        created_at: i64,
        version: &str,
    ) -> Self {
        Self {
            mode,
            wrapped_root_key: wrapped.map(|w| STANDARD.encode(&w.ciphertext)),
            kdf_salt: wrapped.map(|w| STANDARD.encode(&w.salt)),
            kdf_params: wrapped.map(|w| w.params),
            root_fingerprint: root.fingerprint(),
            created_at,
            version: version.to_string(),
        }
    }

    /// The passphrase wrap carried in the header, for passphrase-mode backups.
    pub fn wrapped(&self) -> Result<Option<WrappedRootKey>, CryptoError> {
        let (Some(ciphertext), Some(salt), Some(params)) = (&self.wrapped_root_key, &self.kdf_salt, self.kdf_params)
        else {
            return Ok(None);
        };
        let decode = |text: &str| STANDARD.decode(text).map_err(|_| CryptoError::Malformed);
        Ok(Some(WrappedRootKey {
            salt: decode(salt)?,
            params,
            ciphertext: decode(ciphertext)?,
        }))
    }
}

fn backup_key(root: &RootKey) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, root.bytes())
        .expand(BACKUP_INFO, &mut *key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// Builds a `.skb` file: magic, header length, JSON header, then the encrypted snapshot.
pub fn encrypt_backup(root: &RootKey, header: &BackupHeader, snapshot: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let header_bytes = serde_json::to_vec(header).map_err(|_| CryptoError::Malformed)?;
    let header_len = u32::try_from(header_bytes.len()).map_err(|_| CryptoError::Malformed)?;
    let body = seal(&*backup_key(root)?, snapshot, &header_bytes)?;
    let total = BACKUP_MAGIC.len() + 4 + header_bytes.len() + body.len();
    if total > MAX_BACKUP_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&body);
    Ok(out)
}

pub struct ParsedBackup<'a> {
    pub header: BackupHeader,
    header_bytes: &'a [u8],
    body: &'a [u8],
}

pub fn parse_backup(file: &[u8]) -> Result<ParsedBackup<'_>, CryptoError> {
    if file.len() > MAX_BACKUP_LEN {
        return Err(CryptoError::Malformed);
    }
    let rest = file
        .strip_prefix(BACKUP_MAGIC.as_slice())
        .ok_or(CryptoError::Malformed)?;
    let (len_bytes, rest) = rest.split_first_chunk::<4>().ok_or(CryptoError::Malformed)?;
    let header_len = usize::try_from(u32::from_be_bytes(*len_bytes)).map_err(|_| CryptoError::Malformed)?;
    if header_len > MAX_HEADER_LEN || header_len > rest.len() {
        return Err(CryptoError::Malformed);
    }
    let (header_bytes, body) = rest.split_at(header_len);
    let header = serde_json::from_slice(header_bytes).map_err(|_| CryptoError::Malformed)?;
    Ok(ParsedBackup {
        header,
        header_bytes,
        body,
    })
}

/// Fails with [`CryptoError::Decrypt`] for the wrong root key or any change to the file.
pub fn decrypt_backup(root: &RootKey, backup: &ParsedBackup<'_>) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open(&*backup_key(root)?, backup.body, backup.header_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    /// The production cost is exercised elsewhere; these only need the wrapping logic.
    const CHEAP: KdfParams = KdfParams::FLOOR;
    /// What wraps from before the form marker store.
    const LEGACY: KdfParams = KdfParams {
        normalised: false,
        ..CHEAP
    };

    #[test]
    fn passphrase_wrap_round_trips() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        let back = unwrap_root_key(&wrapped, "correct horse battery").context("unwrap")?;
        assert_eq!(back.fingerprint(), root.fingerprint());
        Ok(())
    }

    #[test]
    fn production_parameters_round_trip() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key(&root, "correct horse battery").context("wrap")?;
        assert_eq!(wrapped.params, KdfParams::new(262_144, 3, 1));
        assert!(wrapped.params.normalised);
        assert!(!wrapped.params.needs_upgrade());
        let back = unwrap_root_key(&wrapped, "correct horse battery").context("unwrap")?;
        assert_eq!(back.fingerprint(), root.fingerprint());
        Ok(())
    }

    #[test]
    fn wraps_at_the_old_default_still_open_and_ask_for_an_upgrade() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let old = KdfParams::new(65_536, 3, 1);
        let wrapped = wrap_root_key_with(&root, "correct horse battery", old).context("wrap")?;
        assert!(wrapped.params.needs_upgrade());
        let back = unwrap_root_key(&wrapped, "correct horse battery").context("unwrap")?;
        assert_eq!(back.fingerprint(), root.fingerprint());
        Ok(())
    }

    #[test]
    fn parameters_below_the_floor_are_refused() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let mut wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        for weak in [
            KdfParams::new(64, 3, 1),
            KdfParams::new(65_535, 3, 1),
            KdfParams::new(262_144, 2, 1),
        ] {
            wrapped.params = weak;
            assert_eq!(
                unwrap_root_key(&wrapped, "correct horse battery").err(),
                Some(CryptoError::Kdf),
                "{weak:?}"
            );
            assert_eq!(
                wrap_root_key_with(&root, "correct horse battery", weak).err(),
                Some(CryptoError::Kdf)
            );
        }
        Ok(())
    }

    #[test]
    fn stored_iterations_and_memory_are_capped() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let mut wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        for excessive in [
            KdfParams::new(65_536, 11, 1),
            KdfParams::new(512 * 1024 + 1, 3, 1),
            KdfParams::new(65_536, 3, 17),
        ] {
            wrapped.params = excessive;
            assert_eq!(
                unwrap_root_key(&wrapped, "correct horse battery").err(),
                Some(CryptoError::Kdf),
                "{excessive:?}"
            );
        }
        assert!(KdfParams::default().argon2().is_ok());
        assert!(KdfParams::new(65_536, 10, 1).argon2().is_ok());
        Ok(())
    }

    #[test]
    fn key_file_text_is_built_without_reallocating() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let text = root.to_key_file_text();
        assert_eq!(text.len(), 45);
        assert_eq!(
            text.capacity(),
            45,
            "sized up front, so pushing the newline never copied it"
        );
        assert!(text.ends_with('\n'));
        assert_eq!(*root.to_base64(), text[..44]);
        let device = DeviceKey::generate().context("device")?;
        let text = device.to_key_file_text();
        assert_eq!((text.len(), text.capacity()), (45, 45));
        assert_eq!(
            DeviceKey::parse(text.as_bytes()).context("parse")?.to_base64(),
            device.to_base64()
        );
        Ok(())
    }

    #[test]
    fn a_byte_order_mark_and_one_line_ending_are_dropped() {
        assert_eq!(trim_input("\u{feff}violet tractor\r\n"), "violet tractor");
        assert_eq!(trim_input("\u{feff}\u{feff}x"), "\u{feff}x", "only one");
        assert_eq!(trim_input("x\u{feff}"), "x\u{feff}", "only a leading one");
        assert_eq!(trim_input("plain"), "plain");
    }

    #[test]
    fn invisible_and_separator_characters_are_refused_in_new_passphrases() {
        for bad in [
            "violet tractor\u{200b}sings beneath",
            "violet tractor\u{a0}sings beneath",
            "violet tractor\u{2028}sings beneath",
            "violet tractor\u{2029}sings beneath",
            "violet tractor\u{85}sings beneath",
            "violet tractor\u{feff}sings beneath",
            "violet tractor\u{202e}sings beneath",
        ] {
            assert!(has_forbidden_characters(bad), "{bad:?}");
            assert!(!passphrase_strength(bad).acceptable, "{bad:?}");
        }
        assert!(!has_forbidden_characters("violet tractor sings beneath ünïcödé"));
    }

    #[test]
    fn composed_and_decomposed_passphrases_open_the_same_wrap() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let composed = "caf\u{e9} violet tractor";
        let decomposed = "cafe\u{301} violet tractor";
        let wrapped = wrap_root_key_with(&root, decomposed, CHEAP).context("wrap")?;
        let opened = unwrap_root_key_checked(&wrapped, composed).context("unwrap")?;
        assert_eq!(opened.root.fingerprint(), root.fingerprint());
        assert!(!opened.needs_rewrap);
        assert_eq!(
            passphrase_strength(composed).score,
            passphrase_strength(decomposed).score
        );
        Ok(())
    }

    #[test]
    fn wraps_made_before_normalisation_still_open_and_ask_to_be_redone() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let decomposed = "cafe\u{301} violet tractor";
        // What an older version stored: a key derived from the passphrase exactly as typed.
        let mut salt = vec![0u8; SALT_LEN];
        fill_random(&mut salt).context("salt")?;
        let kek = derive_kek(decomposed, &salt, LEGACY).context("kek")?;
        let legacy = WrappedRootKey {
            ciphertext: seal(&kek, root.bytes(), ROOT_KEY_AAD).context("seal")?,
            salt,
            params: LEGACY,
        };
        let opened = unwrap_root_key_checked(&legacy, decomposed).context("unwrap")?;
        assert_eq!(opened.root.fingerprint(), root.fingerprint());
        assert!(opened.needs_rewrap);
        assert_eq!(
            unwrap_root_key(&legacy, "caf\u{e9} violet tractor").err(),
            Some(CryptoError::Decrypt),
            "the composed form was never used for this wrap"
        );
        Ok(())
    }

    #[test]
    fn line_endings_are_stripped_once() {
        assert_eq!(strip_line_ending("pass\n"), "pass");
        assert_eq!(strip_line_ending("pass\r\n"), "pass");
        assert_eq!(strip_line_ending("pass\n\n"), "pass\n");
        assert_eq!(strip_line_ending("pass\r"), "pass\r");
        assert_eq!(strip_line_ending(" pass "), " pass ");
    }

    #[test]
    fn control_characters_and_oversized_passphrases_are_refused() {
        for bad in [
            "violet tractor\tsings beneath",
            "violet tractor sings beneath\n",
            "violet\u{7f}tractor sings beneath",
        ] {
            let strength = passphrase_strength(bad);
            assert!(!strength.acceptable, "{bad:?}");
            assert!(validate_passphrase(bad).is_err());
        }
        let long = "violet tractor sings beneath ".repeat(40);
        assert!(long.len() > MAX_PASSPHRASE_BYTES);
        assert!(!passphrase_strength(&long).acceptable);
    }

    #[test]
    fn a_score_of_three_is_no_longer_enough() {
        let three = ["correct horse battery staple", "violet tractor sings", "Tr0ub4dor&3xyz"]
            .into_iter()
            .map(passphrase_strength)
            .find(|s| s.score == 3);
        if let Some(strength) = three {
            assert!(!strength.acceptable);
        }
        assert!(passphrase_strength("violet tractor sings beneath").acceptable);
    }

    #[test]
    fn the_seal_config_mac_covers_every_bound_field() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        let fingerprint = root.fingerprint();
        let remembered = vec![7u8; 57];
        let binding = SealBinding {
            mode: SealMode::Passphrase,
            policy: UnlockPolicy::Manual,
            fingerprint: &fingerprint,
            epoch: 3,
            wrapped: Some(&wrapped),
            remembered: None,
            flags: SealFlags::default(),
        };
        let mac = seal_config_mac(&root, &binding).context("mac")?;
        verify_seal_config(&root, &binding, &mac).context("verify")?;
        let mut other_wrap = wrapped.clone();
        other_wrap.params = KdfParams::default();
        let changed = [
            SealBinding {
                policy: UnlockPolicy::Remember,
                ..binding
            },
            SealBinding {
                mode: SealMode::KeyFile,
                ..binding
            },
            SealBinding {
                fingerprint: "0000000000000000",
                ..binding
            },
            SealBinding { epoch: 2, ..binding },
            SealBinding {
                wrapped: None,
                ..binding
            },
            SealBinding {
                wrapped: Some(&other_wrap),
                ..binding
            },
            SealBinding {
                remembered: Some(&remembered),
                ..binding
            },
            SealBinding {
                flags: SealFlags {
                    reviewer_tokens_migrated: true,
                    ..SealFlags::default()
                },
                ..binding
            },
            SealBinding {
                flags: SealFlags {
                    remember_secret: true,
                    ..SealFlags::default()
                },
                ..binding
            },
            SealBinding {
                flags: SealFlags {
                    wrap_form_signed: true,
                    ..SealFlags::default()
                },
                ..binding
            },
        ];
        for tampered in changed {
            assert_eq!(
                verify_seal_config(&root, &tampered, &mac).err(),
                Some(CryptoError::Decrypt),
                "{tampered:?}"
            );
        }
        let other = RootKey::generate().context("root")?;
        assert!(verify_seal_config(&other, &binding, &mac).is_err());
        assert!(verify_seal_config(&root, &binding, &mac[..16]).is_err());
        Ok(())
    }

    /// A configuration signed before flags existed: the message is exactly the six old fields.
    #[test]
    fn signatures_from_before_flags_still_verify_and_flags_cannot_be_cleared() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let fingerprint = root.fingerprint();
        let binding = SealBinding {
            mode: SealMode::KeyFile,
            policy: UnlockPolicy::Manual,
            fingerprint: &fingerprint,
            epoch: 4,
            wrapped: None,
            remembered: None,
            flags: SealFlags::default(),
        };
        let mut old_message = Vec::new();
        for field in [
            b"key-file".as_slice(),
            b"manual",
            fingerprint.as_bytes(),
            &4i64.to_be_bytes(),
            &[0],
            &[0],
        ] {
            push_field(&mut old_message, field);
        }
        assert_eq!(binding.message().context("message")?, old_message);
        let flagged = SealBinding {
            flags: SealFlags {
                reviewer_tokens_migrated: true,
                remember_secret: true,
                wrap_form_signed: true,
            },
            ..binding
        };
        let mac = seal_config_mac(&root, &flagged).context("mac")?;
        assert!(
            verify_seal_config(&root, &binding, &mac).is_err(),
            "clearing the flags breaks the signature"
        );
        for bits in 0..8 {
            assert_eq!(SealFlags::from_bits(bits).map(SealFlags::bits), Some(bits));
        }
        assert_eq!(SealFlags::from_bits(8), None, "unknown flags are refused");
        Ok(())
    }

    #[test]
    fn spaces_ignorables_private_use_and_unassigned_characters_are_refused() {
        for bad in [
            "violet tractor\u{2002}sings beneath",
            "violet tractor\u{3000}sings beneath",
            "violet tractor\u{202f}sings beneath",
            "violet tractor\u{34f}sings beneath",
            "violet tractor\u{3164}sings beneath",
            "violet tractor\u{fe0f}sings beneath",
            "violet tractor\u{2800}sings beneath",
            "violet tractor\u{115f}sings beneath",
            "violet tractor\u{e000}sings beneath",
            "violet tractor\u{f0000}sings beneath",
            "violet tractor\u{378}sings beneath",
            "violet tractor\u{e01ef}sings beneath",
        ] {
            assert!(has_forbidden_characters(bad), "{bad:?}");
            assert!(!passphrase_strength(bad).acceptable, "{bad:?}");
        }
        assert!(!has_forbidden_characters(
            "violet tractor sings beneath, ünïcödé 日本語 ½"
        ));
    }

    #[test]
    fn new_wraps_use_nfkc_and_older_forms_still_open() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        // Full-width letters and a ligature fold to plain ones under NFKC only.
        let typed = "\u{ff56}iolet tractor \u{fb01}nds beneath";
        let folded = "violet tractor finds beneath";
        let wrapped = wrap_root_key_with(&root, typed, CHEAP).context("wrap")?;
        let opened = unwrap_root_key_checked(&wrapped, folded).context("unwrap")?;
        assert_eq!(opened.root.fingerprint(), root.fingerprint());
        assert!(!opened.needs_rewrap);

        // What the previous version stored: the NFC form, which keeps the full-width letter.
        let mut salt = vec![0u8; SALT_LEN];
        fill_random(&mut salt).context("salt")?;
        let kek = derive_kek(&nfc(typed), &salt, LEGACY).context("kek")?;
        let legacy = WrappedRootKey {
            ciphertext: seal(&kek, root.bytes(), ROOT_KEY_AAD).context("seal")?,
            salt,
            params: LEGACY,
        };
        let opened = unwrap_root_key_checked(&legacy, typed).context("unwrap")?;
        assert_eq!(opened.root.fingerprint(), root.fingerprint());
        assert!(opened.needs_rewrap, "an NFC wrap is redone under NFKC");
        assert_eq!(unwrap_root_key(&legacy, folded).err(), Some(CryptoError::Decrypt));
        Ok(())
    }

    /// A passphrase whose NFKC, NFC and typed forms all differ: a ligature and a combining accent.
    const THREE_FORMS: &str = "\u{fb01}nds cafe\u{301} violet tractor";

    #[test]
    fn a_marked_wrap_costs_one_derivation_whatever_the_passphrase() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        assert!(wrapped.params.normalised);
        assert_eq!(passphrase_forms(&wrapped, THREE_FORMS).len(), 1);
        assert_eq!(passphrase_forms(&wrapped, "plain ascii").len(), 1);

        let legacy = WrappedRootKey {
            params: LEGACY,
            ..wrapped
        };
        assert_eq!(passphrase_forms(&legacy, THREE_FORMS).len(), MAX_UNWRAP_DERIVATIONS);
        assert_eq!(
            passphrase_forms(&legacy, "plain ascii").len(),
            1,
            "identical forms are derived once"
        );
        assert_eq!(passphrase_forms(&legacy, "cafe\u{301} violet").len(), 2);
        Ok(())
    }

    #[test]
    fn an_unmarked_nfkc_wrap_opens_and_asks_to_be_marked() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let mut wrapped = wrap_root_key_with(&root, THREE_FORMS, CHEAP).context("wrap")?;
        wrapped.params.normalised = false;
        let opened = unwrap_root_key_checked(&wrapped, THREE_FORMS).context("unwrap")?;
        assert_eq!(opened.root.fingerprint(), root.fingerprint());
        assert!(opened.needs_rewrap);
        Ok(())
    }

    #[test]
    fn the_form_marker_is_signed_once_the_flag_says_so() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        let mut unmarked = wrapped.clone();
        unmarked.params.normalised = false;
        let fingerprint = root.fingerprint();
        let flags = SealFlags {
            wrap_form_signed: true,
            ..SealFlags::default()
        };
        let binding = |w| SealBinding {
            mode: SealMode::Passphrase,
            policy: UnlockPolicy::Manual,
            fingerprint: &fingerprint,
            epoch: 1,
            wrapped: Some(w),
            remembered: None,
            flags,
        };
        let marked_mac = seal_config_mac(&root, &binding(&wrapped)).context("mac")?;
        assert!(
            verify_seal_config(&root, &binding(&unmarked), &marked_mac).is_err(),
            "clearing the marker breaks the signature"
        );
        let unmarked_mac = seal_config_mac(&root, &binding(&unmarked)).context("mac")?;
        assert!(
            verify_seal_config(&root, &binding(&wrapped), &unmarked_mac).is_err(),
            "setting the marker breaks the signature"
        );
        Ok(())
    }

    #[test]
    fn the_form_marker_is_stored_but_not_signed_without_the_flag() -> anyhow::Result<()> {
        let json = serde_json::to_string(&LEGACY).context("json")?;
        assert!(!json.contains("normalised"), "{json}");
        let back: KdfParams = serde_json::from_str(&json).context("parse")?;
        assert!(!back.normalised, "older wraps read as unmarked");
        let marked: KdfParams =
            serde_json::from_str(&serde_json::to_string(&CHEAP).context("json")?).context("parse")?;
        assert!(marked.normalised);

        // Configurations signed by versions without the marker still verify once it is set.
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        let mut unmarked = wrapped.clone();
        unmarked.params.normalised = false;
        let fingerprint = root.fingerprint();
        let binding = |w| SealBinding {
            mode: SealMode::Passphrase,
            policy: UnlockPolicy::Manual,
            fingerprint: &fingerprint,
            epoch: 1,
            wrapped: Some(w),
            remembered: None,
            flags: SealFlags::default(),
        };
        let mac = seal_config_mac(&root, &binding(&unmarked)).context("mac")?;
        verify_seal_config(&root, &binding(&wrapped), &mac).context("verify")?;
        Ok(())
    }

    #[test]
    fn wrong_passphrase_is_refused() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        assert_eq!(
            unwrap_root_key(&wrapped, "incorrect horse battery").err(),
            Some(CryptoError::Decrypt)
        );
        Ok(())
    }

    #[test]
    fn tampered_wrap_is_refused() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        let mut flipped = wrapped.clone();
        let last = flipped.ciphertext.len() - 1;
        flipped.ciphertext[last] ^= 1;
        assert_eq!(
            unwrap_root_key(&flipped, "correct horse battery").err(),
            Some(CryptoError::Decrypt)
        );
        let mut salted = wrapped.clone();
        salted.salt[0] ^= 1;
        assert_eq!(
            unwrap_root_key(&salted, "correct horse battery").err(),
            Some(CryptoError::Decrypt)
        );
        // A wrap made for another purpose has a different AAD and must not open as a root key.
        let kek = derive_kek("correct horse battery", &wrapped.salt, CHEAP).context("kek")?;
        let other = WrappedRootKey {
            ciphertext: seal(&kek, root.bytes(), REMEMBER_AAD).context("seal")?,
            ..wrapped
        };
        assert_eq!(
            unwrap_root_key(&other, "correct horse battery").err(),
            Some(CryptoError::Decrypt)
        );
        Ok(())
    }

    #[test]
    fn excessive_kdf_parameters_are_refused() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let mut wrapped = wrap_root_key_with(&root, "correct horse battery", CHEAP).context("wrap")?;
        wrapped.params.m = u32::MAX;
        assert_eq!(
            unwrap_root_key(&wrapped, "correct horse battery").err(),
            Some(CryptoError::Kdf)
        );
        Ok(())
    }

    #[test]
    fn passphrases_need_length_and_strength() {
        let short = passphrase_strength("Zq8!vR2#");
        assert!(!short.acceptable);
        assert!(short.warning.is_some());
        assert!(validate_passphrase("Zq8!vR2#").is_err());
        let common = passphrase_strength("password1234");
        assert!(common.score < MIN_PASSPHRASE_SCORE && !common.acceptable);
        let error = validate_passphrase("password1234").err();
        assert!(
            error
                .as_ref()
                .is_some_and(|e| e.to_string().starts_with("the passphrase is too weak") && !e.strength().acceptable)
        );
        let strong = passphrase_strength("violet tractor sings beneath");
        assert!(strong.acceptable, "{strong:?}");
        assert_eq!(validate_passphrase("violet tractor sings beneath"), Ok(()));
    }

    #[test]
    fn remembered_key_needs_the_same_device_key() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let device = DeviceKey::generate().context("device")?;
        let remembered = remember_root_key(&root, &device, None).context("remember")?;
        let parsed = DeviceKey::parse(device.to_base64().as_bytes()).context("parse")?;
        assert_eq!(
            recall_root_key(&remembered, &parsed, None)
                .context("recall")?
                .fingerprint(),
            root.fingerprint()
        );
        let other = DeviceKey::generate().context("device")?;
        assert_eq!(
            recall_root_key(&remembered, &other, None).err(),
            Some(CryptoError::Decrypt)
        );
        assert!(DeviceKey::plausible_file_len(device.to_base64().len() as u64 + 1));
        assert!(!DeviceKey::plausible_file_len(4096));
        Ok(())
    }

    #[test]
    fn a_remember_secret_is_needed_alongside_the_device_key() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let device = DeviceKey::generate().context("device")?;
        let secret = RememberSecret::new(&format!("{}\n", *DeviceKey::generate()?.to_base64())).context("secret")?;
        let remembered = remember_root_key(&root, &device, Some(&secret)).context("remember")?;
        assert_eq!(
            recall_root_key(&remembered, &device, Some(&secret))
                .context("recall")?
                .fingerprint(),
            root.fingerprint()
        );
        assert!(recall_root_key(&remembered, &device, None).is_err());
        let wrong = RememberSecret::new(&DeviceKey::generate()?.to_base64()).context("secret")?;
        assert!(recall_root_key(&remembered, &device, Some(&wrong)).is_err());
        let without = remember_root_key(&root, &device, None).context("remember")?;
        assert!(recall_root_key(&without, &device, Some(&secret)).is_err());
        assert_eq!(
            RememberSecret::new("short\n").err(),
            Some(RememberSecretError::TooShort)
        );
        assert_eq!(
            RememberSecret::new("a remember secret\twith a tab inside it").err(),
            Some(RememberSecretError::ControlCharacters)
        );
        assert_eq!(format!("{secret:?}"), "RememberSecret(redacted)");
        Ok(())
    }

    #[test]
    fn a_remember_secret_must_not_be_guessable() -> anyhow::Result<()> {
        let mut key = [0u8; KEY_LEN];
        fill_random(&mut key)?;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        for strong in [
            STANDARD.encode(key),
            URL_SAFE_NO_PAD.encode(key),
            hex::encode(key),
            "kT9#vQ2!mZ7&pL4@xR8^wN3*bY6%hJ1$".to_string(),
        ] {
            assert!(RememberSecret::new(&strong).is_ok(), "{strong}");
        }
        for _ in 0..200 {
            fill_random(&mut key)?;
            for strong in [STANDARD.encode(key), hex::encode(key)] {
                assert!(RememberSecret::new(&strong).is_ok(), "{strong}");
            }
        }
        for weak in [
            "a".repeat(32),
            "a".repeat(44),
            "e".repeat(40),
            "A".repeat(64),
            hex::encode([7u8; 32]),
            "passwordpasswordpasswordpassword".to_string(),
            "abcdefghijklmnopqrstuvwxyz012345".to_string(),
            // Pass a distinct-byte count, but are a counting run and the base64 alphabet.
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_string(),
            hex::encode((0u8..32).map(|i| i.wrapping_mul(37)).collect::<Vec<_>>()),
            STANDARD.encode("Quietly Typed Words, Base64 Encoded!"),
        ] {
            assert_eq!(
                RememberSecret::new(&weak).err(),
                Some(RememberSecretError::Guessable),
                "{weak}"
            );
        }
        assert!(
            RememberSecretError::Guessable
                .to_string()
                .contains("openssl rand -base64 32")
        );
        Ok(())
    }

    #[test]
    fn setup_codes_are_grouped_and_compared_loosely() -> anyhow::Result<()> {
        let code = generate_setup_code().context("code")?;
        assert_eq!(code.len(), 14);
        assert_eq!(code.split('-').count(), 3);
        assert!(code.chars().all(|c| c == '-' || SETUP_ALPHABET.contains(&(c as u8))));
        assert!(setup_code_matches(&code, &code.to_lowercase()));
        assert!(setup_code_matches(&code, &code.replace('-', " ")));
        assert!(!setup_code_matches(&code, "AAAA-AAAA-AAAA"));
        assert!(!setup_code_matches(&code, ""));
        let padded = format!("{}{}", *code, " ".repeat(MAX_SETUP_CODE_BYTES));
        assert!(!setup_code_matches(&code, &padded));
        assert_ne!(*code, *generate_setup_code().context("code")?);
        Ok(())
    }

    fn sample_backup(root: &RootKey) -> anyhow::Result<Vec<u8>> {
        let wrapped = wrap_root_key_with(root, "correct horse battery", CHEAP).context("wrap")?;
        let header = BackupHeader::new(SealMode::Passphrase, Some(&wrapped), root, 1_700_000_000, "0.1.0");
        encrypt_backup(root, &header, b"SQLite format 3\0snapshot").context("encrypt")
    }

    #[test]
    fn backup_round_trips_and_carries_the_wrap() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let file = sample_backup(&root)?;
        assert!(file.starts_with(BACKUP_MAGIC));
        let parsed = parse_backup(&file).context("parse")?;
        assert_eq!(parsed.header.root_fingerprint, root.fingerprint());
        let wrapped = parsed.header.wrapped().context("wrapped")?.context("present")?;
        let recovered = unwrap_root_key(&wrapped, "correct horse battery").context("unwrap")?;
        let plain = decrypt_backup(&recovered, &parsed).context("decrypt")?;
        assert_eq!(plain.as_slice(), b"SQLite format 3\0snapshot");
        let other = RootKey::generate().context("root")?;
        assert_eq!(decrypt_backup(&other, &parsed).err(), Some(CryptoError::Decrypt));
        Ok(())
    }

    #[test]
    fn tampered_backup_is_refused() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let file = sample_backup(&root)?;

        let mut body = file.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        let parsed = parse_backup(&body).context("parse")?;
        assert_eq!(decrypt_backup(&root, &parsed).err(), Some(CryptoError::Decrypt));

        // Changing the header keeps it valid JSON but breaks the AAD.
        let mut header = file.clone();
        let start = file.windows(10).position(|w| w == b"1700000000").context("timestamp")?;
        header[start..start + 10].copy_from_slice(b"1700000001");
        let parsed = parse_backup(&header).context("parse")?;
        assert_eq!(decrypt_backup(&root, &parsed).err(), Some(CryptoError::Decrypt));

        assert!(parse_backup(b"SKB2rest").is_err());
        assert!(parse_backup(b"SKB1\xff\xff\xff\xff").is_err());
        assert!(parse_backup(&file[..10]).is_err());
        Ok(())
    }

    #[test]
    fn modes_and_policies_parse() {
        for mode in [SealMode::Passphrase, SealMode::KeyFile] {
            assert_eq!(SealMode::parse(mode.as_str()), Some(mode));
        }
        for policy in [
            UnlockPolicy::Manual,
            UnlockPolicy::Remember,
            UnlockPolicy::PassphraseFile,
        ] {
            assert_eq!(UnlockPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(SealMode::parse("other"), None);
        assert_eq!(UnlockPolicy::parse("other"), None);
    }
}
