//! A fake OIDC issuer for tests: fixed Ed25519 keys that mint tokens and serve their JWKS.

pub mod process;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

const KEY1: &[u8] = include_bytes!("../tests/fixtures/key1.pem");
const KEY2: &[u8] = include_bytes!("../tests/fixtures/key2.pem");
const KEY1_X: &str = "JU6vlfmW8OsiPLNDefa9LMXbiahQUxmaaXFlezOkbfg";
const KEY2_X: &str = "Oh-e4vpFJidHtYxwmJqZ7vD291yFEoDn4DGF-7zHOpA";

pub struct TestIssuer {
    pub url: String,
    pub now: i64,
    pem: &'static [u8],
    kid: &'static str,
    x: &'static str,
}

impl TestIssuer {
    pub fn new(url: &str) -> Self {
        Self::with_key(url, 1)
    }

    pub fn with_key(url: &str, key: u8) -> Self {
        let (pem, kid, x) = if key == 2 {
            (KEY2, "key2", KEY2_X)
        } else {
            (KEY1, "key1", KEY1_X)
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        Self {
            url: url.trim_end_matches('/').to_string(),
            now,
            pem,
            kid,
            x,
        }
    }

    pub fn jwks_url(&self) -> String {
        format!("{}/jwks", self.url)
    }

    pub fn jwks(&self) -> Value {
        json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": self.x, "kid": self.kid, "alg": "EdDSA", "use": "sig"}]})
    }

    pub fn discovery(&self) -> Value {
        json!({
            "issuer": self.url,
            "jwks_uri": self.jwks_url(),
            "authorization_endpoint": format!("{}/authorize", self.url),
            "token_endpoint": format!("{}/token", self.url),
            "end_session_endpoint": format!("{}/logout", self.url),
        })
    }

    /// Signs `claims`, filling in `iss`, `iat` and `exp` when absent. Claims set to null are left out.
    pub fn sign(&self, claims: Value) -> Result<String, jsonwebtoken::errors::Error> {
        self.sign_with_kid(claims, self.kid)
    }

    pub fn sign_with_kid(&self, mut claims: Value, kid: &str) -> Result<String, jsonwebtoken::errors::Error> {
        if let Some(map) = claims.as_object_mut() {
            map.entry("iss").or_insert_with(|| json!(self.url));
            map.entry("iat").or_insert_with(|| json!(self.now));
            map.entry("exp").or_insert_with(|| json!(self.now + 300));
            map.retain(|_, value| !value.is_null());
        }
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_ed_pem(self.pem)?;
        jsonwebtoken::encode(&header, &claims, &key)
    }
}
