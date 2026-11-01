use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::clock::Clock;
use crate::net::{NetError, OidcHttp};

const ALLOWED: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];
const CACHE_SECONDS: i64 = 600;
const MIN_REFRESH_SECONDS: i64 = 30;
const LEEWAY_SECONDS: i64 = 30;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwtError {
    #[error("token is malformed")]
    Malformed,
    #[error("signing algorithm is not allowed")]
    Algorithm,
    #[error("no matching signing key")]
    UnknownKey,
    #[error("token failed validation: {0}")]
    Invalid(String),
    #[error("could not fetch signing keys: {0}")]
    Fetch(#[from] NetError),
    #[error("issuer discovery document is invalid")]
    Discovery,
}

/// Where the keys for a token come from.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// Use OIDC discovery on the issuer.
    Issuer,
    Url(String),
    Inline(JwkSet),
}

#[derive(Debug, Clone)]
pub struct Expectations<'a> {
    pub issuer: Option<&'a str>,
    /// Enforced here only for human ID tokens; machine audiences go through claim bindings.
    pub audience: Option<&'a str>,
}

struct CachedKeys {
    keys: Arc<JwkSet>,
    fetched_at: i64,
}

/// Verifies JWTs against remote JWKS with caching and refresh on unknown key ids.
pub struct JwtVerifier {
    http: Arc<dyn OidcHttp>,
    clock: Arc<dyn Clock>,
    keys: Mutex<HashMap<String, CachedKeys>>,
    discovery: Mutex<HashMap<String, (Value, i64)>>,
}

impl JwtVerifier {
    pub fn new(http: Arc<dyn OidcHttp>, clock: Arc<dyn Clock>) -> Self {
        Self {
            http,
            clock,
            keys: Mutex::new(HashMap::new()),
            discovery: Mutex::new(HashMap::new()),
        }
    }

    /// Fetches and caches the issuer's discovery document, checking it names the same issuer.
    pub async fn discover(&self, issuer: &str) -> Result<Value, JwtError> {
        let now = self.clock.now();
        if let Some((doc, at)) = self.discovery.lock().await.get(issuer)
            && now - at < CACHE_SECONDS
        {
            return Ok(doc.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let doc = self.http.get_json(&url).await?;
        let named = doc["issuer"].as_str().map(|s| s.trim_end_matches('/'));
        if named != Some(issuer.trim_end_matches('/')) || doc["jwks_uri"].as_str().is_none() {
            return Err(JwtError::Discovery);
        }
        self.discovery
            .lock()
            .await
            .insert(issuer.to_string(), (doc.clone(), now));
        Ok(doc)
    }

    async fn fetch_keys(&self, url: &str, force: bool) -> Result<Arc<JwkSet>, JwtError> {
        let now = self.clock.now();
        {
            let cache = self.keys.lock().await;
            if let Some(cached) = cache.get(url) {
                let fresh = now - cached.fetched_at < CACHE_SECONDS;
                let throttled = now - cached.fetched_at < MIN_REFRESH_SECONDS;
                if (fresh && !force) || throttled {
                    return Ok(cached.keys.clone());
                }
            }
        }
        let raw = self.http.get_json(url).await?;
        let set: JwkSet = serde_json::from_value(raw).map_err(|_| JwtError::Fetch(NetError::Json))?;
        let set = Arc::new(set);
        self.keys.lock().await.insert(
            url.to_string(),
            CachedKeys {
                keys: set.clone(),
                fetched_at: now,
            },
        );
        Ok(set)
    }

    pub async fn verify(&self, token: &str, source: &KeySource, expect: &Expectations<'_>) -> Result<Value, JwtError> {
        let header = decode_header(token).map_err(|_| JwtError::Malformed)?;
        if !ALLOWED.contains(&header.alg) {
            return Err(JwtError::Algorithm);
        }
        let now = self.clock.now();
        let url = match source {
            KeySource::Inline(set) => return check(token, header.alg, header.kid.as_deref(), set, expect, now),
            KeySource::Url(url) => url.clone(),
            KeySource::Issuer => {
                let issuer = expect.issuer.ok_or(JwtError::Discovery)?;
                let doc = self.discover(issuer).await?;
                doc["jwks_uri"].as_str().ok_or(JwtError::Discovery)?.to_string()
            }
        };
        let keys = self.fetch_keys(&url, false).await?;
        match check(token, header.alg, header.kid.as_deref(), &keys, expect, now) {
            Err(JwtError::UnknownKey) => {
                let refreshed = self.fetch_keys(&url, true).await?;
                check(token, header.alg, header.kid.as_deref(), &refreshed, expect, now)
            }
            other => other,
        }
    }
}

fn check(
    token: &str,
    alg: Algorithm,
    kid: Option<&str>,
    keys: &JwkSet,
    expect: &Expectations<'_>,
    now: i64,
) -> Result<Value, JwtError> {
    let jwk = match kid {
        Some(kid) => keys.find(kid),
        None if keys.keys.len() == 1 => keys.keys.first(),
        None => None,
    }
    .ok_or(JwtError::UnknownKey)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| JwtError::UnknownKey)?;
    let mut validation = Validation::new(alg);
    // Time claims are checked in `check_times` against the injected clock.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    // A claim the configuration names must be present, not merely consistent when present.
    let mut required = vec!["exp"];
    match expect.issuer {
        Some(issuer) => {
            validation.set_issuer(&[issuer]);
            required.push("iss");
        }
        None => validation.iss = None,
    }
    match expect.audience {
        Some(aud) => {
            validation.set_audience(&[aud]);
            required.push("aud");
        }
        None => validation.validate_aud = false,
    }
    validation.set_required_spec_claims(&required);
    let claims = decode::<Value>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| JwtError::Invalid(e.to_string()))?;
    check_issuer(&claims, expect.issuer)?;
    check_times(&claims, now)?;
    Ok(claims)
}

/// The library accepts an `iss` array that merely contains the issuer; only the exact string is.
fn check_issuer(claims: &Value, issuer: Option<&str>) -> Result<(), JwtError> {
    let Some(issuer) = issuer else {
        return Ok(());
    };
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(JwtError::Invalid("iss is not the expected issuer".into()));
    }
    Ok(())
}

fn time_claim(claims: &Value, name: &str) -> Result<Option<i64>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .or_else(|| value.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| JwtError::Invalid(format!("{name} is not a number"))),
    }
}

/// `exp` is required; `nbf` and `iat` must not be in the future.
fn check_times(claims: &Value, now: i64) -> Result<(), JwtError> {
    let exp = time_claim(claims, "exp")?.ok_or_else(|| JwtError::Invalid("missing exp".into()))?;
    if now > exp + LEEWAY_SECONDS {
        return Err(JwtError::Invalid("token has expired".into()));
    }
    if time_claim(claims, "nbf")?.is_some_and(|nbf| now + LEEWAY_SECONDS < nbf) {
        return Err(JwtError::Invalid("token is not valid yet".into()));
    }
    if time_claim(claims, "iat")?.is_some_and(|iat| now + LEEWAY_SECONDS < iat) {
        return Err(JwtError::Invalid("token was issued in the future".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::net::MockOidcHttp;
    use crate::testkit::TestIssuer;
    use anyhow::Context;
    use mockall::predicate::eq;
    use serde_json::json;

    fn verifier(http: MockOidcHttp, clock: Arc<FixedClock>) -> JwtVerifier {
        JwtVerifier::new(Arc::new(http), clock)
    }

    fn discovery_mock(http: &mut MockOidcHttp, issuer: &TestIssuer) {
        let doc = issuer.discovery();
        http.expect_get_json()
            .with(eq(format!("{}/.well-known/openid-configuration", issuer.url)))
            .returning(move |_| Ok(doc.clone()));
    }

    #[tokio::test]
    async fn verifies_via_discovery_and_caches_keys() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://issuer.test");
        let clock = Arc::new(FixedClock::new(issuer.now));
        let mut http = MockOidcHttp::new();
        discovery_mock(&mut http, &issuer);
        let jwks = issuer.jwks();
        http.expect_get_json()
            .with(eq(issuer.jwks_url()))
            .times(1)
            .returning(move |_| Ok(jwks.clone()));
        let v = verifier(http, clock);
        let expect = Expectations {
            issuer: Some(&issuer.url),
            audience: None,
        };
        for _ in 0..3 {
            let token = issuer.sign(json!({"sub": "a", "aud": "sekret"}))?;
            let claims = v.verify(&token, &KeySource::Issuer, &expect).await.context("verify")?;
            assert_eq!(claims["sub"], "a");
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_wrong_issuer_audience_expiry_and_signature() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://issuer.test");
        let other = TestIssuer::with_key("https://issuer.test", 2);
        let set = KeySource::Inline(serde_json::from_value(issuer.jwks()).context("jwks")?);
        let v = verifier(MockOidcHttp::new(), Arc::new(FixedClock::new(issuer.now)));
        let ok = Expectations {
            issuer: Some("https://issuer.test"),
            audience: Some("client"),
        };

        let good = issuer.sign(json!({"aud": "client"}))?;
        assert!(v.verify(&good, &set, &ok).await.is_ok());

        let wrong_aud = issuer.sign(json!({"aud": "someone"}))?;
        assert!(matches!(
            v.verify(&wrong_aud, &set, &ok).await,
            Err(JwtError::Invalid(_))
        ));

        let wrong_iss = Expectations {
            issuer: Some("https://evil.test"),
            ..ok.clone()
        };
        assert!(matches!(
            v.verify(&good, &set, &wrong_iss).await,
            Err(JwtError::Invalid(_))
        ));

        let expired = issuer.sign(json!({"aud": "client", "exp": issuer.now - 3600}))?;
        assert!(matches!(v.verify(&expired, &set, &ok).await, Err(JwtError::Invalid(_))));

        let not_yet = issuer.sign(json!({"aud": "client", "nbf": issuer.now + 3600}))?;
        assert!(matches!(v.verify(&not_yet, &set, &ok).await, Err(JwtError::Invalid(_))));

        let future_iat = issuer.sign(json!({"aud": "client", "iat": issuer.now + 3600, "exp": issuer.now + 7200}))?;
        assert!(matches!(
            v.verify(&future_iat, &set, &ok).await,
            Err(JwtError::Invalid(_))
        ));

        let no_exp = issuer.sign(json!({"aud": "client", "exp": null}))?;
        assert!(v.verify(&no_exp, &set, &ok).await.is_err());

        let skewed = issuer.sign(json!({"aud": "client", "exp": issuer.now - 10, "iat": issuer.now + 10}))?;
        assert!(v.verify(&skewed, &set, &ok).await.is_ok(), "within leeway");

        // Same key id but signed by a different key.
        let forged = other.sign_with_kid(json!({"aud": "client"}), "key1")?;
        assert!(matches!(v.verify(&forged, &set, &ok).await, Err(JwtError::Invalid(_))));
        Ok(())
    }

    #[tokio::test]
    async fn named_issuers_and_audiences_must_be_present_and_exact() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://issuer.test");
        let set = KeySource::Inline(serde_json::from_value(issuer.jwks()).context("jwks")?);
        let v = verifier(MockOidcHttp::new(), Arc::new(FixedClock::new(issuer.now)));
        let both = Expectations {
            issuer: Some("https://issuer.test"),
            audience: Some("client"),
        };
        let issuer_only = Expectations {
            issuer: Some("https://issuer.test"),
            audience: None,
        };
        let neither = Expectations {
            issuer: None,
            audience: None,
        };
        let refused = [
            (json!({"aud": "client", "iss": null}), "no iss"),
            (
                json!({"aud": "client", "iss": ["https://issuer.test", "https://evil.test"]}),
                "iss array",
            ),
            (
                json!({"aud": "client", "iss": ["https://issuer.test"]}),
                "single-item iss array",
            ),
            (json!({"aud": "client", "iss": 7}), "numeric iss"),
            (
                json!({"aud": "client", "iss": "https://issuer.test/"}),
                "a different string",
            ),
            (json!({"aud": null}), "no aud"),
        ];
        for (claims, why) in refused {
            let token = issuer.sign(claims)?;
            assert!(
                matches!(v.verify(&token, &set, &both).await, Err(JwtError::Invalid(_))),
                "{why}"
            );
        }
        let no_aud = issuer.sign(json!({"aud": null}))?;
        assert!(
            v.verify(&no_aud, &set, &issuer_only).await.is_ok(),
            "aud is only required when an audience is expected"
        );
        let no_iss = issuer.sign(json!({"iss": null}))?;
        assert!(
            v.verify(&no_iss, &set, &issuer_only).await.is_err(),
            "iss is required when an issuer is named"
        );
        assert!(v.verify(&no_iss, &set, &neither).await.is_ok(), "and only then");
        let good = issuer.sign(json!({"aud": ["client", "other"]}))?;
        assert!(
            v.verify(&good, &set, &both).await.is_ok(),
            "aud may list several audiences"
        );
        Ok(())
    }

    #[tokio::test]
    async fn expiry_follows_the_injected_clock() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://issuer.test");
        let set = KeySource::Inline(serde_json::from_value(issuer.jwks()).context("jwks")?);
        let clock = Arc::new(FixedClock::new(issuer.now));
        let v = verifier(MockOidcHttp::new(), clock.clone());
        let expect = Expectations {
            issuer: None,
            audience: None,
        };
        let token = issuer.sign(json!({"aud": "client"}))?;
        assert!(v.verify(&token, &set, &expect).await.is_ok());
        clock.advance(300 + LEEWAY_SECONDS + 1);
        assert!(matches!(
            v.verify(&token, &set, &expect).await,
            Err(JwtError::Invalid(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_hmac_and_none() -> anyhow::Result<()> {
        let v = verifier(MockOidcHttp::new(), Arc::new(FixedClock::new(0)));
        let expect = Expectations {
            issuer: None,
            audience: None,
        };
        let hmac = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &json!({"exp": 9_999_999_999i64}),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .context("encode")?;
        let empty = KeySource::Inline(JwkSet { keys: vec![] });
        assert_eq!(v.verify(&hmac, &empty, &expect).await, Err(JwtError::Algorithm));
        let none = "eyJhbGciOiJub25lIn0.eyJleHAiOjk5OTk5OTk5OTl9.";
        assert!(v.verify(none, &empty, &expect).await.is_err());
        assert_eq!(v.verify("garbage", &empty, &expect).await, Err(JwtError::Malformed));
        Ok(())
    }

    #[tokio::test]
    async fn refetches_keys_after_rotation() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://issuer.test");
        let rotated = TestIssuer::with_key("https://issuer.test", 2);
        let clock = Arc::new(FixedClock::new(issuer.now));
        let mut http = MockOidcHttp::new();
        let mut seq = mockall::Sequence::new();
        let first = issuer.jwks();
        let second = rotated.jwks();
        http.expect_get_json()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(first.clone()));
        http.expect_get_json()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(second.clone()));
        let v = verifier(http, clock.clone());
        let source = KeySource::Url("https://issuer.test/jwks".into());
        let expect = Expectations {
            issuer: None,
            audience: None,
        };
        assert!(v.verify(&issuer.sign(json!({}))?, &source, &expect).await.is_ok());
        clock.advance(MIN_REFRESH_SECONDS + 1);
        assert!(v.verify(&rotated.sign(json!({}))?, &source, &expect).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn discovery_must_name_the_same_issuer() {
        let mut http = MockOidcHttp::new();
        http.expect_get_json()
            .returning(|_| Ok(json!({"issuer": "https://evil.test", "jwks_uri": "https://evil.test/k"})));
        let v = verifier(http, Arc::new(FixedClock::new(0)));
        assert_eq!(v.discover("https://issuer.test").await, Err(JwtError::Discovery));
    }
}
