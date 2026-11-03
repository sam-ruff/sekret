use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sekret_api::ErrorBody;
use sekret_core::crypto::CryptoError;
use sekret_core::seal::{PassphraseError, PassphraseStrength};
use sekret_core::validate::ValidationError;
use sekret_store::StoreError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub strength: Option<PassphraseStrength>,
    /// Seconds for a `Retry-After` header.
    pub retry_after: Option<u64>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            strength: None,
            retry_after: None,
        }
    }

    pub fn weak_passphrase(error: PassphraseError) -> Self {
        let strength = error.strength().clone();
        Self {
            strength: Some(strength),
            ..Self::new(StatusCode::BAD_REQUEST, "weak_passphrase", error.to_string())
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn unauthorised() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorised", "authentication required")
    }

    /// Login failures share one message so callers cannot probe which check failed.
    pub fn login_failed() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "login_failed", "login failed")
    }

    pub fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "you do not have permission to do that",
        )
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", format!("{what} not found"))
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn too_many_requests() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests, slow down",
        )
    }

    pub fn sealed() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealed",
            "the server is sealed; unlock it to continue",
        )
    }

    pub fn uninitialised() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "uninitialised",
            "the server has not been set up yet",
        )
    }

    pub fn invalid_passphrase() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_passphrase",
            "the passphrase is wrong",
        )
    }

    /// Another passphrase derivation is running; they are not queued, so memory stays bounded.
    pub fn kdf_busy() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "kdf_busy",
            "another passphrase check is running; try again in a moment",
        )
    }

    /// Too many wrong passphrases recently. The wait is only given rounded, in `Retry-After`.
    pub fn passphrase_backoff(wait: std::time::Duration) -> Self {
        Self {
            retry_after: Some(crate::ratelimit::rounded_wait(wait)),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "passphrase_backoff",
                "too many wrong passphrases; try again shortly",
            )
        }
    }

    /// Replacing the root key waited too long for in-flight changes to finish.
    pub fn rekey_busy() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "other changes are still being written; try again in a moment",
        )
    }

    /// The database's root key is not the one in memory, as after rotating it with the server running.
    pub fn root_key_changed() -> Self {
        tracing::error!(
            "the database's root key fingerprint no longer matches the key in memory; refusing writes until restarted"
        );
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "root_key_changed",
            "the database's root key was changed outside this server; restart it",
        )
    }

    pub fn passphrase_required() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "passphrase_required",
            "this change weakens how the server is unlocked; confirm it with the current passphrase",
        )
    }

    pub fn backup_in_progress() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "backup_in_progress",
            "another backup is being made; try again when it finishes",
        )
    }

    pub fn reauthentication_required(login_url: &str) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "reauthentication_required",
            format!("sign in again to approve this; continue at {login_url}"),
        )
    }

    pub fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "{context}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.code.to_string(),
            message: self.message,
            strength: self.strength,
        };
        let mut response = (self.status, Json(body)).into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from(seconds));
        }
        response
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict => {
                ApiError::conflict("the record already exists or was changed by someone else; reload and try again")
            }
            StoreError::NotFound => ApiError::not_found("record"),
            // Destroying a restricted secret's history is for admins, whom no list keeps off it.
            StoreError::HoldsRestricted => ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "only a project admin can delete this, because it holds restricted secrets",
            ),
            StoreError::Unsupported(message) => ApiError::new(StatusCode::NOT_IMPLEMENTED, "not_implemented", message),
            other => ApiError::internal("store failure", other),
        }
    }
}

impl From<ValidationError> for ApiError {
    fn from(error: ValidationError) -> Self {
        ApiError::bad_request(error.to_string())
    }
}

impl From<CryptoError> for ApiError {
    fn from(error: CryptoError) -> Self {
        ApiError::internal("crypto failure", error)
    }
}
