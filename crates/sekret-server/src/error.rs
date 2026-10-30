use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sekret_api::ErrorBody;
use sekret_core::crypto::CryptoError;
use sekret_core::validate::ValidationError;
use sekret_store::StoreError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
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
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict => {
                ApiError::conflict("the record already exists or was changed by someone else; reload and try again")
            }
            StoreError::NotFound => ApiError::not_found("record"),
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
