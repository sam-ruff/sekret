//! Setup, sealing, unlocking and backups.

use std::net::IpAddr;
use std::path::PathBuf;

use axum::Json;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sekret_api::{
    ChangePassphrase, ErrorBody, InitRequest, InitResponse, PassphraseCheck, PassphraseStrength, SetUnlockPolicy,
    SysStatus, UnsealRequest,
};
use sekret_core::permissions::{Action, BuiltinRole, Subject};
use sekret_core::seal::{
    BackupHeader, MAX_BACKUP_LEN, SealState, encrypt_backup, passphrase_strength, strip_line_ending,
};
use sekret_store::{PrincipalKind, sqlite_file};
use serde_json::json;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use zeroize::Zeroizing;

use super::logo::LogoFile;
use super::{AuditTarget, audit};
use crate::admin::bootstrap_admin_token;
use crate::auth::authenticate;
use crate::auth::{ClientIp, Principal};
use crate::authz::{org_role_slugs, org_rules, require_any};
use crate::error::{ApiError, ApiResult};
use crate::files::{create_private_dir, read_limited};
use crate::seal::{self, ops};
use crate::state::AppState;

const INIT_TOKEN_TTL: i64 = 3600;
/// Every system request body is small; backups have none.
const SYS_BODY_LIMIT: usize = 16 * 1024;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(status))
        .routes(routes!(init))
        .routes(routes!(unseal))
        .routes(routes!(seal_now))
        .routes(routes!(change_passphrase))
        .routes(routes!(set_unlock_policy))
        .routes(routes!(forget_unlock))
        .routes(routes!(check_passphrase))
        .routes(routes!(backup))
        .layer(DefaultBodyLimit::max(SYS_BODY_LIMIT))
}

/// Every passphrase source drops one trailing line ending the same way.
fn normalised(passphrase: Zeroizing<String>) -> Zeroizing<String> {
    let trimmed = strip_line_ending(&passphrase);
    if trimmed.len() == passphrase.len() {
        return passphrase;
    }
    Zeroizing::new(trimmed.to_string())
}

#[utoipa::path(post, path = "/api/v1/sys/passphrase-strength", tag = "system", request_body = PassphraseCheck,
    description = "Open while uninitialised; afterwards only for organisation admins.",
    responses((status = 200, body = PassphraseStrength), (status = 403, body = ErrorBody),
        (status = 429, body = ErrorBody), (status = 503, body = ErrorBody)),
    security((), ("bearer" = [])))]
async fn check_passphrase(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    method: Method,
    headers: HeaderMap,
    Json(request): Json<PassphraseCheck>,
) -> ApiResult<Json<PassphraseStrength>> {
    rate_limit(&state, ip)?;
    match state.keyring.state() {
        SealState::Uninitialised => {}
        SealState::Sealed => return Err(ApiError::sealed()),
        SealState::Unsealed => {
            let principal = authenticate(&state, &method, &headers, ip).await?;
            require_org_admin(&state, &principal).await?;
        }
    }
    let passphrase = normalised(request.passphrase);
    Ok(Json(passphrase_strength(&passphrase)))
}

/// Recorded as the actor for setup and unlock attempts, which have no signed-in caller.
fn system_principal(name: &str) -> Principal {
    Principal {
        kind: PrincipalKind::Identity,
        id: name.into(),
        name: name.into(),
        email: String::new(),
        groups: Vec::new(),
        token_id: String::new(),
        token_kind: "system".into(),
    }
}

async fn require_org_admin(state: &AppState, principal: &Principal) -> ApiResult<()> {
    let slugs = org_role_slugs(state, principal).await?;
    if slugs.iter().any(|s| s == BuiltinRole::OrgAdmin.slug()) {
        return Ok(());
    }
    Err(ApiError::forbidden())
}

fn rate_limit(state: &AppState, ip: IpAddr) -> ApiResult<()> {
    if state.sys_limiter.allow_ip(ip) {
        return Ok(());
    }
    Err(ApiError::too_many_requests())
}

fn current(state: &AppState) -> SysStatus {
    seal::status(&state.config.seal, &state.keyring)
}

async fn audit_tampered(state: &AppState, principal: &Principal, ip: IpAddr, tampered: bool) {
    if tampered {
        audit(
            state,
            principal,
            ip,
            "sys.seal_config.tampered",
            AuditTarget::default(),
            json!({}),
        )
        .await;
    }
}

#[utoipa::path(get, path = "/api/v1/sys/status", tag = "system", responses((status = 200, body = SysStatus)))]
async fn status(State(state): State<AppState>) -> Json<SysStatus> {
    Json(current(&state))
}

#[utoipa::path(post, path = "/api/v1/sys/init", tag = "system", request_body = InitRequest,
    responses((status = 200, body = InitResponse), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 409, body = ErrorBody), (status = 429, body = ErrorBody)))]
async fn init(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<InitRequest>,
) -> ApiResult<Json<InitResponse>> {
    rate_limit(&state, ip)?;
    let InitRequest {
        setup_code,
        mode,
        passphrase,
        unlock_policy,
    } = request;
    let passphrase = passphrase.map(normalised);
    let outcome = ops::init(&state, &setup_code, mode, passphrase, unlock_policy.unwrap_or_default()).await;
    if let Err(error) = &outcome
        && error.code == "invalid_setup_code"
    {
        audit(
            &state,
            &system_principal("setup"),
            ip,
            "sys.init.failed",
            AuditTarget::default(),
            json!({}),
        )
        .await;
    }
    outcome?;
    audit(
        &state,
        &system_principal("setup"),
        ip,
        "sys.init",
        AuditTarget::default(),
        json!({"mode": mode.as_str()}),
    )
    .await;
    let (admin_token, admin_token_expires_at) = bootstrap_admin_token(&state, INIT_TOKEN_TTL).await?;
    ops::after_unlock(&state, None, false).await;
    Ok(Json(InitResponse {
        status: current(&state),
        admin_token,
        admin_token_expires_at,
    }))
}

#[utoipa::path(post, path = "/api/v1/sys/unseal", tag = "system", request_body = UnsealRequest,
    responses((status = 200, body = SysStatus), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
        (status = 429, body = ErrorBody), (status = 503, body = ErrorBody)))]
async fn unseal(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<UnsealRequest>,
) -> ApiResult<Json<SysStatus>> {
    rate_limit(&state, ip)?;
    let passphrase = normalised(request.passphrase);
    let principal = system_principal("unseal");
    match ops::unseal(&state, &ip.to_string(), passphrase.clone()).await {
        Ok(ops::Unsealed::Already) => Ok(Json(current(&state))),
        Ok(ops::Unsealed::Now { tampered }) => {
            audit(&state, &principal, ip, "sys.unseal", AuditTarget::default(), json!({})).await;
            audit_tampered(&state, &principal, ip, tampered).await;
            ops::after_unlock(&state, Some(passphrase), tampered).await;
            Ok(Json(current(&state)))
        }
        Err(error) if error.code == "invalid_passphrase" => {
            let failures = state.passphrase_backoff.failures();
            audit(
                &state,
                &principal,
                ip,
                "sys.unseal.failed",
                AuditTarget::default(),
                json!({"consecutive_failures": failures}),
            )
            .await;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

#[utoipa::path(post, path = "/api/v1/sys/seal", tag = "system",
    description = "Drops the root key from memory. A remembered unlock is kept, so the next restart unlocks \
                   itself; forget the unlock as well to stop that.",
    responses((status = 200, body = SysStatus), (status = 403, body = ErrorBody), (status = 409, body = ErrorBody)),
    security(("bearer" = [])))]
async fn seal_now(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
) -> ApiResult<Json<SysStatus>> {
    require_org_admin(&state, &principal).await?;
    ops::seal(&state)?;
    audit(&state, &principal, ip, "sys.seal", AuditTarget::default(), json!({})).await;
    Ok(Json(current(&state)))
}

#[utoipa::path(post, path = "/api/v1/sys/passphrase", tag = "system", request_body = ChangePassphrase,
    description = "Replaces the root key and re-encrypts every value under it, so the old passphrase opens \
                   nothing in the live database. Backups taken earlier still open with the old passphrase.",
    responses((status = 204), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 409, body = ErrorBody), (status = 429, body = ErrorBody)),
    security(("bearer" = [])))]
async fn change_passphrase(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<ChangePassphrase>,
) -> ApiResult<StatusCode> {
    require_org_admin(&state, &principal).await?;
    rate_limit(&state, ip)?;
    let current = normalised(request.current);
    let new = normalised(request.new);
    match ops::change_passphrase(&state, current, new).await {
        Ok(tampered) => {
            audit(
                &state,
                &principal,
                ip,
                "sys.passphrase",
                AuditTarget::default(),
                json!({"root_key_rotated": true}),
            )
            .await;
            audit_tampered(&state, &principal, ip, tampered).await;
            ops::after_unlock(&state, None, tampered).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(error) => {
            if error.code == "invalid_passphrase" {
                audit_passphrase_failure(&state, &principal, ip).await;
            }
            Err(error)
        }
    }
}

async fn audit_passphrase_failure(state: &AppState, principal: &Principal, ip: IpAddr) {
    audit(
        state,
        principal,
        ip,
        "sys.passphrase.failed",
        AuditTarget::default(),
        json!({"consecutive_failures": state.passphrase_backoff.failures()}),
    )
    .await;
}

#[utoipa::path(put, path = "/api/v1/sys/unlock-policy", tag = "system", request_body = SetUnlockPolicy,
    description = "`remember` and `passphrase-file` need the current passphrase in the body; `manual` does not.",
    responses((status = 200, body = SysStatus), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 409, body = ErrorBody), (status = 429, body = ErrorBody)),
    security(("bearer" = [])))]
async fn set_unlock_policy(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<SetUnlockPolicy>,
) -> ApiResult<Json<SysStatus>> {
    require_org_admin(&state, &principal).await?;
    rate_limit(&state, ip)?;
    let policy = request.policy;
    if let Err(error) = ops::set_unlock_policy(&state, policy, request.passphrase.map(normalised)).await {
        if error.code == "invalid_passphrase" {
            audit_passphrase_failure(&state, &principal, ip).await;
        }
        return Err(error);
    }
    audit(
        &state,
        &principal,
        ip,
        "sys.unlock_policy",
        AuditTarget::default(),
        json!({"policy": policy.as_str()}),
    )
    .await;
    ops::after_unlock(&state, None, false).await;
    Ok(Json(current(&state)))
}

#[utoipa::path(post, path = "/api/v1/sys/forget-unlock", tag = "system",
    responses((status = 200, body = SysStatus), (status = 403, body = ErrorBody), (status = 409, body = ErrorBody)),
    security(("bearer" = [])))]
async fn forget_unlock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
) -> ApiResult<Json<SysStatus>> {
    require_org_admin(&state, &principal).await?;
    ops::forget_unlock(&state).await?;
    audit(
        &state,
        &principal,
        ip,
        "sys.forget_unlock",
        AuditTarget::default(),
        json!({}),
    )
    .await;
    Ok(Json(current(&state)))
}

/// `20261030T224200Z` from Unix seconds.
fn compact_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    // Howard Hinnant's days-to-civil conversion.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::INSUFFICIENT_STORAGE,
        "too_large",
        "the database is too large to back up through the API; copy the file instead",
    )
}

/// Where the snapshot is staged: the configured directory, or beside the database, never `/tmp`,
/// which a scratch container does not have.
fn staging_dir(state: &AppState) -> ApiResult<tempfile::TempDir> {
    let base = match (&state.config.backup_temp_dir, sqlite_file(&state.config.database_url)) {
        (Some(dir), _) => dir.clone(),
        (None, Some(db)) => db
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf),
        // Only an in-memory database, which exists in tests.
        (None, None) => std::env::temp_dir(),
    };
    create_private_dir(&base).map_err(|e| ApiError::internal("backup directory", e))?;
    tempfile::Builder::new()
        .prefix(".sekret-backup-")
        .tempdir_in(&base)
        .map_err(|e| ApiError::internal("backup directory", e))
}

/// The database file and its write-ahead log, which a snapshot can grow to.
fn database_size(state: &AppState) -> u64 {
    let Some(db) = sqlite_file(&state.config.database_url) else {
        return 0;
    };
    let mut wal = db.as_os_str().to_os_string();
    wal.push("-wal");
    [db, PathBuf::from(wal)]
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

#[utoipa::path(post, path = "/api/v1/sys/backup", tag = "system",
    description = "POST, so a browser session needs the CSRF header like any other change.",
    responses((status = 200, description = "An encrypted `.skb` backup", body = LogoFile,
        content_type = "application/octet-stream"),
        (status = 403, body = ErrorBody), (status = 429, body = ErrorBody, description = "Another backup is running"),
        (status = 501, body = ErrorBody, description = "Postgres; use pg_dump"),
        (status = 507, body = ErrorBody, description = "Too large to back up through the API")),
    security(("bearer" = [])))]
async fn backup(State(state): State<AppState>, ClientIp(ip): ClientIp, principal: Principal) -> ApiResult<Response> {
    require_any(&org_rules(&state, &principal).await?, Subject::Backups, Action::Read)?;
    let root = state.keyring.root()?;
    if state.config.database_url.starts_with("postgres") {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "backups through the API need SQLite; use pg_dump for Postgres, whose secret values are already encrypted",
        ));
    }
    let Ok(_running) = state.backup_lock.try_lock() else {
        return Err(ApiError::backup_in_progress());
    };
    if usize::try_from(database_size(&state)).map_or(true, |size| size > MAX_BACKUP_LEN) {
        return Err(too_large());
    }
    let config = state
        .store
        .get_seal_config()
        .await?
        .ok_or_else(ApiError::uninitialised)?;
    // The copy never carries the remembered wrap, and is signed again without it.
    let copy_config = seal::signed(
        &root,
        sekret_store::SealConfig {
            remembered: None,
            ..config.clone()
        },
    )?;
    let dir = staging_dir(&state)?;
    let path = dir.path().join("snapshot.db");
    state
        .store
        .snapshot_to(&path.display().to_string(), copy_config)
        .await?;
    let now = state.clock.now();
    let header = BackupHeader::new(config.mode, config.wrapped.as_ref(), &root, now, sekret_core::VERSION);
    let file = tokio::task::spawn_blocking(move || {
        let snapshot = read_limited(&path, MAX_BACKUP_LEN as u64);
        drop(dir);
        let snapshot = snapshot.map_err(|_| too_large())?;
        encrypt_backup(&root, &header, &snapshot).map_err(ApiError::from)
    })
    .await
    .map_err(|e| ApiError::internal("encrypting the backup", e))??;
    audit(
        &state,
        &principal,
        ip,
        "sys.backup",
        AuditTarget::default(),
        json!({"bytes": file.len()}),
    )
    .await;
    let mut response = file.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let disposition = format!("attachment; filename=\"sekret-backup-{}.skb\"", compact_utc(now));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(|e| ApiError::internal("backup filename", e))?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{compact_utc, normalised};
    use zeroize::Zeroizing;

    #[test]
    fn backup_timestamps_are_compact_utc() {
        assert_eq!(compact_utc(0), "19700101T000000Z");
        assert_eq!(compact_utc(1_793_400_000), "20261030T224000Z");
        assert_eq!(compact_utc(951_825_600), "20000229T120000Z");
    }

    #[test]
    fn json_passphrases_lose_one_line_ending() {
        let n = |s: &str| normalised(Zeroizing::new(s.to_string())).to_string();
        assert_eq!(n("pass\n"), "pass");
        assert_eq!(n("pass\r\n"), "pass");
        assert_eq!(n("pass\n\n"), "pass\n");
        assert_eq!(n("pass"), "pass");
    }
}
