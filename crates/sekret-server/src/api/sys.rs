//! Setup, sealing, unlocking and backups.

use std::net::IpAddr;
use std::path::PathBuf;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use sekret_api::{
    ChangePassphrase, ErrorBody, InitRequest, InitResponse, PassphraseCheck, PassphraseStrength, SetUnlockPolicy,
    SysStatus, UnsealRequest,
};
use sekret_core::permissions::{Action, BuiltinRole, Subject};
use sekret_core::seal::{BackupHeader, MAX_BACKUP_LEN, SealState, encrypt_backup, passphrase_strength, trim_input};
use sekret_store::sqlite_file;
use serde_json::json;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use zeroize::Zeroizing;

use super::logo::LogoFile;
use super::{AuditTarget, audit, audit_refusal};
use crate::auth::authenticate;
use crate::auth::{ClientIp, Principal};
use crate::authz::{org_role_slugs, org_rules, require_any};
use crate::error::{ApiError, ApiResult};
use crate::files::{create_private_dir, read_limited};
use crate::seal;
use crate::seal::ops::{self, Source, detached};
use crate::state::AppState;

/// Every system request body is small; backups have none.
const SYS_BODY_LIMIT: usize = 16 * 1024;
/// Staging directories for backups start with this, so ones left by a crash can be found.
pub const BACKUP_STAGING_PREFIX: &str = ".sekret-backup-";

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(status))
        .routes(routes!(status_detail))
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

/// Marks requests that came in over the host's Unix socket.
#[derive(Debug, Clone, Copy)]
pub struct HostSocket;

/// The status and unseal routes alone, for the host socket. Nothing else is reachable through it.
pub fn host_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/api/v1/sys/status", axum::routing::get(status))
        .route("/api/v1/sys/unseal", axum::routing::post(unseal))
        .layer(Extension(HostSocket))
        .layer(DefaultBodyLimit::max(SYS_BODY_LIMIT))
        .with_state(state)
}

/// Every passphrase source drops a leading byte order mark and one trailing line ending the same way.
fn normalised(passphrase: Zeroizing<String>) -> Zeroizing<String> {
    let trimmed = trim_input(&passphrase);
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
            require_org_admin(&state, &principal, ip).await?;
        }
    }
    let passphrase = normalised(request.passphrase);
    Ok(Json(passphrase_strength(&passphrase)))
}

/// Organisation admins only; a refusal is audited.
async fn require_org_admin(state: &AppState, principal: &Principal, ip: IpAddr) -> ApiResult<()> {
    let slugs = org_role_slugs(state, principal).await?;
    if slugs.iter().any(|s| s == BuiltinRole::OrgAdmin.slug()) {
        return Ok(());
    }
    audit_forbidden(state, principal, ip).await;
    Err(ApiError::forbidden())
}

async fn audit_forbidden(state: &AppState, principal: &Principal, ip: IpAddr) {
    audit_refusal(state, principal, &principal.id, ip, "sys.forbidden", json!({})).await;
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

fn public(state: &AppState) -> SysStatus {
    seal::public_status(&state.config.seal, &state.keyring)
}

#[utoipa::path(get, path = "/api/v1/sys/status", tag = "system",
    description = "Unauthenticated. After setup only `state`, `web_setup` and `version` are filled in; \
                   organisation admins get the rest from `/api/v1/sys/status/detail`.",
    responses((status = 200, body = SysStatus)))]
async fn status(State(state): State<AppState>) -> Json<SysStatus> {
    Json(public(&state))
}

#[utoipa::path(get, path = "/api/v1/sys/status/detail", tag = "system",
    description = "Every status field, including how the server was unlocked and whether an unlock is remembered.",
    responses((status = 200, body = SysStatus), (status = 401, body = ErrorBody), (status = 403, body = ErrorBody)),
    security(("bearer" = [])))]
async fn status_detail(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
) -> ApiResult<Json<SysStatus>> {
    require_org_admin(&state, &principal, ip).await?;
    Ok(Json(current(&state)))
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
    let request = ops::InitRequest {
        setup_code: request.setup_code,
        mode: request.mode,
        passphrase: request.passphrase.map(normalised),
        unlock_policy: request.unlock_policy.unwrap_or_default(),
    };
    let task = state.clone();
    let (admin_token, admin_token_expires_at) = detached(async move { ops::init(&task, ip, request).await }).await?;
    Ok(Json(InitResponse {
        status: current(&state),
        admin_token,
        admin_token_expires_at,
    }))
}

#[utoipa::path(post, path = "/api/v1/sys/unseal", tag = "system", request_body = UnsealRequest,
    description = "Answers with the public status. Also served on the host socket, where the network's \
                   rate limits do not apply.",
    responses((status = 200, body = SysStatus), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
        (status = 429, body = ErrorBody), (status = 503, body = ErrorBody)))]
async fn unseal(
    State(state): State<AppState>,
    host: Option<Extension<HostSocket>>,
    ClientIp(ip): ClientIp,
    Json(request): Json<UnsealRequest>,
) -> ApiResult<Json<SysStatus>> {
    let source = match host {
        Some(_) => Source::HostSocket,
        None => {
            rate_limit(&state, ip)?;
            Source::Network(ip)
        }
    };
    let passphrase = normalised(request.passphrase);
    let task = state.clone();
    detached(async move { ops::unseal(&task, source, passphrase).await }).await?;
    Ok(Json(public(&state)))
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
    require_org_admin(&state, &principal, ip).await?;
    ops::seal(&state).await?;
    audit(&state, &principal, ip, "sys.seal", AuditTarget::default(), json!({})).await;
    Ok(Json(current(&state)))
}

#[utoipa::path(post, path = "/api/v1/sys/passphrase", tag = "system", request_body = ChangePassphrase,
    description = "Replaces the root key and re-encrypts every value under it, so the old passphrase opens \
                   nothing in the live database. Backups taken earlier still open with the old passphrase. \
                   Stored data that no longer decrypts is refused with `unreadable_data`, naming it by id, \
                   unless `skip_unreadable` is set.",
    responses((status = 204), (status = 400, body = ErrorBody), (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 409, body = ErrorBody, description = "`unreadable_data`, `seal_config_tampered` or not in \
            passphrase mode"),
        (status = 429, body = ErrorBody),
        (status = 503, body = ErrorBody)),
    security(("bearer" = [])))]
async fn change_passphrase(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<ChangePassphrase>,
) -> ApiResult<StatusCode> {
    require_org_admin(&state, &principal, ip).await?;
    rate_limit(&state, ip)?;
    let current = normalised(request.current);
    let new = normalised(request.new);
    let task = state.clone();
    let skip = request.skip_unreadable;
    detached(async move { ops::change_passphrase(&task, Source::Network(ip), &principal, current, new, skip).await })
        .await?;
    Ok(StatusCode::NO_CONTENT)
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
    require_org_admin(&state, &principal, ip).await?;
    rate_limit(&state, ip)?;
    let policy = request.policy;
    let passphrase = request.passphrase.map(normalised);
    let task = state.clone();
    detached(async move { ops::set_unlock_policy(&task, Source::Network(ip), &principal, policy, passphrase).await })
        .await?;
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
    require_org_admin(&state, &principal, ip).await?;
    let task = state.clone();
    detached(async move { ops::forget_unlock(&task, &principal, ip).await }).await?;
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

/// Where snapshots are staged: the configured directory, or beside the database, never `/tmp`,
/// which a scratch container does not have.
pub fn staging_base(backup_temp_dir: Option<&std::path::Path>, database_url: &str) -> PathBuf {
    match (backup_temp_dir, sqlite_file(database_url)) {
        (Some(dir), _) => dir.to_path_buf(),
        (None, Some(db)) => db
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf),
        // Only an in-memory database, which exists in tests.
        (None, None) => std::env::temp_dir(),
    }
}

/// Removes staging directories a crash left behind, which may hold a complete copy of the database.
pub fn clean_stale_staging(base: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let stale = name.to_string_lossy().starts_with(BACKUP_STAGING_PREFIX);
        let directory = entry.file_type().is_ok_and(|t| t.is_dir());
        if !stale || !directory {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => tracing::info!(path = %entry.path().display(), "removed a backup staging directory left behind"),
            Err(error) => {
                tracing::warn!(%error, path = %entry.path().display(), "could not remove a stale backup staging directory")
            }
        }
    }
}

fn staging_dir(state: &AppState) -> ApiResult<tempfile::TempDir> {
    let base = staging_base(state.config.backup_temp_dir.as_deref(), &state.config.database_url);
    create_private_dir(&base).map_err(|e| ApiError::internal("backup directory", e))?;
    tempfile::Builder::new()
        .prefix(BACKUP_STAGING_PREFIX)
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
        (status = 403, body = ErrorBody),
        (status = 409, body = ErrorBody, description = "`seal_config_tampered`: the seal configuration failed its \
            integrity check, so it is not backed up"),
        (status = 429, body = ErrorBody, description = "Another backup is running"),
        (status = 501, body = ErrorBody, description = "Postgres; use pg_dump"),
        (status = 507, body = ErrorBody, description = "Too large to back up through the API")),
    security(("bearer" = [])))]
async fn backup(State(state): State<AppState>, ClientIp(ip): ClientIp, principal: Principal) -> ApiResult<Response> {
    if let Err(error) = require_any(&org_rules(&state, &principal).await?, Subject::Backups, Action::Read) {
        audit_forbidden(&state, &principal, ip).await;
        return Err(error);
    }
    if state.config.database_url.starts_with("postgres") {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "backups through the API need SQLite; use pg_dump for Postgres, whose secret values are already encrypted",
        ));
    }
    let Ok(running) = state.backup_lock.clone().try_lock_owned() else {
        return Err(ApiError::backup_in_progress());
    };
    // Runs to the end holding the lock even if the client goes away, so cancelling one backup
    // cannot start a second beside it.
    let task = state.clone();
    let (file, now) = detached(async move {
        let _running = running;
        take_backup(&task, &principal, ip).await
    })
    .await?;
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

/// The encrypted backup file, and when it was taken.
async fn take_backup(state: &AppState, principal: &Principal, ip: IpAddr) -> ApiResult<(Vec<u8>, i64)> {
    if usize::try_from(database_size(state)).map_or(true, |size| size > MAX_BACKUP_LEN) {
        return Err(too_large());
    }
    let seal::ops::BackupSeal { root, copy: config } = seal::ops::backup_seal(state, principal, ip).await?;
    // Held while the snapshot is taken, so a rotation cannot slip in and leave a backup whose
    // header and contents belong to different keys.
    let (dir, path) = {
        let _writing = state.keyring.writing().await;
        if state.keyring.root()?.fingerprint() != root.fingerprint() {
            return Err(ApiError::conflict(
                "the root key changed while the backup was being prepared; try again",
            ));
        }
        let dir = staging_dir(state)?;
        let path = dir.path().join("snapshot.db");
        state
            .store
            .snapshot_to(&path.display().to_string(), config.clone())
            .await?;
        (dir, path)
    };
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
        state,
        principal,
        ip,
        "sys.backup",
        AuditTarget::default(),
        json!({"bytes": file.len()}),
    )
    .await;
    Ok((file, now))
}

#[cfg(test)]
mod tests {
    use super::{BACKUP_STAGING_PREFIX, clean_stale_staging, compact_utc, normalised};
    use anyhow::Context;
    use zeroize::Zeroizing;

    #[test]
    fn backup_timestamps_are_compact_utc() {
        assert_eq!(compact_utc(0), "19700101T000000Z");
        assert_eq!(compact_utc(1_793_400_000), "20261030T224000Z");
        assert_eq!(compact_utc(951_825_600), "20000229T120000Z");
    }

    #[test]
    fn json_passphrases_lose_one_line_ending_and_a_byte_order_mark() {
        let n = |s: &str| normalised(Zeroizing::new(s.to_string())).to_string();
        assert_eq!(n("pass\n"), "pass");
        assert_eq!(n("pass\r\n"), "pass");
        assert_eq!(n("pass\n\n"), "pass\n");
        assert_eq!(n("pass"), "pass");
        assert_eq!(n("\u{feff}pass\n"), "pass");
    }

    #[test]
    fn staging_left_by_a_crash_is_removed_and_nothing_else() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let stale = dir.path().join(format!("{BACKUP_STAGING_PREFIX}abc123"));
        std::fs::create_dir(&stale).context("stale")?;
        std::fs::write(stale.join("snapshot.db"), b"copy").context("snapshot")?;
        let database = dir.path().join("sekret.db");
        std::fs::write(&database, b"db").context("db")?;
        let lookalike = dir.path().join(format!("{BACKUP_STAGING_PREFIX}file"));
        std::fs::write(&lookalike, b"not a directory").context("file")?;
        clean_stale_staging(dir.path());
        assert!(!stale.exists());
        assert!(database.exists() && lookalike.exists());
        Ok(())
    }
}
