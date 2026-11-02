//! Searching, sorting and paging for the audit log, users and machine identities.

use std::cmp::Ordering;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sekret_api::{AuditPage, Identity, SortOrder, User};
use sekret_store::AuditQuery;
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use super::projects::api_audit;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub const DEFAULT_PAGE: i64 = 50;
pub const MAX_PAGE: i64 = 500;

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditParams {
    /// Case-insensitive text matched against action, actor, environment, path, key and address.
    pub q: Option<String>,
    /// Action prefix, such as `secret.` or `secret.read`.
    pub action: Option<String>,
    pub actor_id: Option<String>,
    /// `user` or `identity`.
    pub actor_kind: Option<String>,
    pub environment: Option<String>,
    pub key: Option<String>,
    /// Folder prefix, such as `/app`.
    pub path: Option<String>,
    /// Unix seconds, inclusive.
    pub since: Option<i64>,
    /// Unix seconds, inclusive.
    pub until: Option<i64>,
    /// `desc` (newest first, the default) or `asc`.
    pub order: Option<SortOrder>,
    /// `next_cursor` from the previous page.
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

fn encode_cursor(created_at: i64, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{created_at}:{id}"))
}

fn decode_cursor(cursor: &str) -> ApiResult<(i64, String)> {
    let invalid = || ApiError::bad_request("cursor is not valid");
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    let (created_at, id) = text.split_once(':').ok_or_else(invalid)?;
    Ok((created_at.parse().map_err(|_| invalid())?, id.to_string()))
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// `search_actors_only` keeps `q` off environments, folders and keys the reader may not see, and
/// `restricted_visible` says which entries about restricted secrets they may have, as in
/// [`AuditQuery::restricted_visible`].
pub async fn audit_page(
    state: &AppState,
    project_id: Option<String>,
    params: AuditParams,
    search_actors_only: bool,
    restricted_visible: Option<Vec<(String, String, String)>>,
) -> ApiResult<AuditPage> {
    let limit = params.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let query = AuditQuery {
        restricted_visible,
        project_id,
        search: empty_to_none(params.q),
        search_actors_only,
        action: empty_to_none(params.action),
        actor_id: empty_to_none(params.actor_id),
        actor_kind: empty_to_none(params.actor_kind),
        environment: empty_to_none(params.environment),
        key: empty_to_none(params.key),
        path: empty_to_none(params.path),
        since: params.since,
        until: params.until,
        oldest_first: params.order.unwrap_or_default() == SortOrder::Asc,
        after: params.cursor.as_deref().map(decode_cursor).transpose()?,
        // One extra row tells whether another page exists.
        limit: limit + 1,
    };
    let total = state.store.count_audit(query.clone()).await?;
    let mut entries = state.store.list_audit(query).await?;
    let more = entries.len() as i64 > limit;
    entries.truncate(limit as usize);
    let next_cursor = entries
        .last()
        .filter(|_| more)
        .map(|last| encode_cursor(last.created_at, &last.id));
    Ok(AuditPage {
        entries: entries.into_iter().map(api_audit).collect(),
        total,
        next_cursor,
    })
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserSort {
    #[default]
    Name,
    Email,
    Created,
    LastLogin,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySort {
    #[default]
    Name,
    Created,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UserParams {
    /// Case-insensitive text matched against name, email, groups and id.
    pub q: Option<String>,
    pub status: Option<Status>,
    pub sort: Option<UserSort>,
    /// `asc` is the default for names, `desc` makes sense for dates.
    pub order: Option<SortOrder>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct IdentityParams {
    /// Case-insensitive text matched against name, description and id.
    pub q: Option<String>,
    pub status: Option<Status>,
    pub sort: Option<IdentitySort>,
    pub order: Option<SortOrder>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

fn matches(needle: &str, haystack: &[&str]) -> bool {
    haystack.iter().any(|h| h.to_lowercase().contains(needle))
}

fn ordered(ordering: Ordering, order: Option<SortOrder>) -> Ordering {
    match order.unwrap_or(SortOrder::Asc) {
        SortOrder::Asc => ordering,
        SortOrder::Desc => ordering.reverse(),
    }
}

/// The requested slice, and the number of items before slicing.
fn slice<T>(items: Vec<T>, offset: Option<i64>, limit: Option<i64>) -> (Vec<T>, i64) {
    let total = items.len() as i64;
    let offset = offset.unwrap_or(0).max(0) as usize;
    let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize;
    (items.into_iter().skip(offset).take(limit).collect(), total)
}

pub fn page_users(users: Vec<User>, params: &UserParams) -> (Vec<User>, i64) {
    let needle = params.q.as_deref().unwrap_or_default().trim().to_lowercase();
    let mut users: Vec<User> = users
        .into_iter()
        .filter(|u| params.status.is_none_or(|s| (s == Status::Disabled) == u.disabled))
        .filter(|u| {
            let groups = u.groups.join(" ");
            needle.is_empty() || matches(&needle, &[&u.name, &u.email, &groups, &u.id])
        })
        .collect();
    let sort = params.sort.unwrap_or_default();
    users.sort_by(|a, b| {
        let primary = match sort {
            UserSort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            UserSort::Email => a.email.to_lowercase().cmp(&b.email.to_lowercase()),
            UserSort::Created => a.created_at.cmp(&b.created_at),
            UserSort::LastLogin => a.last_login_at.cmp(&b.last_login_at),
        };
        ordered(primary, params.order).then_with(|| a.id.cmp(&b.id))
    });
    slice(users, params.offset, params.limit)
}

pub fn page_identities(identities: Vec<Identity>, params: &IdentityParams) -> (Vec<Identity>, i64) {
    let needle = params.q.as_deref().unwrap_or_default().trim().to_lowercase();
    let mut identities: Vec<Identity> = identities
        .into_iter()
        .filter(|i| params.status.is_none_or(|s| (s == Status::Disabled) == i.disabled))
        .filter(|i| needle.is_empty() || matches(&needle, &[&i.name, &i.description, &i.id]))
        .collect();
    let sort = params.sort.unwrap_or_default();
    identities.sort_by(|a, b| {
        let primary = match sort {
            IdentitySort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            IdentitySort::Created => a.created_at.cmp(&b.created_at),
        };
        ordered(primary, params.order).then_with(|| a.id.cmp(&b.id))
    });
    slice(identities, params.offset, params.limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str, name: &str, email: &str, disabled: bool, last_login_at: i64) -> User {
        User {
            id: id.into(),
            email: email.into(),
            name: name.into(),
            groups: vec!["sekret-admin".into()],
            disabled,
            created_at: 0,
            last_login_at,
        }
    }

    fn users() -> Vec<User> {
        vec![
            user("u1", "carol", "carol@example.com", false, 30),
            user("u2", "Alice", "alice@example.com", false, 10),
            user("u3", "bob", "bob@example.com", true, 20),
        ]
    }

    fn names(page: (Vec<User>, i64)) -> (Vec<String>, i64) {
        (page.0.into_iter().map(|u| u.name).collect(), page.1)
    }

    #[test]
    fn users_sort_case_insensitively_and_page() {
        let params = UserParams {
            limit: Some(2),
            ..Default::default()
        };
        assert_eq!(
            names(page_users(users(), &params)),
            (vec!["Alice".into(), "bob".into()], 3)
        );
        let second = UserParams {
            offset: Some(2),
            limit: Some(2),
            ..Default::default()
        };
        assert_eq!(names(page_users(users(), &second)), (vec!["carol".into()], 3));
    }

    #[test]
    fn users_search_filter_and_order() {
        let search = UserParams {
            q: Some("ALICE@".into()),
            ..Default::default()
        };
        assert_eq!(names(page_users(users(), &search)), (vec!["Alice".into()], 1));
        let groups = UserParams {
            q: Some("sekret-admin".into()),
            status: Some(Status::Disabled),
            ..Default::default()
        };
        assert_eq!(names(page_users(users(), &groups)), (vec!["bob".into()], 1));
        let recent = UserParams {
            sort: Some(UserSort::LastLogin),
            order: Some(SortOrder::Desc),
            ..Default::default()
        };
        assert_eq!(names(page_users(users(), &recent)).0, ["carol", "bob", "Alice"]);
    }

    #[test]
    fn page_bounds_are_clamped() {
        let silly = UserParams {
            offset: Some(-5),
            limit: Some(0),
            ..Default::default()
        };
        assert_eq!(page_users(users(), &silly).0.len(), 1);
    }

    #[test]
    fn identities_filter_and_sort() {
        let identity = |id: &str, name: &str, created_at: i64, disabled: bool| Identity {
            id: id.into(),
            name: name.into(),
            description: format!("{name} runner"),
            token_ttl: 1,
            token_max_ttl: 1,
            trusted_cidrs: vec![],
            disabled,
            created_at,
            auth_methods: vec![],
        };
        let all = vec![
            identity("i1", "ci", 5, false),
            identity("i2", "ansible", 9, true),
            identity("i3", "k3s", 1, false),
        ];
        let params = IdentityParams {
            status: Some(Status::Active),
            sort: Some(IdentitySort::Created),
            order: Some(SortOrder::Desc),
            ..Default::default()
        };
        let (page, total) = page_identities(all.clone(), &params);
        assert_eq!(page.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["ci", "k3s"]);
        assert_eq!(total, 2);
        let search = IdentityParams {
            q: Some("RUNNER".into()),
            ..Default::default()
        };
        assert_eq!(page_identities(all, &search).1, 3);
    }

    #[test]
    fn cursors_round_trip_and_reject_junk() -> anyhow::Result<()> {
        let cursor = encode_cursor(1700000000, "0192-abc");
        let decoded = decode_cursor(&cursor).map_err(|e| anyhow::anyhow!("cursor: {e:?}"))?;
        assert_eq!(decoded, (1700000000, "0192-abc".into()));
        assert!(decode_cursor("not a cursor!").is_err());
        assert!(decode_cursor(&URL_SAFE_NO_PAD.encode("x:y")).is_err());
        Ok(())
    }
}
