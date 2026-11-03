use std::collections::HashMap;

use sekret_core::permissions::{
    Access, Action, BuiltinRole, Decision, Effect, LISTABLE_ACTIONS, Resource, Rule, Subject, authorise,
};
use sekret_store::{Membership, PrincipalKind, Project, Role, Secret, SecretGrant, User};

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Whether a binding or membership for (`kind`, `id`) applies to `principal`.
pub fn principal_matches(kind: PrincipalKind, id: &str, principal: &Principal) -> bool {
    match (kind, principal.kind) {
        (PrincipalKind::User, PrincipalKind::User) | (PrincipalKind::Identity, PrincipalKind::Identity) => {
            id == principal.id
        }
        (PrincipalKind::Group, PrincipalKind::User) => principal.groups.iter().any(|g| g == id),
        _ => false,
    }
}

/// Rules for a role slug: built-in roles first, then custom roles in that scope.
pub fn role_rules(slug: &str, custom: &[Role], org_scope: bool) -> Option<Vec<Rule>> {
    if let Some(builtin) = BuiltinRole::from_slug(slug).filter(|r| r.is_org_scope() == org_scope) {
        return Some(builtin.rules());
    }
    custom.iter().find(|r| r.slug == slug).map(|r| r.rules.clone())
}

/// Organisation role slugs a principal holds, including implicit ones from configuration.
pub async fn org_role_slugs(state: &AppState, principal: &Principal) -> ApiResult<Vec<String>> {
    let mut slugs: Vec<String> = state
        .store
        .list_org_bindings()
        .await?
        .into_iter()
        .filter(|b| principal_matches(b.principal_kind, &b.principal_id, principal))
        .map(|b| b.role_slug)
        .collect();
    if principal.kind == PrincipalKind::User {
        if !state.config.default_org_role.is_empty() {
            slugs.push(state.config.default_org_role.clone());
        }
        let admin_groups = state
            .config
            .oidc
            .as_ref()
            .map(|o| o.admin_groups.as_slice())
            .unwrap_or_default();
        if principal.groups.iter().any(|g| admin_groups.contains(g)) {
            slugs.push(BuiltinRole::OrgAdmin.slug().to_string());
        }
    }
    slugs.sort();
    slugs.dedup();
    Ok(slugs)
}

pub async fn org_rules(state: &AppState, principal: &Principal) -> ApiResult<Vec<Rule>> {
    let slugs = org_role_slugs(state, principal).await?;
    org_rules_for(state, &slugs).await
}

async fn org_rules_for(state: &AppState, slugs: &[String]) -> ApiResult<Vec<Rule>> {
    let custom = state.store.list_roles("").await?;
    Ok(slugs
        .iter()
        .filter_map(|s| role_rules(s, &custom, true))
        .flatten()
        .collect())
}

fn holds_org_admin(slugs: &[String]) -> bool {
    slugs.iter().any(|s| s == BuiltinRole::OrgAdmin.slug())
}

/// The rules that judge changes to organisation roles and bindings. An org admin is judged by the
/// org-admin role alone, so no deny bound to them, by anyone, can stop them repairing access.
pub async fn org_management_rules(state: &AppState, principal: &Principal) -> ApiResult<Vec<Rule>> {
    let slugs = org_role_slugs(state, principal).await?;
    if holds_org_admin(&slugs) {
        return Ok(BuiltinRole::OrgAdmin.rules());
    }
    org_rules_for(state, &slugs).await
}

pub async fn is_org_admin(state: &AppState, principal: &Principal) -> ApiResult<bool> {
    Ok(holds_org_admin(&org_role_slugs(state, principal).await?))
}

/// The rules that judge changes to a project's roles and members, given the caller's usual
/// `rules` there. An org admin is judged by the org-admin role alone, as in
/// [`org_management_rules`]; a project admin is not, so a deny an org admin binds to them holds.
pub async fn project_management_rules(
    state: &AppState,
    principal: &Principal,
    rules: Vec<Rule>,
) -> ApiResult<Vec<Rule>> {
    if is_org_admin(state, principal).await? {
        return Ok(BuiltinRole::OrgAdmin.rules());
    }
    Ok(rules)
}

/// Whether `principal` holds the project's admin role, directly or through a group.
pub fn is_project_admin(memberships: &[Membership], principal: &Principal) -> bool {
    memberships.iter().any(|m| {
        m.role_slug == BuiltinRole::ProjectAdmin.slug()
            && principal_matches(m.principal_kind, &m.principal_id, principal)
    })
}

/// Whether `principal` manages per-secret access in the project and is exempt from access lists:
/// a project admin or an organisation admin.
pub async fn manages_secret_access(state: &AppState, principal: &Principal, project_id: &str) -> ApiResult<bool> {
    if is_org_admin(state, principal).await? {
        return Ok(true);
    }
    Ok(is_project_admin(
        &state.store.list_memberships(project_id).await?,
        principal,
    ))
}

/// How per-secret access lists bear on one caller in one environment.
#[derive(Debug, Clone, Default)]
pub struct SecretAccess {
    exempt: bool,
    /// Secret id to the actions its list grants the caller, through any entry that reaches them.
    granted: HashMap<String, Vec<Action>>,
    /// Restricted secret id to the access epoch read with the lists, which a write is held to.
    epochs: HashMap<String, i64>,
}

impl SecretAccess {
    /// For callers no list binds: admins and the server's own jobs.
    pub fn exempt() -> Self {
        Self {
            exempt: true,
            ..Self::default()
        }
    }

    /// The caller's share of `grants`, which may cover other principals too.
    pub fn listed(principal: &Principal, grants: Vec<SecretGrant>) -> Self {
        let mut granted: HashMap<String, Vec<Action>> = HashMap::new();
        for grant in grants {
            if !principal_matches(grant.principal_kind, &grant.principal_id, principal) {
                continue;
            }
            let actions = granted.entry(grant.secret_id).or_default();
            for action in grant.actions {
                if LISTABLE_ACTIONS.contains(&action) && !actions.contains(&action) {
                    actions.push(action);
                }
            }
        }
        Self {
            exempt: false,
            granted,
            epochs: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn with_epochs(self, epochs: HashMap<String, i64>) -> Self {
        Self { epochs, ..self }
    }

    /// The access epoch a write to `secret` is held to: the one read with the caller's lists for
    /// a restricted secret that binds them, so a list changed after it was read stops the write.
    pub fn planned_epoch(&self, secret: &Secret) -> i64 {
        if self.exempt || !secret.restricted {
            return secret.access_epoch;
        }
        self.epochs.get(&secret.id).copied().unwrap_or(secret.access_epoch)
    }

    pub fn is_exempt(&self) -> bool {
        self.exempt
    }

    /// Whether the caller is exempt or on the list of the secret with this id, which always
    /// includes reading it.
    pub fn lists_for_read(&self, secret_id: &str) -> bool {
        self.exempt
            || self
                .granted
                .get(secret_id)
                .is_some_and(|actions| actions.contains(&Action::Read))
    }

    /// How lists bear on a check that spans every secret in the project, such as "may this
    /// caller read them all": open only when the caller is exempt or nothing there can be
    /// restricted, since the store refuses turning the setting off while any secret is.
    pub fn spanning(&self, project: &Project) -> Access<'static> {
        if self.exempt || !project.secret_access {
            return Access::Open;
        }
        Access::Unknown
    }

    /// How the secret's list bears on the caller.
    pub fn of(&self, secret: &Secret) -> Access<'_> {
        if self.exempt || !secret.restricted {
            return Access::Open;
        }
        Access::Listed(self.granted.get(&secret.id).map_or(&[], Vec::as_slice))
    }
}

/// The caller's access to secrets in `environment_id` of the project.
pub async fn secret_access(
    state: &AppState,
    principal: &Principal,
    project: &Project,
    environment_id: &str,
) -> ApiResult<SecretAccess> {
    // Nothing can be restricted with the setting off; should anything be, it stays closed.
    if !project.secret_access {
        return Ok(SecretAccess::default());
    }
    if manages_secret_access(state, principal, &project.id).await? {
        return Ok(SecretAccess::exempt());
    }
    let current = state.store.environment_access(environment_id).await?;
    Ok(SecretAccess {
        epochs: current.epochs,
        ..SecretAccess::listed(principal, current.grants)
    })
}

/// A caller's role rules and their access lists, which together decide what they may do with
/// a secret.
#[derive(Clone, Copy)]
pub struct Caller<'a> {
    pub rules: &'a [Rule],
    pub access: &'a SecretAccess,
}

pub type Key<'k> = (PrincipalKind, &'k str);

/// For each principal a binding to (`kind`, `id`) reaches, the bindings that reach them: a user
/// through their own and their groups' bindings, and for a group every user holding it, and the
/// group alone for those who have not signed in yet.
pub fn holders<'k>(users: &'k [User], kind: PrincipalKind, id: &'k str) -> Vec<Vec<Key<'k>>> {
    let reach = |user: &'k User| -> Vec<Key<'k>> {
        std::iter::once((PrincipalKind::User, user.id.as_str()))
            .chain(user.groups.iter().map(|g| (PrincipalKind::Group, g.as_str())))
            .collect()
    };
    match kind {
        PrincipalKind::User => match users.iter().find(|u| u.id == id) {
            Some(user) => vec![reach(user)],
            None => vec![vec![(kind, id)]],
        },
        PrincipalKind::Identity => vec![vec![(kind, id)]],
        PrincipalKind::Group => std::iter::once(vec![(kind, id)])
            .chain(users.iter().filter(|u| u.groups.iter().any(|g| g == id)).map(reach))
            .collect(),
    }
}

/// Bindings that make someone an admin: org-admin bindings, the configured admin groups and, for
/// a project, its admin memberships.
pub async fn admin_bindings(state: &AppState, memberships: &[Membership]) -> ApiResult<Vec<(PrincipalKind, String)>> {
    let mut admins: Vec<(PrincipalKind, String)> = state
        .store
        .list_org_bindings()
        .await?
        .into_iter()
        .filter(|b| b.role_slug == BuiltinRole::OrgAdmin.slug())
        .map(|b| (b.principal_kind, b.principal_id))
        .collect();
    if let Some(oidc) = &state.config.oidc {
        admins.extend(oidc.admin_groups.iter().map(|g| (PrincipalKind::Group, g.clone())));
    }
    admins.extend(
        memberships
            .iter()
            .filter(|m| m.role_slug == BuiltinRole::ProjectAdmin.slug())
            .map(|m| (m.principal_kind, m.principal_id.clone())),
    );
    Ok(admins)
}

/// Whether a binding to (`kind`, `id`) would reach anyone holding one of `admins`.
pub fn reaches_admin(users: &[User], admins: &[(PrincipalKind, String)], kind: PrincipalKind, id: &str) -> bool {
    holders(users, kind, id)
        .iter()
        .flatten()
        .any(|(k, i)| admins.iter().any(|(ak, ai)| ak == k && ai == i))
}

/// Whether `after` holds a deny rule that `before` lacks.
pub fn added_denies(before: &[Rule], after: &[Rule]) -> bool {
    after.iter().any(|r| r.effect == Effect::Deny && !before.contains(r))
}

pub fn has_denies(rules: &[Rule]) -> bool {
    rules.iter().any(|r| r.effect == Effect::Deny)
}

/// Binding a deny to an admin is for admins only, so nobody with delegated rights can lock
/// them out of repairing access.
pub fn deny_needs_admin() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::FORBIDDEN,
        "escalation",
        "only an admin can bind deny rules to an admin",
    )
}

/// The built-in admin roles carry more than their rules, such as exemption from per-secret
/// access lists, so a principal whose rules merely match them cannot hand them out.
pub fn admin_role_needs_admin(role: &str) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::FORBIDDEN,
        "escalation",
        format!("only an admin can grant the built-in {role} role"),
    )
}

/// Organisation rules plus the principal's roles in this project. A role reached more than once,
/// directly and through a group, is counted once.
pub async fn project_rules(state: &AppState, principal: &Principal, project_id: &str) -> ApiResult<Vec<Rule>> {
    let mut rules = org_rules(state, principal).await?;
    let memberships = state.store.list_memberships(project_id).await?;
    let mut mine: Vec<&str> = memberships
        .iter()
        .filter(|m| principal_matches(m.principal_kind, &m.principal_id, principal))
        .map(|m| m.role_slug.as_str())
        .collect();
    if mine.is_empty() {
        return Ok(rules);
    }
    mine.sort_unstable();
    mine.dedup();
    let custom = state.store.list_roles(project_id).await?;
    for slug in mine {
        rules.extend(role_rules(slug, &custom, false).unwrap_or_default());
    }
    Ok(rules)
}

/// Whether the principal can see the project at all.
pub fn can_see_project(rules: &[Rule]) -> bool {
    rules.iter().any(|r| {
        r.effect == sekret_core::permissions::Effect::Allow
            && Subject::PROJECT.contains(&r.subject)
            && !r.actions.is_empty()
    })
}

pub fn allowed(rules: &[Rule], subject: Subject, action: Action, resource: &Resource<'_>) -> bool {
    authorise(rules, subject, action, resource) == Decision::Allow
}

pub fn require(rules: &[Rule], subject: Subject, action: Action, resource: &Resource<'_>) -> ApiResult<()> {
    if allowed(rules, subject, action, resource) {
        return Ok(());
    }
    Err(ApiError::forbidden())
}

pub fn require_any(rules: &[Rule], subject: Subject, action: Action) -> ApiResult<()> {
    require(rules, subject, action, &Resource::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(groups: &[&str]) -> Principal {
        Principal {
            kind: PrincipalKind::User,
            id: "u1".into(),
            name: "U".into(),
            email: String::new(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            token_id: "t".into(),
            token_kind: "session".into(),
        }
    }

    #[test]
    fn group_bindings_match_users_only() {
        let u = user(&["devs"]);
        assert!(principal_matches(PrincipalKind::Group, "devs", &u));
        assert!(!principal_matches(PrincipalKind::Group, "ops", &u));
        assert!(principal_matches(PrincipalKind::User, "u1", &u));
        assert!(!principal_matches(PrincipalKind::Identity, "u1", &u));
        let machine = Principal {
            kind: PrincipalKind::Identity,
            groups: vec!["devs".into()],
            ..u
        };
        assert!(!principal_matches(PrincipalKind::Group, "devs", &machine));
        assert!(principal_matches(PrincipalKind::Identity, "u1", &machine));
    }

    #[test]
    fn builtin_roles_respect_scope() {
        assert!(role_rules("admin", &[], false).is_some());
        assert!(role_rules("admin", &[], true).is_none());
        assert!(role_rules("org-admin", &[], true).is_some());
        assert!(role_rules("org-admin", &[], false).is_none());
        let custom = Role {
            id: "r".into(),
            project_id: "p".into(),
            slug: "reader".into(),
            name: "Reader".into(),
            description: String::new(),
            rules: vec![Rule::allow(Subject::Secrets, &[Action::Read])],
            created_at: 0,
        };
        assert_eq!(
            role_rules("reader", std::slice::from_ref(&custom), false),
            Some(custom.rules.clone())
        );
        assert!(role_rules("missing", &[custom], false).is_none());
    }

    #[test]
    fn project_visibility() {
        assert!(!can_see_project(&BuiltinRole::OrgMember.rules()));
        assert!(can_see_project(&BuiltinRole::Viewer.rules()));
        assert!(!can_see_project(&BuiltinRole::NoAccess.rules()));
    }
}
