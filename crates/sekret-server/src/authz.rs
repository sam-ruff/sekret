use sekret_core::permissions::{Action, BuiltinRole, Decision, Resource, Rule, Subject, authorise};
use sekret_store::{PrincipalKind, Role};

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
    let custom = state.store.list_roles("").await?;
    Ok(slugs
        .iter()
        .filter_map(|s| role_rules(s, &custom, true))
        .flatten()
        .collect())
}

/// Organisation rules plus the principal's roles in this project.
pub async fn project_rules(state: &AppState, principal: &Principal, project_id: &str) -> ApiResult<Vec<Rule>> {
    let mut rules = org_rules(state, principal).await?;
    let memberships = state.store.list_memberships(project_id).await?;
    let mine: Vec<_> = memberships
        .iter()
        .filter(|m| principal_matches(m.principal_kind, &m.principal_id, principal))
        .collect();
    if mine.is_empty() {
        return Ok(rules);
    }
    let custom = state.store.list_roles(project_id).await?;
    for membership in mine {
        rules.extend(role_rules(&membership.role_slug, &custom, false).unwrap_or_default());
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
