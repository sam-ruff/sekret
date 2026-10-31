use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::glob::glob_match;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// See that something exists and read its metadata (for secrets: key names, not values).
    Read,
    /// Read plaintext secret values.
    ReadValue,
    Create,
    Edit,
    Delete,
}

impl Action {
    pub const ALL: [Action; 5] = [
        Action::Read,
        Action::ReadValue,
        Action::Create,
        Action::Edit,
        Action::Delete,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Subject {
    Secrets,
    SecretVersions,
    Snapshots,
    Folders,
    Environments,
    Members,
    Roles,
    AuditLog,
    Settings,
    // Organisation scope
    Projects,
    Identities,
    OrgMembers,
    OrgRoles,
    /// The organisation-wide audit log. Separate from `AuditLog` so an org grant cannot open
    /// every project's log.
    OrgAuditLog,
    /// Encrypted database backups; `read` downloads one.
    Backups,
}

impl Subject {
    pub const PROJECT: [Subject; 9] = [
        Subject::Secrets,
        Subject::SecretVersions,
        Subject::Snapshots,
        Subject::Folders,
        Subject::Environments,
        Subject::Members,
        Subject::Roles,
        Subject::AuditLog,
        Subject::Settings,
    ];
    pub const ORG: [Subject; 6] = [
        Subject::Projects,
        Subject::Identities,
        Subject::OrgMembers,
        Subject::OrgRoles,
        Subject::OrgAuditLog,
        Subject::Backups,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    Allow,
    Deny,
}

/// Restrictions on where a rule applies. Empty lists mean "anywhere".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct Conditions {
    pub environments: Vec<String>,
    /// Globs over folder paths, e.g. `/app/**`.
    pub paths: Vec<String>,
    /// Globs over secret keys, e.g. `DB_*`.
    pub keys: Vec<String>,
    /// Matches when the secret carries any of these tags.
    pub tags: Vec<String>,
}

impl Conditions {
    pub fn is_empty(&self) -> bool {
        self.environments.is_empty() && self.paths.is_empty() && self.keys.is_empty() && self.tags.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Rule {
    pub effect: Effect,
    pub subject: Subject,
    pub actions: Vec<Action>,
    #[serde(default, skip_serializing_if = "Conditions::is_empty")]
    pub conditions: Conditions,
}

impl Rule {
    pub fn allow(subject: Subject, actions: &[Action]) -> Self {
        Self {
            effect: Effect::Allow,
            subject,
            actions: actions.to_vec(),
            conditions: Conditions::default(),
        }
    }

    pub fn deny(subject: Subject, actions: &[Action], conditions: Conditions) -> Self {
        Self {
            effect: Effect::Deny,
            subject,
            actions: actions.to_vec(),
            conditions,
        }
    }
}

/// What is being acted upon. Unset fields are unknown, which never satisfies a condition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resource<'a> {
    pub environment: Option<&'a str>,
    pub path: Option<&'a str>,
    pub key: Option<&'a str>,
    pub tags: &'a [String],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// For an allow rule every non-empty condition must positively match.
fn allow_applies(conditions: &Conditions, resource: &Resource<'_>) -> bool {
    let env_ok = conditions.environments.is_empty()
        || resource
            .environment
            .is_some_and(|env| conditions.environments.iter().any(|e| e == env));
    let path_ok = conditions.paths.is_empty()
        || resource
            .path
            .is_some_and(|path| conditions.paths.iter().any(|g| glob_match(g, path, Some('/'))));
    let key_ok = conditions.keys.is_empty()
        || resource
            .key
            .is_some_and(|key| conditions.keys.iter().any(|g| glob_match(g, key, None)));
    let tags_ok = conditions.tags.is_empty() || resource.tags.iter().any(|t| conditions.tags.contains(t));
    env_ok && path_ok && key_ok && tags_ok
}

/// A deny rule applies unless the resource is known to fall outside it, so a deny scoped to
/// `prod` still blocks a request whose environment is unknown.
fn deny_applies(conditions: &Conditions, resource: &Resource<'_>) -> bool {
    let env_hit = conditions.environments.is_empty()
        || resource
            .environment
            .is_none_or(|env| conditions.environments.iter().any(|e| e == env));
    let path_hit = conditions.paths.is_empty()
        || resource
            .path
            .is_none_or(|path| conditions.paths.iter().any(|g| glob_match(g, path, Some('/'))));
    let key_hit = conditions.keys.is_empty()
        || resource
            .key
            .is_none_or(|key| conditions.keys.iter().any(|g| glob_match(g, key, None)));
    let tags_hit = conditions.tags.is_empty() || resource.tags.iter().any(|t| conditions.tags.contains(t));
    env_hit && path_hit && key_hit && tags_hit
}

pub fn authorise(rules: &[Rule], subject: Subject, action: Action, resource: &Resource<'_>) -> Decision {
    let relevant = || {
        rules
            .iter()
            .filter(|r| r.subject == subject && r.actions.contains(&action))
    };
    if relevant().any(|r| r.effect == Effect::Deny && deny_applies(&r.conditions, resource)) {
        return Decision::Deny;
    }
    if relevant().any(|r| r.effect == Effect::Allow && allow_applies(&r.conditions, resource)) {
        return Decision::Allow;
    }
    Decision::Deny
}

/// Whether any rule could allow `action` on `subject` somewhere, used to decide if a
/// listing should be attempted before filtering each item.
pub fn may_somewhere(rules: &[Rule], subject: Subject, action: Action) -> bool {
    rules.iter().any(|r| {
        r.effect == Effect::Allow
            && r.subject == subject
            && r.actions.contains(&action)
            && !rules.iter().any(|d| {
                d.effect == Effect::Deny
                    && d.subject == subject
                    && d.actions.contains(&action)
                    && d.conditions.is_empty()
            })
    })
}

/// Whether `holder` already has everything `granted` would allow, so handing `granted` to
/// someone cannot escalate beyond the holder's own access. Deliberately conservative: a
/// conditional grant is only covered by an unconditional or identically scoped rule.
pub fn covers(holder: &[Rule], granted: &[Rule]) -> bool {
    granted.iter().filter(|g| g.effect == Effect::Allow).all(|g| {
        g.actions.iter().all(|action| {
            let allowed = holder.iter().any(|h| {
                h.effect == Effect::Allow
                    && h.subject == g.subject
                    && h.actions.contains(action)
                    && (h.conditions.is_empty() || h.conditions == g.conditions)
            });
            let denied = holder
                .iter()
                .any(|h| h.effect == Effect::Deny && h.subject == g.subject && h.actions.contains(action));
            allowed && !denied
        })
    })
}

/// Whether `holder` may take `removed` away from someone. Dropping an allow needs the same
/// cover as granting it; dropping a deny lifts a restriction, so it counts as granting what
/// the deny withheld. A principal can therefore never lift a deny that also binds them.
pub fn may_remove(holder: &[Rule], removed: &[Rule]) -> bool {
    let lifted: Vec<Rule> = removed
        .iter()
        .map(|r| Rule {
            effect: Effect::Allow,
            ..r.clone()
        })
        .collect();
    covers(holder, &lifted)
}

/// Rules present in `before` but missing from `after`.
pub fn dropped_rules(before: &[Rule], after: &[Rule]) -> Vec<Rule> {
    before.iter().filter(|r| !after.contains(r)).cloned().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuiltinRole {
    OrgAdmin,
    OrgMember,
    BackupReader,
    ProjectAdmin,
    Developer,
    Viewer,
    NoAccess,
}

impl BuiltinRole {
    pub const ALL: [BuiltinRole; 7] = [
        BuiltinRole::OrgAdmin,
        BuiltinRole::OrgMember,
        BuiltinRole::BackupReader,
        BuiltinRole::ProjectAdmin,
        BuiltinRole::Developer,
        BuiltinRole::Viewer,
        BuiltinRole::NoAccess,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            BuiltinRole::OrgAdmin => "org-admin",
            BuiltinRole::OrgMember => "org-member",
            BuiltinRole::BackupReader => "backup-reader",
            BuiltinRole::ProjectAdmin => "admin",
            BuiltinRole::Developer => "developer",
            BuiltinRole::Viewer => "viewer",
            BuiltinRole::NoAccess => "no-access",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.slug() == slug)
    }

    pub fn is_org_scope(self) -> bool {
        matches!(
            self,
            BuiltinRole::OrgAdmin | BuiltinRole::OrgMember | BuiltinRole::BackupReader
        )
    }

    pub fn rules(self) -> Vec<Rule> {
        use Action::*;
        use Subject::*;
        match self {
            BuiltinRole::OrgAdmin => Subject::ORG
                .into_iter()
                .chain(Subject::PROJECT)
                .map(|s| Rule::allow(s, &Action::ALL))
                .collect(),
            BuiltinRole::OrgMember => vec![
                Rule::allow(Projects, &[Create]),
                Rule::allow(Identities, &[Read]),
                Rule::allow(OrgMembers, &[Read]),
                Rule::allow(OrgRoles, &[Read]),
            ],
            BuiltinRole::BackupReader => vec![Rule::allow(Backups, &[Read])],
            BuiltinRole::ProjectAdmin => Subject::PROJECT
                .into_iter()
                .map(|s| Rule::allow(s, &Action::ALL))
                .collect(),
            BuiltinRole::Developer => vec![
                Rule::allow(Secrets, &Action::ALL),
                Rule::allow(SecretVersions, &[Read, ReadValue]),
                Rule::allow(Snapshots, &[Read, Edit]),
                Rule::allow(Folders, &[Read, Create, Edit, Delete]),
                Rule::allow(Environments, &[Read]),
                Rule::allow(Members, &[Read]),
                Rule::allow(Roles, &[Read]),
                Rule::allow(AuditLog, &[Read]),
            ],
            BuiltinRole::Viewer => vec![
                Rule::allow(Secrets, &[Read, ReadValue]),
                Rule::allow(SecretVersions, &[Read]),
                Rule::allow(Snapshots, &[Read]),
                Rule::allow(Folders, &[Read]),
                Rule::allow(Environments, &[Read]),
                Rule::allow(Members, &[Read]),
                Rule::allow(Roles, &[Read]),
            ],
            BuiltinRole::NoAccess => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use proptest::prelude::*;

    fn secret<'a>(env: &'a str, path: &'a str, key: &'a str) -> Resource<'a> {
        Resource {
            environment: Some(env),
            path: Some(path),
            key: Some(key),
            tags: &[],
        }
    }

    fn scoped(effect: Effect, actions: &[Action], conditions: Conditions) -> Rule {
        Rule {
            effect,
            subject: Subject::Secrets,
            actions: actions.to_vec(),
            conditions,
        }
    }

    #[test]
    fn nothing_is_allowed_by_default() {
        assert_eq!(
            authorise(&[], Subject::Secrets, Action::Read, &Resource::default()),
            Decision::Deny
        );
    }

    #[test]
    fn viewer_can_read_values_but_not_write() {
        let rules = BuiltinRole::Viewer.rules();
        let r = secret("prod", "/", "DB");
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::ReadValue, &r),
            Decision::Allow
        );
        assert_eq!(authorise(&rules, Subject::Secrets, Action::Edit, &r), Decision::Deny);
        assert_eq!(
            authorise(&rules, Subject::Members, Action::Create, &Resource::default()),
            Decision::Deny
        );
    }

    #[test]
    fn conditions_restrict_allow_rules() {
        let rules = vec![scoped(
            Effect::Allow,
            &[Action::Read, Action::ReadValue],
            Conditions {
                environments: vec!["dev".into()],
                paths: vec!["/app/**".into()],
                ..Default::default()
            },
        )];
        let check = |r: &Resource| authorise(&rules, Subject::Secrets, Action::ReadValue, r);
        assert_eq!(check(&secret("dev", "/app/db", "X")), Decision::Allow);
        assert_eq!(check(&secret("prod", "/app/db", "X")), Decision::Deny);
        assert_eq!(check(&secret("dev", "/other", "X")), Decision::Deny);
        assert_eq!(check(&Resource::default()), Decision::Deny);
    }

    #[test]
    fn key_and_tag_conditions() {
        let rules = vec![
            scoped(
                Effect::Allow,
                &[Action::ReadValue],
                Conditions {
                    keys: vec!["DB_*".into()],
                    ..Default::default()
                },
            ),
            scoped(
                Effect::Allow,
                &[Action::Edit],
                Conditions {
                    tags: vec!["shared".into()],
                    ..Default::default()
                },
            ),
        ];
        assert_eq!(
            authorise(
                &rules,
                Subject::Secrets,
                Action::ReadValue,
                &secret("x", "/", "DB_PASS")
            ),
            Decision::Allow
        );
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::ReadValue, &secret("x", "/", "API")),
            Decision::Deny
        );
        let tags = vec!["shared".to_string()];
        let tagged = Resource {
            tags: &tags,
            ..secret("x", "/", "A")
        };
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::Edit, &tagged),
            Decision::Allow
        );
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::Edit, &secret("x", "/", "A")),
            Decision::Deny
        );
    }

    #[test]
    fn deny_beats_allow_and_applies_when_resource_is_unknown() {
        let mut rules = BuiltinRole::ProjectAdmin.rules();
        rules.push(scoped(
            Effect::Deny,
            &[Action::ReadValue],
            Conditions {
                environments: vec!["prod".into()],
                ..Default::default()
            },
        ));
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::ReadValue, &secret("prod", "/", "A")),
            Decision::Deny
        );
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::ReadValue, &secret("dev", "/", "A")),
            Decision::Allow
        );
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::ReadValue, &Resource::default()),
            Decision::Deny
        );
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::Read, &secret("prod", "/", "A")),
            Decision::Allow
        );
    }

    #[test]
    fn rules_round_trip_through_json() -> anyhow::Result<()> {
        let rule = scoped(
            Effect::Deny,
            &[Action::ReadValue],
            Conditions {
                paths: vec!["/a".into()],
                ..Default::default()
            },
        );
        let json = serde_json::to_string(&rule).context("serialise")?;
        assert!(json.contains("\"read-value\""));
        assert_eq!(serde_json::from_str::<Rule>(&json).context("parse")?, rule);
        Ok(())
    }

    #[test]
    fn covering_prevents_escalation() {
        let admin = BuiltinRole::ProjectAdmin.rules();
        let developer = BuiltinRole::Developer.rules();
        let viewer = BuiltinRole::Viewer.rules();
        assert!(covers(&admin, &developer));
        assert!(covers(&developer, &viewer));
        assert!(!covers(&viewer, &developer));
        assert!(!covers(&developer, &admin));

        let dev_only = vec![scoped(
            Effect::Allow,
            &[Action::ReadValue],
            Conditions {
                environments: vec!["dev".into()],
                ..Default::default()
            },
        )];
        assert!(covers(&dev_only, &dev_only));
        assert!(!covers(
            &dev_only,
            &[Rule::allow(Subject::Secrets, &[Action::ReadValue])]
        ));

        let mut admin_without_prod = admin.clone();
        admin_without_prod.push(Rule::deny(
            Subject::Secrets,
            &[Action::ReadValue],
            Conditions {
                environments: vec!["prod".into()],
                ..Default::default()
            },
        ));
        assert!(!covers(&admin_without_prod, &viewer));
    }

    #[test]
    fn denies_cannot_be_lifted_by_those_they_bind() {
        let admin = BuiltinRole::ProjectAdmin.rules();
        let no_prod_values = vec![Rule::deny(
            Subject::Secrets,
            &[Action::ReadValue],
            Conditions {
                environments: vec!["prod".into()],
                ..Default::default()
            },
        )];
        let restricted_admin: Vec<Rule> = admin.iter().chain(&no_prod_values).cloned().collect();
        assert!(may_remove(&admin, &no_prod_values));
        assert!(!may_remove(&restricted_admin, &no_prod_values));
        assert!(may_remove(&admin, &BuiltinRole::Viewer.rules()));
        assert!(!may_remove(&BuiltinRole::Viewer.rules(), &admin));

        let weakened = dropped_rules(&restricted_admin, &admin);
        assert_eq!(weakened, no_prod_values);
        assert!(dropped_rules(&admin, &restricted_admin).is_empty());
    }

    #[test]
    fn builtin_slugs_round_trip() {
        for role in BuiltinRole::ALL {
            assert_eq!(BuiltinRole::from_slug(role.slug()), Some(role));
        }
    }

    fn arb_action() -> impl Strategy<Value = Action> {
        prop::sample::select(Action::ALL.to_vec())
    }

    fn arb_conditions() -> impl Strategy<Value = Conditions> {
        (
            prop::collection::vec(prop::sample::select(vec!["dev", "prod", "staging"]), 0..2),
            prop::collection::vec(prop::sample::select(vec!["/**", "/app/**", "/app", "/db/*"]), 0..2),
        )
            .prop_map(|(envs, paths)| Conditions {
                environments: envs.into_iter().map(String::from).collect(),
                paths: paths.into_iter().map(String::from).collect(),
                ..Default::default()
            })
    }

    fn arb_rule() -> impl Strategy<Value = Rule> {
        (
            any::<bool>(),
            prop::collection::vec(arb_action(), 1..3),
            arb_conditions(),
        )
            .prop_map(|(allow, actions, c)| scoped(if allow { Effect::Allow } else { Effect::Deny }, &actions, c))
    }

    fn arb_resource() -> impl Strategy<Value = (String, String)> {
        (
            prop::sample::select(vec!["dev", "prod", "staging"]),
            prop::sample::select(vec!["/", "/app", "/app/x", "/db/y"]),
        )
            .prop_map(|(e, p)| (e.to_string(), p.to_string()))
    }

    proptest! {
        #[test]
        fn an_unconditional_deny_always_wins(rules in prop::collection::vec(arb_rule(), 0..6), action in arb_action(), (env, path) in arb_resource()) {
            let mut rules = rules;
            rules.push(Rule::deny(Subject::Secrets, &[action], Conditions::default()));
            let resource = secret(&env, &path, "K");
            prop_assert_eq!(authorise(&rules, Subject::Secrets, action, &resource), Decision::Deny);
        }

        #[test]
        fn adding_conditions_never_widens_access(rules in prop::collection::vec(arb_rule(), 0..6), extra in arb_conditions(), action in arb_action(), (env, path) in arb_resource()) {
            let resource = secret(&env, &path, "K");
            let narrowed: Vec<Rule> = rules.iter().cloned().map(|mut r| {
                // Restricting a previously unrestricted field is a strict narrowing.
                if r.effect == Effect::Allow {
                    if r.conditions.environments.is_empty() { r.conditions.environments = extra.environments.clone(); }
                    if r.conditions.paths.is_empty() { r.conditions.paths = extra.paths.clone(); }
                }
                r
            }).collect();
            if authorise(&narrowed, Subject::Secrets, action, &resource) == Decision::Allow {
                prop_assert_eq!(authorise(&rules, Subject::Secrets, action, &resource), Decision::Allow);
            }
        }

        #[test]
        fn rules_for_other_subjects_never_grant(rules in prop::collection::vec(arb_rule(), 0..6), action in arb_action()) {
            prop_assert_eq!(authorise(&rules, Subject::Roles, action, &Resource::default()), Decision::Deny);
        }
    }
}
