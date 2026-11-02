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
    /// `None` when the tags are unknown, so a deny scoped by tag still applies.
    pub tags: Option<&'a [String]>,
    /// How the secret's own access list bears on the caller, for checks on secrets and their
    /// versions.
    pub access: Access<'a>,
}

/// A secret's access list as it applies to one caller. It narrows what the caller's roles
/// allow on that secret and never widens it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Access<'a> {
    /// The secret is not restricted, or the caller is exempt from access lists.
    Open,
    /// The secret is restricted; these are the actions its list grants the caller, empty when
    /// they are not on it.
    Listed(&'a [Action]),
    /// Not known, which allows nothing on secrets, so a check that forgets the list fails closed.
    #[default]
    Unknown,
}

/// The actions an access list entry can grant.
pub const LISTABLE_ACTIONS: [Action; 4] = [Action::Read, Action::ReadValue, Action::Edit, Action::Delete];

impl Access<'_> {
    /// Whether the list lets `action` through. Creating over a restricted secret, which brings a
    /// deleted one back, counts as editing it.
    pub fn permits(self, action: Action) -> bool {
        let wanted = match action {
            Action::Create => Action::Edit,
            other => other,
        };
        match self {
            Access::Open => true,
            Access::Listed(granted) => granted.contains(&wanted),
            Access::Unknown => false,
        }
    }
}

/// Subjects that are about one secret, and so answer to its access list.
fn follows_access_lists(subject: Subject) -> bool {
    matches!(subject, Subject::Secrets | Subject::SecretVersions)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Most path and key patterns one role may hold, so checking it stays cheap.
pub const MAX_ROLE_PATTERNS: usize = 200;
/// Most path and key patterns across every role that reaches one principal in a project,
/// directly or through their groups.
pub const MAX_PRINCIPAL_PATTERNS: usize = 400;

/// The path and key patterns in `rules`, which are what make a check cost anything.
pub fn pattern_count(rules: &[Rule]) -> usize {
    rules
        .iter()
        .map(|r| r.conditions.paths.len() + r.conditions.keys.len())
        .sum()
}

/// One condition list against one field. `unknown` is the answer when the field is unset.
fn condition_hits(list: &[String], field: Option<&str>, unknown: bool, hit: impl Fn(&str, &str) -> bool) -> bool {
    if list.is_empty() {
        return true;
    }
    field.map_or(unknown, |value| list.iter().any(|item| hit(item, value)))
}

fn tags_hit(list: &[String], tags: Option<&[String]>, unknown: bool) -> bool {
    if list.is_empty() {
        return true;
    }
    tags.map_or(unknown, |tags| tags.iter().any(|t| list.contains(t)))
}

/// Whether every condition holds, checking the cheap ones first and stopping at the first miss.
/// An unknown field counts as `unknown`.
fn conditions_hold(conditions: &Conditions, resource: &Resource<'_>, unknown: bool) -> bool {
    condition_hits(&conditions.environments, resource.environment, unknown, |e, env| {
        e == env
    }) && tags_hit(&conditions.tags, resource.tags, unknown)
        && condition_hits(&conditions.keys, resource.key, unknown, |g, key| {
            glob_match(g, key, None)
        })
        && condition_hits(&conditions.paths, resource.path, unknown, |g, path| {
            glob_match(g, path, Some('/'))
        })
}

/// For an allow rule every non-empty condition must positively match.
fn allow_applies(conditions: &Conditions, resource: &Resource<'_>) -> bool {
    conditions_hold(conditions, resource, false)
}

/// A deny rule applies unless the resource is known to fall outside it, so a deny scoped to
/// `prod` still blocks a request whose environment is unknown.
fn deny_applies(conditions: &Conditions, resource: &Resource<'_>) -> bool {
    conditions_hold(conditions, resource, true)
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
    if follows_access_lists(subject) && !resource.access.permits(action) {
        return Decision::Deny;
    }
    if relevant().any(|r| r.effect == Effect::Allow && allow_applies(&r.conditions, resource)) {
        return Decision::Allow;
    }
    Decision::Deny
}

/// Whether a deny rule applies to `action` on `resource`, whatever else is allowed.
pub fn denied(rules: &[Rule], subject: Subject, action: Action, resource: &Resource<'_>) -> bool {
    rules.iter().any(|r| {
        r.effect == Effect::Deny
            && r.subject == subject
            && r.actions.contains(&action)
            && deny_applies(&r.conditions, resource)
    })
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
            tags: Some(&[]),
            access: Access::Open,
        }
    }

    #[test]
    fn an_access_list_narrows_but_never_widens() {
        let developer = BuiltinRole::Developer.rules();
        let viewer = BuiltinRole::Viewer.rules();
        let granted = [Action::Read, Action::ReadValue, Action::Edit];
        let listed = |granted: &'static [Action]| Resource {
            access: Access::Listed(granted),
            ..secret("prod", "/", "DB")
        };
        let check = |rules: &[Rule], action, r: &Resource| authorise(rules, Subject::Secrets, action, r);
        let with_grant = Resource {
            access: Access::Listed(&granted),
            ..secret("prod", "/", "DB")
        };
        assert_eq!(check(&developer, Action::ReadValue, &with_grant), Decision::Allow);
        assert_eq!(check(&developer, Action::Edit, &with_grant), Decision::Allow);
        assert_eq!(
            check(&developer, Action::Create, &with_grant),
            Decision::Allow,
            "bringing a restricted secret back counts as editing it"
        );
        assert_eq!(check(&developer, Action::Delete, &with_grant), Decision::Deny);
        assert_eq!(
            check(&viewer, Action::Edit, &with_grant),
            Decision::Deny,
            "the list cannot grant what the role does not"
        );
        for action in Action::ALL {
            assert_eq!(check(&developer, action, &listed(&[])), Decision::Deny, "{action:?}");
            assert_eq!(
                authorise(&developer, Subject::SecretVersions, action, &listed(&[])),
                Decision::Deny,
                "{action:?} on versions"
            );
        }
        assert_eq!(
            check(&developer, Action::ReadValue, &listed(&[Action::Read])),
            Decision::Deny
        );
        assert_eq!(
            check(&developer, Action::Read, &listed(&[Action::Read])),
            Decision::Allow
        );
    }

    #[test]
    fn an_unknown_list_fails_closed_on_secrets_only() {
        let admin = BuiltinRole::ProjectAdmin.rules();
        let unknown = Resource {
            access: Access::Unknown,
            ..secret("prod", "/", "DB")
        };
        assert_eq!(
            authorise(&admin, Subject::Secrets, Action::Read, &unknown),
            Decision::Deny
        );
        assert_eq!(
            authorise(&admin, Subject::SecretVersions, Action::Read, &unknown),
            Decision::Deny
        );
        let environment = Resource {
            environment: Some("prod"),
            ..Default::default()
        };
        for subject in [Subject::Snapshots, Subject::Folders, Subject::Environments] {
            assert_eq!(
                authorise(&admin, subject, Action::Read, &environment),
                Decision::Allow,
                "{subject:?} has no access list"
            );
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
    fn only_a_matching_deny_counts_as_denied() {
        let env = |slug: &'static str| Resource {
            environment: Some(slug),
            ..Default::default()
        };
        let prod_only = Conditions {
            environments: vec!["prod".into()],
            ..Default::default()
        };
        let rules = vec![
            Rule::allow(Subject::Secrets, &Action::ALL),
            Rule::deny(Subject::Environments, &[Action::Read], prod_only),
        ];
        assert!(denied(&rules, Subject::Environments, Action::Read, &env("prod")));
        assert!(!denied(&rules, Subject::Environments, Action::Read, &env("dev")));
        assert!(
            !denied(&rules, Subject::Environments, Action::Edit, &env("prod")),
            "other actions are untouched"
        );
        assert!(
            denied(&rules, Subject::Environments, Action::Read, &Resource::default()),
            "an unknown environment fails closed"
        );
        assert!(
            !denied(&[], Subject::Environments, Action::Read, &env("prod")),
            "no allow is not a deny"
        );
        let by_tag = vec![Rule::deny(
            Subject::Environments,
            &[Action::Read],
            Conditions {
                tags: vec!["restricted".into()],
                ..Default::default()
            },
        )];
        assert!(
            denied(&by_tag, Subject::Environments, Action::Read, &env("dev")),
            "a whole environment never knows its tags"
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
            tags: Some(&tags),
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
        let unknown = Resource {
            tags: None,
            ..secret("x", "/", "A")
        };
        assert_eq!(
            authorise(&rules, Subject::Secrets, Action::Edit, &unknown),
            Decision::Deny,
            "unknown tags never satisfy an allow"
        );
    }

    #[test]
    fn a_deny_scoped_by_tag_applies_when_tags_are_unknown() {
        let mut rules = BuiltinRole::ProjectAdmin.rules();
        rules.push(scoped(
            Effect::Deny,
            &[Action::Read, Action::ReadValue],
            Conditions {
                tags: vec!["pci".into()],
                ..Default::default()
            },
        ));
        let pci = vec!["pci".to_string()];
        let other = vec!["web".to_string()];
        let with = |tags: Option<&'static [String]>| Resource {
            tags,
            ..secret("prod", "/", "CARD")
        };
        let check = |r: &Resource| authorise(&rules, Subject::Secrets, Action::Read, r);
        assert_eq!(
            check(&Resource {
                tags: Some(&pci),
                ..with(None)
            }),
            Decision::Deny
        );
        assert_eq!(
            check(&Resource {
                tags: Some(&other),
                ..with(None)
            }),
            Decision::Allow
        );
        assert_eq!(check(&with(Some(&[]))), Decision::Allow);
        assert_eq!(check(&with(None)), Decision::Deny, "unknown tags may be pci");
        let whole_environment = Resource {
            environment: Some("prod"),
            ..Default::default()
        };
        assert_eq!(check(&whole_environment), Decision::Deny);
    }

    #[test]
    fn a_folder_deny_covers_the_folder_and_everything_under_it() {
        let paths = |p: &str| Conditions {
            paths: vec![p.into()],
            ..Default::default()
        };
        let deny = scoped(Effect::Deny, &[Action::Read, Action::ReadValue], paths("/payments/**"));
        let allow = scoped(Effect::Allow, &[Action::Read, Action::ReadValue], paths("/payments/**"));
        let mut denied = BuiltinRole::Developer.rules();
        denied.push(deny);
        let cases: &[(&[Rule], &str, Decision)] = &[
            (&denied, "/payments", Decision::Deny),
            (&denied, "/payments/stripe", Decision::Deny),
            (&denied, "/payments/stripe/live", Decision::Deny),
            (&denied, "/", Decision::Allow),
            (&denied, "/payments-old", Decision::Allow),
            (&denied, "/other/payments", Decision::Allow),
            (std::slice::from_ref(&allow), "/payments", Decision::Allow),
            (std::slice::from_ref(&allow), "/payments/stripe", Decision::Allow),
            (std::slice::from_ref(&allow), "/paymentsx", Decision::Deny),
            (std::slice::from_ref(&allow), "/", Decision::Deny),
        ];
        for (rules, path, expected) in cases {
            for action in [Action::Read, Action::ReadValue] {
                assert_eq!(
                    authorise(rules, Subject::Secrets, action, &secret("prod", path, "KEY")),
                    *expected,
                    "{action:?} at {path}"
                );
            }
        }
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

    #[test]
    fn only_path_and_key_patterns_are_counted() {
        let conditions = Conditions {
            environments: vec!["prod".into(), "dev".into()],
            paths: vec!["/a/**".into(), "/b/*".into()],
            keys: vec!["DB_*".into()],
            tags: vec!["pii".into()],
        };
        let rules = vec![
            scoped(Effect::Allow, &[Action::Read], conditions.clone()),
            scoped(Effect::Deny, &[Action::Edit], conditions),
            Rule::allow(Subject::Secrets, &[Action::Read]),
        ];
        assert_eq!(pattern_count(&rules), 6);
        assert_eq!(pattern_count(&[]), 0);
    }

    /// Every condition list must hit, whichever misses first, and an unknown field misses an
    /// allow but hits a deny.
    #[test]
    fn any_missing_condition_stops_the_rule() {
        let conditions = Conditions {
            environments: vec!["prod".into()],
            paths: vec!["/app/**".into()],
            keys: vec!["DB_*".into()],
            tags: vec!["pii".into()],
        };
        let tags = ["pii".to_string()];
        let full = Resource {
            environment: Some("prod"),
            path: Some("/app/x"),
            key: Some("DB_URL"),
            tags: Some(&tags),
            access: Access::Open,
        };
        assert!(allow_applies(&conditions, &full));
        assert!(deny_applies(&conditions, &full));
        let misses = [
            Resource {
                environment: Some("dev"),
                ..full.clone()
            },
            Resource {
                path: Some("/other"),
                ..full.clone()
            },
            Resource {
                key: Some("API_KEY"),
                ..full.clone()
            },
            Resource {
                tags: Some(&[]),
                ..full.clone()
            },
        ];
        for miss in &misses {
            assert!(!allow_applies(&conditions, miss), "{miss:?}");
            assert!(!deny_applies(&conditions, miss), "{miss:?}");
        }
        let unknowns = [
            Resource {
                environment: None,
                ..full.clone()
            },
            Resource {
                path: None,
                ..full.clone()
            },
            Resource {
                key: None,
                ..full.clone()
            },
            Resource {
                tags: None,
                ..full.clone()
            },
        ];
        for unknown in &unknowns {
            assert!(!allow_applies(&conditions, unknown), "{unknown:?}");
            assert!(deny_applies(&conditions, unknown), "{unknown:?}");
        }
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
        fn an_access_list_never_widens_access(rules in prop::collection::vec(arb_rule(), 0..6), granted in prop::collection::vec(arb_action(), 0..4), action in arb_action(), (env, path) in arb_resource()) {
            let open = secret(&env, &path, "K");
            let listed = Resource { access: Access::Listed(&granted), ..open.clone() };
            if authorise(&rules, Subject::Secrets, action, &listed) == Decision::Allow {
                prop_assert_eq!(authorise(&rules, Subject::Secrets, action, &open), Decision::Allow);
            }
        }

        #[test]
        fn rules_for_other_subjects_never_grant(rules in prop::collection::vec(arb_rule(), 0..6), action in arb_action()) {
            prop_assert_eq!(authorise(&rules, Subject::Roles, action, &Resource::default()), Decision::Deny);
        }
    }
}
