//! `sekret secrets access` and `sekret projects secret-access`: per-secret access lists.

use std::io::Write;

use anyhow::bail;
use clap::{Args, Subcommand, ValueEnum};
use sekret_api::{
    Action, GrantRequest, Identity, PrincipalKind, PrincipalRef, SecretAccess, SecretAccessChange, SecretAccessSetting,
    SecretGrant, User,
};
use sekret_client::{Location, SekretApi};

use super::format::{one_line, table};

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Show whether a secret is restricted and who is on its access list.
    List { key: String },
    /// Add principals to a secret's access list, or change what they may do. Admins only.
    Grant {
        key: String,
        #[command(flatten)]
        who: Principals,
        /// What they may do. Read is always included, and granting someone already listed
        /// replaces what they had. A list narrows what roles allow and never widens it.
        #[arg(long, value_enum, value_delimiter = ',', default_value = "read,read-value")]
        allow: Vec<AccessAction>,
    },
    /// Take principals off a secret's access list. Admins only.
    Revoke {
        key: String,
        #[command(flatten)]
        who: Principals,
    },
    /// Restrict a secret to its access list, project admins and organisation admins. Needs
    /// per-secret access on for the project.
    Restrict { key: String },
    /// Open a restricted secret to everyone its role rules allow again, and clear its list.
    Unrestrict { key: String },
}

impl AccessCommand {
    /// Whether it writes to the server rather than only reading.
    pub fn changes(&self) -> bool {
        !matches!(self, AccessCommand::List { .. })
    }
}

/// Principals named on the command line. Each flag can be repeated.
#[derive(Debug, Clone, Default, Args)]
#[group(required = true, multiple = true)]
pub struct Principals {
    /// A machine identity, by id or name.
    #[arg(long = "identity", value_name = "ID_OR_NAME")]
    pub identities: Vec<String>,
    /// A user, by id or email.
    #[arg(long = "user", value_name = "ID_OR_EMAIL")]
    pub users: Vec<String>,
    /// A group from the identity provider, by name.
    #[arg(long = "group", value_name = "NAME")]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AccessAction {
    Read,
    ReadValue,
    Edit,
    Delete,
}

impl From<AccessAction> for Action {
    fn from(value: AccessAction) -> Self {
        match value {
            AccessAction::Read => Action::Read,
            AccessAction::ReadValue => Action::ReadValue,
            AccessAction::Edit => Action::Edit,
            AccessAction::Delete => Action::Delete,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

/// The identity `wanted` names: an exact id, else the one identity with that name.
pub fn pick_identity(wanted: &str, candidates: &[Identity]) -> anyhow::Result<String> {
    if let Some(found) = candidates.iter().find(|i| i.id == wanted) {
        return Ok(found.id.clone());
    }
    let named: Vec<&Identity> = candidates.iter().filter(|i| i.name == wanted).collect();
    match named.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => bail!("no machine identity has the id or name {}", one_line(wanted)),
        _ => bail!(
            "more than one machine identity is called {}; give its id instead",
            one_line(wanted)
        ),
    }
}

/// The user `wanted` names: an exact id, else the one user with that email.
pub fn pick_user(wanted: &str, candidates: &[User]) -> anyhow::Result<String> {
    if let Some(found) = candidates.iter().find(|u| u.id == wanted) {
        return Ok(found.id.clone());
    }
    let named: Vec<&User> = candidates
        .iter()
        .filter(|u| !u.email.is_empty() && u.email.eq_ignore_ascii_case(wanted))
        .collect();
    match named.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => bail!(
            "no user has the id or email {}; they must have signed in once",
            one_line(wanted)
        ),
        _ => bail!(
            "more than one user has the email {}; give their id instead",
            one_line(wanted)
        ),
    }
}

/// A search that matched more than it returned may have left out the one meant, or a second
/// with the same name, so only an exact id is trusted from it.
fn complete<T>(wanted: &str, total: i64, items: &[T], id_of: impl Fn(&T) -> &str) -> anyhow::Result<()> {
    let shown = i64::try_from(items.len()).unwrap_or(i64::MAX);
    if total > shown && !items.iter().any(|i| id_of(i) == wanted) {
        bail!(
            "{} matches {total} principals, too many to tell which is meant; give the id instead",
            one_line(wanted)
        );
    }
    Ok(())
}

/// Whether the caller may not search principals, in which case only an id can be sent, for the
/// server to check.
fn may_not_search(error: &sekret_client::ClientError) -> bool {
    matches!(error, sekret_client::ClientError::Api { status: 403, .. })
}

/// Whether `text` has the shape of the ids sekret gives users and identities.
fn looks_like_id(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// What was typed, when searching is not allowed: an id is passed on, a name cannot be looked up.
fn unsearched(kind: &str, wanted: &str) -> anyhow::Result<String> {
    if looks_like_id(wanted) {
        return Ok(wanted.to_string());
    }
    bail!(
        "you may not look up {kind}s by name here, so give the {kind}'s id instead of {}",
        one_line(wanted)
    )
}

async fn resolve(api: &dyn SekretApi, who: &Principals) -> anyhow::Result<Vec<PrincipalRef>> {
    let mut resolved = Vec::new();
    for wanted in &who.identities {
        let principal_id = match api.find_identities(wanted.clone()).await {
            Ok(page) => {
                complete(wanted, page.total, &page.items, |i| &i.id)?;
                pick_identity(wanted, &page.items)?
            }
            Err(error) if may_not_search(&error) => unsearched("identity", wanted)?,
            Err(error) => return Err(error.into()),
        };
        resolved.push(PrincipalRef {
            principal_kind: PrincipalKind::Identity,
            principal_id,
        });
    }
    for wanted in &who.users {
        let principal_id = match api.find_users(wanted.clone()).await {
            Ok(page) => {
                complete(wanted, page.total, &page.items, |u| &u.id)?;
                pick_user(wanted, &page.items)?
            }
            Err(error) if may_not_search(&error) => unsearched("user", wanted)?,
            Err(error) => return Err(error.into()),
        };
        resolved.push(PrincipalRef {
            principal_kind: PrincipalKind::User,
            principal_id,
        });
    }
    for group in &who.groups {
        resolved.push(PrincipalRef {
            principal_kind: PrincipalKind::Group,
            principal_id: group.clone(),
        });
    }
    Ok(resolved)
}

/// The entries on `access` that `who` names, by id or by the name the list shows. Revoking is
/// judged against the list itself, so a name that is not on it fails rather than removing nobody.
pub fn listed_principals(access: &SecretAccess, who: &Principals) -> anyhow::Result<Vec<PrincipalRef>> {
    let wanted = who
        .identities
        .iter()
        .map(|w| (PrincipalKind::Identity, w))
        .chain(who.users.iter().map(|w| (PrincipalKind::User, w)))
        .chain(who.groups.iter().map(|w| (PrincipalKind::Group, w)));
    let mut found = Vec::new();
    for (kind, name) in wanted {
        let of_kind = || access.grants.iter().filter(|g| g.principal_kind == kind);
        let exact: Vec<&SecretGrant> = of_kind().filter(|g| g.principal_id == *name).collect();
        let named: Vec<&SecretGrant> = if exact.is_empty() {
            of_kind()
                .filter(|g| g.principal_name.eq_ignore_ascii_case(name))
                .collect()
        } else {
            exact
        };
        match named.as_slice() {
            [one] => found.push(PrincipalRef {
                principal_kind: kind,
                principal_id: one.principal_id.clone(),
            }),
            [] => bail!(
                "no {} {} is on this secret's access list",
                kind_label(kind),
                one_line(name)
            ),
            _ => bail!(
                "more than one {} on the list is called {}; give the id instead",
                kind_label(kind),
                one_line(name)
            ),
        }
    }
    Ok(found)
}

fn kind_label(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "user",
        PrincipalKind::Group => "group",
        PrincipalKind::Identity => "identity",
    }
}

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Read => "read",
        Action::ReadValue => "read-value",
        Action::Create => "create",
        Action::Edit => "edit",
        Action::Delete => "delete",
    }
}

pub fn describe_access(access: &SecretAccess) -> String {
    let state = match (access.restricted, access.grants.is_empty()) {
        (true, _) => "restricted: yes, only the principals below and admins can reach it\n",
        (false, true) => "restricted: no, role rules alone decide who can reach it\n",
        (false, false) => "restricted: no, so the list below has no effect until the secret is restricted\n",
    };
    if access.grants.is_empty() {
        return format!("{state}no one is on the access list\n");
    }
    let rows: Vec<Vec<String>> = access
        .grants
        .iter()
        .map(|g| {
            vec![
                kind_label(g.principal_kind).to_string(),
                g.principal_name.clone(),
                g.principal_id.clone(),
                g.actions
                    .iter()
                    .map(|a| action_label(*a))
                    .collect::<Vec<_>>()
                    .join(", "),
            ]
        })
        .collect();
    format!("{state}{}", table(&["KIND", "NAME", "ID", "ALLOWED"], &rows))
}

pub async fn run(api: &dyn SekretApi, at: Location, command: AccessCommand, out: &mut dyn Write) -> anyhow::Result<()> {
    let access = match command {
        AccessCommand::List { key } => api.secret_access(at, key).await?,
        AccessCommand::Grant { key, who, allow } => {
            let actions: Vec<Action> = allow.into_iter().map(Action::from).collect();
            let grant = resolve(api, &who)
                .await?
                .into_iter()
                .map(|p| GrantRequest {
                    principal_kind: p.principal_kind,
                    principal_id: p.principal_id,
                    actions: actions.clone(),
                })
                .collect();
            let change = SecretAccessChange {
                grant,
                ..Default::default()
            };
            api.change_secret_access(at, key, change).await?
        }
        AccessCommand::Revoke { key, who } => {
            let current = api.secret_access(at.clone(), key.clone()).await?;
            let change = SecretAccessChange {
                revoke: listed_principals(&current, &who)?,
                ..Default::default()
            };
            api.change_secret_access(at, key, change).await?
        }
        AccessCommand::Restrict { key } => {
            let change = SecretAccessChange {
                restricted: Some(true),
                ..Default::default()
            };
            api.change_secret_access(at, key, change).await?
        }
        AccessCommand::Unrestrict { key } => {
            let change = SecretAccessChange {
                restricted: Some(false),
                ..Default::default()
            };
            api.change_secret_access(at, key, change).await?
        }
    };
    write!(out, "{}", describe_access(&access))?;
    Ok(())
}

pub fn describe_setting(setting: &SecretAccessSetting) -> String {
    let mut text = format!("per-secret access: {}\n", if setting.enabled { "on" } else { "off" });
    let hidden = setting
        .restricted_count
        .saturating_sub(i64::try_from(setting.restricted.len()).unwrap_or(i64::MAX));
    if setting.restricted_count == 0 {
        text.push_str("no secrets are restricted\n");
        return text;
    }
    text.push_str(&format!("restricted secrets: {}\n", setting.restricted_count));
    let rows: Vec<Vec<String>> = setting
        .restricted
        .iter()
        .map(|s| {
            let place = if s.path == "/" {
                s.key.clone()
            } else {
                format!("{}/{}", s.path, s.key)
            };
            vec![
                s.environment.clone(),
                place,
                if s.deleted { "yes".into() } else { "no".into() },
                s.grants.to_string(),
            ]
        })
        .collect();
    text.push_str(&table(&["ENVIRONMENT", "KEY", "DELETED", "ENTRIES"], &rows));
    if hidden > 0 {
        text.push_str(&format!("{hidden} more are in places your roles hide from you\n"));
    }
    text
}

pub async fn project_setting(api: &dyn SekretApi, project: String, state: Option<OnOff>) -> anyhow::Result<String> {
    let setting = match state {
        None => api.secret_access_setting(project).await?,
        Some(state) => api.set_secret_access_setting(project, state == OnOff::On).await?,
    };
    Ok(describe_setting(&setting))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekret_api::RestrictedSecret;

    fn identity(id: &str, name: &str) -> Identity {
        Identity {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            token_ttl: 0,
            token_max_ttl: 0,
            trusted_cidrs: vec![],
            disabled: false,
            created_at: 0,
            auth_methods: vec![],
        }
    }

    fn user(id: &str, email: &str) -> User {
        User {
            id: id.into(),
            email: email.into(),
            name: String::new(),
            groups: vec![],
            disabled: false,
            created_at: 0,
            last_login_at: 0,
        }
    }

    #[test]
    fn identities_are_found_by_id_then_by_a_unique_name() -> anyhow::Result<()> {
        let all = [
            identity("i1", "web"),
            identity("i2", "worker"),
            identity("i3", "worker"),
        ];
        assert_eq!(pick_identity("i2", &all)?, "i2");
        assert_eq!(pick_identity("web", &all)?, "i1");
        assert!(
            pick_identity("worker", &all)
                .err()
                .is_some_and(|e| e.to_string().contains("more than one"))
        );
        assert!(pick_identity("missing", &all).is_err());
        Ok(())
    }

    #[test]
    fn a_truncated_search_only_trusts_an_exact_id() {
        let page = [identity("i1", "web"), identity("i2", "web-2")];
        assert!(complete("web", 2, &page, |i| &i.id).is_ok(), "every match is here");
        let refused = complete("web", 150, &page, |i| &i.id);
        assert!(refused.err().is_some_and(|e| e.to_string().contains("give the id")));
        assert!(complete("i2", 150, &page, |i| &i.id).is_ok(), "an exact id is enough");
    }

    #[tokio::test]
    async fn without_search_rights_the_id_is_sent_for_the_server_to_check() -> anyhow::Result<()> {
        use anyhow::Context;
        let forbidden = || sekret_client::ClientError::Api {
            status: 403,
            code: "forbidden".into(),
            message: "no".into(),
            retry_after: None,
        };
        let mut api = sekret_client::MockSekretApi::new();
        api.expect_find_identities().returning(move |_| Err(forbidden()));
        const ID: &str = "0192d4a8-0000-7000-8000-00000000000a";
        api.expect_change_secret_access()
            .withf(|_, _, change| change.grant.len() == 1 && change.grant[0].principal_id == ID)
            .times(1)
            .returning(|_, _, _| {
                Ok(SecretAccess {
                    restricted: true,
                    grants: vec![],
                })
            });
        let grant = |name: &str| AccessCommand::Grant {
            key: "DB".into(),
            who: Principals {
                identities: vec![name.into()],
                ..Default::default()
            },
            allow: vec![AccessAction::Read],
        };
        run(&api, at(), grant(ID), &mut Vec::new()).await.context("grant")?;
        let refused = run(&api, at(), grant("checkout-pod"), &mut Vec::new()).await;
        assert!(
            refused
                .err()
                .is_some_and(|e| e.to_string().contains("give the identity's id")),
            "a name is never passed off as an id"
        );
        Ok(())
    }

    fn entry(kind: PrincipalKind, id: &str, name: &str) -> SecretGrant {
        SecretGrant {
            principal_kind: kind,
            principal_id: id.into(),
            principal_name: name.into(),
            actions: vec![Action::Read],
            created_at: 0,
        }
    }

    #[test]
    fn revocations_must_name_someone_on_the_list() -> anyhow::Result<()> {
        let access = SecretAccess {
            restricted: true,
            grants: vec![
                entry(PrincipalKind::Identity, "i1", "checkout-pod"),
                entry(PrincipalKind::User, "u1", "ann@example.com"),
                entry(PrincipalKind::Group, "ops", "ops"),
            ],
        };
        let who = Principals {
            identities: vec!["checkout-pod".into()],
            users: vec!["u1".into()],
            groups: vec!["ops".into()],
        };
        let found = listed_principals(&access, &who)?;
        let ids: Vec<&str> = found.iter().map(|p| p.principal_id.as_str()).collect();
        assert_eq!(ids, ["i1", "u1", "ops"]);
        let typo = Principals {
            groups: vec!["Ops-team".into()],
            ..Default::default()
        };
        assert!(
            listed_principals(&access, &typo)
                .err()
                .is_some_and(|e| e.to_string().contains("no group Ops-team is on"))
        );
        Ok(())
    }

    #[test]
    fn ids_have_one_shape() {
        assert!(looks_like_id("0192d4a8-0000-7000-8000-00000000000a"));
        assert!(!looks_like_id("checkout-pod"));
        assert!(!looks_like_id("0192d4a8-0000-7000-8000-00000000000g"));
    }

    #[test]
    fn users_are_found_by_id_then_by_email() -> anyhow::Result<()> {
        let all = [user("u1", "ann@example.com"), user("u2", "")];
        assert_eq!(pick_user("u2", &all)?, "u2");
        assert_eq!(pick_user("ANN@example.com", &all)?, "u1");
        assert!(pick_user("", &all).is_err(), "an empty email never matches");
        assert!(pick_user("bob@example.com", &all).is_err());
        Ok(())
    }

    fn at() -> Location {
        Location {
            project: "app".into(),
            environment: "prod".into(),
            path: "/".into(),
        }
    }

    #[tokio::test]
    async fn grants_resolve_names_and_send_one_change() -> anyhow::Result<()> {
        use anyhow::Context;
        let mut api = sekret_client::MockSekretApi::new();
        api.expect_find_identities().times(1).returning(|_| {
            Ok(sekret_api::IdentityPage {
                items: vec![identity("i1", "web")],
                total: 1,
            })
        });
        api.expect_find_users().times(1).returning(|_| {
            Ok(sekret_api::UserPage {
                items: vec![user("u1", "ann@example.com")],
                total: 1,
            })
        });
        api.expect_change_secret_access()
            .withf(|at, key, change| {
                let wanted = [
                    (PrincipalKind::Identity, "i1"),
                    (PrincipalKind::User, "u1"),
                    (PrincipalKind::Group, "ops"),
                ];
                at.environment == "prod"
                    && key == "DB"
                    && change.restricted.is_none()
                    && change.revoke.is_empty()
                    && change.grant.len() == 3
                    && change.grant.iter().zip(wanted).all(|(g, (kind, id))| {
                        g.principal_kind == kind && g.principal_id == id && g.actions == [Action::Read, Action::Edit]
                    })
            })
            .times(1)
            .returning(|_, _, _| {
                Ok(SecretAccess {
                    restricted: true,
                    grants: vec![],
                })
            });
        let command = AccessCommand::Grant {
            key: "DB".into(),
            who: Principals {
                identities: vec!["web".into()],
                users: vec!["ann@example.com".into()],
                groups: vec!["ops".into()],
            },
            allow: vec![AccessAction::Read, AccessAction::Edit],
        };
        let mut out = Vec::new();
        run(&api, at(), command, &mut out).await.context("grant")?;
        assert!(String::from_utf8(out).context("utf8")?.starts_with("restricted: yes"));
        Ok(())
    }

    #[tokio::test]
    async fn restricting_and_unrestricting_send_only_the_flag() -> anyhow::Result<()> {
        use anyhow::Context;
        let mut api = sekret_client::MockSekretApi::new();
        for wanted in [true, false] {
            api.expect_change_secret_access()
                .withf(move |_, _, change| {
                    change.restricted == Some(wanted) && change.grant.is_empty() && change.revoke.is_empty()
                })
                .times(1)
                .returning(move |_, _, _| {
                    Ok(SecretAccess {
                        restricted: wanted,
                        grants: vec![],
                    })
                });
        }
        let mut out = Vec::new();
        run(&api, at(), AccessCommand::Restrict { key: "DB".into() }, &mut out)
            .await
            .context("restrict")?;
        run(&api, at(), AccessCommand::Unrestrict { key: "DB".into() }, &mut out)
            .await
            .context("unrestrict")?;
        Ok(())
    }

    #[test]
    fn access_lists_are_described_plainly() {
        let empty = SecretAccess {
            restricted: false,
            grants: vec![],
        };
        assert_eq!(
            describe_access(&empty),
            "restricted: no, role rules alone decide who can reach it\nno one is on the access list\n"
        );
        let listed = SecretAccess {
            restricted: true,
            grants: vec![SecretGrant {
                principal_kind: PrincipalKind::Identity,
                principal_id: "i1".into(),
                principal_name: "web\u{1b}[31m".into(),
                actions: vec![Action::Read, Action::ReadValue],
                created_at: 0,
            }],
        };
        let text = describe_access(&listed);
        assert!(text.starts_with("restricted: yes"));
        assert!(text.contains("read, read-value"));
        assert!(!text.contains('\u{1b}'), "names cannot drive the terminal");
    }

    #[test]
    fn the_setting_lists_restricted_secrets_and_says_how_many_are_hidden() {
        let setting = SecretAccessSetting {
            enabled: true,
            restricted: vec![RestrictedSecret {
                environment: "prod".into(),
                path: "/payments".into(),
                key: "STRIPE".into(),
                deleted: false,
                grants: 2,
            }],
            restricted_count: 3,
        };
        let text = describe_setting(&setting);
        assert!(text.starts_with("per-secret access: on\nrestricted secrets: 3\n"));
        assert!(text.contains("/payments/STRIPE"));
        assert!(text.contains("2 more are in places your roles hide from you"));
        let off = SecretAccessSetting {
            enabled: false,
            restricted: vec![],
            restricted_count: 0,
        };
        assert_eq!(
            describe_setting(&off),
            "per-secret access: off\nno secrets are restricted\n"
        );
    }
}
