use std::collections::BTreeMap;

use kube::{CustomResource, CustomResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const READY: &str = "Ready";

/// Syncs secrets from a sekret project path into a native Kubernetes Secret.
#[derive(CustomResource, Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "sekret.sam-ruff.github.io",
    version = "v1alpha1",
    kind = "SekretSecret",
    namespaced,
    status = "SekretSecretStatus",
    shortname = "sks",
    printcolumn = r#"{"name":"Target","type":"string","jsonPath":".spec.target.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Keys","type":"integer","jsonPath":".status.secretCount"}"#,
    printcolumn = r#"{"name":"Synced","type":"date","jsonPath":".status.lastSyncedAt"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SekretSecretSpec {
    pub project: String,
    pub environment: String,
    #[serde(default = "default_path")]
    #[schemars(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    /// Only sync these keys; every key at the path when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    pub target: TargetSpec,
    /// How often to resync, such as `30s`, `5m` or `1h`.
    #[serde(default = "default_refresh_interval")]
    #[schemars(default = "default_refresh_interval")]
    pub refresh_interval: String,
    pub auth: AuthSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TargetSpec {
    /// Name of the Secret to manage in the same namespace.
    pub name: String,
    #[serde(rename = "type", default = "default_secret_type")]
    #[schemars(default = "default_secret_type")]
    pub secret_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthSpec {
    /// The sekret machine identity configured for Kubernetes auth.
    pub identity_id: String,
    /// Service account in this resource's namespace whose token is presented to sekret.
    pub service_account_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SekretSecretStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub condition_type: String,
    /// `True`, `False` or `Unknown`.
    pub status: String,
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl SekretSecretStatus {
    pub fn ready(&self) -> Option<&Condition> {
        self.conditions.iter().find(|c| c.condition_type == READY)
    }
}

fn default_path() -> String {
    "/".into()
}

fn default_refresh_interval() -> String {
    "5m".into()
}

fn default_secret_type() -> String {
    "Opaque".into()
}

/// Renders the `SekretSecret` CustomResourceDefinition as YAML, ready for `kubectl apply`.
pub fn crd_yaml() -> anyhow::Result<String> {
    Ok(serde_saphyr::to_string(&SekretSecret::crd())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn defaults_apply_when_fields_are_omitted() -> anyhow::Result<()> {
        let spec: SekretSecretSpec = serde_json::from_value(serde_json::json!({
            "project": "app",
            "environment": "prod",
            "target": {"name": "app-env"},
            "auth": {"identityId": "id", "serviceAccountName": "app"}
        }))
        .context("spec")?;
        assert_eq!(spec.path, "/");
        assert!(!spec.recursive);
        assert_eq!(spec.refresh_interval, "5m");
        assert_eq!(spec.target.secret_type, "Opaque");
        assert_eq!(spec.keys, None);
        Ok(())
    }

    #[test]
    fn crd_yaml_names_the_group_and_kind() -> anyhow::Result<()> {
        let yaml = crd_yaml().context("yaml")?;
        assert!(yaml.contains("name: sekretsecrets.sekret.sam-ruff.github.io"));
        assert!(yaml.contains("kind: SekretSecret"));
        Ok(())
    }

    #[test]
    fn checked_in_chart_crd_matches_generated() -> anyhow::Result<()> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/helm/sekret-operator/crds/sekretsecrets.yaml"
        );
        let checked_in = std::fs::read_to_string(path).context("chart CRD")?;
        let generated = crd_yaml().context("yaml")?;
        assert_eq!(
            checked_in.trim_end(),
            generated.trim_end(),
            "chart CRD is stale; regenerate it from sekret_operator::crd_yaml()"
        );
        Ok(())
    }
}
