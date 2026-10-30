use async_trait::async_trait;
use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
use kube::api::{Api, Patch, PatchParams, PostParams};

use crate::crd::{SekretSecret, SekretSecretStatus};

#[derive(Debug, thiserror::Error)]
pub enum KubeError {
    #[error("{0}")]
    Api(String),
    #[error("the API server returned an empty token")]
    EmptyToken,
}

impl From<kube::Error> for KubeError {
    fn from(error: kube::Error) -> Self {
        KubeError::Api(error.to_string())
    }
}

/// The Kubernetes operations the reconciler needs, all scoped to one namespace.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait KubeApi: Send + Sync {
    async fn get_secret(&self, namespace: String, name: String) -> Result<Option<Secret>, KubeError>;
    async fn create_secret(&self, namespace: String, secret: Secret) -> Result<(), KubeError>;
    async fn replace_secret(&self, namespace: String, secret: Secret) -> Result<(), KubeError>;
    /// Mints a short-lived token for a service account via the TokenRequest API.
    async fn request_token(
        &self,
        namespace: String,
        service_account: String,
        audience: String,
        expiry_seconds: i64,
    ) -> Result<String, KubeError>;
    async fn patch_status(&self, namespace: String, name: String, status: SekretSecretStatus) -> Result<(), KubeError>;
}

pub struct KubeClient {
    client: kube::Client,
}

impl KubeClient {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

const FIELD_MANAGER: &str = "sekret-operator";

#[async_trait]
impl KubeApi for KubeClient {
    async fn get_secret(&self, namespace: String, name: String) -> Result<Option<Secret>, KubeError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &namespace);
        Ok(api.get_opt(&name).await?)
    }

    async fn create_secret(&self, namespace: String, secret: Secret) -> Result<(), KubeError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &namespace);
        let params = PostParams {
            field_manager: Some(FIELD_MANAGER.into()),
            ..PostParams::default()
        };
        api.create(&params, &secret).await?;
        Ok(())
    }

    async fn replace_secret(&self, namespace: String, secret: Secret) -> Result<(), KubeError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &namespace);
        let name = secret.metadata.name.clone().unwrap_or_default();
        let params = PostParams {
            field_manager: Some(FIELD_MANAGER.into()),
            ..PostParams::default()
        };
        api.replace(&name, &params, &secret).await?;
        Ok(())
    }

    async fn request_token(
        &self,
        namespace: String,
        service_account: String,
        audience: String,
        expiry_seconds: i64,
    ) -> Result<String, KubeError> {
        let api: Api<ServiceAccount> = Api::namespaced(self.client.clone(), &namespace);
        let request = TokenRequest {
            spec: TokenRequestSpec {
                audiences: vec![audience],
                expiration_seconds: Some(expiry_seconds),
                ..TokenRequestSpec::default()
            },
            ..TokenRequest::default()
        };
        let response = api
            .create_token_request(&service_account, &PostParams::default(), &request)
            .await?;
        response
            .status
            .map(|s| s.token)
            .filter(|t| !t.is_empty())
            .ok_or(KubeError::EmptyToken)
    }

    async fn patch_status(&self, namespace: String, name: String, status: SekretSecretStatus) -> Result<(), KubeError> {
        let api: Api<SekretSecret> = Api::namespaced(self.client.clone(), &namespace);
        let patch = serde_json::json!({ "status": status });
        api.patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
        Ok(())
    }
}
