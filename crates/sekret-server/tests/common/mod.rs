#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use reqwest::{Method, StatusCode};
use sekret_core::crypto::RootKey;
use sekret_server::clock::SystemClock;
use sekret_server::config::{HumanOidcConfig, ServerConfig};
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::state::{AppState, Dependencies, build_state};
use sekret_store::SqlStore;
use serde_json::{Value, json};

pub struct Harness {
    pub base: String,
    pub client: reqwest::Client,
    pub state: AppState,
    pub admin: String,
}

pub struct Options {
    pub database_url: String,
    pub oidc: Option<HumanOidcConfig>,
    /// A clock the test can move; the system clock when absent.
    pub clock: Option<Arc<sekret_server::clock::FixedClock>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            database_url: SQLITE.into(),
            oidc: None,
            clock: None,
        }
    }
}

pub const SQLITE: &str = "sqlite::memory:";

/// `ApiError` is not a `std::error::Error`, so `anyhow::Context` cannot wrap it.
pub fn api_error(context: &'static str) -> impl FnOnce(sekret_server::error::ApiError) -> anyhow::Error {
    move |error| anyhow::anyhow!("{context}: {error:?}")
}

pub struct PostgresDb {
    pub url: String,
    _container: testcontainers_modules::testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>,
}

/// A throwaway Postgres, or `None` (skip) when Docker is unavailable and `SEKRET_REQUIRE_POSTGRES` is unset.
pub async fn postgres() -> anyhow::Result<Option<PostgresDb>> {
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    let container = match testcontainers_modules::postgres::Postgres::default().start().await {
        Ok(c) => c,
        Err(error) if std::env::var_os("SEKRET_REQUIRE_POSTGRES").is_none() => {
            eprintln!("skipping postgres test: {error}");
            return Ok(None);
        }
        Err(error) => anyhow::bail!("postgres container failed: {error}"),
    };
    let port = container.get_host_port_ipv4(5432).await.context("port")?;
    Ok(Some(PostgresDb {
        url: format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        _container: container,
    }))
}

/// Runs each `async fn name(database_url: String) -> anyhow::Result<()>` as `name::sqlite` and `name::postgres`.
#[macro_export]
macro_rules! on_both_backends {
    ($($name:ident),* $(,)?) => {
        $(
            mod $name {
                #[tokio::test]
                async fn sqlite() -> anyhow::Result<()> {
                    super::$name(super::common::SQLITE.to_string()).await
                }

                #[tokio::test]
                async fn postgres() -> anyhow::Result<()> {
                    let Some(db) = super::common::postgres().await? else {
                        return Ok(());
                    };
                    super::$name(db.url.clone()).await
                }
            }
        )*
    };
}

pub fn options(database_url: String) -> Options {
    Options {
        database_url,
        ..Options::default()
    }
}

pub async fn start(options: Options) -> anyhow::Result<Harness> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = Arc::new(SqlStore::connect(&options.database_url).await.context("store")?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.context("bind")?;
    let addr = listener.local_addr().context("addr")?;
    let mut config = ServerConfig::for_tests(&options.database_url);
    config.public_url = format!("http://{addr}");
    config.oidc = options.oidc;
    let root_key = RootKey::generate().context("root key")?;
    sekret_server::check_root_key(store.as_ref(), &root_key.fingerprint())
        .await
        .context("root key check")?;
    let state = build_state(Dependencies {
        store,
        root_key,
        config,
        clock: match &options.clock {
            Some(clock) => clock.clone(),
            None => Arc::new(SystemClock),
        },
        http: Arc::new(ReqwestOidcHttp::new(true).context("http")?),
        token_reviewer: Arc::new(ReqwestTokenReviewer::new(true)),
    });
    let app = sekret_server::app(state.clone());
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            eprintln!("test server stopped: {error}");
        }
    });
    let admin = sekret_server::admin::bootstrap_admin(&state, 3600)
        .await
        .map_err(api_error("bootstrap"))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("client")?;
    Ok(Harness {
        base: format!("http://{addr}"),
        client,
        state,
        admin,
    })
}

impl Harness {
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.context("request")?;
        let status = response.status();
        let text = response.text().await.context("body")?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::String(text))))
    }

    pub async fn get(&self, path: &str, token: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::GET, path, Some(token), None).await
    }

    pub async fn post(&self, path: &str, token: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::POST, path, Some(token), Some(body)).await
    }

    pub async fn put(&self, path: &str, token: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::PUT, path, Some(token), Some(body)).await
    }

    pub async fn patch(&self, path: &str, token: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::PATCH, path, Some(token), Some(body)).await
    }

    pub async fn delete(&self, path: &str, token: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::DELETE, path, Some(token), None).await
    }

    pub async fn create_project(&self, slug: &str) -> anyhow::Result<Value> {
        let (status, body) = self
            .post("/api/v1/projects", &self.admin, json!({"slug": slug, "name": slug}))
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        Ok(body)
    }

    pub async fn set_secrets(
        &self,
        project: &str,
        env: &str,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> anyhow::Result<Value> {
        let upserts: Vec<Value> = pairs.iter().map(|(k, v)| json!({"key": k, "value": v})).collect();
        let (status, body) = self
            .post(
                &format!("/api/v1/projects/{project}/environments/{env}/secrets/batch"),
                &self.admin,
                json!({"path": path, "upserts": upserts}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        Ok(body)
    }

    /// Creates an identity with universal auth, a client secret and the given project role.
    pub async fn machine(&self, name: &str, project: &str, role: &str) -> anyhow::Result<(String, String)> {
        let (status, identity) = self
            .post("/api/v1/identities", &self.admin, json!({"name": name}))
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{identity}");
        let id = identity["id"].as_str().context("id")?.to_string();
        let (status, body) = self
            .put(
                &format!("/api/v1/identities/{id}/auth/universal"),
                &self.admin,
                json!({"kind": "universal"}),
            )
            .await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, secret) = self
            .post(
                &format!("/api/v1/identities/{id}/client-secrets"),
                &self.admin,
                json!({}),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{secret}");
        let (status, body) = self
            .post(
                &format!("/api/v1/projects/{project}/members"),
                &self.admin,
                json!({"principal_kind": "identity", "principal_id": id, "role": role}),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, token) = self
            .call(
                Method::POST,
                "/api/v1/auth/universal/login",
                None,
                Some(json!({"client_id": id, "client_secret": secret["client_secret"]})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{token}");
        Ok((id, token["access_token"].as_str().context("token")?.to_string()))
    }
}
