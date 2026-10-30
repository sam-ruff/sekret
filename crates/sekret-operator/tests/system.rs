//! End to end: a k3s cluster, an in-process sekret server and the controller.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::{Namespace, Secret, ServiceAccount};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleRef, Subject};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config, CustomResourceExt};
use sekret_client::ClientOptions;
use sekret_core::crypto::RootKey;
use sekret_operator::{
    AuthSpec, Context, HttpSekretFactory, KubeClient, SekretSecret, SekretSecretSpec, TargetSpec, run_controller,
};
use sekret_server::clock::SystemClock;
use sekret_server::config::ServerConfig;
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::state::{Dependencies, build_state};
use sekret_store::SqlStore;
use serde_json::{Value, json};
use testcontainers_modules::k3s::{K3s, KUBE_SECURE_PORT};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

const K3S_TAG: &str = "v1.33.5-k3s1";
const NAMESPACE: &str = "apps";
const SERVICE_ACCOUNT: &str = "reader";

struct Cluster {
    client: Client,
    url: String,
    ca_pem: String,
    _container: ContainerAsync<K3s>,
    _conf_dir: tempfile::TempDir,
}

async fn start_cluster() -> Cluster {
    let conf_dir = tempfile::tempdir().expect("temp dir");
    let container = K3s::default()
        .with_conf_mount(conf_dir.path())
        .with_tag(K3S_TAG)
        .with_privileged(true)
        .with_userns_mode("host")
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .expect("start k3s");
    let port = container.get_host_port_ipv4(KUBE_SECURE_PORT).await.expect("k3s port");
    let kubeconfig = container.image().read_kube_config().expect("kubeconfig");
    let kubeconfig = Kubeconfig::from_yaml(&kubeconfig).expect("parse kubeconfig");
    let ca_data = kubeconfig
        .clusters
        .first()
        .and_then(|c| c.cluster.as_ref())
        .and_then(|c| c.certificate_authority_data.clone())
        .expect("cluster CA");
    let ca_pem = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(ca_data)
            .expect("CA base64"),
    )
    .expect("CA PEM");
    let mut config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
        .await
        .expect("kube config");
    let url = format!("https://127.0.0.1:{port}");
    config.cluster_url = url.parse().expect("url");
    // k3s is on loopback, so a proxy from HTTPS_PROXY could never reach it.
    config.proxy_url = None;
    let client = Client::try_from(config).expect("kube client");
    Cluster {
        client,
        url,
        ca_pem,
        _container: container,
        _conf_dir: conf_dir,
    }
}

async fn get_json(client: &Client, path: &str) -> Value {
    let request = http::Request::get(path).body(Vec::new()).expect("request");
    let text = client.request_text(request).await.expect(path);
    serde_json::from_str(&text).expect("json")
}

struct Sekret {
    base: String,
    admin: String,
    http: reqwest::Client,
}

impl Sekret {
    async fn start() -> Self {
        let store = Arc::new(SqlStore::connect("sqlite::memory:").await.expect("store"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut config = ServerConfig::for_tests("sqlite::memory:");
        config.public_url = format!("http://{addr}");
        let root_key = RootKey::generate().expect("root key");
        sekret_server::check_root_key(store.as_ref(), &root_key.fingerprint())
            .await
            .expect("root key check");
        let state = build_state(Dependencies {
            store,
            root_key,
            config,
            clock: Arc::new(SystemClock),
            http: Arc::new(ReqwestOidcHttp::new(true).expect("http")),
            token_reviewer: Arc::new(ReqwestTokenReviewer::new(true)),
        });
        let app = sekret_server::app(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve");
        });
        let admin = sekret_server::admin::bootstrap_admin(&state, 3600)
            .await
            .expect("bootstrap");
        Self {
            base: format!("http://{addr}"),
            admin,
            http: reqwest::Client::new(),
        }
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: Value) -> Value {
        let response = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.admin)
            .json(&body)
            .send()
            .await
            .expect("request");
        let status = response.status();
        let text = response.text().await.expect("body");
        assert!(status.is_success(), "{path}: {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    async fn set_secrets(&self, pairs: &[(&str, &str)]) {
        let upserts: Vec<Value> = pairs.iter().map(|(k, v)| json!({"key": k, "value": v})).collect();
        self.send(
            reqwest::Method::POST,
            "/api/v1/projects/app/environments/prod/secrets/batch",
            json!({"path": "/", "upserts": upserts}),
        )
        .await;
    }

    /// Creates an identity that accepts service account tokens from `apps/reader`, verified by `method`.
    async fn kubernetes_identity(&self, name: &str, method: Value) -> String {
        let identity = self
            .send(reqwest::Method::POST, "/api/v1/identities", json!({"name": name}))
            .await;
        let id = identity["id"].as_str().expect("id").to_string();
        let mut config = json!({
            "kind": "kubernetes",
            "namespaces": [NAMESPACE], "service_accounts": [SERVICE_ACCOUNT], "audiences": ["sekret"]
        });
        for (key, value) in method.as_object().expect("method object") {
            config[key] = value.clone();
        }
        self.send(
            reqwest::Method::PUT,
            &format!("/api/v1/identities/{id}/auth/kubernetes"),
            config,
        )
        .await;
        self.send(
            reqwest::Method::POST,
            "/api/v1/projects/app/members",
            json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
        )
        .await;
        id
    }
}

async fn create_named<K>(api: &Api<K>, object: K)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    api.create(&PostParams::default(), &object).await.expect("create");
}

async fn wait_for<F, Fut, T>(what: &str, timeout: Duration, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn secret_value(secret: &Secret, key: &str) -> Option<String> {
    let bytes = secret.data.as_ref()?.get(key)?;
    String::from_utf8(bytes.0.clone()).ok()
}

async fn service_account_token(client: &Client, namespace: &str, name: &str, audience: &str) -> String {
    let request = TokenRequest {
        spec: TokenRequestSpec {
            audiences: vec![audience.into()],
            expiration_seconds: Some(600),
            ..TokenRequestSpec::default()
        },
        ..TokenRequest::default()
    };
    Api::<ServiceAccount>::namespaced(client.clone(), namespace)
        .create_token_request(name, &PostParams::default(), &request)
        .await
        .expect("token request")
        .status
        .expect("token status")
        .token
}

/// TokenReview mode works with a dedicated reviewer token, and is refused without one because the
/// API server does not accept a `sekret`-audience token as a bearer.
async fn token_review_logins(cluster: &Cluster, sekret: &Sekret, issuer: &str) {
    let client = &cluster.client;
    create_named(
        &Api::<ServiceAccount>::namespaced(client.clone(), "kube-system"),
        ServiceAccount {
            metadata: ObjectMeta {
                name: Some("sekret-reviewer".into()),
                ..ObjectMeta::default()
            },
            ..ServiceAccount::default()
        },
    )
    .await;
    create_named(
        &Api::<ClusterRoleBinding>::all(client.clone()),
        ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some("sekret-reviewer".into()),
                ..ObjectMeta::default()
            },
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".into(),
                kind: "ClusterRole".into(),
                name: "system:auth-delegator".into(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".into(),
                name: "sekret-reviewer".into(),
                namespace: Some("kube-system".into()),
                ..Subject::default()
            }]),
        },
    )
    .await;
    let reviewer = service_account_token(client, "kube-system", "sekret-reviewer", issuer).await;
    let review = |reviewer: Option<&str>| {
        let mut method = json!({"mode": "token-review", "host": cluster.url, "ca_cert": cluster.ca_pem});
        if let Some(token) = reviewer {
            method["reviewer_jwt"] = json!(token);
        }
        method
    };
    let with_reviewer = sekret.kubernetes_identity("reviewed", review(Some(&reviewer))).await;
    let without_reviewer = sekret.kubernetes_identity("self-reviewed", review(None)).await;

    let workload = service_account_token(client, NAMESPACE, SERVICE_ACCOUNT, "sekret").await;
    let login = |identity_id: String| {
        let workload = workload.clone();
        async move {
            let response = sekret
                .http
                .post(format!("{}/api/v1/auth/kubernetes/login", sekret.base))
                .json(&json!({"identity_id": identity_id, "token": workload}))
                .send()
                .await
                .expect("login");
            let status = response.status();
            (status, response.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let (status, body) = login(with_reviewer).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert!(body["access_token"].as_str().is_some_and(|t| t.starts_with("skt_")));
    let (status, _) = login(without_reviewer).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn syncs_a_sekret_path_into_a_kubernetes_secret() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cluster = start_cluster().await;
    let client = cluster.client.clone();

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    create_named(&crds, SekretSecret::crd()).await;
    let resources: Api<SekretSecret> = Api::namespaced(client.clone(), NAMESPACE);
    wait_for("the CRD to be served", Duration::from_secs(60), || async {
        resources.list(&Default::default()).await.ok()
    })
    .await;
    create_named(
        &Api::<Namespace>::all(client.clone()),
        Namespace {
            metadata: ObjectMeta {
                name: Some(NAMESPACE.into()),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        },
    )
    .await;
    create_named(
        &Api::<ServiceAccount>::namespaced(client.clone(), NAMESPACE),
        ServiceAccount {
            metadata: ObjectMeta {
                name: Some(SERVICE_ACCOUNT.into()),
                ..ObjectMeta::default()
            },
            ..ServiceAccount::default()
        },
    )
    .await;

    let issuer = get_json(&client, "/.well-known/openid-configuration").await["issuer"]
        .as_str()
        .expect("issuer")
        .to_string();
    let jwks = get_json(&client, "/openid/v1/jwks").await;

    let sekret = Sekret::start().await;
    sekret
        .send(
            reqwest::Method::POST,
            "/api/v1/projects",
            json!({"slug": "app", "name": "app"}),
        )
        .await;
    sekret
        .set_secrets(&[
            ("DATABASE_URL", "postgres://db/app"),
            ("API_KEY", "k1"),
            ("UNUSED", "x"),
        ])
        .await;
    let identity_id = sekret
        .kubernetes_identity("operator", json!({"mode": "jwks", "issuer": issuer, "jwks": jwks}))
        .await;

    let factory = HttpSekretFactory::new(sekret.base.clone(), ClientOptions::default()).expect("factory");
    let ctx = Arc::new(Context::new(
        Arc::new(KubeClient::new(client.clone())),
        Arc::new(factory),
    ));
    let controller = tokio::spawn(run_controller(client.clone(), ctx, Some(NAMESPACE), 2));

    let resource = SekretSecret::new(
        "app-config",
        SekretSecretSpec {
            project: "app".into(),
            environment: "prod".into(),
            path: "/".into(),
            recursive: false,
            keys: Some(vec!["DATABASE_URL".into(), "API_KEY".into()]),
            target: TargetSpec {
                name: "app-env".into(),
                secret_type: "Opaque".into(),
                labels: Default::default(),
                annotations: Default::default(),
            },
            refresh_interval: "10s".into(),
            auth: AuthSpec {
                identity_id,
                service_account_name: SERVICE_ACCOUNT.into(),
            },
        },
    );
    create_named(&resources, resource).await;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), NAMESPACE);
    let secret = wait_for("the synced Secret", Duration::from_secs(60), || async {
        secrets.get_opt("app-env").await.ok().flatten()
    })
    .await;
    assert_eq!(
        secret_value(&secret, "DATABASE_URL").as_deref(),
        Some("postgres://db/app")
    );
    assert_eq!(secret_value(&secret, "API_KEY").as_deref(), Some("k1"));
    assert_eq!(secret_value(&secret, "UNUSED"), None, "keys filter applies");
    let labels = secret.metadata.labels.clone().unwrap_or_default();
    assert_eq!(
        labels.get("app.kubernetes.io/managed-by").map(String::as_str),
        Some("sekret-operator")
    );
    let owners = secret.metadata.owner_references.clone().unwrap_or_default();
    assert_eq!(owners.first().map(|o| o.kind.as_str()), Some("SekretSecret"));

    let status = wait_for("Ready=True", Duration::from_secs(30), || async {
        let current = resources.get("app-config").await.ok()?;
        let status = current.status?;
        status.ready().is_some_and(|c| c.status == "True").then_some(status)
    })
    .await;
    assert_eq!(status.secret_count, Some(2));
    assert!(status.last_synced_at.is_some());

    token_review_logins(&cluster, &sekret, &issuer).await;

    sekret.set_secrets(&[("API_KEY", "k2")]).await;
    wait_for("the refreshed value", Duration::from_secs(60), || async {
        let secret = secrets.get_opt("app-env").await.ok().flatten()?;
        (secret_value(&secret, "API_KEY").as_deref() == Some("k2")).then_some(())
    })
    .await;

    controller.abort();
}
