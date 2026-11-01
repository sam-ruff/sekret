//! End to end: a k3s cluster, an in-process sekret server and the controller.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine;
use k8s_openapi::api::admissionregistration::v1::{ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding};
use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::{Namespace, Secret, ServiceAccount};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, Role, RoleBinding, RoleRef, Subject};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config, CustomResourceExt, Resource};
use sekret_client::ClientOptions;
use sekret_operator::{
    ALLOW_ANNOTATION, AuthSpec, Context, HttpSekretFactory, KubeClient, SekretSecret, SekretSecretSpec, TargetSpec,
    run_controller,
};
use sekret_server::clock::{Clock, SystemClock};
use sekret_server::config::ServerConfig;
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::seal::{AutoInit, StartupSecrets, open_keyring};
use sekret_server::state::{Dependencies, build_state};
use sekret_store::SqlStore;
use serde_json::{Value, json};
use testcontainers_modules::k3s::{K3s, KUBE_SECURE_PORT};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use zeroize::Zeroizing;

const K3S_TAG: &str = "v1.33.5-k3s1";
const PASSPHRASE: &str = "violet tractor sings beneath";
const NAMESPACE: &str = "apps";
const SERVICE_ACCOUNT: &str = "reader";
/// Exists in the namespace but has not opted in to SekretSecrets.
const UNAPPROVED_ACCOUNT: &str = "payments";
/// Where the chart is installed; the controller runs as its service account.
const OPERATOR_NAMESPACE: &str = "sekret-system";
const OPERATOR_USER: &str = "system:serviceaccount:sekret-system:sekret-sekret-operator";

struct Cluster {
    client: Client,
    config: Config,
    url: String,
    ca_pem: String,
    _container: ContainerAsync<K3s>,
    _conf_dir: tempfile::TempDir,
}

async fn start_cluster() -> anyhow::Result<Cluster> {
    let conf_dir = tempfile::tempdir().context("temp dir")?;
    let container = K3s::default()
        .with_conf_mount(conf_dir.path())
        .with_tag(K3S_TAG)
        .with_privileged(true)
        .with_userns_mode("host")
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .context("start k3s")?;
    let port = container
        .get_host_port_ipv4(KUBE_SECURE_PORT)
        .await
        .context("k3s port")?;
    let kubeconfig = container.image().read_kube_config().context("kubeconfig")?;
    let kubeconfig = Kubeconfig::from_yaml(&kubeconfig).context("parse kubeconfig")?;
    let ca_data = kubeconfig
        .clusters
        .first()
        .and_then(|c| c.cluster.as_ref())
        .and_then(|c| c.certificate_authority_data.clone())
        .context("cluster CA")?;
    let ca_pem = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(ca_data)
            .context("CA base64")?,
    )
    .context("CA PEM")?;
    let mut config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
        .await
        .context("kube config")?;
    let url = format!("https://127.0.0.1:{port}");
    config.cluster_url = url.parse().context("url")?;
    // k3s is on loopback, so a proxy from HTTPS_PROXY could never reach it.
    config.proxy_url = None;
    let client = Client::try_from(config.clone()).context("kube client")?;
    Ok(Cluster {
        client,
        config,
        url,
        ca_pem,
        _container: container,
        _conf_dir: conf_dir,
    })
}

/// A client that acts as the operator's service account, so the chart's RBAC and admission
/// policies apply to it.
fn operator_client(cluster: &Cluster) -> anyhow::Result<Client> {
    let mut config = cluster.config.clone();
    config.auth_info.impersonate = Some(OPERATOR_USER.into());
    Client::try_from(config).context("operator client")
}

/// Installs the chart's service account, RBAC and admission policies as `helm template` renders
/// them. Set HELM when helm is not on PATH.
async fn install_chart(client: &Client) -> anyhow::Result<()> {
    let helm = std::env::var("HELM").unwrap_or_else(|_| "helm".into());
    let chart = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/helm/sekret-operator");
    let output = std::process::Command::new(&helm)
        .args(["template", "sekret", chart, "--namespace", OPERATOR_NAMESPACE])
        .args(["--set", "sekret.serverUrl=https://sekret.example.com"])
        .arg("--set")
        .arg(format!("watchNamespaces={{{NAMESPACE}}}"))
        .args(["--show-only", "templates/serviceaccount.yaml"])
        .args(["--show-only", "templates/rbac.yaml"])
        .args(["--show-only", "templates/token-policy.yaml"])
        .output()
        .with_context(|| format!("run {helm}; the operator system test needs helm"))?;
    anyhow::ensure!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).context("helm output")?;
    let documents: Vec<Value> = serde_saphyr::from_multiple(&rendered).context("parse the rendered chart")?;
    for document in documents.into_iter().filter(|d| !d.is_null()) {
        let kind = document["kind"].as_str().context("kind")?.to_string();
        let namespace = document["metadata"]["namespace"].as_str().map(str::to_string);
        let namespaced = || namespace.clone().with_context(|| format!("{kind} has no namespace"));
        match kind.as_str() {
            "ServiceAccount" => {
                let api = Api::<ServiceAccount>::namespaced(client.clone(), &namespaced()?);
                create_named(&api, serde_json::from_value(document)?).await?;
            }
            "Role" => {
                let api = Api::<Role>::namespaced(client.clone(), &namespaced()?);
                create_named(&api, serde_json::from_value(document)?).await?;
            }
            "RoleBinding" => {
                let api = Api::<RoleBinding>::namespaced(client.clone(), &namespaced()?);
                create_named(&api, serde_json::from_value(document)?).await?;
            }
            "ValidatingAdmissionPolicy" => {
                let api = Api::<ValidatingAdmissionPolicy>::all(client.clone());
                create_named(&api, serde_json::from_value(document)?).await?;
            }
            "ValidatingAdmissionPolicyBinding" => {
                let api = Api::<ValidatingAdmissionPolicyBinding>::all(client.clone());
                create_named(&api, serde_json::from_value(document)?).await?;
            }
            other => anyhow::bail!("unexpected {other} in the rendered chart"),
        }
    }
    Ok(())
}

fn plain_secret(name: &str, secret_type: &str, annotations: &[(&str, &str)]) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(name.into()),
            annotations: Some(
                annotations
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            ..ObjectMeta::default()
        },
        type_: Some(secret_type.into()),
        ..Secret::default()
    }
}

/// The admission policy stops the operator from writing a Secret the token controller would fill
/// with a long-lived token, whatever its RBAC allows.
async fn operator_cannot_write_token_secrets(admin: &Client, operator: &Client) -> anyhow::Result<()> {
    let as_operator: Api<Secret> = Api::namespaced(operator.clone(), NAMESPACE);
    let as_admin: Api<Secret> = Api::namespaced(admin.clone(), NAMESPACE);
    let token_secret = plain_secret(
        "minted",
        "kubernetes.io/service-account-token",
        &[("kubernetes.io/service-account.name", SERVICE_ACCOUNT)],
    );
    // Policies take a moment to load, so retry until the denial shows up.
    let denial = wait_for("the Secret policy to load", Duration::from_secs(90), || async {
        match as_operator.create(&PostParams::default(), &token_secret).await {
            Ok(_) => {
                let _ = as_admin.delete("minted", &Default::default()).await;
                None
            }
            Err(error) => Some(error.to_string()),
        }
    })
    .await;
    assert!(denial.contains("only write Secrets that carry data"), "{denial}");

    let annotated = plain_secret(
        "annotated",
        "Opaque",
        &[("kubernetes.io/service-account.name", SERVICE_ACCOUNT)],
    );
    let denial = as_operator
        .create(&PostParams::default(), &annotated)
        .await
        .err()
        .context("an Opaque Secret with a service account annotation must be refused")?;
    assert!(
        denial.to_string().contains("may not write service account annotations"),
        "{denial}"
    );
    Ok(())
}

/// The admission policy confines the operator's writes to Secrets a SekretSecret controls, so a
/// bug or a stolen token cannot overwrite other Secrets its RBAC reaches.
async fn operator_writes_only_its_own_secrets(
    admin: &Client,
    operator: &Client,
    owner: &SekretSecret,
    other: &SekretSecret,
) -> anyhow::Result<()> {
    let as_operator: Api<Secret> = Api::namespaced(operator.clone(), NAMESPACE);
    let as_admin: Api<Secret> = Api::namespaced(admin.clone(), NAMESPACE);
    let owner_ref = owner.controller_owner_ref(&()).context("owner reference")?;
    let other_ref = other.controller_owner_ref(&()).context("other owner reference")?;
    let managed = |mut secret: Secret, owner| {
        secret.metadata.labels = Some(
            [(
                "app.kubernetes.io/managed-by".to_string(),
                "sekret-operator".to_string(),
            )]
            .into(),
        );
        secret.metadata.owner_references = Some(vec![owner]);
        secret
    };

    let denial = as_operator
        .create(&PostParams::default(), &plain_secret("stray", "Opaque", &[]))
        .await
        .err()
        .context("an unmarked Secret must be refused")?;
    assert!(
        denial
            .to_string()
            .contains("only write Secrets it manages for a SekretSecret"),
        "{denial}"
    );

    as_admin
        .create(&PostParams::default(), &plain_secret("foreign", "Opaque", &[]))
        .await
        .context("admin creates a Secret the operator does not own")?;
    let foreign = as_admin.get("foreign").await.context("foreign secret")?;
    let denial = as_operator
        .replace("foreign", &PostParams::default(), &managed(foreign, owner_ref.clone()))
        .await
        .err()
        .context("taking over a Secret by adding an owner must be refused")?;
    assert!(
        denial
            .to_string()
            .contains("only change Secrets its SekretSecret already controls"),
        "{denial}"
    );

    let owned = as_admin.get("app-env").await.context("synced secret")?;
    let denial = as_operator
        .replace("app-env", &PostParams::default(), &managed(owned, other_ref))
        .await
        .err()
        .context("moving a Secret to another SekretSecret must be refused")?;
    assert!(
        denial
            .to_string()
            .contains("only change Secrets its SekretSecret already controls"),
        "{denial}"
    );
    as_admin
        .delete("foreign", &Default::default())
        .await
        .context("clean up")?;
    Ok(())
}

async fn get_json(client: &Client, path: &str) -> anyhow::Result<Value> {
    let request = http::Request::get(path).body(Vec::new()).context("request")?;
    let text = client.request_text(request).await.with_context(|| path.to_string())?;
    serde_json::from_str(&text).context("json")
}

struct Sekret {
    base: String,
    admin: String,
    http: reqwest::Client,
}

impl Sekret {
    /// A passphrase-mode server set up through the production start path, so it can be sealed.
    async fn start() -> anyhow::Result<Self> {
        let store = Arc::new(SqlStore::connect("sqlite::memory:").await.context("store")?);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let addr = listener.local_addr().context("addr")?;
        let mut config = ServerConfig::for_tests("sqlite::memory:");
        config.public_url = format!("http://{addr}");
        let secrets = StartupSecrets {
            unlock_passphrase: None,
            auto_init: Some(AutoInit {
                passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
            }),
        };
        let opened = open_keyring(store.as_ref(), SystemClock.now(), &config.seal, secrets)
            .await
            .context("open keyring")?;
        let state = build_state(Dependencies {
            store,
            keyring: opened.keyring,
            config,
            clock: Arc::new(SystemClock),
            http: Arc::new(ReqwestOidcHttp::new(true).context("http")?),
            token_reviewer: Arc::new(ReqwestTokenReviewer::new(true)),
        });
        let app = sekret_server::app(state.clone());
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
                eprintln!("serve: {error}");
            }
        });
        let admin = sekret_server::admin::bootstrap_admin(&state, 3600)
            .await
            .map_err(|error| anyhow::anyhow!("bootstrap: {error:?}"))?;
        Ok(Self {
            base: format!("http://{addr}"),
            admin,
            http: reqwest::Client::new(),
        })
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: Value) -> anyhow::Result<Value> {
        let response = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.admin)
            .json(&body)
            .send()
            .await
            .context("request")?;
        let status = response.status();
        let text = response.text().await.context("body")?;
        assert!(status.is_success(), "{path}: {status} {text}");
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn unseal(&self) -> anyhow::Result<Value> {
        let response = self
            .http
            .post(format!("{}/api/v1/sys/unseal", self.base))
            .json(&json!({"passphrase": PASSPHRASE}))
            .send()
            .await
            .context("unseal")?;
        let status = response.status();
        let body: Value = response.json().await.context("json")?;
        assert!(status.is_success(), "unseal: {status} {body}");
        Ok(body)
    }

    async fn set_secrets(&self, pairs: &[(&str, &str)]) -> anyhow::Result<()> {
        let upserts: Vec<Value> = pairs.iter().map(|(k, v)| json!({"key": k, "value": v})).collect();
        self.send(
            reqwest::Method::POST,
            "/api/v1/projects/app/environments/prod/secrets/batch",
            json!({"path": "/", "upserts": upserts}),
        )
        .await?;
        Ok(())
    }

    /// Creates an identity that accepts service account tokens from `apps/reader`, verified by `method`.
    async fn kubernetes_identity(&self, name: &str, method: Value) -> anyhow::Result<String> {
        let identity = self
            .send(reqwest::Method::POST, "/api/v1/identities", json!({"name": name}))
            .await?;
        let id = identity["id"].as_str().context("id")?.to_string();
        let mut config = json!({
            "kind": "kubernetes",
            "namespaces": [NAMESPACE], "service_accounts": [SERVICE_ACCOUNT], "audiences": ["sekret"]
        });
        for (key, value) in method.as_object().context("method object")? {
            config[key] = value.clone();
        }
        self.send(
            reqwest::Method::PUT,
            &format!("/api/v1/identities/{id}/auth/kubernetes"),
            config,
        )
        .await?;
        self.send(
            reqwest::Method::POST,
            "/api/v1/projects/app/members",
            json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
        )
        .await?;
        Ok(id)
    }
}

async fn create_named<K>(api: &Api<K>, object: K) -> anyhow::Result<()>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    api.create(&PostParams::default(), &object).await.context("create")?;
    Ok(())
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

async fn service_account_token(client: &Client, namespace: &str, name: &str, audience: &str) -> anyhow::Result<String> {
    let request = TokenRequest {
        spec: TokenRequestSpec {
            audiences: vec![audience.into()],
            expiration_seconds: Some(600),
            ..TokenRequestSpec::default()
        },
        ..TokenRequest::default()
    };
    Ok(Api::<ServiceAccount>::namespaced(client.clone(), namespace)
        .create_token_request(name, &PostParams::default(), &request)
        .await
        .context("token request")?
        .status
        .context("token status")?
        .token)
}

/// TokenReview mode works with a dedicated reviewer token, and is refused without one because the
/// API server does not accept a `sekret`-audience token as a bearer.
async fn token_review_logins(cluster: &Cluster, sekret: &Sekret, issuer: &str) -> anyhow::Result<()> {
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
    .await?;
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
    .await?;
    let reviewer = service_account_token(client, "kube-system", "sekret-reviewer", issuer).await?;
    let review = |reviewer: Option<&str>| {
        let mut method = json!({"mode": "token-review", "host": cluster.url, "ca_cert": cluster.ca_pem});
        if let Some(token) = reviewer {
            method["reviewer_jwt"] = json!(token);
        }
        method
    };
    let with_reviewer = sekret.kubernetes_identity("reviewed", review(Some(&reviewer))).await?;
    let without_reviewer = sekret.kubernetes_identity("self-reviewed", review(None)).await?;

    let workload = service_account_token(client, NAMESPACE, SERVICE_ACCOUNT, "sekret").await?;
    let login = |identity_id: String| {
        let workload = workload.clone();
        async move {
            let response = sekret
                .http
                .post(format!("{}/api/v1/auth/kubernetes/login", sekret.base))
                .json(&json!({"identity_id": identity_id, "token": workload}))
                .send()
                .await
                .context("login")?;
            let status = response.status();
            anyhow::Ok((status, response.json::<Value>().await.unwrap_or(Value::Null)))
        }
    };
    let (status, body) = login(with_reviewer).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert!(body["access_token"].as_str().is_some_and(|t| t.starts_with("skt_")));
    let (status, _) = login(without_reviewer).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn syncs_a_sekret_path_into_a_kubernetes_secret() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cluster = start_cluster().await?;
    let client = cluster.client.clone();

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    create_named(&crds, SekretSecret::crd()).await?;
    let resources: Api<SekretSecret> = Api::namespaced(client.clone(), NAMESPACE);
    wait_for("the CRD to be served", Duration::from_secs(60), || async {
        resources.list(&Default::default()).await.ok()
    })
    .await;
    for name in [NAMESPACE, OPERATOR_NAMESPACE] {
        create_named(
            &Api::<Namespace>::all(client.clone()),
            Namespace {
                metadata: ObjectMeta {
                    name: Some(name.into()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        )
        .await?;
    }
    install_chart(&client).await?;
    let operator = operator_client(&cluster)?;
    operator_cannot_write_token_secrets(&client, &operator).await?;
    let accounts = Api::<ServiceAccount>::namespaced(client.clone(), NAMESPACE);
    create_named(
        &accounts,
        ServiceAccount {
            metadata: ObjectMeta {
                name: Some(SERVICE_ACCOUNT.into()),
                annotations: Some([(ALLOW_ANNOTATION.to_string(), "true".to_string())].into()),
                ..ObjectMeta::default()
            },
            ..ServiceAccount::default()
        },
    )
    .await?;
    create_named(
        &accounts,
        ServiceAccount {
            metadata: ObjectMeta {
                name: Some(UNAPPROVED_ACCOUNT.into()),
                ..ObjectMeta::default()
            },
            ..ServiceAccount::default()
        },
    )
    .await?;

    let issuer = get_json(&client, "/.well-known/openid-configuration").await?["issuer"]
        .as_str()
        .context("issuer")?
        .to_string();
    let jwks = get_json(&client, "/openid/v1/jwks").await?;

    let sekret = Sekret::start().await?;
    sekret
        .send(
            reqwest::Method::POST,
            "/api/v1/projects",
            json!({"slug": "app", "name": "app"}),
        )
        .await?;
    sekret
        .set_secrets(&[
            ("DATABASE_URL", "postgres://db/app"),
            ("API_KEY", "k1"),
            ("UNUSED", "x"),
        ])
        .await?;
    let identity_id = sekret
        .kubernetes_identity("operator", json!({"mode": "jwks", "issuer": issuer, "jwks": jwks}))
        .await?;

    let factory = HttpSekretFactory::new(sekret.base.clone(), ClientOptions::default()).context("factory")?;
    let ctx = Arc::new(Context::new(
        Arc::new(KubeClient::new(operator.clone())),
        Arc::new(factory),
    ));
    let controller = tokio::spawn(run_controller(operator.clone(), ctx, Some(NAMESPACE), 2));

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
    let mut unapproved = resource.clone();
    unapproved.metadata.name = Some("unapproved".into());
    unapproved.spec.target.name = "unapproved-env".into();
    unapproved.spec.auth.service_account_name = UNAPPROVED_ACCOUNT.into();
    create_named(&resources, resource).await?;
    create_named(&resources, unapproved).await?;

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

    let mut relabelled = secrets.get("app-env").await.context("synced secret")?;
    relabelled
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert("kubernetes.io/service-account.name".into(), SERVICE_ACCOUNT.into());
    let denial = Api::<Secret>::namespaced(operator.clone(), NAMESPACE)
        .replace("app-env", &PostParams::default(), &relabelled)
        .await
        .err()
        .context("the operator must not add a service account annotation to a Secret")?;
    assert!(
        denial.to_string().contains("may not write service account annotations"),
        "{denial}"
    );
    let owner = resources.get("app-config").await.context("resource")?;
    let other = resources.get("unapproved").await.context("other resource")?;
    operator_writes_only_its_own_secrets(&client, &operator, &owner, &other).await?;

    let refused = wait_for(
        "the unapproved account to be refused",
        Duration::from_secs(30),
        || async {
            let status = resources.get("unapproved").await.ok()?.status?;
            status.ready().filter(|c| c.status == "False").map(|c| c.reason.clone())
        },
    )
    .await;
    assert_eq!(refused, "ServiceAccountNotAllowed");
    assert!(
        secrets.get_opt("unapproved-env").await.context("get")?.is_none(),
        "no Secret for an account that has not opted in"
    );

    token_review_logins(&cluster, &sekret, &issuer).await?;

    sekret.set_secrets(&[("API_KEY", "k2")]).await?;
    wait_for("the refreshed value", Duration::from_secs(60), || async {
        let secret = secrets.get_opt("app-env").await.ok().flatten()?;
        (secret_value(&secret, "API_KEY").as_deref() == Some("k2")).then_some(())
    })
    .await;

    // Sealing the server fails every sync, so the resource goes not-ready and the Secret keeps
    // its last values; unsealing brings it back without restarting anything.
    let sealed = sekret
        .send(reqwest::Method::POST, "/api/v1/sys/seal", json!({}))
        .await?;
    assert_eq!(sealed["state"], "sealed");
    let ready_is = |wanted: &'static str| {
        let resources = resources.clone();
        move || {
            let resources = resources.clone();
            async move {
                let status = resources.get("app-config").await.ok()?.status?;
                status.ready().is_some_and(|c| c.status == wanted).then_some(status)
            }
        }
    };
    let not_ready = wait_for("Ready=False while sealed", Duration::from_secs(60), ready_is("False")).await;
    assert!(not_ready.ready().is_some_and(|c| c.reason != "Synced"));
    let kept = secrets.get("app-env").await.context("secret while sealed")?;
    assert_eq!(secret_value(&kept, "API_KEY").as_deref(), Some("k2"));

    assert_eq!(sekret.unseal().await?["state"], "unsealed");
    wait_for("Ready=True after unsealing", Duration::from_secs(60), ready_is("True")).await;
    sekret.set_secrets(&[("API_KEY", "k3")]).await?;
    wait_for("a value written after unsealing", Duration::from_secs(60), || async {
        let secret = secrets.get_opt("app-env").await.ok().flatten()?;
        (secret_value(&secret, "API_KEY").as_deref() == Some("k3")).then_some(())
    })
    .await;

    controller.abort();
    Ok(())
}
