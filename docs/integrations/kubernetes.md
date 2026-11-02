# Kubernetes

The sekret operator copies secrets into ordinary Kubernetes `Secret` objects and keeps them up to date. Pods then use them the usual way, as environment variables or mounted files, with nothing sekret-specific inside the pod.

Each `SekretSecret` resource names a project, environment and folder, a target `Secret`, and a service account in its own namespace. The operator mints a short-lived token for that service account with the audience `sekret`, logs in to sekret as the machine identity named in the resource, fetches the values, writes the `Secret`, and logs out. It never stores a sekret credential.

## Install the operator

The chart is in `deploy/helm/sekret-operator` in the repository:

```sh
helm install sekret-operator deploy/helm/sekret-operator \
  --namespace sekret-system --create-namespace \
  --set image.repository=ghcr.io/sam-ruff/sekret \
  --set sekret.serverUrl=https://sekret.example.com
```

By default the operator watches only the namespace it is installed in. List the namespaces it should serve in `watchNamespaces`, and the chart gives it a `Role` and `RoleBinding` in each one and nothing anywhere else:

```sh
helm install sekret-operator deploy/helm/sekret-operator \
  --namespace sekret-system --create-namespace \
  --set image.repository=ghcr.io/sam-ruff/sekret \
  --set sekret.serverUrl=https://sekret.example.com \
  --set 'watchNamespaces={web,api}'
```

| Value | Default | What it does |
|---|---|---|
| `sekret.serverUrl` | none | The sekret server. Required. |
| `sekret.allowInsecureHttp` | `false` | Allows a plain `http://` server that is not on loopback. Service account tokens and secret values then cross the network unencrypted, so the operator refuses such a URL without it. |
| `sekret.caBundle.configMapName` | none | A ConfigMap holding the CA certificate of a server with a private CA. |
| `sekret.clientCertificate.secretName` | none | A `kubernetes.io/tls` Secret to present to a server that requires mutual TLS. |
| `watchNamespaces` | the release namespace | The namespaces to watch, each with its own `Role`. |
| `clusterWide` | `false` | Watches every namespace with a `ClusterRole`. Cannot be combined with `watchNamespaces`. |
| `tokenServiceAccounts` | all | Names of the only service accounts the operator may read and mint tokens for, in every watched namespace. Kubernetes enforces this through RBAC, so set it: the opt-in annotation below is only checked by the operator. The install notes warn while it is empty. |
| `serviceAccount.create` | `true` | Creates the operator's own service account. With `false`, name an existing account in `serviceAccount.name`. |
| `serviceAccount.name` | the release name | The operator's service account. Required when `serviceAccount.create` is `false`. The chart refuses `default`, since every pod in the namespace that names no account runs as it and would get the operator's rights. |
| `tokenPolicy.enabled` | `true` | Installs two `ValidatingAdmissionPolicy` objects. One lets the operator request only tokens with the `sekret` audience that expire within ten minutes, and none in `kube-system`. The other lets it write only the `Secret` types listed below and no `kubernetes.io/service-account.*` annotations, so it cannot have the cluster fill in a long-lived service account token instead. It also limits the operator to `Secret`s it manages: each must carry the label `app.kubernetes.io/managed-by: sekret-operator` and be controlled by a `SekretSecret`, an update may not move a `Secret` to another owner or take over one that has none, and nothing may be written in `kube-system`. So a bug in the operator, or someone holding its token, cannot overwrite your other `Secret`s. This guards what the operator writes, not what it reads: it can still read every `Secret` its role reaches. Needs Kubernetes 1.30 or later; set it to `false` on older clusters. |
| `tokenPolicy.acknowledgeClusterWideWithoutPolicy` | `false` | The chart refuses `clusterWide: true` with `tokenPolicy.enabled: false`, since the operator could then mint any token for any service account in the cluster. Set this to `true` to accept that. |

!!! warning "Cluster-wide mode is close to cluster-admin"
    With `clusterWide: true` the operator can read and write every `Secret` in the cluster and mint a token for any service account, including powerful ones in `kube-system`. Anyone who takes over the operator's pod or token gets the same reach. The token policy narrows what those tokens can be used for, but prefer listing namespaces in `watchNamespaces` unless you really need every one.

The chart's old `watchNamespace` value has gone. A release that still sets it fails to render, with a message saying to use `watchNamespaces` or `clusterWide` instead.

When running the binary directly, `sekret operator` needs either `--namespace web,api` (or `SEKRET_OPERATOR_NAMESPACE`) or `--all-namespaces` (or `SEKRET_OPERATOR_ALL_NAMESPACES=true`). It does not fall back to watching the whole cluster. `--allow-insecure-http` (or `SEKRET_OPERATOR_ALLOW_INSECURE_HTTP`) matches `sekret.allowInsecureHttp`. The operator uses `HTTPS_PROXY` and `NO_PROXY` only for an `https://` server; a plain `http://` or loopback server is always reached directly, so a proxy never sees its tokens in the clear.

## Configure sekret

Create a machine identity with a [Kubernetes auth method](../user-guide/machine-identities.md#kubernetes) that allows the namespace and service account you will use, and give it a role on the project.

## Let a service account be used

The operator only mints a token for a service account that carries the annotation `sekret.sam-ruff.github.io/allow-sekretsecret: "true"`. Without it, the `SekretSecret` stays not ready with the reason `ServiceAccountNotAllowed`, and no token is requested.

The annotation is a check inside the operator, not a cluster control. Its RBAC still lets it mint tokens for every service account in the watched namespaces, so a bug, or someone holding the operator's token, could skip the check. `tokenServiceAccounts` is the version Kubernetes enforces: list the accounts there as well.

!!! warning "Creating a SekretSecret is a powerful right"
    The operator acts with its own rights, not those of whoever created the `SekretSecret`. Anyone who can create a `SekretSecret` in a namespace, and read the `Secret` it writes, can use the sekret access of every opted-in service account there, without being allowed to create pods or tokens for those accounts. Grant `create` on `sekretsecrets` only to people who may already act as those service accounts. The right to annotate service accounts (`update` or `patch` on `serviceaccounts`) is just as powerful, because it can opt an account in. Give each workload its own service account and opt in only the ones meant for the operator.

## Sync a secret

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-secrets
  namespace: web
  annotations:
    sekret.sam-ruff.github.io/allow-sekretsecret: "true"
---
apiVersion: sekret.sam-ruff.github.io/v1alpha1
kind: SekretSecret
metadata:
  name: web-config
  namespace: web
spec:
  project: web
  environment: prod
  path: /
  keys: [DATABASE_URL, SESSION_KEY]  # optional; every key at the path when omitted
  refreshInterval: 5m
  target:
    name: web-env
    type: Opaque
  auth:
    identityId: 0192d4a8-0000-7000-8000-000000000000
    serviceAccountName: web-secrets
```

```sh
kubectl -n web get sekretsecrets
NAME         TARGET    READY   KEYS   SYNCED
web-config   web-env   True    2      2026-10-30T12:00:00Z
```

The operator owns the `Secret` it creates and refuses to overwrite one it did not create. Deleting the `SekretSecret` deletes the `Secret`. When a sync fails, the `Ready` condition says why, and the last good copy of the `Secret` stays in place.

The `type` can be `Opaque`, `kubernetes.io/tls`, `kubernetes.io/basic-auth`, `kubernetes.io/ssh-auth`, `kubernetes.io/dockercfg` or `kubernetes.io/dockerconfigjson`. Types that make the cluster act on the Secret, such as service account tokens, are refused, and so are `annotations` starting with `kubernetes.io/service-account.`.

The operator runs from the same binary as everything else, as `sekret operator`. `sekret operator crd` prints the CustomResourceDefinition.
