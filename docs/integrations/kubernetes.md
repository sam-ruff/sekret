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

With `watchNamespace` empty, the operator watches every namespace and is granted cluster-wide rights to read and write `Secret` objects and create service account tokens. Set `watchNamespace` to confine it to one namespace with a `Role` instead, which is the safer choice if only one namespace needs it. For a server with a private CA, put the CA certificate in a ConfigMap and set `sekret.caBundle.configMapName`.

## Configure sekret

Create a machine identity with a [Kubernetes auth method](../user-guide/machine-identities.md#kubernetes) that allows the namespace and service account you will use, and give it a role on the project.

## Sync a secret

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-secrets
  namespace: web
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

The `type` can be `Opaque`, `kubernetes.io/tls`, `kubernetes.io/basic-auth`, `kubernetes.io/ssh-auth`, `kubernetes.io/dockercfg` or `kubernetes.io/dockerconfigjson`. Types that make the cluster act on the Secret, such as service account tokens, are refused.

The operator runs from the same binary as everything else, as `sekret operator`. `sekret operator crd` prints the CustomResourceDefinition.
