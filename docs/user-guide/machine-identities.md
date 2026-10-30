# Machine identities

A machine identity is an account for software: a CI pipeline, a pod, an Ansible run. It holds roles like a person does, and it logs in by presenting a credential to one of its auth methods. A successful login returns a short-lived access token, one hour by default, that the machine uses like a person's token.

Each identity has a token lifetime (`token_ttl`, default 3600 seconds) and a maximum lifetime (`token_max_ttl`, default 24 hours, at most a year). A token can be renewed with `POST /api/v1/auth/token/renew` until it reaches its maximum. An identity can also have trusted CIDRs, which limit where it can log in from and where its tokens can be used.

Create identities under *Organisation > Machine identities* in the web interface, then give them project roles under each project's *Members* tab. Disabling an identity revokes its tokens straight away.

There are three auth methods, and an identity can have any of them.

## OIDC

For anything that already has a signed token from an OIDC issuer: GitHub Actions, GitLab CI, a Keycloak service account, Forgejo Actions. sekret fetches the issuer's signing keys, checks the token's signature, issuer and lifetime, then checks the claims against the identity's bindings.

Bindings need at least one audience, plus either subject patterns or claim patterns, so that a token for some other workload at the same issuer cannot get in. Patterns use `*` as a wildcard.

```json
{
  "kind": "oidc",
  "issuer": "https://token.actions.githubusercontent.com",
  "bindings": {
    "audiences": ["sekret"],
    "subjects": ["repo:your-org/your-repo:ref:refs/heads/main"],
    "claims": {"repository_owner": ["your-org"]}
  }
}
```

Claim names may be JSON pointers (`/realm_access/roles`) for nested claims. See [GitHub Actions](../integrations/github-actions.md) for the workflow side.

## Kubernetes

For pods. The pod presents a service account token with the audience `sekret`, and sekret checks it one of two ways.

In JWKS mode, sekret checks the token's signature against the cluster's service account signing keys. Give it the cluster's issuer and either the keys themselves (from `kubectl get --raw /openid/v1/jwks`) or a URL to fetch them. It needs no network path to the cluster, but a deleted service account's tokens keep working until they expire, ten minutes for tokens minted by the operator.

In TokenReview mode, sekret asks the cluster's API server whether the token is valid. That needs a network path to the API server, its CA certificate, and a reviewer token: the token of a service account bound to the `system:auth-delegator` cluster role. The reviewer token is encrypted under the root key, shown as `[redacted]` afterwards, and sent only to the API server it was entered for. Changing the host, CA or mode requires entering it again.

Either way, the binding lists which namespaces and service account names are allowed, with `*` patterns.

```json
{
  "kind": "kubernetes",
  "mode": "jwks",
  "issuer": "https://kubernetes.default.svc.cluster.local",
  "jwks": {"keys": [{"kty": "RSA", "kid": "...", "n": "...", "e": "AQAB"}]},
  "namespaces": ["web"],
  "service_accounts": ["web-secrets"],
  "audiences": ["sekret"]
}
```

## Universal auth

A client id (the identity's id) and a client secret, for machines with no token of their own, such as a host running Ansible. Client secrets start with `sks_`, are shown once at creation, and are stored only as a hash. Each can have a lifetime and a maximum number of uses.

```sh
sekret login --client-id "$IDENTITY_ID" --client-secret-file /etc/app/sekret-secret
```

Revoking a client secret, or removing the universal auth method, revokes every access token it issued.
