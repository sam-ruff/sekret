# Security model

sekret protects secrets at rest with envelope encryption and protects access with short-lived tokens and fine-grained roles. It does not protect secrets from the server itself. Whoever controls the server process, or holds both the database and the root key, can read every value. That is the price of having no keys on clients, and it makes sekret a poor fit if you need to hide secrets from the people who run it.

## Encryption

Each project has a random 256-bit data key, stored wrapped (encrypted) under the root key. Each value is encrypted with its project's data key using XChaCha20-Poly1305, with a random 192-bit nonce per version. The additional authenticated data ties the ciphertext to its project, secret and version, so copying a ciphertext from one row or project to another makes it fail to decrypt rather than show up under the wrong name. Stored credentials, such as Kubernetes reviewer tokens, are encrypted under the root key and tied to their identity the same way.

Key material is wiped from memory when it is dropped. Key names, folder paths, comments, tags and the audit log are not encrypted.

## Tokens

Every token, whether a browser session, a CLI login or a machine login, is 256 random bits, stored only as a SHA-256 hash, and has an expiry and a maximum lifetime. Tokens can be revoked one at a time, all at once for an identity, or by revoking the credential that issued them. Browser sessions travel in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` over HTTPS), and every request that changes something and carries a session cookie must also carry an `x-sekret-csrf` header, which another site's form cannot add.

## Sign-in

Browser sign-in uses the OIDC authorisation code flow with PKCE, a one-time state value tied to the browser by a cookie, and a nonce checked in the ID token. Machine logins accept only asymmetric signatures (RS, PS, ES and EdDSA families), check expiry, not-before and issued-at against the server's clock with 30 seconds of leeway, and require bindings that pin the audience and the subject or other claims.

Login endpoints are rate limited per client address.

## Transport

By default sekret speaks plain HTTP and expects a reverse proxy to provide TLS. It can also serve HTTPS itself and require client certificates (mutual TLS); see [Configuration](configuration.md#tls-and-mutual-tls).

Outgoing requests, to OIDC issuers and Kubernetes API servers, must use HTTPS unless `--allow-insecure-http` is set, never carry credentials in the URL, and do not follow redirects.

## The web interface

The interface is served with a Content Security Policy that allows scripts only from the server itself, forbids framing, and sets `nosniff`. Uploaded logos are decoded and re-encoded as PNG before they are stored, so no uploaded file is ever served back as sent.

## Reporting a problem

Please report security issues privately through GitHub's security advisories on the repository rather than in a public issue.
