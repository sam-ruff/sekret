# sekret

## Private notes

Read `PRIVATE.md` in the repository root before doing anything involving accounts, credentials, signing keys, external registrations or infrastructure. It is gitignored and holds details that must not appear in this repository. The pre-commit hook refuses any commit that tracks a `PRIVATE.md`. Never copy its contents into tracked files, commit messages, issues or pull requests. If it is missing, create it from the outline in the `new-repo-setup` skill and ask the owner for the details.

## Hooks

Run `scripts/install-hooks.sh` once after cloning. It points git at `.githooks`.

## Working here

- Rust workspace under `crates/`, frontend under `web/`, Ansible collection under `integrations/ansible/`, Helm chart under `deploy/helm/`.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` must pass.
- The binary embeds whatever is in `web/dist` at compile time. Run `npm run build` in `web/` first for a binary with the interface; `scripts/build-release.sh` does this and checks the result with `sekret admin web-check`.
- Docs live in `docs/` and build with Zensical (`uvx zensical build`, config in `zensical.toml`). Keep them in step with behaviour changes.
- The container image copies the prebuilt `dist/sekret-linux-amd64` into a `scratch` image; `docker build .` needs `scripts/build-release.sh` run first.
- Releases come from semantic-release on `main` through the shared workflows in `sam-ruff/actions`: conventional commits decide the version, then the musl binary, the GHCR image and the docs site are published from the tag.
- CI runs only on the self-hosted runner pool. Keep "Require approval for all outside collaborators" set in the repository's Actions settings: a fork pull request can rewrite the workflow, so that setting, not the workflow's own `if:` guards, is what keeps untrusted code off the runners.
- `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!` and `unimplemented!` are denied everywhere, tests included. Return errors and use `?` with context.

## Finishing a feature

Every new feature goes through all of these before it is merged or released. None of them is optional for a change that touches the API, authentication, cryptography, configuration or the interface.

- **Tests that prove the behaviour.**
  - **Coverage:** add unit tests, server integration tests on both SQLite and Postgres (`on_both_backends!`), CLI integration tests against the real binary, and Playwright tests in both the mock suite and the live suite, on desktop and mobile.
  - **Existing tests:** extend them where the feature changes what they cover, rather than only adding new ones beside them.
  - **Options:** every configuration option is tested through each way it can be set (YAML file, flag and environment variable), including precedence between them and combinations with other options that change its meaning. Each test asserts the option actually changes behaviour, not just that it parses.
- **A thorough security audit.**
  - **Who:** fresh agents on the same model, given the code but not the author's conclusions.
  - **Scope:** split by area, such as cryptography, server authorisation and state, configuration and files, CLI, and web. Cover at least:
    - authorisation on every new route;
    - state machine bypasses;
    - cryptographic construction and misuse;
    - timing and oracle leaks;
    - secrets reaching logs, errors, audit entries, backups or the browser;
    - file permissions, symlinks and races;
    - rate limiting and denial of service;
    - injection and XSS;
    - CSRF;
    - configuration that silently weakens security;
    - upgrade and downgrade paths from older databases.
  - **Follow-through:** every finding is fixed or explicitly accepted with a reason, with a regression test for each fix. Repeat the audit until it comes back clean.
- **A UI and UX review** by a fresh agent driving the running app in a browser, at mobile and desktop widths and in light and dark themes. It checks layout, copy, empty, error and loading states, keyboard use and accessibility, and that the flow makes sense to someone new to sekret. Fix what it finds.
- **Docs.** Update the docs pages and the README where behaviour changes, and refresh screenshots that show the changed screens.
