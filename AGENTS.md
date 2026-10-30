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
