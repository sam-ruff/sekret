# GitHub Actions

A workflow can log in to sekret with the OIDC token GitHub issues to every job, so there is no stored credential to leak or rotate. The job needs `id-token: write`, and sekret needs a machine identity whose OIDC auth method trusts GitHub's issuer and your repository.

## Set up the identity

Create a machine identity, add an OIDC auth method, and bind it to your repository and branch:

```json
{
  "kind": "oidc",
  "issuer": "https://token.actions.githubusercontent.com",
  "bindings": {
    "audiences": ["sekret"],
    "subjects": ["repo:your-org/your-repo:ref:refs/heads/main"]
  }
}
```

The subject is how GitHub names the job's context. Pull request jobs have `repo:your-org/your-repo:pull_request`, and jobs using an environment have `repo:your-org/your-repo:environment:production`. A binding on `repository_owner` or `job_workflow_ref` in `claims` can narrow it further.

Then give the identity a role on the project, usually `viewer`, or a custom role limited to the environment the workflow deploys.

## Use it in a workflow

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: [self-hosted, linux]
    env:
      SEKRET_URL: https://sekret.example.com
      SEKRET_PROJECT: web
    steps:
      - uses: actions/checkout@v4
      - name: Install sekret
        run: curl -fsSL https://raw.githubusercontent.com/sam-ruff/sekret/main/install.sh | SEKRET_INSTALL_DIR="$HOME/.local/bin" sh
      - name: Log in
        run: echo "SEKRET_TOKEN=$(sekret login --github-actions --identity-id ${{ vars.SEKRET_IDENTITY_ID }} --print-token)" >> "$GITHUB_ENV"
      - name: Deploy with secrets
        run: sekret run -e prod -- ./deploy.sh
```

`--print-token` prints the access token instead of saving it, and writing it to `$GITHUB_ENV` makes it available to later steps. GitHub masks values in logs only when it knows them, so add `echo "::add-mask::$token"` if you print the token anywhere else.

The token lasts for the identity's `token_ttl`, an hour by default, which covers most jobs.
