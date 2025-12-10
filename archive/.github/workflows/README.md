# Github Actions

Mobius uses Github Actions for continuous integration (CI). This document describes best practices
and at patterns for writing and maintaining Mobius's Github Actions workflows.

## Bash

By default, Github Actions sets the shell to `bash -e` for linux and MacOS runners. To help write
safer bash scripts in run jobs and avoid common issues, override the default by adding the following
to the workflow file

```
defaults:
  run:
    # fail-fast using bash -eo pipefail. See https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#exit-codes-and-error-action-preference
    shell: bash
```

By specifying the default shell to `bash`, some extra flags are set. The option `pipefail` changes
the behaviour when using the pipe `|` operator such that if any command in a pipeline fails, that
commands return code will be used a the return code for the whole pipeline. Consider the following
example in `test-go.yaml`

```
    - name: Run Go Tests
      run: |
        # omitted ...
          make test-go 2>&1 | tee /tmp/gotest.log
```

If the `pipefail` option was *not* set, this job would always succeed because `tee` would always
return success. This is not the intended behavior.  Instead, we want the job to fail if `make
test-go` fails.

## Concurrency

Github Action runners are limited. If a lot of workflows are queued, they will wait in pending until
a runner becomes available. This has caused issue in the past where workflows take an excessively long
time to start. To help with this issue, use the following in workflows

```
# This allows a subsequently queued workflow run to interrupt previous runs
concurrency:
  group: ${{ github.workflow }}-${{ github.head_ref || github.run_id}}
  cancel-in-progress: true
```

When a workflow is triggered via a pull request, it will cancel previous running workflows for that
pull request. This is especially useful when changes are pushed to a pull request frequently.
Manually triggered workflows, workflows that run on a schedule, and workflows triggered by pushes to
`main` are unaffected.

## Notable workflows

### Core CI/CD

- **build-and-deploy.yml**: Main CI/CD pipeline - tests, builds, and pushes
  Docker images for all components (server, cli, client, cocoon). Handles
  multi-arch builds and SBOM generation.
- **unit-tests.yml**: Runs unit tests per Go module (server/api, server/cli,
  client/client, cocoon/portal, common/shared) with coverage aggregation.
- **golangci-lint.yml**: Lints Go code across all modules on push/PR.

### Security & Compliance

- **codeql.yml**: CodeQL security analysis for Go and JavaScript/TypeScript
  code.
- **dependency-review.yml**: Reviews dependencies for known vulnerabilities on
  PRs.
- **check-vulnerabilities-in-released-docker-images.yml**: Scans released
  container images using Trivy with VEX support.
- **code-sign-windows.yml**: Signs Windows binaries for release.
- **update-security.yml**: Monthly security documentation updates and
  vulnerability checks.

### Deployment & Infrastructure

- **release-helm.yaml**: Publishes Helm charts to GitHub Pages on releases.
- **update-tuf-timestamp-signature.yaml**: Updates TUF (The Update Framework)
  timestamps.

### Automation & Maintenance

- **conventional-commits.yml**: Validates PR titles follow conventional commits
  spec.
- **auto-label.yml**: Automatically labels PRs based on file changes and
  content.
- **auto-label-issues.yml**: Automatically labels issues based on templates.
- **auto-triage-issues.yml**: Auto-triages new issues.
- **close-stale-eng-initiated-issues.yml**: Closes stale engineering-initiated
  issues.
- **setup-labels.yml**: Sets up repository labels.
- **update-certs.yml**: Updates certificates.
- **update-osquery-versions.yml**: Updates osquery version references.
- **check-updates-timestamps.yml**: Checks update timestamps.

### Deployment with Score

The platform uses [Score](https://score.dev) for platform-agnostic deployment
specifications. Score files are located at:

- `score.yaml` - Main platform specification
- `deployments/score.yaml` - Deployment-specific configuration
- Component-specific score files in module directories

Use `score-compose` to generate Docker Compose configurations from Score specs:

```bash
score-compose init
score-compose generate score.yaml
```
