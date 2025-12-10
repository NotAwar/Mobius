# Automatic Labeling System

This repository uses an automatic labeling system for issues and pull requests to help with organization and triage.

## Issue Templates

We provide several issue templates that automatically apply appropriate labels:

### 🐛 Bug Report (`bug_report.yml`)

- **Labels**: `bug`, `triage`
- Use this template to report bugs or unexpected behavior
- Includes structured fields for description, steps to reproduce, expected vs actual behavior, and environment information

### ✨ Feature Request (`feature_request.yml`)

- **Labels**: `enhancement`, `triage`
- Use this template to suggest new features or enhancements
- Includes fields for problem statement, proposed solution, alternatives, and use cases

### 📖 Documentation Issue (`documentation.yml`)

- **Labels**: `documentation`, `triage`
- Use this template to report documentation issues or improvements
- Includes fields for issue type, location, and suggested fixes

### 🔒 Security Issue (`security.yml`)

- **Labels**: `security`, `triage`
- Use this template to report security vulnerabilities or concerns
- **Note**: For sensitive vulnerabilities, use GitHub's private security advisory feature

### 🔄 Release QA (`release-qa.md`)

- **Labels**: `release`, `qa`, `~engineering-initiated`
- Template for release quality assurance testing
- Includes comprehensive testing checklists for all components

## Automatic Pull Request Labeling

Pull requests are automatically labeled based on:

### File Changes

- **`backend`**: Changes to `server/api/`, `cocoon/portal/`, `common/shared/`
- **`frontend`**: Changes to `ui/web/`, `*.svelte`, `*.ts`, `*.js`, `*.css`, `*.html`
- **`cli`**: Changes to `server/cli/`
- **`client`**: Changes to `client/client/`
- **`cocoon`**: Changes to `cocoon/portal/`
- **`documentation`**: Changes to `docs/`, `*.md`, `*.rst`, `*.txt`
- **`configuration`**: Changes to `*.yml`, `*.yaml`, `*.json`, `*.toml`, `*.ini`, `Dockerfile*`, `docker-compose*`
- **`ci/cd`**: Changes to `.github/`, `scripts/`, `tools/`, `Makefile`, `.golangci.yml`
- **`security`**: Changes to security-related directories
- **`database`**: Changes to migrations, schema, datastore
- **`testing`**: Changes to test files
- **`deployment`**: Changes to deployment configurations
- **`dependencies`**: Changes to `go.mod`, `package.json`, etc.

### Size Labels

- **`size/small`**: 1-5 files changed
- **`size/medium`**: 6-15 files changed
- **`size/large`**: 16-50 files changed
- **`size/extra-large`**: 50+ files changed

### Title/Content Analysis

- **`bug`**: Title contains "fix" or "bug"
- **`enhancement`**: Title contains "feat" or "feature"
- **`documentation`**: Title contains "doc" or "docs"
- **`security`**: Title contains "security" or "sec"
- **`testing`**: Title contains "test" or "tests"
- **`refactor`**: Title contains "refactor" or "cleanup"
- **`performance`**: Title contains "performance" or "perf"
- **`ci/cd`**: Title contains "ci" or "build"
- **`breaking-change`**: Title or body contains "breaking"
- **`work-in-progress`**: Title contains "wip" or "draft"
- **`priority/high`**: Title or body contains "urgent" or "critical"

## Automatic Issue Labeling

Issues are automatically labeled based on:

### Template Selection

Labels are automatically applied based on the issue template used (see templates above).

### Content Analysis

- **Platform labels**: `platform/macos`, `platform/windows`, `platform/linux`, `platform/ios`, `platform/android`
- **Priority labels**: `priority/high` for urgent/critical issues
- **Type detection**: Additional labels based on issue content

## Available Labels

### Type Labels

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Documentation improvements
- `security` - Security related issues
- `testing` - Testing related
- `refactor` - Code refactoring
- `performance` - Performance improvements

### Component Labels

- `backend` - Backend/server changes
- `frontend` - Frontend/UI changes
- `cli` - Command line interface
- `client` - Client library
- `cocoon` - Cocoon component
- `database` - Database related
- `deployment` - Deployment related

### Process Labels

- `triage` - Needs initial review
- `work-in-progress` - Work in progress
- `breaking-change` - Breaking changes
- `ci/cd` - CI/CD related
- `configuration` - Configuration changes
- `dependencies` - Dependency updates

### Priority Labels

- `priority/high` - High priority
- `priority/medium` - Medium priority
- `priority/low` - Low priority

### Size Labels

- `size/small` - Small changes (1-5 files)
- `size/medium` - Medium changes (6-15 files)
- `size/large` - Large changes (16-50 files)
- `size/extra-large` - Extra large changes (50+ files)

### Platform Labels

- `platform/macos` - macOS specific
- `platform/windows` - Windows specific
- `platform/linux` - Linux specific
- `platform/ios` - iOS specific
- `platform/android` - Android specific

### Workflow Labels

- `release` - Release related
- `qa` - Quality assurance
- `~engineering-initiated` - Engineering initiated
- `stale` - Stale issue or PR

## Manual Label Management

Repository maintainers can:

1. Run the "Setup Repository Labels" workflow to create/update all labels
2. Manually add or remove labels as needed
3. Create custom labels for specific needs

The automatic labeling system is designed to supplement, not replace, manual curation by maintainers.

## Integration with Existing Workflows

The labeling system integrates with:

- **Stale Issue Management**: Uses `~engineering-initiated` and `stale` labels
- **Release Process**: Uses `release` and `qa` labels for release management
- **Triage Process**: Adds `triage` label to new items needing review

## Troubleshooting

If automatic labeling isn't working:

1. Check that the workflow permissions are correct
2. Ensure the repository has the necessary labels (run the setup workflow)
3. Verify that issue templates are properly formatted
4. Check workflow run logs for errors

For questions or improvements to the labeling system, please open an issue using the appropriate template.
