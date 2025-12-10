# Conventional Commits for Mobius

This repository enforces [Conventional Commits](https://www.conventionalcommits.org/) for all pull requests merged into the main branch.

## Requirements

### PR Title Format
All pull request titles must follow the Conventional Commits format:

```
<type>[optional scope]: <description>
```

**Examples:**
- `feat: add user authentication`
- `fix: resolve memory leak in server`
- `docs: update API documentation`
- `feat(cli): add new command for device management`
- `fix(server): handle null pointer exception`
- `feat!: remove deprecated API endpoints` (breaking change)

### Allowed Types

| Type | Description | Example |
|------|-------------|---------|
| `feat` | New feature | `feat: add device enrollment endpoint` |
| `fix` | Bug fix | `fix: resolve login timeout issue` |
| `docs` | Documentation changes | `docs: update installation guide` |
| `style` | Code style changes (formatting, etc.) | `style: fix linting errors` |
| `refactor` | Code refactoring | `refactor: simplify authentication logic` |
| `perf` | Performance improvements | `perf: optimize database queries` |
| `test` | Adding or updating tests | `test: add unit tests for user service` |
| `build` | Build system or dependency changes | `build: update Go version to 1.21` |
| `ci` | CI/CD configuration changes | `ci: add security scanning workflow` |
| `chore` | Maintenance tasks | `chore: update dependencies` |
| `revert` | Revert previous changes | `revert: undo feature X implementation` |

### Scope (Optional)
The scope provides additional contextual information:
- `cli` - Changes to command-line interface
- `server` - Changes to server components  
- `client` - Changes to client components
- `web` - Changes to web interface
- `api` - Changes to API endpoints
- `deps` - Dependency updates

### Breaking Changes
For breaking changes, add an exclamation mark (`!`) after the type/scope:
- `feat!: remove deprecated API`
- `fix(api)!: change response format`

Breaking changes should also include `BREAKING CHANGE:` in the commit body or footer explaining the change.

## Validation

### Automated Checks
- **PR Title Validation**: All PRs to main are automatically checked for conventional commit format
- **Individual Commits**: Advisory checking of individual commits (not enforced)

### Local Development
To validate commits locally:

1. Install dependencies:
   ```bash
   npm install
   ```

2. Check your last commit:
   ```bash
   npm run commitlint
   ```

## Rationale

1. **Consistent History**: Maintains a clean, searchable git history
2. **Automated Tooling**: Enables automatic changelog generation and semantic versioning
3. **Clear Intent**: Makes it immediately clear what type of change was made
4. **Release Notes**: Facilitates automatic generation of release notes

## Examples

### Good PR Titles ✅
- `feat: implement device enrollment API`
- `fix(server): resolve database connection timeout`
- `docs: add conventional commits documentation`
- `chore(deps): bump Go modules to latest versions`
- `test: add integration tests for MDM endpoints`
- `feat!: remove legacy authentication system` (breaking change)

### Bad PR Titles ❌
- `Update server` (missing type)
- `Fix bug` (too vague)
- `Feat: Add Feature` (capitalized subject)
- `fix server issues.` (ends with period)
- `WIP: working on auth` (work in progress)

## Questions?

If you have questions about conventional commits or need help formatting your PR title, please:
1. Check the [Conventional Commits specification](https://www.conventionalcommits.org/)
2. Look at recent merged PRs for examples
3. Ask in the engineering Slack channel
