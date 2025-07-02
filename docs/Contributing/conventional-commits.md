# Conventional Commits Configuration

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification.

## Commit Message Format

Each commit message consists of a **header**, a **body** and a **footer**.

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Type

Must be one of the following:

- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to our CI configuration files and scripts
- **docs**: Documentation only changes
- **feat**: A new feature
- **fix**: A bug fix
- **perf**: A code change that improves performance
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **test**: Adding missing tests or correcting existing tests

### Scope

The scope should be the name of the npm package affected (as perceived by the person reading the changelog generated from commit messages).

Examples:

- `frontend`
- `server`
- `orbit`
- `cli`
- `docs`
- `api`

### Description

The description contains a succinct description of the change:

- use the imperative, present tense: "change" not "changed" nor "changes"
- don't capitalize the first letter
- no dot (.) at the end

### Body

Just as in the **description**, use the imperative, present tense: "change" not "changed" nor "changes".
The body should include the motivation for the change and contrast this with previous behavior.

### Footer

The footer should contain any information about **Breaking Changes** and is also the place to reference GitHub issues that this commit **Closes**.

**Breaking Changes** should start with the word `BREAKING CHANGE:` with a space or two newlines. The rest of the commit message is then used for this.

## Examples

### Simple fix

```
fix(server): resolve authentication timeout issue
```

### Feature with scope and body

```
feat(frontend): add device status dashboard

Add a new dashboard component that displays real-time device status
information with automatic refresh capabilities.

Closes #123
```

### Breaking change

```
feat(api): change authentication endpoint structure

BREAKING CHANGE: The authentication endpoint now requires a different
request structure. Update your clients to use the new format.
```

## Automated Release Notes

This project uses these conventional commits to automatically generate:

- Version bumps (patch for fix, minor for feat, major for BREAKING CHANGE)
- Changelog entries
- Release notes

## Validation

All commits are validated using conventional commit standards through:

- Pre-commit hooks
- CI/CD pipeline checks
- PR title validation

## References

- [Conventional Commits Specification](https://www.conventionalcommits.org/)
- [Angular Commit Message Guidelines](https://github.com/angular/angular/blob/master/CONTRIBUTING.md#commit)
