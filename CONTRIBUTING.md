# Contributing to Mobius

Thank you for your interest in contributing to Mobius! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Go 1.25+ 
- Node.js 18+ (for web UI development)
- Docker (for containerized development)
- Git

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/Mobius.git
   cd Mobius
   ```
3. Install dependencies:
   ```bash
   make build
   ```
4. Run tests:
   ```bash
   make test
   ```

## How to Contribute

### Reporting Issues

Please use our [issue templates](.github/ISSUE_TEMPLATE/) to report:
- **Bugs**: Use the bug report template
- **Feature Requests**: Use the feature request template
- **Security Issues**: Use GitHub Security Advisories (privately)

### Pull Requests

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Follow our naming conventions**:
   - `feature/` - New features
   - `fix/` - Bug fixes
   - `docs/` - Documentation updates
   - `chore/` - Maintenance tasks

3. **Make your changes**:
   - Write clear, concise commit messages
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Test your changes**:
   ```bash
   make test
   make lint
   ```

5. **Create a Pull Request**:
   - Use our [PR template](.github/pull_request_template.md)
   - Link to related issues
   - Provide clear description of changes

### Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
- `feat(server): add device enrollment endpoint`
- `fix(cli): resolve authentication timeout issue`
- `docs: update installation instructions`

## Code Style

### Go Code

- Follow standard Go formatting (`gofmt`)
- Use meaningful variable and function names
- Add comments for public APIs
- Keep functions small and focused
- Write tests for new functionality

### Web UI

- Use TypeScript for type safety
- Follow the existing component structure
- Write unit tests for components
- Update documentation for new features

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific module tests
cd mobius-server && go test ./...
cd mobius-web && npm test
```

### Writing Tests

- Write unit tests for all new functionality
- Use table-driven tests in Go where appropriate
- Mock external dependencies
- Ensure tests are deterministic

## Documentation

- Update relevant documentation for changes
- Use clear, concise language
- Include code examples where helpful
- Update API documentation for new endpoints

## Code Review Process

1. All code changes require review
2. Reviewers will check for:
   - Code quality and style
   - Test coverage
   - Documentation updates
   - Security considerations
3. Address review feedback promptly
4. Squash commits before merging if requested

## Release Process

Releases are managed by maintainers:
1. Version bumps follow [semantic versioning](https://semver.org/)
2. Changes are documented in CHANGELOG.md
3. Releases are tagged and published automatically

## Community Guidelines

- Be respectful and constructive
- Help others learn and grow
- Ask questions if something is unclear
- Share knowledge and best practices

## Getting Help

- **Documentation**: Check the [README](README.md) and [docs](docs/) folder
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for general questions
- **Community**: Join our community channels (links in README)

## License

By contributing to Mobius, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to Mobius! 🚀