# Changelog

All notable changes to Mobius will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-07-02

### Added

- Complete rebranding from Fleet to Mobius
- New brand colors: #1c2f38 (primary), #d4af37 (accent)
- Montserrat font support for logo usage
- Comprehensive AI agent documentation (agents.md)
- Developer guide for humans (humans.md)
- Modernized version system following semantic versioning

### Changed

- Updated all version references from v4.x.x to v1.x.x format
- Migrated Go module path from github.com/notawar/mobius/v4 to github.com/notawar/mobius
- Updated Docker image tags and infrastructure references
- Standardized release candidate naming to rc-minor-mobius-v1.x.x pattern
- Improved color scheme with official brand colors

### Removed

- Legacy Fleet branding references
- Auto-generated old TUF documentation (orbit/old-TUF.md)
- Version-specific newsletter templates
- Outdated v4 version references throughout codebase

### Technical

- Updated Go import paths across all packages
- Modernized Makefile with new version patterns
- Updated CI/CD workflows for new versioning scheme
- Cleaned up legacy documentation and references

---

**Note**: This represents the first major release of Mobius as an independent product,
having been forked and rebranded from the Fleet open-source project. All previous
v4.x.x versions were part of the Fleet legacy codebase.

For orbit agent changes, see [orbit/CHANGELOG.md](orbit/CHANGELOG.md).
