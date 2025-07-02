# Mobius Codebase Technical Overview for AI Agents

This document provides a comprehensive technical overview of the Mobius MDM (Mobile Device Management) platform codebase, designed specifically for future AI agents and automated tools working with this project.

## Project Overview

Mobius is a modern MDM platform forked from the open-source Fleet project. It has been extensively rebranded and restructured to remove legacy Fleet dependencies and establish its own identity and development practices.

### Core Architecture

The Mobius platform follows a microservices-oriented architecture with the following main components:

1. **Backend Server** (`/server/`) - Go-based API server
2. **Frontend** (`/frontend/`) - React/TypeScript web application  
3. **Orbit Agent** (`/orbit/`) - Go-based agent that runs on managed devices
4. **CLI Tools** (`/cmd/`, `/tools/`) - Command-line utilities and management tools
5. **Website** (`/website/`) - Sails.js-based marketing/documentation site

### Key Technologies

- **Backend**: Go 1.24+, MySQL 8.0+, Redis 6+
- **Frontend**: React 18, TypeScript, Webpack
- **Agent**: Go, cross-platform (Windows, macOS, Linux)
- **CLI**: Go, distributed as `mobiuscli`
- **Website**: Node.js, Sails.js framework
- **Infrastructure**: Docker, Kubernetes, Terraform

## Directory Structure Deep Dive

### `/server/` - Backend API Server

- **`/mdm/`** - Mobile Device Management core logic
- **`/vulnerabilities/`** - Security vulnerability scanning and management
- **`/auth/`** - Authentication and authorization
- **`/datastore/`** - Database abstraction layer
- **`/service/`** - Business logic and service layer

### `/frontend/` - React Web Application

- **`/components/`** - Reusable UI components
- **`/pages/`** - Page-level components and routing
- **`/utilities/`** - Helper functions and utilities
- **`/interfaces/`** - TypeScript type definitions
- **`/test/`** - Frontend test suite

### `/orbit/` - Device Agent

- Cross-platform agent that communicates with Mobius server
- Handles policy enforcement, software deployment, and system monitoring
- Built with Go, packaged as native installers

### `/cmd/` - CLI Applications

- **`mobius/`** - Main server binary
- **`mobiuscli/`** - Administrative CLI tool

### `/tools/` - Development and Release Tools

- **`/release/`** - Automated release scripts
- **`/tuf/`** - The Update Framework for agent updates
- **`/mobiuscli-npm/`** - NPM package for mobiuscli distribution

## Data Flow and Communication

```text
[Managed Device] <-> [Orbit Agent] <-> [Mobius Server] <-> [Web Dashboard]
                                            |
                                       [Database]
                                       [Redis Cache]
```

### Agent Communication

- Agents communicate via HTTPS with certificate pinning
- Uses TUF (The Update Framework) for secure updates
- Supports both push and pull communication patterns

### API Architecture

- RESTful APIs with JSON payloads
- JWT-based authentication
- Rate limiting and security headers implemented

## Development Patterns

### Version Management

- Uses semantic versioning (v1.x.x format)
- Release candidates follow `rc-minor-mobius-v1.x.x` pattern
- Automated releases via GitHub Actions

### Testing Strategy

- Go backend: Standard Go testing with testify
- Frontend: Jest with React Testing Library
- Integration tests for critical paths
- Security scanning with various tools

### Build System

- Makefile-based build system
- Docker multi-stage builds
- Cross-compilation for multiple platforms
- Automated dependency management

## Configuration Management

### Environment Variables

- `MOBIUS_LICENSE_KEY` - Premium feature activation
- `MOBIUS_MYSQL_*` - Database configuration
- `MOBIUS_REDIS_*` - Cache configuration
- `MOBIUS_LOG_*` - Logging configuration

### Config Files

- `mobius.yml` - Main server configuration
- `package.json` - Frontend dependencies
- `go.mod` - Go module dependencies
- `docker-compose.yml` - Local development setup

## Security Considerations

### Authentication & Authorization

- Multi-factor authentication support
- Role-based access control (RBAC)
- Session management with Redis
- API key management for programmatic access

### Data Protection

- Encryption at rest and in transit
- PII handling and GDPR compliance
- Audit logging for compliance
- Secure software distribution via TUF

## Deployment Patterns

### Infrastructure

- Container-first deployment with Docker
- Kubernetes manifests in `/charts/`
- Terraform modules for cloud deployment
- Support for AWS, GCP, and on-premises

### Scaling

- Horizontal scaling via load balancers
- Database read replicas supported
- Redis clustering for high availability
- CDN integration for asset delivery

## Integration Points

### External Services

- Identity providers (SAML, OIDC)
- Vulnerability databases
- Software repositories
- Cloud storage backends

### APIs

- GraphQL endpoint for complex queries
- REST APIs for standard operations
- Webhook support for real-time notifications
- CLI for automation and scripting

## Monitoring and Observability

### Logging

- Structured JSON logging
- Multiple log levels (debug, info, warn, error)
- Centralized log aggregation support
- Performance metrics collection

### Health Checks

- Database connectivity checks
- Redis availability monitoring
- Agent heartbeat tracking
- Service dependency validation

## Development Guidelines for AI Agents

When working with this codebase:

1. **Always run tests** before and after changes
2. **Update version strings** consistently across all relevant files
3. **Maintain backward compatibility** for agent communications
4. **Follow Go and React best practices** for new code
5. **Update documentation** when changing APIs or behavior
6. **Consider security implications** of all changes
7. **Test cross-platform compatibility** for agent changes

## Common Tasks for AI Agents

- **Adding new API endpoints**: Follow patterns in `/server/service/`
- **Frontend feature development**: Use existing component patterns
- **Agent functionality**: Extend orbit capabilities carefully
- **Release management**: Use automated release tools
- **Security updates**: Follow CVE response procedures
- **Performance optimization**: Profile before and after changes

## Legacy Cleanup Status

This codebase has been cleaned of Fleet-specific references and updated with Mobius branding. The version system has been modernized to follow conventional commits and semantic versioning practices.

Key areas that have been updated:

- All branding references changed from Fleet to Mobius
- Version strings standardized to v1.x.x format
- Logo and color scheme updated (#1c2f38 background, #d4af37 accent)
- Legacy documentation and support artifacts removed
- Build and release processes modernized

## Future Considerations

- Migration to newer React patterns (hooks, context)
- GraphQL API expansion
- Enhanced real-time capabilities
- Improved agent resilience
- Extended platform support
- Advanced analytics and reporting

This document should be updated as the codebase evolves to maintain accuracy for future AI agents working on this project.
