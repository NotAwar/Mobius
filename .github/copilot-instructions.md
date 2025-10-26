# Copilot Instructions for Mobius MDM Platform

## Repository Overview

Mobius is a modern, API-first Mobile Device Management (MDM) platform designed for self-hosted environments. It provides comprehensive device management, policy enforcement, and application distribution across Windows, macOS, Linux, iOS, and Android devices.

**Key Characteristics:**
- Enterprise MDM solution (not open source)
- Go-based backend with Svelte frontend
- Multi-module monorepo architecture
- Containerized deployment with Docker
- RESTful API with JWT authentication
- Production-ready with comprehensive CI/CD

## Architecture & Structure

### Core Modules (Go Workspace)
```
server/api/          # Core API server and business logic
├── api/                # HTTP routing, handlers, middleware
├── pkg/service/        # Business logic implementations  
├── cmd/api-server/     # Standalone API server (current)
└── cmd/mobius/         # Legacy server (deprecated)

server/cli/             # Command-line management tool
├── cmd/mobiuscli/      # CLI application
└── pkg/               # CLI business logic

server/client/          # Device client agents
├── cmd/client/         # Cross-platform device client
└── pkg/               # Client libraries

cocoon/portal/          # Enterprise web portal (future)
├── cmd/cocoon/         # Web application server
└── pkg/               # Portal business logic

shared/                 # Common libraries and utilities
└── pkg/               # Shared Go packages (crypto, http, file ops)

ui/web/             # Svelte frontend application
├── src/               # Svelte source code
├── static/            # Static assets
└── build/             # Build output (copied to server/api/static/)
```

### Technology Stack
- **Backend**: Go 1.25.3, RESTful API, JWT auth, CORS, rate limiting
- **Frontend**: Svelte 5, TypeScript, Vite, Vitest for testing
- **Database**: Embedded storage solutions
- **Containerization**: Docker with security hardening
- **CI/CD**: GitHub Actions with 20+ workflows
- **Monitoring**: Health checks, Prometheus metrics, structured logging

## Development Workflow

### Build System
Use the Makefile for common operations:
```bash
make help              # Show available targets
make build            # Build both frontend and backend
make build-frontend   # Build Svelte frontend only
make build-backend    # Build Go backend only
make test             # Run all tests across modules
make dev              # Start development servers
make clean            # Clean build artifacts
```

### Frontend Development (ui/web/)
```bash
cd ui/web
npm install           # Install dependencies
npm run dev          # Development server
npm run build        # Production build
npm test             # Run Vitest tests
npm run check        # TypeScript and Svelte checks
```

### Backend Development
```bash
# Each Go module can be built independently
cd server/api && go build -o mobius-api cmd/api-server/main.go
cd server/cli && go build -o mobiuscli cmd/mobiuscli/main.go

# Run tests
go test ./...         # In any module directory
```

### API Server Quick Start
```bash
cd server/api
go run cmd/api-server/main.go
# Server starts on http://localhost:8081
# Default credentials: admin@mobius.local / admin123
```

## Code Standards & Practices

### Go Code Guidelines
- Follow standard Go conventions and formatting
- Use clear package structure with separation of concerns
- Implement proper error handling and logging
- Use dependency injection for testability
- Maintain clean API boundaries between modules

### Frontend Guidelines
- Use TypeScript for type safety
- Follow Svelte 5 best practices
- Implement comprehensive testing with Vitest
- Use semantic commit messages
- Maintain responsive design principles

### Security Requirements
- All dependencies must be kept up-to-date
- Security vulnerabilities must be addressed immediately
- Use secure coding practices (input validation, CORS, etc.)
- Implement proper authentication and authorization
- Follow Docker security best practices (non-root users)

## Testing Strategy

### Go Testing
- Unit tests for all business logic
- Integration tests for API endpoints
- Mock external dependencies
- Use table-driven tests where appropriate

### Frontend Testing
- Component testing with Testing Library
- Unit tests for utility functions
- Integration tests for user workflows
- Visual regression testing where needed

## Deployment & Infrastructure

### Docker Configuration
- `Dockerfile`: Main application container
- `Dockerfile.combined`: Combined services
- `Dockerfile-desktop-linux`: Desktop client
- Security hardening with non-root user (UID 1001)

### Environment Configuration
- Development: Local builds with hot reload
- Production: Containerized deployment
- CI/CD: Automated testing and deployment pipelines

## API Design Principles

### RESTful API Standards
- Use standard HTTP methods and status codes
- Implement consistent error response format
- Use semantic versioning for API versions
- Provide comprehensive OpenAPI 3.1 documentation

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (admin/operator/viewer)
- Secure token handling and refresh mechanisms

## Licensing & Business Context

### Product Tiers
- **Community**: Free tier with basic features
- **Professional**: Advanced features for small/medium teams
- **Enterprise**: Full feature set for large organizations

### Key Features
- Multi-platform device support
- Policy engine and enforcement
- Application distribution
- License management
- Self-hosted deployment

## Common Tasks & Patterns

### Adding New API Endpoints
1. Define handler in `server/api/api/handlers/`
2. Add route in `server/api/api/router/`
3. Implement business logic in `server/api/pkg/service/`
4. Add tests for all layers
5. Update API documentation

### Adding Frontend Features
1. Create Svelte components in `ui/web/src/`
2. Add TypeScript types
3. Implement API client calls
4. Add comprehensive tests
5. Update navigation and routing

### Security Updates
1. Monitor for dependency vulnerabilities
2. Update packages using npm overrides or go.mod
3. Test thoroughly across all modules
4. Update security documentation
5. Validate with security scanning tools

## CI/CD Workflows

The repository includes comprehensive GitHub Actions workflows:
- Build and deployment pipelines
- Security vulnerability scanning
- Dependency checks and updates
- Multi-platform Docker builds
- Automated testing and quality checks

When contributing, ensure all CI checks pass and follow the established patterns for robust, secure, and maintainable code.

## Troubleshooting Common Issues

### Build Issues
- Ensure Go 1.25.3+ is installed
- Run `go mod tidy` in each module
- Check frontend dependencies with `npm install`
- Use `make clean` to reset build state

### Development Setup
- Use `make dev` for full development environment
- Check API server logs for authentication issues
- Verify frontend builds complete successfully
- Ensure Docker daemon is running for container operations

Remember: This is an enterprise MDM platform focused on security, reliability, and scalability. All changes should maintain these core principles while following established architectural patterns.
=======
# Mobius Mobile Device Management Platform

**CRITICAL: Always follow these instructions first. Only fall back to additional search and context gathering if the information here is incomplete or found to be in error.**

Mobius is a comprehensive Mobile Device Management (MDM) platform written in Go with a Svelte frontend. It provides device management, policy enforcement, and application distribution across Windows, macOS, Linux, iOS, and Android devices.

## Working Effectively

### Bootstrap and Build Process

**CRITICAL BUILD TIMING - NEVER CANCEL COMMANDS:**
- Go dependency download: **NEVER CANCEL** - takes 60-70 seconds. Set timeout to 120+ seconds.
- CLI build: **NEVER CANCEL** - takes 60-75 seconds. Set timeout to 120+ seconds.
- Server build: **NEVER CANCEL** - takes 10-20 seconds. Set timeout to 60+ seconds.
- Frontend build: **NEVER CANCEL** - takes 15-20 seconds. Set timeout to 60+ seconds.
- Complete Makefile build: **NEVER CANCEL** - takes 15-20 seconds total. Set timeout to 60+ seconds.
- Go tests: **NEVER CANCEL** - takes 30-35 seconds. Set timeout to 90+ seconds.

### Required Environment
```bash
# Check versions
go version  # Must be Go 1.25.3+
node --version  # Node.js 20+ required
npm --version   # npm 10+ required
```

### Build Commands (Execute in Order)
```bash
# 1. Sync Go workspace and download dependencies
go work sync  # ~5 seconds

# 2. Download Go dependencies for all modules - NEVER CANCEL: 60-70 seconds
cd server/api && go mod download
cd ../server/cli && go mod download  
cd ../server/client && go mod download
cd ../cocoon/portal && go mod download
cd ../shared && go mod download
cd ..

# 3. Install frontend dependencies - NEVER CANCEL: 8-10 seconds
cd ui/web && npm ci && cd ..

# 4. Build frontend - NEVER CANCEL: 15-20 seconds
cd ui/web && npm run build && cd ..

# 5. Build all Go components - NEVER CANCEL: Total 60-90 seconds
mkdir -p build
cd server/api && go build -o ../build/mobius-api ./cmd/api-server  # 10-20 seconds
cd ../server/cli && go build -o ../build/mobiuscli ./cmd/mobiuscli    # 60-75 seconds
cd ../server/client && go build -o ../build/server/client ./cmd/client  # <1 second
cd ../cocoon/portal && go build -o ../build/cocoon/portal ./cmd/cocoon  # <1 second
cd ..

# Alternative: Use Makefile for complete build - NEVER CANCEL: 15-20 seconds
make clean && make build
```

### Testing
```bash
# Run Go tests for all modules - NEVER CANCEL: 30-35 seconds
go test -count=1 ./server/api/... ./server/cli/... ./server/client/... ./cocoon/portal/... ./shared/...

# Run frontend tests - NEVER CANCEL: 2-3 seconds
cd ui/web && npm test && cd ..

# Run frontend type checking
cd ui/web && npm run check && cd ..
```

### Running the Application
```bash
# Start the API server (includes frontend)
./build/mobius-api serve --port 8081
# OR from server/api directory:
cd server/api && ./mobius-api serve --port 8081

# Default credentials:
# Email: admin@mobius.local
# Password: admin123

# Server starts at: http://localhost:8081
```

### CLI Usage
```bash
# Test CLI functionality
./build/mobiuscli --help

# Key CLI commands:
./build/mobiuscli login          # Authenticate with server
./build/mobiuscli get devices    # List devices
./build/mobiuscli get policies   # List policies
./build/mobiuscli apply          # Apply configurations
./build/mobiuscli query          # Run live queries
```

## Validation

### Manual Testing Scenarios
Always test these core workflows after making changes:

1. **API Server Health Check**
```bash
# Start server: ./build/mobius-api serve --port 8081
curl http://localhost:8081/api/v1/health
# Should return: {"status":"healthy",...}
```

2. **Authentication Flow**
```bash
# Login and get token
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mobius.local","password":"admin123"}'
# Should return: {"token":"token_admin-1_...","user":{...}}
```

3. **Core API Endpoints**
```bash
TOKEN="your_token_here"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/v1/license/status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/v1/devices
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/v1/policies
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/v1/applications
```

4. **Frontend Integration**
```bash
# Verify frontend is served
curl http://localhost:8081/
# Should return HTML starting with: <!doctype html>
```

5. **CLI Functionality**
```bash
./build/mobiuscli --help  # Should show full command list
./build/mobiuscli login   # Test login flow
```

### CI/CD Validation
Always run these before committing:
```bash
# Frontend validation
cd ui/web && npm run check  # Type checking
cd ui/web && npm test       # Unit tests

# Go validation  
go test -count=1 ./...          # All Go tests

# Build validation
make clean && make build        # Complete build process
```

## Repository Structure

```
/
├── server/api/          # Core API server
│   ├── cmd/api-server/     # Main server entry point
│   ├── api/                # HTTP handlers and routing
│   ├── pkg/service/        # Business logic
│   └── static/             # Built frontend files (generated)
├── server/cli/             # Command-line interface
│   └── cmd/mobiuscli/      # CLI entry point
├── server/client/          # Device client agents
├── cocoon/portal/          # Enterprise web portal
├── ui/web/             # Svelte frontend application
│   ├── src/                # Frontend source code
│   └── build/              # Built frontend (generated)
├── shared/                 # Common Go libraries
├── tests/                  # Comprehensive test suite
│   ├── test_mdm_functionality.sh    # 29 test scenarios
│   ├── test_websocket_functionality.sh  # 6 scenarios
│   └── run_all_tests.sh    # Test runner
└── .github/workflows/      # CI/CD pipelines
```

## Key Architecture Components

### Backend (Go)
- **server/api**: Core MDM server with REST API (builds to ~10MB binary)
- **server/cli**: Administrative CLI tool (builds to ~49MB binary) 
- **server/client**: Device client agent (builds to ~8.5MB binary)
- **cocoon/portal**: Enterprise portal service (builds to ~7.9MB binary)
- **shared**: Common libraries used across components

### Frontend (Svelte)
- **ui/web**: Admin web interface built with SvelteKit
- Built using Vite with TypeScript support
- Static files served by the API server at runtime

### Database & Storage
- Currently uses mock/in-memory services for development
- Designed for PostgreSQL/MySQL in production
- File storage abstraction for various backends

## Troubleshooting

### Common Build Issues
- **Go workspace sync failures**: Run `go work sync` first
- **Frontend build failures**: Ensure Node.js 20+ and run `npm ci` first
- **Binary not found**: Check that build completed in `build/` directory
- **Server won't start**: Verify port 8081 is available

### Performance Issues
- **Slow builds**: Normal - CLI build takes 60-75 seconds, be patient
- **Test timeouts**: Tests can take 30+ seconds, never cancel early
- **Large binaries**: Expected - CLI is 49MB due to embedded dependencies

### Development Tips
- Use `make dev` for development with auto-reload
- Frontend served at `/` when server running
- API endpoints at `/api/v1/*`
- Default admin credentials: `admin@mobius.local` / `admin123`
- WebSocket endpoint available at `/ws` for real-time features

## Docker & Deployment

### Container Builds
```bash
# Build individual component containers
docker build -f server/api/Dockerfile .
docker build -f server/cli/Dockerfile .
docker build -f server/client/Dockerfile . 
docker build -f cocoon/portal/Dockerfile .
```

### Production Deployment
- Use GitHub Actions workflows in `.github/workflows/`
- Multi-arch builds for linux/amd64 and linux/arm64
- Signed container images with Cosign
- SBOM generation with Syft

## Security Considerations

- JWT-based authentication with role-based access control
- HTTPS/TLS required for production
- Rate limiting and CORS protection built-in
- Security scanning via Trivy in CI/CD
- Secrets management via environment variables

## Important Files and Locations

### Configuration
- `go.work` - Go workspace configuration
- `package.json` - Frontend dependencies in `ui/web/`
- `Makefile` - Build automation
- `.github/workflows/build-and-deploy.yml` - Main CI/CD pipeline

### Documentation
- `README.md` - Project overview
- `docs/MASTER_PLAN.md` - Comprehensive development plan
- `SECURITY.md` - Security policies and procedures

### Testing
- `tests/run_all_tests.sh` - Comprehensive test runner
- `tests/test_mdm_functionality.sh` - 29 MDM test scenarios
- `tests/test_websocket_functionality.sh` - 6 WebSocket test scenarios

Remember: **ALWAYS** validate changes by running the complete build and test process. The platform is mission-critical infrastructure - never skip validation steps.

