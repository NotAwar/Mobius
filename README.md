# Mobius Mobile Device Management Platform

![Mobius logo](common/assets/Mobius-Logo-Text_1.png)

[![Build & Deploy](https://github.com/MobiusDM/Mobius/actions/workflows/build-and-deploy.yml/badge.svg)](https://github.com/MobiusDM/Mobius/actions/workflows/build-and-deploy.yml)
[![Unit Tests](https://github.com/MobiusDM/Mobius/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/MobiusDM/Mobius/actions/workflows/unit-tests.yml)

Mobius is a modern, API-first Mobile Device Management (MDM) platform designed for self-hosted environments. It provides comprehensive device management, policy enforcement, and application distribution across Windows, macOS, Linux, iOS, and Android devices.

## 🚀 Quick Start

### Start the API Server

```bash
# Build and run the API server
cd server/api
go build -o mobius-api ./cmd/api-server/
./mobius-api
```

The server starts on `http://localhost:8081` with these default credentials:

- **Email**: `admin@mobius.local`  
- **Password**: `admin123`

### Test the API

```bash
# Health check
curl http://localhost:8081/api/v1/health

# Login and get token
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mobius.local","password":"admin123"}'

# Check license status
curl http://localhost:8081/api/v1/license/status \
  -H "Authorization: Bearer <token>"
```

## Architecture Overview

Mobius follows a clean, API-first architecture with clear separation of concerns:

### Core Components

```text
server/
├── api/                # Core API server and business logic
│   ├── api/            # HTTP routing, handlers, middleware
│   ├── pkg/service/    # Business logic implementations  
│   ├── cmd/api-server/ # Standalone API server
│   └── cmd/mobius/     # Legacy server (deprecated)
├── cli/                # Command-line management tool
│   ├── cmd/mobiuscli/  # CLI application
│   └── pkg/            # CLI business logic
└── package-search/     # Package search service

client/
└── client/             # Device client agents
    ├── cmd/client/     # Cross-platform device client
    └── pkg/            # Client libraries

ui/
└── web/                # Svelte web application
    ├── src/            # Frontend source code
    └── static/         # Static assets

cocoon/
└── portal/             # Enterprise web portal
    ├── cmd/cocoon/     # Web application server
    └── pkg/            # Portal business logic

common/
├── shared/             # Common libraries and utilities
│   └── pkg/            # Shared Go packages
└── assets/             # Images, logos, and other assets
```

## Key Features

### Production Ready

- **RESTful API**: Complete endpoint coverage with OpenAPI 3.1 specification
- **Authentication**: JWT-based auth with role-based access control (admin/operator/viewer)
- **Security**: CORS, rate limiting, security headers, input validation
- **Monitoring**: Health checks, Prometheus metrics, structured logging
- **Containerization**: Optimized Docker images with security best practices

### Enterprise Features

- **License Management**: Professional, and Enterprise tiers
- **Multi-Platform**: Support for Windows, macOS, Linux, iOS, and Android
- **Policy Engine**: Create, assign, and enforce device policies
- **Application Distribution**: Secure app packaging and deployment
- **Device Management**: Enrollment, monitoring, and remote management

### Self-Hosted

- **Data Control**: Complete ownership of device and user data
- **Customization**: Open architecture for custom integrations
- **Cost Effective**: No per-device licensing fees to third parties
- **Scalable**: Microservices-ready design for enterprise deployment

## Products

### Mobius Server (`server/api/`)

The core backend server that provides:

- **Device Management**: osquery orchestration and MDM protocols
- **REST API**: Complete API for device management operations
- **Web Interface**: Admin GUI is a separate React app that talks to the API
- **Security**: Vulnerability scanning and compliance monitoring
- **Multi-tenancy**: Team-based device organization

**Target Environment**: Deployed on servers/cloud infrastructure

### Mobius CLI (`server/cli/`)

Command-line interface for:

- **Configuration Management**: GitOps-style device policy management
- **Server Administration**: Remote server management
- **Data Analysis**: Query execution and data export
- **Automation**: Scripting and integration support

**Target Environment**: Administrator workstations and CI/CD pipelines

### Shared Libraries (`shared/`)

Common utilities used by both products:

- Certificate management
- HTTP client libraries  
- File operations
- Cryptographic utilities

## Installation & Usage

### Option 1: Direct Execution (Development)

Each product can be built and run independently:

```bash
# Build and run API server
cd server/api
go build -o mobius-api ./cmd/api-server
./mobius-api

# Build CLI  
cd server/cli
go build -o mobiuscli ./cmd/mobiuscli
```

### Option 2: Docker Deployment

Run with Docker Compose:

```bash
# Using docker-compose.yml (hardcoded MySQL/Redis)
docker-compose up -d

# Or using docker-compose.score.yaml (pre-configured for production)
docker-compose -f docker-compose.score.yaml up -d
```

### Option 3: Score-Based Deployment (Recommended for Production)

Mobius supports the [Score specification](https://score.dev) for platform-agnostic deployments. Score allows you to define your workload once and deploy it anywhere - Docker Compose, Kubernetes, or other platforms.

#### What is Score?

Score is a specification for describing cloud workloads in a vendor-neutral way. Instead of writing multiple deployment configurations (docker-compose.yml for local, Kubernetes manifests for production), you write one `score.yaml` file that can be translated to any platform.

#### Installing Score CLI

```bash
# macOS (Homebrew)
brew install score-spec/tap/score-compose

# Linux/WSL (direct download)
SCORE_VERSION="0.19.2"
wget "https://github.com/score-spec/score-compose/releases/download/${SCORE_VERSION}/score-compose_${SCORE_VERSION}_linux_amd64.tar.gz"
tar -xzf "score-compose_${SCORE_VERSION}_linux_amd64.tar.gz"
sudo mv score-compose /usr/local/bin/
sudo chmod +x /usr/local/bin/score-compose

# Verify installation
score-compose --version
```

#### Deploying with Score

1. **Generate Docker Compose from Score specification:**

```bash
# For API server
cd server/api
score-compose generate score.yaml --output docker-compose.generated.yaml

# For full platform deployment
cd deployments
score-compose generate score.yaml --output docker-compose.generated.yaml
```

2. **Customize environment variables (optional):**

```bash
# Override defaults with .env file
cat > .env << EOF
MOBIUS_MYSQL_ADDRESS=mysql:3306
MOBIUS_MYSQL_DATABASE=mobius
MOBIUS_MYSQL_USERNAME=mobius
MOBIUS_MYSQL_PASSWORD=secure-password-here
MOBIUS_REDIS_ADDRESS=redis:6379
MOBIUS_SERVER_ADDRESS=0.0.0.0:8081
MOBIUS_STATIC_DIR=./static
MOBIUS_LOGGING_JSON=true
EOF
```

3. **Deploy with generated Docker Compose:**

```bash
docker-compose -f docker-compose.generated.yaml up -d
```

#### Score Environment Variables

Mobius reads the following Score-compatible environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `MOBIUS_SERVER_ADDRESS` | Server bind address | `:8081` |
| `MOBIUS_STATIC_DIR` | Static files directory (frontend) | `./static` |
| `MOBIUS_MYSQL_ADDRESS` | MySQL server address | `localhost:3306` |
| `MOBIUS_MYSQL_DATABASE` | MySQL database name | `mobius` |
| `MOBIUS_MYSQL_USERNAME` | MySQL username | (empty) |
| `MOBIUS_MYSQL_PASSWORD` | MySQL password | (empty) |
| `MOBIUS_REDIS_ADDRESS` | Redis server address | `localhost:6379` |
| `MOBIUS_REDIS_PASSWORD` | Redis password | (empty) |
| `MOBIUS_LOGGING_JSON` | Enable JSON logging | `false` |

#### Kubernetes Deployment

Use `score-k8s` to generate Kubernetes manifests:

```bash
# Install score-k8s
brew install score-spec/tap/score-k8s

# Generate Kubernetes manifests
score-k8s generate score.yaml --output k8s-manifests/

# Deploy to Kubernetes
kubectl apply -f k8s-manifests/
```

#### Benefits of Score

- **Write Once, Deploy Anywhere**: Single `score.yaml` works for Docker, Kubernetes, Helm, etc.
- **Environment Consistency**: Same configuration across dev, staging, production
- **Vendor Independence**: No lock-in to specific orchestration platforms
- **CI/CD Integration**: Automated validation ensures specs stay valid (see `.github/workflows/build-and-deploy.yml`)
- **Type Safety**: Strongly-typed resource dependencies (MySQL, Redis) prevent configuration errors

#### Example Score Specification

```yaml
apiVersion: score.dev/v1b1
metadata:
  name: mobius-api
  description: Mobius MDM API Server

containers:
  api:
    image: ghcr.io/mobiusdm/mobius/api:latest
    variables:
      MOBIUS_MYSQL_ADDRESS: "${resources.mysql.host}:${resources.mysql.port}"
      MOBIUS_MYSQL_DATABASE: "${resources.mysql.database}"
      MOBIUS_SERVER_ADDRESS: "0.0.0.0:8081"
      MOBIUS_STATIC_DIR: "./static"

service:
  ports:
    api:
      port: 8081
      targetPort: 8081

resources:
  mysql:
    type: mysql
  redis:
    type: redis
```

For complete Score specifications, see:

- `server/api/score.yaml` - API server deployment
- `server/cli/score.yaml` - CLI tools deployment
- `client/client/score.yaml` - Device client deployment
- `cocoon/portal/score.yaml` - Enterprise portal deployment
- `deployments/score.yaml` - Full platform deployment

## Development

The products are designed with clear separation:

- **Server**: Handles device connections, data storage, and management logic
- **CLI**: Provides administrative interface and automation capabilities
- **Shared**: Common code that both products depend on

This structure enables:

- Independent releases and versioning
- Clear product boundaries
- Focused development teams
- Simplified deployment scenarios

## Security

For security vulnerabilities, responsible disclosure procedures, and security best practices, please see our [Security Policy](SECURITY.md).

Key security features:

- JWT-based authentication with RBAC
- HTTPS/TLS encryption for all communications  
- Rate limiting and DDoS protection
- Comprehensive audit logging
- Vulnerability scanning and dependency management

## License

Mobius is not open source.
