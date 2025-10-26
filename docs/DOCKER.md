# Docker Configuration Guide

This document explains the purpose of each Dockerfile in the Mobius MDM platform and how to use them.

## Dockerfiles Overview

All Dockerfiles use **Go 1.25.3 Alpine** base images for optimal security and size.

### Main Platform Dockerfile

**Location:** `deployments/Dockerfile`

**Purpose:** Main production Dockerfile that builds the complete Mobius MDM platform with integrated web UI.

**What it builds:**

- Svelte frontend (Node.js 24-alpine stage)
- Go API server with embedded static files
- Multi-stage build for minimal image size

**Usage:**

```bash
docker build -f deployments/Dockerfile -t mobius:latest .
docker run -p 8081:8081 mobius:latest
```

**Entry point:** `server/api/cmd/api-server/main.go`

---

### Service-Specific Dockerfiles

#### 1. API Server

**Location:** `server/api/Dockerfile`

**Purpose:** Standalone API server without frontend build step.

**Usage:**

```bash
docker build -f server/api/Dockerfile -t mobius-api:latest .
```

**Entry point:** `cmd/api-server/main.go`

---

#### 2. CLI Tool

**Location:** `server/cli/Dockerfile`

**Purpose:** Command-line management tool for Mobius MDM administration.

**Usage:**

```bash
docker build -f server/cli/Dockerfile -t mobiuscli:latest .
docker run mobiuscli:latest --help
```

**Entry point:** `cmd/mobiuscli/main.go`

---

#### 3. Device Client

**Location:** `client/client/Dockerfile`

**Purpose:** Agent that runs on managed devices to communicate with Mobius server.

**Usage:**

```bash
docker build -f client/client/Dockerfile -t mobius-client:latest .
```

**Entry point:** `cmd/client/main.go`

---

#### 4. Enterprise Portal (Cocoon)

**Location:** `cocoon/portal/Dockerfile`

**Purpose:** Enterprise web portal service for advanced management features.

**Usage:**

```bash
docker build -f cocoon/portal/Dockerfile -t mobius-cocoon:latest .
docker run -p 8082:8082 mobius-cocoon:latest
```

**Entry point:** `cmd/cocoon/main.go`
**Default port:** 8082

---

#### 5. Package Search Service

**Location:** `server/mobius-package-search/Dockerfile`

**Purpose:** Microservice for searching packages across multiple platforms (APT, Homebrew, Flatpak, Windows).

**Usage:**

```bash
docker build -f server/mobius-package-search/Dockerfile -t package-search:latest .
```

**Entry point:** `main.go`

---

### Specialized Tool Dockerfiles

#### 6. SCEP Server

**Location:** `server/api/server/mdm/scep/Dockerfile`

**Purpose:** Simple Certificate Enrollment Protocol (SCEP) server for MDM certificate management.

**Usage:**

```bash
cd server/api/server/mdm/scep
docker build -t mobius-scep:latest .
```

**Context:** Used for Apple MDM certificate provisioning

---

#### 7. MDM Migration Proxy

**Location:** `server/api/tools/mdm/migration/mdmproxy/Dockerfile`

**Purpose:** Proxy tool for migrating devices from other MDM solutions to Mobius.

**Usage:**

```bash
cd server/api/tools/mdm/migration/mdmproxy
docker build -t mdm-migration-proxy:latest .
```

**Context:** Used during migration projects

---

## Docker Compose Files

See [DOCKER_COMPOSE.md](./DOCKER_COMPOSE.md) for documentation on the various docker-compose configurations.

## Building All Images

To build all service images:

```bash
# Main platform (recommended for production)
docker build -f deployments/Dockerfile -t mobius:latest .

# Individual services (for microservices deployment)
docker build -f server/api/Dockerfile -t mobius-api:latest .
docker build -f server/cli/Dockerfile -t mobiuscli:latest .
docker build -f client/client/Dockerfile -t mobius-client:latest .
docker build -f cocoon/portal/Dockerfile -t mobius-cocoon:latest .
docker build -f server/mobius-package-search/Dockerfile -t package-search:latest .
```

## Image Sizes (Approximate)

- **mobius:latest** (main platform): ~100MB
- **mobius-api**: ~60MB
- **mobiuscli**: ~50MB
- **mobius-client**: ~30MB
- **mobius-cocoon**: ~40MB
- **package-search**: ~30MB
- **mobius-scep**: ~20MB
- **mdm-migration-proxy**: ~25MB

All images use Alpine Linux base for minimal size and security.

## Security

All Dockerfiles:

- Use specific Go version (1.25.3) for reproducibility
- Use Alpine Linux for minimal attack surface
- Run as non-root user where applicable
- Include only necessary runtime dependencies
- Multi-stage builds to exclude build tools from final image

## Environment Variables

See each service's README for specific environment variables:

- [Server API README](../server/api/README.md)
- [CLI README](../server/cli/README.md)
- [Client README](../client/client/README.md)
- [Cocoon README](../cocoon/portal/README.md)
