# Docker Compose Configuration Guide

This document explains the different docker-compose files in the Mobius MDM
platform and their intended use cases.

## Docker Compose Files Overview

### 1. docker-compose.yml - Full Development Environment

**Location:** `docker-compose.yml` (root)

**Purpose:** Complete development setup with all dependencies for local
development and testing.

**What it includes:**

- MySQL 8.0.36 (production database)
- MySQL Test (separate instance for testing with optimized settings)
- Redis (caching and pub/sub)
- Mobius services (when uncommented)

**Use cases:**

- Local development
- Running integration tests
- Full platform testing
- CI/CD pipelines

**Key features:**

- GTID consistency for production-like behavior
- Separate test database with performance optimizations
- Configurable MySQL image (supports MariaDB)
- Platform-specific settings (x86_64, ARM64 support)

**Usage:**

```bash
# Start development environment
docker-compose up -d

# Start with specific services
docker-compose up -d mysql redis

# Run tests
docker-compose up mysql_test
```

**Ports:**

- MySQL: 3306
- MySQL Test: 33060 (if configured)
- Redis: 6379

---

### 2. docker-compose.score.yaml - Production-like Deployment

**Location:** `docker-compose.score.yaml` (root)

**Purpose:** Production-like deployment configuration integrated with
Score specification for cloud-native deployments.

**What it includes:**

- MySQL 8.0.36 with persistent volumes
- Redis 7 Alpine
- Mobius API Server (with frontend)
- Mobius CLI (tools profile)
- Mobius Client (client profile)
- Mobius Cocoon Portal (enterprise profile)

**Use cases:**

- Production deployment testing
- Score.dev integration testing
- Demonstrating full platform stack
- Container orchestration validation

**Key features:**

- Health checks for all services
- Service dependencies properly configured
- Profile-based service activation
- Production-ready restart policies
- Named volumes for data persistence
- Dedicated network

**Usage:**

```bash
# Start core services (API, MySQL, Redis)
docker-compose -f docker-compose.score.yaml up -d

# Include CLI tools
docker-compose -f docker-compose.score.yaml --profile tools up -d

# Include device client
docker-compose -f docker-compose.score.yaml --profile client up -d

# Include enterprise portal
docker-compose -f docker-compose.score.yaml --profile enterprise up -d

# Full stack with all services
docker-compose -f docker-compose.score.yaml --profile tools \
  --profile client --profile enterprise up -d
```

**Ports:**

- API Server: 8081
- Cocoon Portal: 8082
- MySQL: 3306
- Redis: 6379

**Profiles:**

- `tools`: Mobius CLI utilities
- `client`: Device client agent
- `enterprise`: Cocoon enterprise portal

---

### 3. nanomdm Docker Compose - MDM Service

**Location:** `server/api/server/mdm/nanomdm/docker-compose.yml`

**Purpose:** Specialized setup for the NanoMDM service component used for
Apple device management.

**What it includes:**

- NanoMDM service configuration
- MDM-specific dependencies

**Use cases:**

- Testing Apple MDM functionality
- Developing NanoMDM integrations
- MDM service isolation

**Usage:**

```bash
cd server/api/server/mdm/nanomdm
docker-compose up -d
```

---

## Choosing the Right Configuration

### Use `docker-compose.yml` when

- Developing locally
- Running tests
- Need separate test database
- Working on core platform features
- CI/CD pipeline execution

### Use `docker-compose.score.yaml` when

- Testing production deployment
- Demonstrating full platform
- Validating Score specifications
- Testing service orchestration
- Deploying to staging/production

### Use `nanomdm/docker-compose.yml` when

- Working specifically on Apple MDM features
- Testing NanoMDM integration
- Debugging MDM service issues

## Environment Variables

### Common Variables

Both main compose files support these environment variables:

**MySQL Configuration:**

- `MOBIUS_MYSQL_IMAGE`: MySQL image (default: `mysql:8.0.36`)
- `MOBIUS_MYSQL_PLATFORM`: Platform architecture (default: `linux/x86_64`)
- `MYSQL_ROOT_PASSWORD`: Root password (default: `toor`)
- `MYSQL_DATABASE`: Database name (default: `mobius`)
- `MYSQL_USER`: Database user (default: `mobius`)
- `MYSQL_PASSWORD`: Database password (default: `insecure`)

**Mobius Configuration:**

- `MOBIUS_SERVER_ADDRESS`: Server bind address (default: `0.0.0.0:8081`)
- `MOBIUS_MYSQL_ADDRESS`: MySQL connection (default: `mysql:3306`)
- `MOBIUS_REDIS_ADDRESS`: Redis connection (default: `redis:6379`)
- `MOBIUS_LOGGING_JSON`: Enable JSON logging (default: `true`)

## Data Persistence

### docker-compose.yml

- Uses named volume: `mysql-persistent-volume`
- Data persists across container restarts

### docker-compose.score.yaml

- Uses named volume: `mysql-data`
- Configured with production-like persistence

## Networking

### docker-compose.yml

- Uses default bridge network
- Services communicate via service names

### docker-compose.score.yaml

- Uses custom network: `mobius_network`
- Better isolation and control

## Health Checks

The `docker-compose.score.yaml` includes health checks for:

- **MySQL**: `mysqladmin ping`
- **Redis**: `redis-cli ping`

Services wait for dependencies to be healthy before starting.

## Tips

1. **Clean start:**

   ```bash
   docker-compose down -v  # Remove volumes
   docker-compose up -d
   ```

2. **View logs:**

   ```bash
   docker-compose logs -f mobius-api
   ```

3. **Rebuild after code changes:**

   ```bash
   docker-compose build --no-cache
   docker-compose up -d
   ```

4. **Check service status:**

   ```bash
   docker-compose ps
   ```

5. **Access database:**

   ```bash
   docker-compose exec mysql mysql -u mobius -pinsecure mobius
   ```

## See Also

- [Docker Configuration Guide](./DOCKER.md) - Individual Dockerfile documentation
- [Main README](../README.md) - General platform documentation
- [Score Specification](../deployments/score.yaml) - Score.dev configuration
