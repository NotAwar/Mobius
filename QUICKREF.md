# Mobius Quick Reference Guide

## 🚀 Quick Start

### Starting the System

```bash
# Start API server
/tmp/mobius-api

# Start UI server (in web directory)
cd web && PORT=3000 node build/index.js

# Check status
./scripts/status-dashboard.sh
```

### Accessing Services

- **UI Dashboard**: <http://localhost:3000>
- **API Server**: <http://localhost:3001>
- **API Health**: <http://localhost:3001/api/v1/health>

## 📊 System Overview

### Core Components

- **API Server** (Port 3001) - Go/Fiber REST API
- **UI Server** (Port 3000) - SvelteKit dashboard
- **Kubernetes Cluster** - KIND cluster (mobius-cluster)
- **Databases** - 4 CNPG PostgreSQL clusters

### Database Architecture

| Database | Purpose | Storage |
|----------|---------|---------|
| mobius-app | SvelteKit app data (users, sessions) | 10Gi |
| mobius-clients | Client registry & configurations | 20Gi |
| mobius-osquery | Telemetry & query results | 50Gi |
| mobius-audit | Audit logs (partitioned) | 30Gi |

## 🔌 API Endpoints

### Health & Status

```bash
GET /api/v1/health              # Basic health
GET /api/v1/health/detailed     # Detailed status
GET /api/v1/health/live         # Liveness probe
GET /api/v1/health/ready        # Readiness probe
```

### Cluster Management

```bash
GET /api/v1/cluster/status      # Cluster status
GET /api/v1/cluster/nodes       # List nodes
GET /api/v1/cluster/pods        # List all pods
GET /api/v1/cluster/namespaces  # List namespaces
GET /api/v1/cluster/deployments # List deployments
GET /api/v1/cluster/services    # List services

# Pod Operations
GET    /api/v1/cluster/pods/:namespace/:name/logs  # Get pod logs
DELETE /api/v1/cluster/pods/:namespace/:name        # Delete pod
POST   /api/v1/cluster/pods/:namespace/:name/restart # Restart pod
```

### PostgreSQL Management

```bash
GET  /api/v1/postgres/databases      # List CNPG clusters
POST /api/v1/postgres/databases      # Create database
DELETE /api/v1/postgres/databases/:name # Delete database
```

### Headscale VPN

```bash
GET  /api/v1/headscale/users   # List users
POST /api/v1/headscale/users   # Create user
GET  /api/v1/headscale/nodes   # List VPN nodes
```

## 🗄️ Database Operations

### Connect to Databases

```bash
# App database
kubectl --kubeconfig=configs/cluster/kubeconfig exec -it mobius-app-1 -- \
  psql -U postgres -d mobius_app

# Clients database
kubectl --kubeconfig=configs/cluster/kubeconfig exec -it mobius-clients-1 -- \
  psql -U postgres -d mobius_clients

# OSQuery database
kubectl --kubeconfig=configs/cluster/kubeconfig exec -it mobius-osquery-1 -- \
  psql -U postgres -d mobius_osquery

# Audit database
kubectl --kubeconfig=configs/cluster/kubeconfig exec -it mobius-audit-1 -- \
  psql -U postgres -d mobius_audit
```

### Run Migrations

```bash
# Single database
cat migrations/app/001_initial_schema.up.sql | \
  kubectl --kubeconfig=configs/cluster/kubeconfig exec -i mobius-app-1 -- \
  psql -U postgres -d mobius_app

# All databases
for db in app clients osquery audit; do
  cat migrations/$db/001_initial_schema.up.sql | \
    kubectl --kubeconfig=configs/cluster/kubeconfig exec -i mobius-$db-1 -- \
    psql -U postgres -d mobius_$db
done
```

### View Database Status

```bash
# Check cluster status
kubectl --kubeconfig=configs/cluster/kubeconfig get clusters

# Check tables in a database
kubectl --kubeconfig=configs/cluster/kubeconfig exec mobius-app-1 -- \
  psql -U postgres -d mobius_app -c "\dt"
```

## 🛠️ Development Commands

### Building

```bash
# Build API server
go build -o /tmp/mobius-api ./cmd/api-only/

# Build full server (with setup)
go build -o /tmp/mobius-server ./cmd/server/

# Build UI
cd web && npm run build
```

### Testing

```bash
# Run status dashboard
./scripts/status-dashboard.sh

# Test API endpoints
curl http://localhost:3001/api/v1/health | jq .
curl http://localhost:3001/api/v1/cluster/namespaces | jq .

# Check UI
curl -I http://localhost:3000
```

### Kubernetes Operations

```bash
# Get all resources
kubectl --kubeconfig=configs/cluster/kubeconfig get all -A

# View pod logs
kubectl --kubeconfig=configs/cluster/kubeconfig logs -n cnpg-system <pod-name>

# Describe resource
kubectl --kubeconfig=configs/cluster/kubeconfig describe cluster mobius-app
```

## 📈 Monitoring

### View API Logs

The API server logs all requests with audit information:

- Request method and path
- Status code
- Duration in milliseconds
- Client IP address
- User agent
- Request ID (for correlation)

### Database Metrics

```bash
# Check cluster health
kubectl --kubeconfig=configs/cluster/kubeconfig get clusters

# Check pod status
kubectl --kubeconfig=configs/cluster/kubeconfig get pods -l cnpg.io/cluster

# View database size
kubectl --kubeconfig=configs/cluster/kubeconfig exec mobius-app-1 -- \
  psql -U postgres -d mobius_app -c "SELECT pg_size_pretty(pg_database_size('mobius_app'))"
```

## 🔒 Security Features

### Active Security Measures

- ✓ **Audit Logging** - Every request is logged with full context
- ✓ **Rate Limiting** - 100 requests per minute per IP
- ✓ **Request ID Tracking** - Unique ID for each request
- ✓ **Database Isolation** - Separate clusters per data domain
- ✓ **Error Handling** - Structured error responses

### Default Credentials

**Note:** Change these in production!

```
App DB:     postgres / changeme-app-password
Clients DB: postgres / changeme-clients-password
OSQuery DB: postgres / changeme-osquery-password
Audit DB:   postgres / changeme-audit-password
```

## 🎯 Next Steps

### Recommended Improvements

1. **Authentication** - Implement Keycloak integration
2. **RBAC** - Add role-based access control
3. **Backups** - Configure automated database backups
4. **Monitoring** - Add Prometheus/Grafana
5. **WebSockets** - Real-time updates
6. **Testing** - Integration and E2E tests

### Configuration

- API config: `internal/api/server.go` (DefaultConfig)
- Database schemas: `migrations/*/001_initial_schema.up.sql`
- UI config: `web/src/lib/api.ts`
- Cluster config: `configs/cluster/kubeconfig`

## 📚 Documentation

- [API Routes](docs/API_ROUTES.md) - Complete endpoint documentation
- [Database Schema](docs/DATABASE_SCHEMA.md) - Database design details
- [Rate Limiting](docs/RATE_LIMITING.md) - Rate limiting configuration

## 🆘 Troubleshooting

### API not responding

```bash
# Check if process is running
ps aux | grep mobius-api

# Check port availability
lsof -ti:3001

# Restart API
killall mobius-api && /tmp/mobius-api &
```

### Database connection issues

```bash
# Check cluster status
kubectl --kubeconfig=configs/cluster/kubeconfig get clusters

# Check pod status
kubectl --kubeconfig=configs/cluster/kubeconfig get pods -l cnpg.io/cluster

# View pod logs
kubectl --kubeconfig=configs/cluster/kubeconfig logs mobius-app-1
```

### UI not loading

```bash
# Check UI process
ps aux | grep node

# Check port
lsof -ti:3000

# Restart UI
cd web && PORT=3000 node build/index.js &
```

---

**Version:** 1.0.0  
**Last Updated:** December 17, 2025
