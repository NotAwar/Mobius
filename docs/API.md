# Mobius API Documentation

## Overview

The Mobius API provides a comprehensive interface for managing Kubernetes clusters, PostgreSQL databases, Headscale VPN, clients, users, and OSQuery integrations. All protected endpoints require authentication via Keycloak and enforce role-based access control (RBAC).

## Authentication

### Keycloak OAuth2/OpenID Connect

All protected endpoints require a valid JWT token obtained from Keycloak. The token must be included in the `Authorization` header:

```
Authorization: Bearer <jwt_token>
```

### Obtaining a Token

```bash
curl -X POST "https://keycloak.example.com/auth/realms/mobius/protocol/openid-connect/token" \
  -d "client_id=mobius-api" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "grant_type=password" \
  -d "username=admin@example.com" \
  -d "password=your_password"
```

### Third-Party Identity Providers

Keycloak supports federation with external identity providers:

- **Azure Active Directory (AD)**
- **AWS Cognito**
- **Google Workspace**
- **GitHub**
- **GitLab**
- **LDAP/Active Directory**

Configure these in your Keycloak realm under "Identity Providers".

## Authorization (RBAC)

### Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| **admin** | Full system access | All permissions (18) |
| **operator** | Read/write operational access | Read/write for cluster, postgres, headscale, clients, osquery (11 perms) |
| **viewer** | Read-only access | Read-only for all resources except user management (8 perms) |
| **user** | Limited user access | Read own user data, view audit logs (2 perms) |

### Permissions

| Permission | Resources Affected |
|------------|-------------------|
| `cluster:read`, `cluster:write`, `cluster:delete` | Kubernetes cluster operations |
| `postgres:read`, `postgres:write`, `postgres:delete` | PostgreSQL database management |
| `headscale:read`, `headscale:write`, `headscale:delete` | Headscale VPN management |
| `user:read`, `user:write`, `user:delete` | User management |
| `client:read`, `client:write`, `client:delete` | Client device management |
| `osquery:read`, `osquery:write`, `osquery:delete` | OSQuery management |
| `audit:read` | Audit log access |
| `config:read`, `config:write` | Configuration management |

## Base URL

```
http://localhost:3001/api/v1
```

## Public Endpoints (No Authentication)

### Health Checks

#### Basic Health Check

```http
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Liveness Probe

```http
GET /health/live
```

#### Readiness Probe

```http
GET /health/ready
```

## Protected Endpoints (Authentication Required)

### Health - Detailed

#### Get Detailed Health Information

```http
GET /health/detailed
```

**Required Permission:** `cluster:read`

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "services": {
    "cluster": "healthy",
    "postgres": "healthy",
    "headscale": "healthy"
  },
  "databases": {
    "app": "connected",
    "clients": "connected",
    "osquery": "connected",
    "audit": "connected"
  }
}
```

---

## User Management

### List Users

```http
GET /users?role=admin&active=true&limit=50&offset=0
```

**Required Permission:** `user:read`

**Query Parameters:**

- `role` (optional): Filter by role (admin, operator, viewer, user)
- `active` (optional): Filter by active status (true, false)
- `limit` (optional): Number of results (default: 50)
- `offset` (optional): Offset for pagination (default: 0)

**Response:**

```json
{
  "users": [
    {
      "id": "uuid",
      "email": "admin@example.com",
      "username": "admin",
      "first_name": "Admin",
      "last_name": "User",
      "role": "admin",
      "active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### Get User

```http
GET /users/:id
```

**Required Permission:** `user:read`

### Create User

```http
POST /users
Content-Type: application/json

{
  "email": "newuser@example.com",
  "username": "newuser",
  "first_name": "New",
  "last_name": "User",
  "role": "operator",
  "active": true
}
```

**Required Permission:** `user:write`

### Update User

```http
PUT /users/:id
Content-Type: application/json

{
  "first_name": "Updated",
  "role": "viewer"
}
```

**Required Permission:** `user:write`

### Delete User

```http
DELETE /users/:id
```

**Required Permission:** `user:delete`

### Get User Preferences

```http
GET /users/:id/preferences
```

**Required Permission:** `user:read` or `user:write`

**Response:**

```json
{
  "theme": "dark",
  "language": "en",
  "timezone": "America/New_York",
  "notifications": {
    "email": true,
    "push": false
  }
}
```

### Update User Preferences

```http
PUT /users/:id/preferences
Content-Type: application/json

{
  "theme": "light",
  "language": "en",
  "timezone": "UTC"
}
```

**Required Permission:** `user:write`

### Reset User Password

```http
POST /users/:id/reset-password
```

**Required Permission:** `user:write`

---

## Client Management

### List Clients

```http
GET /clients?status=online&os_type=darwin&tag=production&limit=50&offset=0
```

**Required Permission:** `client:read`

**Query Parameters:**

- `status` (optional): Filter by status (online, offline, inactive)
- `os_type` (optional): Filter by OS type (darwin, linux, windows)
- `tag` (optional): Filter by tag
- `limit` (optional): Number of results (default: 50)
- `offset` (optional): Offset for pagination (default: 0)

**Response:**

```json
{
  "clients": [
    {
      "id": "uuid",
      "hostname": "macbook-pro-01",
      "os_type": "darwin",
      "os_version": "14.2.1",
      "agent_version": "1.2.3",
      "ip_address": "192.168.1.100",
      "status": "online",
      "last_seen": "2024-01-15T10:30:00Z",
      "tags": ["production", "office"],
      "metadata": {},
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### Get Client

```http
GET /clients/:id
```

**Required Permission:** `client:read`

### Register Client

```http
POST /clients
Content-Type: application/json

{
  "hostname": "new-laptop",
  "os_type": "linux",
  "os_version": "Ubuntu 22.04",
  "agent_version": "1.2.3",
  "ip_address": "192.168.1.101",
  "tags": ["development"]
}
```

**Required Permission:** `client:write`

### Update Client

```http
PUT /clients/:id
Content-Type: application/json

{
  "status": "inactive",
  "tags": ["archived"]
}
```

**Required Permission:** `client:write`

### Delete Client

```http
DELETE /clients/:id
```

**Required Permission:** `client:delete`

### Add Client Tag

```http
POST /clients/:id/tags
Content-Type: application/json

{
  "tag": "production"
}
```

**Required Permission:** `client:write`

### Remove Client Tag

```http
DELETE /clients/:id/tags/:tag
```

**Required Permission:** `client:write`

### Get Client Groups

```http
GET /clients/groups
```

**Required Permission:** `client:read`

### Get Client Configuration

```http
GET /clients/:id/configuration
```

**Required Permission:** `client:read`

### Update Client Configuration

```http
PUT /clients/:id/configuration
Content-Type: application/json

{
  "check_in_interval": 300,
  "osquery_enabled": true
}
```

**Required Permission:** `client:write`

### Get Client Check-ins

```http
GET /clients/:id/check-ins?limit=50
```

**Required Permission:** `client:read`

### Manual Client Check-in

```http
POST /clients/:id/check-in
```

**Required Permission:** `client:write`

---

## OSQuery Management

### List Queries

```http
GET /osquery/queries?platform=darwin&active=true&limit=50&offset=0
```

**Required Permission:** `osquery:read`

**Query Parameters:**

- `platform` (optional): Filter by platform (darwin, linux, windows, all)
- `active` (optional): Filter by active status
- `limit`, `offset`: Pagination

**Response:**

```json
{
  "queries": [
    {
      "id": "uuid",
      "name": "system_info",
      "query": "SELECT * FROM system_info;",
      "description": "Get system information",
      "platform": "all",
      "interval": 3600,
      "active": true,
      "tags": ["system", "inventory"],
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### Get Query

```http
GET /osquery/queries/:id
```

**Required Permission:** `osquery:read`

### Create Query

```http
POST /osquery/queries
Content-Type: application/json

{
  "name": "listening_ports",
  "query": "SELECT * FROM listening_ports WHERE port != 0;",
  "description": "Monitor listening network ports",
  "platform": "all",
  "interval": 300,
  "active": true,
  "tags": ["network", "security"]
}
```

**Required Permission:** `osquery:write`

### Update Query

```http
PUT /osquery/queries/:id
Content-Type: application/json

{
  "interval": 600,
  "active": false
}
```

**Required Permission:** `osquery:write`

### Delete Query

```http
DELETE /osquery/queries/:id
```

**Required Permission:** `osquery:delete`

### Execute Query

```http
POST /osquery/queries/:id/execute
Content-Type: application/json

{
  "client_ids": ["uuid1", "uuid2"],
  "async": true
}
```

**Required Permission:** `osquery:write`

**Response:**

```json
{
  "message": "Query execution initiated",
  "query_id": "uuid",
  "client_ids": ["uuid1", "uuid2"],
  "async": true,
  "job_id": "job-uuid"
}
```

### List Packs

```http
GET /osquery/packs
```

**Required Permission:** `osquery:read`

### Create Pack

```http
POST /osquery/packs
Content-Type: application/json

{
  "name": "security_monitoring",
  "description": "Security-focused queries",
  "platform": "all",
  "active": true,
  "queries": ["query-uuid-1", "query-uuid-2"],
  "tags": ["security", "compliance"]
}
```

**Required Permission:** `osquery:write`

### Get Query Results

```http
GET /osquery/results?query_id=uuid&client_id=uuid&success=true&limit=50&offset=0
```

**Required Permission:** `osquery:read`

**Response:**

```json
{
  "results": [
    {
      "id": "uuid",
      "query_id": "uuid",
      "client_id": "uuid",
      "executed_at": "2024-01-15T10:30:00Z",
      "success": true,
      "row_count": 1,
      "results": [
        {
          "hostname": "macbook-pro-01",
          "cpu_brand": "Apple M1 Pro",
          "memory_mb": "16384"
        }
      ],
      "duration_ms": 45,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### Export Results

```http
GET /osquery/results/export?format=json&query_id=uuid
```

**Required Permission:** `osquery:read`

**Query Parameters:**

- `format`: json or csv
- `query_id`: Filter by query

---

## Cluster Management

### Get Cluster Status

```http
GET /cluster/status
```

**Required Permission:** `cluster:read`

### List Nodes

```http
GET /cluster/nodes
```

**Required Permission:** `cluster:read`

### List Pods

```http
GET /cluster/pods
```

**Required Permission:** `cluster:read`

### Get Pod Logs

```http
GET /cluster/pods/:namespace/:name/logs
```

**Required Permission:** `cluster:read`

### Delete Pod

```http
DELETE /cluster/pods/:namespace/:name
```

**Required Permission:** `cluster:delete`

### Restart Pod

```http
POST /cluster/pods/:namespace/:name/restart
```

**Required Permission:** `cluster:write`

---

## PostgreSQL Management

### List Databases

```http
GET /postgres/databases
```

**Required Permission:** `postgres:read`

### Create Database

```http
POST /postgres/databases
Content-Type: application/json

{
  "name": "newdb",
  "owner": "postgres"
}
```

**Required Permission:** `postgres:write`

### Delete Database

```http
DELETE /postgres/databases/:name
```

**Required Permission:** `postgres:delete`

---

## Headscale Management

### List Users

```http
GET /headscale/users
```

**Required Permission:** `headscale:read`

### Create User

```http
POST /headscale/users
Content-Type: application/json

{
  "name": "newuser"
}
```

**Required Permission:** `headscale:write`

### List Nodes

```http
GET /headscale/nodes
```

**Required Permission:** `headscale:read`

---

## Audit Logs

### Get Audit Logs

```http
GET /audit/logs?source=api&limit=100&offset=0
```

**Required Permission:** `audit:read`

**Query Parameters:**

- `source` (optional): Filter by source
- `limit`, `offset`: Pagination

### Get Audit Sources

```http
GET /audit/sources
```

**Required Permission:** `audit:read`

---

## Error Responses

### 400 Bad Request

```json
{
  "error": "Validation error",
  "message": "Name is required"
}
```

### 401 Unauthorized

```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication token"
}
```

### 403 Forbidden

```json
{
  "error": "Forbidden",
  "message": "Insufficient permissions"
}
```

### 404 Not Found

```json
{
  "error": "Not Found",
  "message": "Resource not found"
}
```

### 500 Internal Server Error

```json
{
  "error": "Internal Server Error",
  "message": "An unexpected error occurred"
}
```

---

## Environment Variables

```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=3001
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s
SERVER_IDLE_TIMEOUT=120s

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_MAX_CONNS=25
DB_MIN_CONNS=5
DB_MAX_CONN_LIFETIME=1h
DB_MAX_CONN_IDLE_TIME=30m

# Keycloak Configuration
KEYCLOAK_REALM_URL=https://keycloak.example.com/auth/realms/mobius
KEYCLOAK_CLIENT_ID=mobius-api
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_ENABLED=true

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
```

---

## Rate Limiting

The API implements rate limiting on a per-IP basis:

- **100 requests per minute** for authenticated users
- **20 requests per minute** for unauthenticated endpoints

Exceeded rate limits return HTTP 429 Too Many Requests.

---

## Pagination

All list endpoints support pagination using `limit` and `offset` query parameters:

- Default `limit`: 50
- Maximum `limit`: 200
- Default `offset`: 0

---

## Filtering

Many endpoints support filtering through query parameters. Supported filters vary by endpoint (see specific endpoint documentation).

---

## Future Enhancements

- WebSocket support for real-time updates
- GraphQL endpoint for flexible queries
- File upload/download capabilities
- Backup/restore endpoints
- Prometheus metrics export
- OpenAPI/Swagger specification
