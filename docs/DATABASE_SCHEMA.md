# Database Schema Design

## Overview

Mobius uses CloudNativePG (CNPG) to manage multiple PostgreSQL database clusters, each dedicated to a specific data domain. This separation ensures clear data boundaries, independent scaling, and easier maintenance.

## Database Clusters

### 1. **mobius-app** (SvelteKit Application Data)

**Purpose:** Store application-specific data for the web UI
**Connection:** Used by SvelteKit frontend for sessions, user preferences, UI state

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- User preferences
CREATE TABLE user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    theme VARCHAR(50) DEFAULT 'dark',
    refresh_interval INTEGER DEFAULT 5000,
    auto_refresh BOOLEAN DEFAULT true,
    notifications_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Environment Variable:**

```
DATABASE_URL=postgres://mobius_app:password@mobius-app-rw.default.svc.cluster.local:5432/mobius_app
```

### 2. **mobius-clients** (Client Registry & Configuration)

**Purpose:** Store managed client information, configurations, and onboarding data
**Connection:** Used by API for client management operations

```sql
-- Clients table
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50) NOT NULL, -- linux, darwin, windows
    os_version VARCHAR(100),
    architecture VARCHAR(50), -- amd64, arm64, etc.
    ip_address INET,
    mac_address MACADDR,
    headscale_node_id VARCHAR(255),
    last_seen TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending', -- pending, active, inactive, offline
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(hostname)
);

-- Client configurations
CREATE TABLE client_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    config_key VARCHAR(255) NOT NULL,
    config_value TEXT,
    config_type VARCHAR(50), -- string, number, boolean, json
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(client_id, config_key)
);

-- Client tags
CREATE TABLE client_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    tag_name VARCHAR(100) NOT NULL,
    tag_value VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(client_id, tag_name)
);

-- Client groups
CREATE TABLE client_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Client group memberships
CREATE TABLE client_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    group_id UUID REFERENCES client_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(client_id, group_id)
);
```

**Environment Variable:**

```
CLIENTS_DATABASE_URL=postgres://mobius_clients:password@mobius-clients-rw.default.svc.cluster.local:5432/mobius_clients
```

### 3. **mobius-osquery** (OSQuery Data)

**Purpose:** Store telemetry and system data collected from OSQuery agents
**Connection:** Used by API for data ingestion and querying

```sql
-- OSQuery results
CREATE TABLE osquery_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL, -- References clients table in mobius-clients
    query_name VARCHAR(255) NOT NULL,
    calendar_time TIMESTAMP NOT NULL,
    unix_time BIGINT NOT NULL,
    epoch BIGINT,
    counter BIGINT,
    columns JSONB NOT NULL, -- Flexible storage for query results
    action VARCHAR(50), -- added, removed, snapshot
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_osquery_results_client_id ON osquery_results(client_id);
CREATE INDEX idx_osquery_results_query_name ON osquery_results(query_name);
CREATE INDEX idx_osquery_results_calendar_time ON osquery_results(calendar_time DESC);
CREATE INDEX idx_osquery_results_columns ON osquery_results USING gin(columns);

-- OSQuery scheduled queries
CREATE TABLE osquery_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    query TEXT NOT NULL,
    interval INTEGER NOT NULL, -- seconds
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- OSQuery packs
CREATE TABLE osquery_packs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    platform VARCHAR(50), -- linux, darwin, windows, all
    version VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Pack queries relationship
CREATE TABLE osquery_pack_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pack_id UUID REFERENCES osquery_packs(id) ON DELETE CASCADE,
    query_id UUID REFERENCES osquery_queries(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(pack_id, query_id)
);
```

**Environment Variable:**

```
OSQUERY_DATABASE_URL=postgres://mobius_osquery:password@mobius-osquery-rw.default.svc.cluster.local:5432/mobius_osquery
```

### 4. **mobius-audit** (Audit Logging)

**Purpose:** Store audit logs for all actions performed in the system
**Connection:** Write-only for most services, read for audit reporting

```sql
-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP DEFAULT NOW() NOT NULL,
    user_id UUID, -- Can be NULL for system actions
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100) NOT NULL, -- client, cluster, database, etc.
    resource_id VARCHAR(255),
    resource_name VARCHAR(255),
    method VARCHAR(10), -- GET, POST, PUT, DELETE, etc.
    endpoint VARCHAR(500),
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    status_code INTEGER,
    error_message TEXT,
    metadata JSONB, -- Additional context
    duration_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for audit queries
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX idx_audit_logs_metadata ON audit_logs USING gin(metadata);
```

**Environment Variable:**

```
AUDIT_DATABASE_URL=postgres://mobius_audit:password@mobius-audit-rw.default.svc.cluster.local:5432/mobius_audit
```

## CNPG Cluster Configurations

Each database cluster should be deployed with:

- **Instances**: 1-3 (1 for dev, 3 for production)
- **Storage**: 10Gi minimum (adjust based on data volume)
- **Backup**: Enabled with retention policy
- **Monitoring**: Prometheus metrics enabled
- **Connection Pooling**: PgBouncer enabled

## Migration Strategy

1. Create CNPG clusters for each domain
2. Apply initial schema migrations
3. Update environment variables in services
4. Deploy database migration tool (golang-migrate or similar)
5. Implement automatic migration on startup

## Connection Strings

All services should use the read-write service endpoint:

```
<cluster-name>-rw.<namespace>.svc.cluster.local:5432
```

For read-only operations (future optimization):

```
<cluster-name>-ro.<namespace>.svc.cluster.local:5432
```

## Security Considerations

1. **Credentials**: Store in Kubernetes secrets
2. **TLS**: Enable for all connections in production
3. **RBAC**: Separate users for different services
4. **Network Policies**: Restrict database access to authorized pods only
5. **Encryption**: Enable at-rest encryption for sensitive data
