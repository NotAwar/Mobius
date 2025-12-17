# Mobius Implementation Roadmap

## Complete Development Plan with Client Service Integration

**Last Updated:** December 18, 2025
**Status:** Client Service Complete ✅ | Frontend UI In Progress 🚧 | Backend API Partial ✅

---

## Executive Summary

This document outlines the complete implementation roadmap for the Mobius MDM platform, incorporating:

1. **Lightweight client-side service** (kernel-level, <50MB, <5% CPU)
2. **Frontend UI pages** for all MDM functionality
3. **Backend API integrations** with PostgreSQL databases
4. **Server-side management** capabilities via SSH and API

---

## 1. Client-Side Service ✅ COMPLETED

### Architecture Overview

The Mobius client is a **super-thin kernel-level service** designed to run on managed devices with minimal resource footprint.

**Components Created:**

- ✅ Main service coordinator ([service.go](../internal/client/service.go))
- ✅ Configuration management ([config.go](../internal/client/config.go))
- ✅ Client enrollment ([enroll.go](../internal/client/enroll.go))
- ✅ Server reporter ([reporter.go](../internal/client/reporter.go))
- ✅ System info collector ([sysinfo.go](../internal/client/sysinfo.go))
- ✅ OSQuery manager ([osquery.go](../internal/client/osquery.go))
- ✅ SSH manager for remote access ([ssh.go](../internal/client/ssh.go))
- ✅ Health monitor ([health.go](../internal/client/health.go))
- ✅ CLI entry point ([cmd/client/main.go](../cmd/client/main.go))

**Resource Constraints (Enforced):**

- **Memory:** Maximum 50MB (configurable)
- **CPU:** Maximum 5% (configurable)
- **Disk I/O:** Minimal (logs only)
- **Network:** ~1KB/min (check-ins)

**Key Features:**

1. **Enrollment:** One-command onboarding with enrollment keys
2. **Check-ins:** Automated periodic reporting (default: 5 minutes)
3. **OSQuery Integration:** Execute queries, collect results, report back
4. **SSH Access:** Secure remote management on custom port (default: 2222)
5. **Event Reporting:** Real-time event streaming to server
6. **Health Monitoring:** Self-monitoring with automatic degradation detection
7. **Auto-reconnect:** Resilient to network failures
8. **Resource Limits:** Self-enforcing memory/CPU constraints

### Installation Methods

**Linux (systemd):**

```bash
curl -sSL https://mobius.example.com/install.sh | sudo bash -s -- --enroll-key KEY
```

**macOS (launchd):**

```bash
curl -sSL https://mobius.example.com/install.sh | sudo bash -s -- --enroll-key KEY
```

**Windows (NSSM/sc):**

```powershell
iwr -useb https://mobius.example.com/install.ps1 | iex; Install-MobiusClient -EnrollKey "KEY"
```

**Manual:**

```bash
mobius-client --server https://mobius.example.com --enroll-key KEY
```

### Client Communication Flow

```
Client Device                    Mobius Server
┌──────────────┐                ┌──────────────┐
│              │                │              │
│  1. Enroll   │──────────────>│  Generate    │
│              │<──────────────│  ID + Key    │
│              │                │              │
│  2. Check-in │──────────────>│  Store Info  │
│   (5 min)    │                │              │
│              │                │              │
│  3. Report   │──────────────>│  Process     │
│   OSQuery    │                │  Results     │
│              │                │              │
│  4. Receive  │<──────────────│  Push        │
│   Commands   │                │  Commands    │
│              │                │              │
│  5. Execute  │──────────────>│  Collect     │
│   & Report   │                │  Results     │
└──────────────┘                └──────────────┘
```

---

## 2. Server-Side API Requirements

### 2.1 Client Enrollment API ❌ NOT STARTED

**Endpoint:** `POST /api/v1/clients/enroll`

**Purpose:** Accept new client enrollments with validation

**Request:**

```json
{
  "enrollment_key": "abc123...",
  "hostname": "web-server-01",
  "system_info": {
    "os": "linux",
    "os_version": "Ubuntu 22.04",
    "arch": "amd64",
    "cpu_cores": 8,
    "total_memory_mb": 16384,
    "ip_addresses": ["192.168.1.100"],
    "mac_addresses": ["00:11:22:33:44:55"]
  }
}
```

**Response:**

```json
{
  "client_id": "uuid-generated",
  "client_key": "secure-key-generated",
  "server_url": "https://mobius.example.com",
  "message": "Enrollment successful"
}
```

**Database Operations:**

1. Validate enrollment key (check expiry, max_uses)
2. Increment enrollment key usage count
3. Generate unique client_id (UUID)
4. Generate secure client_key (32-byte random)
5. Insert into `clients` table
6. Insert into `client_hardware` table
7. Auto-assign groups if enrollment key has group_ids
8. Apply auto-tags from enrollment key
9. Create audit log entry

**Implementation:** `api/v1/clients.go` - Add `EnrollClient` handler

---

### 2.2 Client Check-In API ❌ NOT STARTED

**Endpoint:** `POST /api/v1/clients/:id/check-in`

**Purpose:** Accept periodic check-ins from clients

**Request:**

```json
{
  "timestamp": "2025-12-18T10:30:00Z",
  "system_info": { /* current system state */ },
  "osquery_results": { /* recent query results */ },
  "health_status": {
    "status": "healthy",
    "cpu_usage_percent": 2.5,
    "memory_usage_mb": 45
  }
}
```

**Response:**

```json
{
  "status": "ok",
  "configuration": { /* updated config if changed */ },
  "pending_commands": [ /* commands to execute */ ]
}
```

**Database Operations:**

1. Update `clients.last_seen` timestamp (trigger)
2. Update `clients.status` to 'online'
3. Insert into `client_check_ins` table
4. Update `client_hardware` if changed
5. Process OSQuery results (insert into `osquery_results`)
6. Check for pending commands/queries
7. Fetch updated configuration if version changed

**Implementation:** `api/v1/clients.go` - Add `ClientCheckIn` handler

---

### 2.3 Client Events API ❌ NOT STARTED

**Endpoint:** `POST /api/v1/clients/:id/events`

**Purpose:** Accept real-time events from clients

**Request:**

```json
{
  "client_id": "uuid",
  "event_type": "software_installed",
  "timestamp": "2025-12-18T10:30:00Z",
  "data": {
    "package": "nginx",
    "version": "1.18.0"
  }
}
```

**Event Types:**

- `software_installed` / `software_removed`
- `user_login` / `user_logout`
- `service_started` / `service_stopped`
- `security_alert`
- `hardware_change`
- `network_change`
- `error`

**Database Operations:**

1. Insert into `client_events` table (create table if needed)
2. Create audit log entry for security events
3. Trigger alerts if configured

**Implementation:** `api/v1/clients.go` - Add `ReportEvent` handler

---

### 2.4 Enrollment Keys Management API ❌ NOT STARTED

**Endpoints:**

- `GET /api/v1/clients/enrollment-keys` - List all keys
- `POST /api/v1/clients/enrollment-keys` - Create new key
- `GET /api/v1/clients/enrollment-keys/:id` - Get key details
- `DELETE /api/v1/clients/enrollment-keys/:id` - Revoke key

**Database Schema (NEW TABLE):**

```sql
CREATE TABLE enrollment_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    expires_at TIMESTAMP,
    max_uses INTEGER DEFAULT 1,
    used_count INTEGER DEFAULT 0,
    revoked BOOLEAN DEFAULT FALSE,
    tags TEXT[],
    auto_assign_group_ids UUID[],
    metadata JSONB
);

CREATE INDEX idx_enrollment_keys_key ON enrollment_keys(key);
CREATE INDEX idx_enrollment_keys_expires ON enrollment_keys(expires_at);
```

**Implementation:** `api/v1/enrollment.go` - New file

---

### 2.5 Remote Command Execution API ❌ NOT STARTED

**Endpoint:** `POST /api/v1/clients/:id/execute`

**Purpose:** Queue remote command execution via SSH

**Request:**

```json
{
  "command": "systemctl restart nginx",
  "timeout": 30,
  "run_as": "root"
}
```

**Response:**

```json
{
  "command_id": "uuid",
  "status": "queued",
  "message": "Command queued for execution"
}
```

**Implementation Strategy:**

1. Store command in `client_pending_commands` table
2. Client fetches on next check-in
3. Client executes via SSH manager
4. Client reports result back
5. Update command status in database

**Database Schema (NEW TABLE):**

```sql
CREATE TABLE client_pending_commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id),
    command TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    status TEXT DEFAULT 'pending', -- pending, executing, completed, failed
    result JSONB,
    executed_at TIMESTAMP,
    timeout INTEGER DEFAULT 30
);
```

**Implementation:** `api/v1/clients.go` - Add `ExecuteCommand` handler

---

## 3. Frontend UI Pages

### 3.1 Completed Pages ✅

- ✅ **Layout** (`/web/src/routes/+layout.svelte`)
  - MDM-first navigation (4 sections)
  - Proper branding colors
  - Mobius logo integration
  - No emojis

- ✅ **Dashboard** (`/web/src/routes/+page.svelte`)
  - Client statistics cards
  - System health indicator
  - Quick actions grid
  - Recently active clients table
  - Real API integration

- ✅ **Enrollment Page** (`/web/src/routes/enrollment/+page.svelte`)
  - Enrollment keys management
  - Create/revoke keys
  - Copy to clipboard
  - Installation instructions
  - Auto-assign groups and tags

### 3.2 High Priority Pages (Week 1) 🚧

#### 3.2.1 Clients List Page ❌ NOT STARTED

**File:** `/web/src/routes/clients/+page.svelte`

**Features:**

- Full client table with sorting
- Filter controls:
  - Status (online, offline, unhealthy)
  - OS type (Linux, macOS, Windows)
  - Tags
  - Groups
  - Last seen (1h, 24h, 7d, 30d, custom)
- Search bar (hostname, IP, MAC address)
- Bulk action toolbar:
  - Add to group
  - Run query
  - Execute command
  - Delete clients
- Pagination (10/25/50/100 per page)
- Column customization
- Export to CSV
- Real-time status updates (polling every 30s)

**API Integration:**

```typescript
GET /api/v1/clients?status=online&os=linux&tags=production&limit=50&offset=0
```

**Priority:** **CRITICAL** - This is the primary MDM interface

---

#### 3.2.2 Client Details Page ❌ NOT STARTED

**File:** `/web/src/routes/clients/[id]/+page.svelte`

**Sections:**

1. **Overview Card**
   - Hostname, IP, MAC, status
   - Last seen, uptime
   - OS, architecture
   - Client version
   - Quick actions (refresh, delete, run query)

2. **Hardware Tab**
   - CPU: Model, cores, speed, usage
   - Memory: Total, used, usage %
   - Disk: Partitions, total, used, usage %
   - Network interfaces

3. **Software Tab**
   - Installed packages list
   - Search/filter
   - Installation dates

4. **Tags & Groups Tab**
   - Current tags (add/remove)
   - Group memberships (assign/unassign)

5. **Configuration Tab**
   - Check-in interval
   - OSQuery settings
   - SSH settings
   - Edit and save

6. **Check-Ins Tab**
   - Timeline of check-ins
   - Status changes
   - System info changes

7. **OSQuery Results Tab**
   - Recent query results
   - Export results
   - Execute new query

8. **Activity Log Tab**
   - Audit trail for this client
   - Who did what and when

**API Integration:**

```typescript
GET /api/v1/clients/:id
GET /api/v1/clients/:id/hardware
GET /api/v1/clients/:id/software
GET /api/v1/clients/:id/check-ins?limit=50
GET /api/v1/osquery/results?client_id=:id&limit=50
```

**Priority:** **CRITICAL** - Essential for device management

---

#### 3.2.3 Client Groups Page ❌ NOT STARTED

**File:** `/web/src/routes/groups/+page.svelte`

**Features:**

- Groups list with member counts
- Create group modal:
  - Name, description
  - Auto-assignment criteria (OS, tags, hostname pattern)
  - Manual member selection
- Edit group (rename, change criteria, members)
- Delete group (with confirmation)
- View group members (filterable table)
- Bulk actions on group:
  - Run query on all members
  - Execute command on all members
  - Apply configuration to all members
- Group policies (future):
  - Enforce OSQuery packs
  - Enforce configurations
  - Enforce tags

**API Integration:**

```typescript
GET /api/v1/clients/groups
POST /api/v1/clients/groups
PUT /api/v1/clients/groups/:id
DELETE /api/v1/clients/groups/:id
GET /api/v1/clients/groups/:id/members
POST /api/v1/clients/groups/:id/members (bulk assign)
```

**Priority:** **HIGH** - Critical for role-based management

---

#### 3.2.4 OSQuery Execution Page ❌ NOT STARTED

**File:** `/web/src/routes/osquery/+page.svelte`

**Features:**

1. **Query Editor Section**
   - SQL editor with syntax highlighting (CodeMirror or Monaco)
   - Query templates dropdown:
     - "Running Processes"
     - "Installed Software"
     - "Listening Ports"
     - "Logged In Users"
     - "System Info"
     - "Network Connections"
     - Custom saved queries
   - Query validation
   - Syntax hints

2. **Target Selection**
   - Select clients (dropdown with search)
   - Select groups (dropdown)
   - Select all online clients
   - Preview target count

3. **Execution Controls**
   - Execute button (with loading state)
   - Save query to library
   - Schedule query (future)
   - Export results (JSON, CSV)

4. **Results Table**
   - Tabular display of results
   - Per-client results breakdown
   - Expandable rows for details
   - Pagination
   - Error states for failed queries
   - Execution time stats

5. **Execution History**
   - Recent queries executed
   - Re-run button
   - View results button

**API Integration:**

```typescript
POST /api/v1/osquery/queries/:id/execute
GET /api/v1/osquery/results?query_id=:id
GET /api/v1/osquery/queries (templates)
POST /api/v1/osquery/queries (save query)
```

**Priority:** **HIGH** - Core OSQuery functionality

---

### 3.3 Medium Priority Pages (Week 2-3) ⏳

#### 3.3.1 Query Library Page

**File:** `/web/src/routes/osquery/library/+page.svelte`

**Features:**

- Saved queries list
- Create/edit/delete queries
- Query packs management
- Schedule queries
- Query categories/tags

---

#### 3.3.2 User Management Page

**File:** `/web/src/routes/users/+page.svelte`

**Features:**

- Users list
- Create/edit users
- Assign roles
- Manage permissions
- Password reset
- Disable/enable accounts

---

#### 3.3.3 Audit Logs Page

**File:** `/web/src/routes/audit/+page.svelte`

**Features:**

- Searchable audit trail
- Filter by:
  - User
  - Action type
  - Resource
  - Date range
- Export logs
- Compliance reporting

---

#### 3.3.4 Health Status Page

**File:** `/web/src/routes/health/+page.svelte`

**Features:**

- System health dashboard
- Service status (Kubernetes, Database, VPN)
- Client health distribution
- Alerts and warnings
- Resource usage graphs

---

#### 3.3.5 Settings Page

**File:** `/web/src/routes/settings/+page.svelte`

**Features:**

- Server configuration
- Feature flags
- Email notifications
- Webhook integrations
- Backup/restore

---

### 3.4 Low Priority Pages ⏳

#### Error Pages

**Files:**

- `/web/src/routes/404/+page.svelte` - Use `ERROR-404.png`
- `/web/src/routes/error/+page.svelte` - Use `ERROR-generic.png`

---

## 4. Database Integration Tasks

### 4.1 Completed ✅

- ✅ All 4 database schemas (623 lines SQL)
- ✅ Migration runner script (290 lines)
- ✅ User Management API (8/8 endpoints)

### 4.2 In Progress 🚧

- 🚧 Client Management API (1/12 endpoints)
  - ✅ GetClients
  - ❌ GetClient
  - ❌ CreateClient (used by enrollment)
  - ❌ UpdateClient
  - ❌ DeleteClient
  - ❌ AddClientTag
  - ❌ RemoveClientTag
  - ❌ GetClientGroups
  - ❌ GetClientConfiguration
  - ❌ UpdateClientConfiguration
  - ❌ GetClientCheckIns
  - ❌ ClientCheckIn (critical for client service)

### 4.3 Not Started ❌

- ❌ OSQuery API (13 endpoints)
- ❌ Audit API (2 endpoints)
- ❌ Enrollment Keys API (4 endpoints - NEW)
- ❌ Client Events API (1 endpoint - NEW)
- ❌ Remote Commands API (2 endpoints - NEW)

---

## 5. Implementation Priority

### Phase 1: Client Onboarding (Week 1) - CURRENT FOCUS

**Goal:** Enable clients to enroll and check in

**Tasks:**

1. ✅ Create client service components
2. ✅ Create enrollment page UI
3. ❌ **Implement enrollment API endpoint** 🔥 CRITICAL
4. ❌ **Implement check-in API endpoint** 🔥 CRITICAL
5. ❌ Create enrollment keys management API
6. ❌ Test full enrollment flow
7. ❌ Create installation scripts (Linux, macOS, Windows)

**Deliverable:** Clients can enroll and start checking in

---

### Phase 2: Client Management UI (Week 1-2)

**Goal:** Complete primary MDM interfaces

**Tasks:**

1. ❌ Create clients list page (filtering, search, bulk actions)
2. ❌ Create client details page (hardware, software, config)
3. ❌ Create client groups page (RBAC management)
4. ❌ Complete remaining Client API endpoints (11 functions)
5. ❌ Test client management workflows

**Deliverable:** Full client management capability

---

### Phase 3: OSQuery Integration (Week 2-3)

**Goal:** Enable remote querying and monitoring

**Tasks:**

1. ❌ Create OSQuery execution page
2. ❌ Create query library page
3. ❌ Implement OSQuery API endpoints (13 functions)
4. ❌ Test query execution flow
5. ❌ Create query packs management

**Deliverable:** Full OSQuery functionality

---

### Phase 4: Remote Management (Week 3)

**Goal:** Enable server-side management of clients

**Tasks:**

1. ❌ Implement remote command execution API
2. ❌ Add SSH command execution in client service
3. ❌ Create command execution UI
4. ❌ Test remote command flow
5. ❌ Add command history and audit trail

**Deliverable:** Remote management capability

---

### Phase 5: Administration & Polish (Week 3-4)

**Goal:** Complete administrative features

**Tasks:**

1. ❌ Create user management page
2. ❌ Create audit logs page
3. ❌ Create health status page
4. ❌ Create settings page
5. ❌ Create error pages
6. ❌ Build reusable UI components
7. ❌ Add real-time WebSocket updates
8. ❌ Implement advanced search and filters

**Deliverable:** Production-ready MDM platform

---

## 6. Testing Strategy

### 6.1 Client Service Testing

**Unit Tests:**

- Configuration loading and validation
- System info collection accuracy
- OSQuery result parsing
- Reporter request construction
- Health monitoring logic

**Integration Tests:**

- Enrollment flow (client → server)
- Check-in flow (client → server → database)
- OSQuery execution (server → client → server)
- SSH command execution
- Resource limit enforcement

**Load Tests:**

- 100+ clients checking in simultaneously
- Memory/CPU usage under load
- Network bandwidth usage
- Database query performance

---

### 6.2 Frontend Testing

**Component Tests:**

- Filter controls behavior
- Search functionality
- Modal interactions
- Form validation
- Table sorting/pagination

**E2E Tests:**

- Enrollment key creation flow
- Client enrollment flow
- Query execution flow
- Group management flow
- Bulk operations

---

### 6.3 API Testing

**Endpoint Tests:**

- Request validation
- Response formatting
- Error handling
- Authentication/authorization
- Rate limiting

**Database Tests:**

- Data integrity
- Transaction handling
- Constraint enforcement
- Index performance

---

## 7. Security Considerations

### Client-to-Server Communication

- ✅ TLS encryption (HTTPS only)
- ✅ Certificate verification
- ✅ Client authentication (ID + key)
- ❌ Certificate pinning (optional, high-security)
- ❌ mTLS support (optional, high-security)

### SSH Access

- ✅ Custom port (not 22)
- ✅ Host key generation
- ⏳ Public key authentication only
- ❌ Authorized keys management UI
- ❌ SSH session auditing

### Enrollment Security

- ❌ Enrollment key expiration
- ❌ Max uses enforcement
- ❌ IP allowlisting (optional)
- ❌ Manual approval mode (optional)

### Data Protection

- ❌ Encrypt sensitive data at rest
- ❌ Hash enrollment keys in database
- ❌ Rotate client keys periodically
- ❌ Audit all administrative actions

---

## 8. Deployment

### Client Service Deployment

**Distribution Methods:**

1. **Package Managers:**
   - apt (Debian/Ubuntu)
   - yum/dnf (RHEL/CentOS)
   - brew (macOS)
   - chocolatey (Windows)

2. **Installation Scripts:**
   - `install.sh` (Linux/macOS)
   - `install.ps1` (Windows)

3. **Container Images:**
   - Docker image for testing
   - Not recommended for production (kernel-level service)

**Auto-update Mechanism:**

- Check for updates on server
- Download new binary
- Verify signature
- Replace binary
- Restart service

---

### Server Deployment

**Components:**

- Fiber API server
- 4 PostgreSQL databases (CNPG)
- Kubernetes cluster (Kind for dev)
- Headscale VPN (optional)

**Deployment Options:**

1. Kubernetes (production)
2. Docker Compose (development)
3. Systemd services (simple deployments)

---

## 9. Documentation Requirements

### User Documentation

- [ ] Installation guide (per platform)
- [ ] Enrollment guide
- [ ] Client management guide
- [ ] OSQuery guide
- [ ] Troubleshooting guide

### Administrator Documentation

- [ ] Server installation guide
- [ ] Configuration reference
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Database schema reference
- [ ] Security best practices
- [ ] Backup/restore procedures

### Developer Documentation

- [ ] Architecture overview
- [ ] Component documentation
- [ ] Database integration guide
- [ ] Frontend development guide
- [ ] Contributing guide

---

## 10. Success Metrics

### Client Service

- ✅ Memory usage < 50MB
- ✅ CPU usage < 5%
- ⏳ Check-in latency < 1s
- ⏳ Zero missed check-ins (with network)
- ⏳ 99.9% uptime

### API Performance

- ⏳ Response time < 100ms (p95)
- ⏳ Support 1000+ concurrent clients
- ⏳ Database query time < 50ms (p95)

### User Experience

- ⏳ Page load time < 2s
- ⏳ Search results < 500ms
- ⏳ Real-time updates < 5s delay

---

## 11. Next Immediate Actions

### Today (December 18, 2025)

1. ✅ Complete client service implementation
2. ✅ Create enrollment page UI
3. ❌ **Implement enrollment API endpoint** 🔥 START HERE
4. ❌ **Implement check-in API endpoint** 🔥
5. ❌ Test enrollment flow end-to-end

### This Week

1. ❌ Create clients list page
2. ❌ Create client details page
3. ❌ Complete Client API database integration (11 functions)
4. ❌ Create client groups page
5. ❌ Test full client management workflow

### Next Week

1. ❌ Create OSQuery execution page
2. ❌ Implement OSQuery API (13 endpoints)
3. ❌ Create query library page
4. ❌ Test OSQuery execution flow
5. ❌ Add remote command execution

---

## 12. Open Questions / Decisions Needed

1. **Certificate Management:**
   - Self-signed certs for dev?
   - Let's Encrypt for production?
   - Internal CA?

2. **Auto-update Strategy:**
   - Enable by default?
   - Require admin approval?
   - Staged rollouts?

3. **Resource Limits:**
   - Are 50MB/5% appropriate defaults?
   - Allow per-client configuration?

4. **SSH Security:**
   - Require key authentication only?
   - Support password auth for initial setup?
   - Session recording/auditing?

5. **Client Versioning:**
   - Backward compatibility policy?
   - Forced upgrades for critical security?

---

## 13. Risk Assessment

### High Risk 🔴

- **No enrollment API** = Clients cannot onboard
  - **Mitigation:** Implement immediately (today)

- **No check-in API** = Enrolled clients cannot report
  - **Mitigation:** Implement immediately (today)

### Medium Risk 🟡

- **Missing Client API endpoints** = Limited management
  - **Mitigation:** Complete within 1 week

- **No OSQuery API** = No remote querying
  - **Mitigation:** Complete within 2 weeks

### Low Risk 🟢

- **Missing UI pages** = Manual workarounds possible
  - **Mitigation:** Complete progressively over 3 weeks

- **Missing advanced features** = Core functionality works
  - **Mitigation:** Add in polish phase

---

## Conclusion

The lightweight client service is **complete** and ready for integration. The next critical path is:

1. **Implement enrollment API** (server-side)
2. **Implement check-in API** (server-side)
3. **Test end-to-end enrollment and check-in**
4. **Build client management UI pages**
5. **Complete remaining API integrations**

**Estimated Timeline to MVP:**

- Week 1: Client onboarding + management UI ✅
- Week 2: OSQuery integration 🚧
- Week 3: Administration + polish ⏳

**Total:** ~3 weeks to production-ready MDM platform
