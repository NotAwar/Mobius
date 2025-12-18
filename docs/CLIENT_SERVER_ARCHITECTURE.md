# Mobius Architecture: Client-Server Separation

## Overview

Mobius is built as a distributed MDM (Mobile Device Management) platform with clear separation between:

1. **Management Server** - Centralized control plane (runs on your infrastructure)
2. **Client Daemon** - Lightweight agent (runs on managed devices)
3. **Web UI** - Administrative interface (served by management server)

## Component Separation

```text
┌──────────────────────────────────────────────────────────────────┐
│                     Your Infrastructure                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Management Server (cmd/server/)                            │  │
│  │                                                            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │ REST API │  │  Web UI  │  │ Database │  │   VPN    │  │  │
│  │  │ (Fiber)  │  │ (Svelte) │  │  (CNPG)  │  │(Headscale│  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │  │
│  │                                                            │  │
│  │  Listen on: 0.0.0.0:3001                                  │  │
│  │  Accessible via: https://management.yourcompany.com       │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (API calls)
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Laptop #1    │      │ Server #2    │      │ Desktop #3   │
│              │      │              │      │              │
│ ┌──────────┐ │      │ ┌──────────┐ │      │ ┌──────────┐ │
│ │  Client  │ │      │ │  Client  │ │      │ │  Client  │ │
│ │  Daemon  │ │      │ │  Daemon  │ │      │ │  Daemon  │ │
│ └──────────┘ │      │ └──────────┘ │      │ └──────────┘ │
│              │      │              │      │              │
│ macOS        │      │ Linux        │      │ Windows      │
│ 192.168.1.10 │      │ 10.0.1.50    │      │ 172.16.0.5   │
└──────────────┘      └──────────────┘      └──────────────┘
   Managed Device       Managed Device       Managed Device
```

## Why Separate Builds?

### Client Daemon (`cmd/client/`)

- **Purpose**: Runs on end-user devices (laptops, servers, workstations)
- **Size**: Must be small (~5-10MB binary)
- **Dependencies**: Minimal (no database, no web server)
- **Resources**: < 50MB RAM, < 5% CPU
- **Network**: Outbound HTTPS only (initiates connections to server)
- **Privileges**: Runs as system service (root/SYSTEM)
- **Distribution**: Single binary per platform (mobius-client-linux-amd64, etc.)

### Management Server (`cmd/server/`)

- **Purpose**: Runs on your infrastructure
- **Size**: Can be larger (~50-100MB with all dependencies)
- **Dependencies**: Full stack (database, Kubernetes, VPN)
- **Resources**: Scales based on fleet size
- **Network**: Listens on ports (3001 for API, others for services)
- **Privileges**: Runs in containerized environment
- **Distribution**: Docker image or Kubernetes deployment

## Build Process

### Client Daemon Build

```bash
# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o mobius-client-linux-amd64 ./cmd/client
GOOS=darwin GOARCH=amd64 go build -o mobius-client-darwin-amd64 ./cmd/client
GOOS=darwin GOARCH=arm64 go build -o mobius-client-darwin-arm64 ./cmd/client
GOOS=windows GOARCH=amd64 go build -o mobius-client-windows-amd64.exe ./cmd/client

# Package for distribution
tar czf mobius-client-linux-amd64.tar.gz mobius-client-linux-amd64
zip mobius-client-windows-amd64.zip mobius-client-windows-amd64.exe
```

**Distributed as:**

- Direct downloads from your server
- Package repositories (apt, yum, brew, choco)
- Configuration management tools (Ansible, Puppet, Chef)

### Server Build

```bash
# Build server binary
go build -o mobius-server ./cmd/server

# Or build Docker image
docker build -t mobius-server:latest -f Dockerfile.server .

# Or deploy to Kubernetes
kubectl apply -f deployments/
```

## Enrollment Flow (Server-Initiated)

This is the key to understanding how clients connect to the server:

### 1. Admin Provisions Enrollment Key (Server-Side)

Admin uses Web UI or API to create an enrollment key:

```bash
# Via API
curl -X POST https://management.yourcompany.com/api/v1/clients/enrollment-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "Engineering Team Q1 2025",
    "max_uses": 50,
    "expires_at": "2025-03-31T23:59:59Z",
    "tags": ["engineering", "development"],
    "group_ids": ["eng-group-uuid"]
  }'

# Returns:
{
  "id": "key-uuid",
  "key": "eyJhbGc...BASE64_ENCODED_KEY",
  "name": "Engineering Team Q1 2025",
  "created_at": "2025-01-15T10:00:00Z"
}
```

**What the server stores:**

```sql
INSERT INTO enrollment_keys (
  id, name, key, expires_at, max_uses, 
  tags, auto_assign_group_ids
) VALUES (
  'key-uuid',
  'Engineering Team Q1 2025',
  'eyJhbGc...BASE64_ENCODED_KEY',
  '2025-03-31 23:59:59',
  50,
  ARRAY['engineering', 'development'],
  ARRAY['eng-group-uuid']
);
```

### 2. Client Installation (Managed Device)

The enrollment key is distributed to device owners via:

- Email
- Internal wiki/documentation
- Automated deployment scripts
- Configuration management

**Manual Installation:**

```bash
# On Linux
wget https://releases.yourcompany.com/mobius-client-linux-amd64
sudo mv mobius-client-linux-amd64 /usr/local/bin/mobius-client
sudo chmod +x /usr/local/bin/mobius-client

# Enroll with the key
sudo mobius-client enroll \
  --server=https://management.yourcompany.com \
  --key=eyJhbGc...BASE64_ENCODED_KEY

# Start the service
sudo systemctl enable mobius-client
sudo systemctl start mobius-client
```

**Automated Installation (e.g., Ansible):**

```yaml
- name: Deploy Mobius Client
  hosts: all
  tasks:
    - name: Download client
      get_url:
        url: https://releases.yourcompany.com/mobius-client-linux-amd64
        dest: /usr/local/bin/mobius-client
        mode: '0755'
    
    - name: Enroll client
      command: >
        /usr/local/bin/mobius-client enroll
        --server=https://management.yourcompany.com
        --key={{ enrollment_key }}
    
    - name: Start service
      systemd:
        name: mobius-client
        state: started
        enabled: yes
```

### 3. Enrollment Process (Client → Server)

When client runs enrollment:

```
Client (Managed Device)                Server (Your Infrastructure)
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ 1. Collect System Info                                          │
│    - Hostname, OS, CPU, Memory                                  │
│    - Network interfaces                                         │
│    - MAC address                                                │
│                                                                  │
│ 2. POST /api/v1/clients/enroll      ──────────►                │
│    {                                                             │
│      "enrollment_key": "eyJhbGc...",                           │
│      "hostname": "eng-laptop-42",                               │
│      "system_info": {                                            │
│        "os_type": "darwin",                                      │
│        "cpu_cores": 8,                                           │
│        "total_memory_mb": 16384                                 │
│      }                                                           │
│    }                                                             │
│                                                                  │
│                                         3. Server Validates:    │
│                                            - Key exists          │
│                                            - Not revoked         │
│                                            - Not expired         │
│                                            - Under max uses      │
│                                                                  │
│                                         4. Server Provisions:   │
│                                            - Generate client_id  │
│                                            - Generate client_key │
│                                            - Create DB record    │
│                                            - Apply auto-tags     │
│                                            - Add to groups       │
│                                                                  │
│                                ◄────────── 5. Response          │
│    {                                                             │
│      "client_id": "client-uuid",                                │
│      "client_key": "SECRET_AUTH_KEY",                           │
│      "server_url": "https://management.yourcompany.com",        │
│      "configuration": {                                          │
│        "check_in_interval": 300,                                │
│        "osquery_interval": 60,                                   │
│        "enable_osquery": true,                                   │
│        "enable_ssh": true,                                       │
│        "ssh_port": 2222                                          │
│      }                                                           │
│    }                                                             │
│                                                                  │
│ 6. Save Configuration                                           │
│    /etc/mobius/client.yaml:                                     │
│    ---                                                           │
│    server_url: https://management.yourcompany.com               │
│    client_id: client-uuid                                        │
│    client_key: SECRET_AUTH_KEY                                  │
│    check_in_interval: 300                                        │
│    osquery_interval: 60                                          │
│    ssh_port: 2222                                                │
│                                                                  │
│ 7. Start Client Daemon                                          │
│    - Reads config from /etc/mobius/client.yaml                  │
│    - Starts check-in timer (5 minutes)                          │
│    - Starts OSQuery collector (1 minute)                        │
│    - Starts SSH server (port 2222)                              │
│    - Monitors resource usage                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Ongoing Operation (Client → Server Check-ins)

Once enrolled, client checks in periodically:

```
Every 5 minutes:

Client                                    Server
├─────────────────────────────────────────────────────────┤
│                                                          │
│ POST /api/v1/clients/:id/check-in  ───────►            │
│ Headers:                                                 │
│   X-Client-ID: client-uuid                              │
│   X-Client-Key: SECRET_AUTH_KEY                         │
│ Body:                                                    │
│   {                                                      │
│     "timestamp": "2025-01-15T10:05:00Z",                │
│     "system_info": { ... },                             │
│     "osquery_results": { ... },                         │
│     "health_status": { ... }                            │
│   }                                                      │
│                                                          │
│                             Server:                     │
│                             - Validates credentials     │
│                             - Updates last_seen         │
│                             - Stores results in DB      │
│                             - Checks for pending cmds   │
│                                                          │
│                               ◄─────────────            │
│   {                                                      │
│     "status": "ok",                                      │
│     "configuration": { ... },                           │
│     "pending_commands": [                               │
│       {                                                  │
│         "id": "cmd-uuid",                               │
│         "type": "execute_query",                        │
│         "payload": {                                     │
│           "query": "SELECT * FROM processes"            │
│         }                                                │
│       }                                                  │
│     ]                                                    │
│   }                                                      │
│                                                          │
│ Executes pending commands                               │
│ Returns results in next check-in                        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## API-First Design

**Every action is API-driven:**

### Web UI → Server API

```javascript
// Admin clicks "Execute Query" in Web UI
fetch('https://management.yourcompany.com/api/v1/osquery/execute', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + adminToken,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    query: 'SELECT * FROM listening_ports',
    target_type: 'clients',
    target_ids: ['client-uuid-1', 'client-uuid-2']
  })
})
```

### Server → Database

```go
// Server stores command for delivery
db.Exec(`
  INSERT INTO pending_commands (id, client_id, type, payload, created_at)
  VALUES ($1, $2, 'execute_query', $3, NOW())
`, commandID, clientID, queryPayload)
```

### Client → Server (on next check-in)

```go
// Client checks in and receives pending command
resp, _ := apiClient.CheckIn(&CheckInRequest{...})

for _, cmd := range resp.PendingCommands {
    if cmd.Type == "execute_query" {
        // Execute query
        results := osquery.Execute(cmd.Payload["query"])
        // Results sent in next check-in
    }
}
```

## Security Model

### Client Authentication

- Each client has unique `client_id` and `client_key`
- Keys are 256-bit cryptographically secure random strings
- Keys transmitted via HTTPS only
- Keys stored encrypted on client filesystem

### Server Authentication

- TLS certificate validation (HTTPS)
- Optional: Certificate pinning for extra security
- Optional: Mutual TLS (client certificates)

### Network Security

- Clients only make outbound connections (firewall-friendly)
- No inbound ports needed on client devices
- All communication over HTTPS (port 443)
- Optional: VPN mesh via Headscale for SSH access

## Deployment Scenarios

### Small Deployment (< 100 devices)

```
Single server:
- Docker Compose with all services
- PostgreSQL database
- 2 CPU, 4GB RAM sufficient
- Clients check in every 5 minutes
```

### Medium Deployment (100-1000 devices)

```
Kubernetes cluster:
- 3 server replicas (load balanced)
- PostgreSQL with replication
- 4-8 CPU, 8-16GB RAM
- Clients check in every 5 minutes
```

### Large Deployment (1000+ devices)

```
Kubernetes cluster:
- 10+ server replicas
- PostgreSQL cluster (CNPG)
- Redis for caching
- 16+ CPU, 32+ GB RAM
- Clients check in every 10 minutes (reduced frequency)
- Separate read replicas for reporting
```

## Advantages of This Architecture

1. **Zero Trust**: Clients authenticate every API call
2. **Firewall Friendly**: Clients only make outbound HTTPS connections
3. **Scalable**: Stateless server can scale horizontally
4. **Resilient**: Clients retry failed check-ins automatically
5. **Efficient**: Small client footprint, minimal resource usage
6. **Flexible**: API-first design enables custom integrations
7. **Secure**: No management software running on server-accessible ports on clients
8. **Cross-Platform**: Single codebase compiles for Linux/macOS/Windows

## Development Workflow

### Working on Client

```bash
cd /path/to/mobius
go run cmd/client/main.go --config=dev-config.yaml
```

### Working on Server

```bash
cd /path/to/mobius
go run cmd/server/main.go
```

### Building for Production

```bash
# Client
make build-client-all  # Builds for all platforms

# Server
make build-server      # Builds server binary
make docker-server     # Builds Docker image
```

## Next Steps

See:

- `/pkg/README.md` for shared API and models documentation
- `/docs/CLIENT_SERVICE.md` for client daemon details
- `/docs/API_ARCHITECTURE.md` for API endpoint documentation
- `/docs/DEPLOYMENT.md` for production deployment guide

---

This architecture ensures clear separation of concerns, security, and scalability while maintaining a simple deployment model for administrators.
