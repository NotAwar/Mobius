# Mobius Shared Packages (`/pkg`)

This directory contains reusable code shared between the Mobius server and client components. Following Go best practices, `/pkg` contains library code that can be safely imported by external applications.

## Package Structure

### `pkg/models/`

Shared data models and types used across client and server.

**`client.go`** - Core client-related models:

- `Client` - Managed device representation
- `SystemInfo` - Detailed system information collected from clients
- `EnrollmentRequest/Response` - Enrollment protocol messages
- `CheckInRequest/Response` - Check-in protocol messages
- `Command` - Server commands to be executed on clients
- `ClientConfiguration` - Client configuration structure

**Usage:**

```go
import "mobius/pkg/models"

// Server-side: Create client record
client := &models.Client{
    ID:       uuid.New().String(),
    Hostname: "web-server-01",
    OSType:   "linux",
    Status:   "online",
}

// Client-side: Collect system info
sysInfo := &models.SystemInfo{
    Hostname:      hostname,
    OSType:        "darwin",
    CPUCores:      8,
    TotalMemoryMB: 16384,
}
```

### `pkg/api/`

HTTP API client library for communicating with the Mobius management server.

**`client.go`** - API client implementation:

- `Client` - HTTP client with authentication
- `NewClient()` - Create authenticated API client
- `Enroll()` - Perform client enrollment
- `CheckIn()` - Send periodic check-in
- `ReportHardwareInfo()` - Report hardware changes
- `ReportOSQueryResults()` - Submit OSQuery results
- `FetchConfiguration()` - Retrieve current configuration

**Usage:**

```go
import "mobius/pkg/api"

// Client-side: Create API client
client := api.NewClient(
    "https://management.example.com",
    "client-id-here",
    "client-key-here",
)

// Enroll a new client
resp, err := client.Enroll(enrollmentKey, systemInfo)
if err != nil {
    log.Fatal(err)
}

// Perform check-in
checkInReq := &models.CheckInRequest{
    Timestamp:    time.Now(),
    SystemInfo:   currentInfo,
    HealthStatus: healthData,
}
checkInResp, err := client.CheckIn(checkInReq)
```

## Architecture Benefits

### 1. **API-First Design**

All communication between client and server uses the same API definitions. The server exposes HTTP endpoints, and the client uses the shared API client library to communicate with those endpoints.

```text
┌─────────────────┐         HTTP/JSON          ┌─────────────────┐
│                 │  ──────────────────────►   │                 │
│  Client Daemon  │                             │  Server API     │
│  (uses pkg/api) │  ◄──────────────────────   │  (uses models)  │
│                 │         pkg/models          │                 │
└─────────────────┘                             └─────────────────┘
```

### 2. **Type Safety**

Shared models ensure type safety across client-server boundary. Changes to data structures are reflected in both components automatically.

### 3. **Consistent Protocols**

Enrollment, check-in, and reporting protocols are defined once and used everywhere. No risk of protocol drift between components.

### 4. **Reusability**

Other tools can import these packages to interact with the Mobius platform:

- CLI tools for administration
- Monitoring integrations
- Custom client implementations
- Third-party extensions

## Development Guidelines

### Adding New Models

1. Define the struct in appropriate file under `pkg/models/`
2. Add JSON tags for API serialization
3. Document the purpose and fields
4. Update this README with usage examples

### Adding New API Methods

1. Add method to `pkg/api/client.go`
2. Ensure proper error handling
3. Use shared models for request/response
4. Document the endpoint and parameters

### Versioning

- Breaking changes to models require API version bump
- Add new fields as optional (pointer types or with `omitempty`)
- Deprecate fields before removing them

## Server-Driven Enrollment

The enrollment process is designed to be server-driven:

1. **Admin creates enrollment key** (via API or UI)
   - Server generates secure 256-bit key
   - Admin configures tags, groups, expiry, max uses
   - Server stores key with configuration

2. **Client enrolls** (minimal client configuration needed)

   ```bash
   mobius-client enroll \
     --server=https://management.example.com \
     --key=BASE64_ENROLLMENT_KEY
   ```

3. **Server provisions client**
   - Validates enrollment key
   - Generates client ID and authentication key
   - Returns full configuration (check-in interval, OSQuery settings, etc.)
   - Automatically assigns tags and groups

4. **Client saves configuration and starts**
   - All settings come from server
   - Client only needs to know server URL initially
   - Future updates pushed from server via check-in responses

This ensures:

- ✓ Zero-touch deployment (installer just needs enrollment key)
- ✓ Centralized configuration management
- ✓ Consistent settings across fleet
- ✓ Easy remote provisioning

## API Coverage

All platform features are accessible via API:

### Client Management

- `POST /api/v1/clients/enroll` - Enroll new client
- `GET /api/v1/clients` - List all clients
- `GET /api/v1/clients/:id` - Get client details
- `PUT /api/v1/clients/:id` - Update client
- `DELETE /api/v1/clients/:id` - Remove client
- `POST /api/v1/clients/:id/check-in` - Client check-in
- `POST /api/v1/clients/:id/tags` - Add tag
- `DELETE /api/v1/clients/:id/tags/:tag` - Remove tag

### Enrollment Keys

- `GET /api/v1/clients/enrollment-keys` - List keys
- `POST /api/v1/clients/enrollment-keys` - Create key
- `DELETE /api/v1/clients/enrollment-keys/:id` - Revoke key

### Configuration

- `GET /api/v1/clients/:id/configuration` - Get config
- `PUT /api/v1/clients/:id/configuration` - Update config

### Groups

- `GET /api/v1/clients/groups` - List groups
- `POST /api/v1/clients/groups` - Create group
- `PUT /api/v1/clients/groups/:id` - Update group
- `DELETE /api/v1/clients/groups/:id` - Delete group

### OSQuery

- `POST /api/v1/osquery/execute` - Execute query
- `GET /api/v1/osquery/queries` - List queries
- `POST /api/v1/osquery/queries` - Save query
- `POST /api/v1/osquery/results` - Submit results

All API endpoints are documented and used by both the web UI and client daemon.

## Testing

### Unit Tests

```bash
go test ./pkg/...
```

### Integration Tests

```bash
go test -tags=integration ./pkg/...
```

### Client-Server Compatibility

Ensure client and server are built from the same commit to guarantee protocol compatibility.

## Examples

### Complete Enrollment Flow

**Admin (via API):**

```bash
curl -X POST https://management.example.com/api/v1/clients/enrollment-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "name": "Production Servers Batch 1",
    "max_uses": 100,
    "expires_at": "2025-12-31T23:59:59Z",
    "tags": ["production", "web"],
    "group_ids": ["prod-group-id"]
  }'
# Returns: {"key": "BASE64_KEY..."}
```

**Client (automated installation):**

```bash
# Download client
wget https://releases.mobius.com/mobius-client-linux-amd64

# Install
sudo mv mobius-client-linux-amd64 /usr/local/bin/mobius-client
sudo chmod +x /usr/local/bin/mobius-client

# Enroll (this is ALL the client needs to know!)
sudo mobius-client enroll \
  --server=https://management.example.com \
  --key=BASE64_KEY

# Start service
sudo systemctl enable mobius-client
sudo systemctl start mobius-client
```

**Result:**

- Client auto-configured with all server settings
- Automatically added to production group
- Tagged with "production" and "web"
- Starts checking in every 5 minutes
- OSQuery running every 60 seconds
- SSH server available on port 2222

### Custom Integration

```go
package main

import (
    "log"
    "mobius/pkg/api"
    "mobius/pkg/models"
)

func main() {
    // Custom monitoring tool
    client := api.NewClient(
        "https://management.example.com",
        "monitoring-tool-id",
        "monitoring-tool-key",
    )
    
    // Get all online clients
    resp, err := client.GetClients(map[string]string{
        "status": "online",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Found %d online clients", len(resp.Clients))
}
```

## Future Enhancements

- [ ] WebSocket support for real-time communication
- [ ] Batch operation models (bulk commands, queries)
- [ ] Plugin system for custom collectors
- [ ] gRPC protocol support
- [ ] Client SDK for other languages (Python, Rust)

## Contributing

When adding shared code:

1. Ensure it's truly reusable (needed by 2+ components)
2. Keep dependencies minimal
3. Document all exported types and functions
4. Add examples to this README
5. Write tests

---

**Note:** The `/pkg` directory follows Go community conventions for shareable library code. Internal-only code stays in `/internal/`.
