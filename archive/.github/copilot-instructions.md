# Copilot Instructions for Mobius MDM Platform

**CRITICAL: Follow these instructions first. Fall back to additional context gathering only if information here is incomplete.**

## Platform Overview

Mobius is an API-first, enterprise Mobile Device Management (MDM) platform with a Go backend and Svelte 5 frontend. It manages devices, policies, and applications across Windows, macOS, Linux, iOS, and Android made for being self-hosted in diverse environments.

**Architecture Pattern**: Multi-module Go workspace (6 modules) + SvelteKit SPA served as static files by the API server.

## Repository Structure & Module Organization

```
go.work defines 6 Go modules:
├── server/api/          # Core MDM API server (builds: mobius-api ~10MB)
│   ├── cmd/api-server/  # Main entry point - starts on :8081
│   ├── api/             # HTTP: router.go, *_handlers.go, middleware
│   ├── pkg/service/     # Business logic: services.go (in-memory mock - CURRENT)
│   └── pkg/websocket/   # Real-time events: hub.go, client.go
├── server/cli/          # Admin CLI tool (builds: mobiuscli ~49MB, slow build)
├── client/client/       # Device agent (builds: mobius-client ~8.5MB)
├── cocoon/portal/       # Enterprise portal (builds: mobius-cocoon ~7.9MB)
├── server/mobius-package-search/  # Package search microservice
└── common/shared/       # Shared libraries (crypto, http, file utilities)

ui/web/                  # Svelte 5 + TypeScript frontend
├── src/                 # SvelteKit source
├── build/               # Built static files (generated)
└── svelte.config.js     # @sveltejs/adapter-static, fallback: index.html
```

**Key Build Flow**: `ui/web/build/` → copied to → `server/api/static/` → served by API server at `/`

**IMPORTANT - Module Paths**: Use exact paths from `go.work`:
- Device client: `./client/client` (NOT `./server/client`)
- Shared libs: `./common/shared` (NOT `./shared`)

## Critical Build Timing (Windows PowerShell)

**NEVER CANCEL THESE COMMANDS - SET LONG TIMEOUTS:**

```powershell
# 1. Go workspace sync (5s)
go work sync

# 2. Dependency downloads (60-70s TOTAL - BE PATIENT)
cd server/api; go mod download
cd ../cli; go mod download
cd ../../client/client; go mod download  
cd ../../cocoon/portal; go mod download
cd ../../common/shared; go mod download
cd ../..

# 3. Frontend deps (8-10s)
cd ui/web; npm ci; cd ../..

# 4. Build frontend (15-20s)
cd ui/web; npm run build; cd ../..

# 5. Build all Go modules (60-90s for CLI, 10-20s for others)
New-Item -ItemType Directory -Force -Path build
cd server/api; go build -o ../../build/mobius-api ./cmd/api-server
cd ../cli; go build -o ../../build/mobiuscli ./cmd/mobiuscli  # SLOW 60-75s
cd ../../client/client; go build -o ../../build/mobius-client ./cmd/client
cd ../../cocoon/portal; go build -o ../../build/mobius-cocoon ./cmd/cocoon
cd ../..

# Alternative: Use Makefile (15-20s)
make clean; make build
```

**Test Execution (30-35s for Go tests):**
```powershell
go test -count=1 ./server/api/... ./server/cli/... ./client/client/... ./cocoon/portal/... ./common/shared/...
cd ui/web; npm test; cd ../..
```

## API Architecture Patterns

### Service Layer Pattern (Dependency Injection)

**Handler → Service Interface → Implementation (Mock or DB)**

Example from `server/api/cmd/api-server/main.go`:
```go
// Initialize services (currently using mock implementations)
licenseService := service.NewLicenseService()      // Mock for dev
deviceService := service.NewDeviceService()
// ... other services

// Inject into Dependencies struct
deps := &api.Dependencies{
    LicenseService: licenseService,
    DeviceService:  deviceService,
    WSHub:          wsHub,  // WebSocket hub for real-time events
    StaticDir:      "./static",
}

router := api.NewRouter(deps)  // Create Gorilla mux router
```

**Service Implementation Location**:
- **Current (Development)**: `server/api/pkg/service/services.go` - In-memory mock services with mutex-protected maps
- **Note**: `*_service_db.go` files exist but are NOT USED - mock implementation is the current working version

### Router Pattern (Gorilla Mux)

From `server/api/api/router.go`:
```go
r := mux.NewRouter()
r.Use(LoggingMiddleware, CORSMiddleware, SecurityHeadersMiddleware)

api := r.PathPrefix("/api/v1").Subrouter()

// Public routes
api.HandleFunc("/health", HealthHandler).Methods("GET")
api.HandleFunc("/auth/login", deps.handleLogin).Methods("POST")

// Protected routes (JWT middleware)
protected := api.PathPrefix("").Subrouter()
protected.Use(deps.authMiddleware)
protected.HandleFunc("/devices", deps.handleListDevices).Methods("GET")

// SPA fallback for frontend routes
r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if !strings.HasPrefix(r.URL.Path, "/api/") {
        http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
    }
})
```

**Handler Convention**: `func (d *Dependencies) handle<Action>(w http.ResponseWriter, r *http.Request)`

## Real-Time Features (WebSocket)

**Event Broadcasting Architecture** (`server/api/pkg/websocket/hub.go`):

```go
type EventType string  // device_status_change, policy_assignment, etc.
type Event struct {
    Type      EventType
    Timestamp time.Time
    Data      interface{}  // Strongly-typed: DeviceStatusChangeData, etc.
}

// Hub maintains clients and broadcasts events
type Hub struct {
    clients   map[*Client]bool
    broadcast chan Event
    register  chan *Client
    // ...
}
```

**Integration Pattern**: Services call `hub.BroadcastEvent()` after state changes:
```go
// In DeviceServiceImpl.EnrollDevice():
if d.wsNotifier != nil {
    d.wsNotifier.NotifyDeviceStatusChange(device.ID, "", "enrolled")
}
```

**WebSocket Endpoint**: `/api/v1/ws` (protected route)

## Frontend Build Integration

**Why Static Adapter**: API server serves both API and UI from single binary.

`ui/web/svelte.config.js`:
```javascript
adapter: adapter({
    pages: 'build',
    assets: 'build',
    fallback: 'index.html',  // SPA routing
    strict: false
})
```

**Build Output**: `ui/web/build/` contains `index.html`, `_app/`, `assets/`  
**Deployment**: Makefile copies `ui/web/build/*` → `server/api/static/`

## Testing Infrastructure

**Bash Test Suites** (in `common/tests/`):
- `test_mdm_functionality.sh`: 29 API endpoint scenarios
- `test_websocket_functionality.sh`: 6 real-time event scenarios  
- `run_all_tests.sh`: Orchestrates all test suites with color output

**Validation Pattern** (from test scripts):
```bash
TOKEN=$(curl -s POST /api/v1/auth/login -d '{"email":"admin@mobius.local","password":"admin123"}' | jq -r .token)
curl -H "Authorization: Bearer $TOKEN" /api/v1/devices
```

## Development Workflow

### Quick Start
```powershell
# Build and run (PowerShell)
cd server/api
go build -o mobius-api ./cmd/api-server
./mobius-api

# Access
# UI: http://localhost:8081
# API: http://localhost:8081/api/v1/health
# Credentials: admin@mobius.local / admin123
```

### Adding New API Endpoints

1. **Define handler** in `server/api/api/<feature>_handlers.go`:
   ```go
   func (d *Dependencies) handleNewFeature(w http.ResponseWriter, r *http.Request) {
       // Parse request → Call service → JSON response
   }
   ```

2. **Register route** in `server/api/api/router.go`:
   ```go
   protected.HandleFunc("/new-feature", deps.handleNewFeature).Methods("GET")
   ```

3. **Implement service** in `server/api/pkg/service/services.go`:
   ```go
   func (s *ServiceImpl) NewFeature() (*Result, error) {
       s.mu.Lock()  // Always lock for mock services
       defer s.mu.Unlock()
       // ... business logic
   }
   ```

4. **Add tests**: Unit tests + bash integration test in `common/tests/`

### Docker Build Pattern

**Multi-stage Dockerfile** (`server/api/Dockerfile`):
```dockerfile
# Stage 1: Go builder with workspace context
FROM golang:1.25.3-alpine AS builder
COPY go.work go.work.sum ./
COPY server/api/go.mod ./server/api/
# ... copy all module go.mod files
RUN go work sync && (cd server/api && go mod download)
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o mobius-api ./cmd/api-server

# Stage 2: Minimal runtime
FROM alpine:3.20
RUN addgroup -S app && adduser -S -G app app  # Non-root user
COPY --from=builder /app/server/api/mobius-api .
COPY --from=builder /app/server/api/static ./static
USER app
CMD ["./mobius-api"]
```

**Deployment Options** (Platform-Agnostic):
- **Container-native**: Docker, Podman, containerd
- **Orchestration**: Kubernetes (Helm charts in `deployments/charts/mobius/`)
- **Score Specification**: `server/api/score.yaml` - Platform-agnostic deployment config
- **Future**: Terraform modules, PowerShell deployment scripts, web UI deployment wizard
- **CI/CD**: Multi-arch builds (linux/amd64, linux/arm64) with Cosign signing

## Common Gotchas

1. **Module Path Confusion**: Always use paths from `go.work`:
   - Device client: `./client/client` (NOT `./server/client`)
   - Shared libs: `./common/shared` (NOT `./shared`)

2. **Frontend Not Showing**: Verify `server/api/static/` contains built files from `ui/web/build/`

3. **WebSocket Not Connected**: Ensure `wsHub.Run(ctx)` goroutine started in `main.go`

4. **Slow Builds**: CLI build is inherently slow (49MB binary). Use build cache, don't cancel.

5. **Test Scripts (Bash)**: Integration tests in `common/tests/*.sh` require bash environment:
   - **Windows**: Use WSL, Git Bash, or similar (OS-agnostic test strategy TBD)
   - **Linux/macOS**: Run directly with `bash test_mdm_functionality.sh`
   - Server must be running on `:8081` before executing tests

## Security & Production Patterns

- **Auth**: JWT tokens with role-based access (admin/operator/viewer)
- **Middleware Chain**: Logging → CORS → Security Headers → Auth (for protected routes)
- **Input Validation**: Always decode JSON, validate required fields, sanitize inputs
- **Secret Management**: Environment variables for DB credentials (see `score.yaml`)
- **Docker Hardening**: Non-root user (UID app), minimal Alpine base, no CGO

## CI/CD Workflows

20+ GitHub Actions in `.github/workflows/`:
- `build-and-deploy.yml`: Main pipeline  
- `unit-tests.yml`: Go test runner
- `golangci-lint.yml`: Go linting
- `codeql.yml`: Security analysis
- Multi-arch Docker builds (amd64/arm64) with Cosign signing

**Validation Before Commit**:
```powershell
cd ui/web; npm run check; npm test  # Frontend
go test -count=1 ./...              # All Go modules
make clean; make build              # Full build
```

## Reference Files

- **Architecture**: `docs/MASTER_PLAN.md` (development phases, 80% complete)
- **API Docs**: `server/api/API_README.md` (endpoint reference)
- **Main Entry**: `server/api/cmd/api-server/main.go` (service wiring)
- **Router**: `server/api/api/router.go` (all routes defined here)
- **Build**: `Makefile` (cross-platform build orchestration)

