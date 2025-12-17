# API Architecture

## Structure

The Mobius API follows a clean architecture pattern with clear separation of concerns:

```
api/
└── v1/
    ├── handler.go       # Main handler with service dependencies
    ├── routes.go        # Route registration
    ├── health.go        # Health check endpoints
    ├── cluster.go       # Kubernetes cluster handlers
    ├── postgres.go      # PostgreSQL handlers
    └── headscale.go     # Headscale VPN handlers

pkg/
└── services/
    ├── interfaces.go    # Service interface definitions
    ├── cluster.go       # Cluster service implementation (kubectl)
    ├── postgres.go      # PostgreSQL service (CNPG)
    └── headscale.go     # Headscale service (CLI)

internal/
└── api/
    └── server.go        # Fiber server setup and middleware
```

## Design Principles

### Versioning

- All API endpoints are versioned under `/api/v1/`
- Legacy `/api/` routes redirect to `/api/v1/` for backward compatibility
- Future versions can be added as `/api/v2/` without breaking existing clients

### Service Layer

- Business logic is isolated in `pkg/services/`
- Services implement interfaces for easy testing and mocking
- Each service handles interaction with external systems (kubectl, CNPG, Headscale)
- Services return graceful fallbacks when cluster is unavailable

### Handler Layer

- Handlers in `api/v1/` focus on HTTP concerns (request/response)
- Minimal business logic - delegates to services
- Proper error handling and status codes
- Input validation on all POST/DELETE endpoints

### Middleware

- Recovery middleware catches panics
- Logger middleware for request logging
- CORS enabled for web dashboard (localhost:5173, 8081, 4173, 3001)

## API Endpoints

### Health & Status

```
GET /api/v1/health                 # API health check
GET /api/v1/status/cluster         # Kubernetes cluster status
GET /api/v1/status/postgres        # PostgreSQL/CNPG status
GET /api/v1/status/headscale       # Headscale VPN status
```

### Cluster Management  

```
GET /api/v1/cluster/nodes          # List Kubernetes nodes
GET /api/v1/cluster/pods           # List all pods
```

### PostgreSQL Management

```
GET    /api/v1/postgres/databases       # List databases
POST   /api/v1/postgres/databases       # Create database
DELETE /api/v1/postgres/databases/:name # Delete database
```

### Headscale Management

```
GET  /api/v1/headscale/users  # List users
POST /api/v1/headscale/users  # Create user
GET  /api/v1/headscale/nodes  # List nodes
```

## Implementation Details

### Cluster Service

- Uses `kubectl` commands via `os/exec`
- Parses JSON output from kubectl
- Falls back to mock data if kubectl unavailable
- Kubeconfig path: `configs/cluster/kubeconfig`

### PostgreSQL Service

- Uses `kubectl` to interact with CNPG operator
- Queries `clusters.postgresql.cnpg.io` CRDs
- Database creation/deletion via CRDs (TODO)
- Checks CNPG operator pods in `cnpg-system` namespace

### Headscale Service

- Discovers Headscale pod dynamically
- Executes Headscale CLI commands via `kubectl exec`
- User creation, listing via CLI
- Node management and status tracking

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "Error message description"
}
```

Status codes:

- `200` - Success
- `201` - Created
- `400` - Bad Request (invalid input)
- `500` - Internal Server Error

## Testing

### Manual Testing

```bash
# Start API server (standalone for testing)
cd /home/awar/Desktop/Mobius
go run cmd/server/main.go

# Or run full deployment
/tmp/mobius-server
```

### Automated Testing

```bash
# Test all endpoints
./scripts/test-api.sh

# Individual endpoint test
curl http://localhost:3000/api/v1/health
curl http://localhost:3000/api/v1/status/cluster
```

### With Web Dashboard

```bash
# Start dev server
cd web
npm run dev  # Access at localhost:5173

# API calls will hit localhost:3000/api/v1/*
```

## Future Enhancements

### Short-term

- [ ] Parse kubectl JSON output properly (currently returns mock data structure)
- [ ] Implement CNPG database creation/deletion via CRDs
- [ ] Add request validation middleware
- [ ] Add rate limiting

### Medium-term

- [ ] Add authentication (JWT tokens)
- [ ] Implement WebSocket for real-time updates
- [ ] Add Prometheus metrics endpoint
- [ ] Add request/response logging to file
- [ ] Add API documentation (Swagger/OpenAPI)

### Long-term

- [ ] Add caching layer (Redis)
- [ ] Implement RBAC for endpoints
- [ ] Add audit logging
- [ ] Support multiple clusters
- [ ] Add backup/restore endpoints

## Development Guide

### Adding a New Endpoint

1. **Define the service interface** (`pkg/services/interfaces.go`):

```go
type MyService interface {
    GetData(ctx context.Context) ([]Data, error)
}
```

2. **Implement the service** (`pkg/services/myservice.go`):

```go
type MyServiceImpl struct {
    logger *logrus.Logger
}

func NewMyService(logger *logrus.Logger) *MyServiceImpl {
    return &MyServiceImpl{logger: logger}
}

func (s *MyServiceImpl) GetData(ctx context.Context) ([]Data, error) {
    // Implementation
}
```

3. **Add handler** (`api/v1/myhandler.go`):

```go
func (h *Handler) GetMyData(c *fiber.Ctx) error {
    data, err := h.myService.GetData(c.Context())
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    return c.JSON(fiber.Map{"data": data})
}
```

4. **Register route** (`api/v1/routes.go`):

```go
router.Get("/my/data", h.GetMyData)
```

5. **Update handler constructor** (`api/v1/handler.go`):

```go
type Handler struct {
    myService services.MyService
}

func NewHandler(..., myService services.MyService) *Handler {
    return &Handler{..., myService: myService}
}
```

6. **Wire up in server** (`internal/api/server.go`):

```go
myService := services.NewMyService(s.logger)
v1Handler := v1.NewHandler(..., myService)
```

## Security Considerations

- API runs on localhost only by default
- CORS restricts origins to known localhost ports
- No authentication currently - add JWT for production
- Kubectl commands use configured kubeconfig
- No input sanitization for shell commands - validate carefully
- Services fail gracefully when cluster unavailable

## Performance

- API responds quickly when cluster available
- Kubectl commands add ~100-500ms latency
- No caching - every request hits kubectl
- WebSocket support planned for real-time updates
- Consider adding Redis cache for frequently accessed data
