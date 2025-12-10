# Server Code Structure

The Mobius server has been refactored into a modular, maintainable structure:

## Directory Layout

```
cmd/server/
  main.go                    # Main entry point, orchestrates everything

internal/
  docker/
    daemon.go                # Docker daemon management
  kind/
    cluster.go               # KIND cluster management
  privileges/
    check.go                 # Privilege checking and elevation
  deploy/
    deployer.go             # Kubernetes deployment utilities
```

## Component Overview

### `cmd/server/main.go`

The main entry point that:

- Initializes logging
- Checks/elevates privileges
- Starts Docker daemon
- Creates KIND cluster
- Coordinates application lifecycle
- **This is where you add your custom initialization logic**

### `internal/docker/daemon.go`

Manages the isolated Docker daemon:

- `EnsureInstalled()` - Auto-installs Docker if needed
- `EnsureDirectories()` - Creates and configures directories
- `Start()` - Starts the daemon
- `Stop()` - Gracefully stops the daemon

### `internal/kind/cluster.go`

Manages KIND Kubernetes clusters:

- `NewCluster()` - Creates cluster manager
- `Create()` - Creates the cluster
- `Delete()` - Deletes the cluster
- `List()` - Lists existing clusters
- Includes `Loggerus` adapter for KIND's logging interface

### `internal/privileges/check.go`

Handles privilege management:

- `CheckAndElevate()` - Auto-elevates to sudo if needed
- `FormatErrorMessage()` - Formats helpful error messages

### `internal/deploy/deployer.go`

Kubernetes deployment utilities:

- `Apply()` - Apply Kubernetes manifests
- `WaitForDeployment()` - Wait for deployments to be ready
- `CreateNamespace()` - Create namespaces
- `GetPods()` - List pods

## Adding Custom Logic

### 1. Deploy Services After Cluster Creation

In `cmd/server/main.go`, after cluster creation:

```go
// Create deployer
deployer := deploy.NewDeployer(kubeconfigPath, logger)

// Create namespace
if err := deployer.CreateNamespace("mobius-system"); err != nil {
    logger.Fatalf("Failed to create namespace: %v", err)
}

// Deploy your MDM server
if err := deployer.Apply("deployments/mdm-server.yaml"); err != nil {
    logger.Fatalf("Failed to deploy MDM server: %v", err)
}

// Wait for it to be ready
if err := deployer.WaitForDeployment("mobius-system", "mdm-server", 5*time.Minute); err != nil {
    logger.Fatalf("MDM server did not start: %v", err)
}

logger.Info("All services deployed and ready!")
```

### 2. Add HTTP Server

Create `internal/api/server.go`:

```go
package api

import (
    "net/http"
    "github.com/sirupsen/logrus"
)

type Server struct {
    logger *logrus.Logger
}

func NewServer(logger *logrus.Logger) *Server {
    return &Server{logger: logger}
}

func (s *Server) Start(addr string) error {
    http.HandleFunc("/health", s.healthHandler)
    http.HandleFunc("/api/v1/devices", s.devicesHandler)
    
    s.logger.Infof("Starting API server on %s", addr)
    return http.ListenAndServe(addr, nil)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

func (s *Server) devicesHandler(w http.ResponseWriter, r *http.Request) {
    // Your device management logic
}
```

Then in `main.go`:

```go
// Start API server in background
apiServer := api.NewServer(logger)
go func() {
    if err := apiServer.Start(":8080"); err != nil {
        logger.Errorf("API server failed: %v", err)
    }
}()
```

### 3. Add Database Connection

Create `internal/database/db.go`:

```go
package database

import (
    "database/sql"
    _ "github.com/lib/pq"
)

type DB struct {
    conn *sql.DB
}

func Connect(dsn string) (*DB, error) {
    conn, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }
    
    if err := conn.Ping(); err != nil {
        return nil, err
    }
    
    return &DB{conn: conn}, nil
}
```

### 4. Add MDM Protocol Handlers

Create `internal/mdm/handler.go`:

```go
package mdm

import (
    "net/http"
    "github.com/sirupsen/logrus"
)

type Handler struct {
    logger *logrus.Logger
}

func NewHandler(logger *logrus.Logger) *Handler {
    return &Handler{logger: logger}
}

func (h *Handler) HandleEnrollment(w http.ResponseWriter, r *http.Request) {
    // Apple/Windows MDM enrollment logic
}

func (h *Handler) HandleCheckin(w http.ResponseWriter, r *http.Request) {
    // Device check-in logic
}
```

## Running the Server

```bash
# Development
go run cmd/server/main.go

# Production build
go build -o mobius-server cmd/server/main.go
sudo ./mobius-server
```

## Benefits of This Structure

1. **Modularity** - Each component is isolated and reusable
2. **Testability** - Easy to unit test individual packages
3. **Maintainability** - Clear separation of concerns
4. **Extensibility** - Add new packages without touching existing code
5. **Readability** - Each file has a single, clear purpose

## Example: Full Deployment Flow

```go
func main() {
    logger := logrus.New()
    // ... setup ...
    
    // Start infrastructure
    dockerDaemon, _ := docker.Start(logger)
    defer dockerDaemon.Stop()
    
    cluster := kind.NewCluster(logger, config)
    cluster.Create()
    defer cluster.Delete()
    
    // Deploy applications
    deployer := deploy.NewDeployer(kubeconfigPath, logger)
    deployer.CreateNamespace("mobius-system")
    deployer.Apply("deployments/postgres.yaml")
    deployer.Apply("deployments/mdm-server.yaml")
    deployer.Apply("deployments/api-server.yaml")
    deployer.Apply("deployments/web-ui.yaml")
    
    // Start API server
    apiServer := api.NewServer(logger)
    go apiServer.Start(":8080")
    
    // Wait for shutdown
    <-signalChan
}
```

## Next Steps

1. Create deployment manifests in `deployments/`
2. Add your MDM protocol handlers in `internal/mdm/`
3. Implement API endpoints in `internal/api/`
4. Add database schemas and migrations in `internal/database/`
5. Build web UI integration in `internal/ui/`
