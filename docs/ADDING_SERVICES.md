# Complete Example: Adding Custom Deployment

This guide shows how to extend the Mobius server with your own services.

## Example: Adding a Web API Server

### Step 1: Create the API Package

Create `internal/api/server.go`:

```go
package api

import (
 "encoding/json"
 "net/http"
 "time"

 "github.com/sirupsen/logrus"
)

type Server struct {
 logger *logrus.Logger
 srv    *http.Server
}

type HealthResponse struct {
 Status    string    `json:"status"`
 Timestamp time.Time `json:"timestamp"`
}

func NewServer(logger *logrus.Logger, addr string) *Server {
 s := &Server{
  logger: logger,
 }

 mux := http.NewServeMux()
 mux.HandleFunc("/health", s.handleHealth)
 mux.HandleFunc("/api/v1/devices", s.handleDevices)

 s.srv = &http.Server{
  Addr:    addr,
  Handler: mux,
 }

 return s
}

func (s *Server) Start() error {
 s.logger.Infof("Starting API server on %s", s.srv.Addr)
 return s.srv.ListenAndServe()
}

func (s *Server) Shutdown() error {
 s.logger.Info("Shutting down API server...")
 return s.srv.Close()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
 resp := HealthResponse{
  Status:    "healthy",
  Timestamp: time.Now(),
 }
 w.Header().Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
 // Your device management logic here
 w.Header().Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(map[string]string{
  "message": "Device API endpoint",
 })
}
```

### Step 2: Update main.go

Edit `cmd/server/main.go`:

```go
package main

import (
 "os"
 "os/signal"
 "path/filepath"
 "syscall"
 "time"

 "github.com/sirupsen/logrus"
 "mobius/internal/api"      // Add this
 "mobius/internal/deploy"   // Add this
 "mobius/internal/docker"
 "mobius/internal/kind"
 "mobius/internal/privileges"
)

func main() {
 // Setup logger
 logger := logrus.New()
 logger.SetFormatter(&logrus.JSONFormatter{})
 logger.SetOutput(os.Stdout)
 logger.SetLevel(logrus.TraceLevel)

 // Check and elevate privileges if needed
 privileges.CheckAndElevate(logger)

 // Start Docker daemon
 logger.Info("Initializing Mobius server...")
 dockerDaemon, err := docker.Start(logger)
 if err != nil {
  logger.Fatalf("Failed to start Docker daemon: %s", privileges.FormatErrorMessage(err))
 }
 defer dockerDaemon.Stop()

 // Get absolute path for config files
 configPath, _ := filepath.Abs("configs/cluster/config.yaml")
 kubeconfigPath, _ := filepath.Abs("configs/cluster/kubeconfig")

 // Create KIND cluster
 cluster := kind.NewCluster(logger, kind.Config{
  Name:           "mobius-cluster",
  ConfigPath:     configPath,
  KubeconfigPath: kubeconfigPath,
 })

 if err := cluster.Create(); err != nil {
  logger.Fatalf("Failed to create cluster: %v", err)
 }

 // Ensure cleanup on exit
 defer func() {
  if err := cluster.Delete(); err != nil {
   logger.Warnf("Failed to delete cluster: %v", err)
  }
 }()

 // Deploy services to the cluster
 logger.Info("Deploying services to cluster...")
 deployer := deploy.NewDeployer(kubeconfigPath, logger)

 // Create namespace
 if err := deployer.CreateNamespace("mobius-system"); err != nil {
  logger.Fatalf("Failed to create namespace: %v", err)
 }

 // Deploy PostgreSQL
 if err := deployer.Apply("deployments/examples/postgres.yaml"); err != nil {
  logger.Warnf("Failed to deploy PostgreSQL: %v", err)
 } else {
  logger.Info("Waiting for PostgreSQL to be ready...")
  if err := deployer.WaitForDeployment("mobius-system", "postgres", 2*time.Minute); err != nil {
   logger.Warnf("PostgreSQL not ready: %v", err)
  } else {
   logger.Info("PostgreSQL is ready!")
  }
 }

 // Deploy MDM server
 if err := deployer.Apply("deployments/examples/mdm-server.yaml"); err != nil {
  logger.Warnf("Failed to deploy MDM server: %v", err)
 } else {
  logger.Info("Waiting for MDM server to be ready...")
  if err := deployer.WaitForDeployment("mobius-system", "mdm-server", 2*time.Minute); err != nil {
   logger.Warnf("MDM server not ready: %v", err)
  } else {
   logger.Info("MDM server is ready!")
  }
 }

 // Start local API server
 apiServer := api.NewServer(logger, ":8080")
 go func() {
  if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
   logger.Errorf("API server error: %v", err)
  }
 }()
 defer apiServer.Shutdown()

 logger.Info("=================================================================")
 logger.Info("Mobius server is running!")
 logger.Info("=================================================================")
 logger.Infof("Kubeconfig: %s", kubeconfigPath)
 logger.Info("API Server: http://localhost:8080")
 logger.Info("Health Check: http://localhost:8080/health")
 logger.Info("Press Ctrl+C to stop")
 logger.Info("=================================================================")

 // Setup signal handling
 signChn := make(chan os.Signal, 1)
 signal.Notify(signChn, syscall.SIGINT, syscall.SIGTERM)

 // Wait for shutdown signal
 <-signChn
 logger.Info("Shutdown signal received, cleaning up...")
}
```

### Step 3: Create Deployment Manifest

Create `deployments/api-server.yaml`:

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: mobius-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
    spec:
      containers:
      - name: api-server
        image: mobius/api-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: LOG_LEVEL
          value: "info"
        - name: KUBECONFIG
          value: "/etc/kubeconfig/config"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: api-server
  namespace: mobius-system
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: api-server
```

### Step 4: Test It

```bash
# Build and run
go run cmd/server/main.go

# In another terminal, test the API
curl http://localhost:8080/health

# Check cluster services
export KUBECONFIG=configs/cluster/kubeconfig
kubectl get all -n mobius-system
```

## Example Output

```
INFO[0000] Initializing Mobius server...
INFO[0001] Docker daemon is ready
INFO[0002] Creating KIND cluster 'mobius-cluster'...
INFO[0015] KIND cluster 'mobius-cluster' created successfully
INFO[0015] Deploying services to cluster...
INFO[0016] Creating namespace: mobius-system
INFO[0016] Applying manifest: deployments/examples/postgres.yaml
INFO[0017] Waiting for PostgreSQL to be ready...
INFO[0045] PostgreSQL is ready!
INFO[0045] Applying manifest: deployments/examples/mdm-server.yaml
INFO[0046] Waiting for MDM server to be ready...
INFO[0078] MDM server is ready!
INFO[0078] Starting API server on :8080
INFO[0078] =================================================================
INFO[0078] Mobius server is running!
INFO[0078] =================================================================
INFO[0078] Kubeconfig: /home/awar/Desktop/Mobius/configs/cluster/kubeconfig
INFO[0078] API Server: http://localhost:8080
INFO[0078] Health Check: http://localhost:8080/health
INFO[0078] Press Ctrl+C to stop
INFO[0078] =================================================================
```

## Adding More Services

### Database Connection

Create `internal/database/db.go`:

```go
package database

import (
 "database/sql"
 "fmt"

 _ "github.com/lib/pq"
 "github.com/sirupsen/logrus"
)

type DB struct {
 conn   *sql.DB
 logger *logrus.Logger
}

func Connect(dsn string, logger *logrus.Logger) (*DB, error) {
 logger.Infof("Connecting to database...")
 conn, err := sql.Open("postgres", dsn)
 if err != nil {
  return nil, fmt.Errorf("failed to open database: %w", err)
 }

 if err := conn.Ping(); err != nil {
  return nil, fmt.Errorf("failed to ping database: %w", err)
 }

 logger.Info("Database connection established")
 return &DB{conn: conn, logger: logger}, nil
}

func (db *DB) Close() error {
 db.logger.Info("Closing database connection")
 return db.conn.Close()
}
```

Then in `main.go`:

```go
import "mobius/internal/database"

// After deploying PostgreSQL
db, err := database.Connect(
 "postgresql://mobius:changeme@localhost:5432/mobius?sslmode=disable",
 logger,
)
if err != nil {
 logger.Fatalf("Database connection failed: %v", err)
}
defer db.Close()
```

### Background Worker

Create `internal/worker/worker.go`:

```go
package worker

import (
 "context"
 "time"

 "github.com/sirupsen/logrus"
)

type Worker struct {
 logger *logrus.Logger
 stop   chan struct{}
}

func NewWorker(logger *logrus.Logger) *Worker {
 return &Worker{
  logger: logger,
  stop:   make(chan struct{}),
 }
}

func (w *Worker) Start() {
 w.logger.Info("Starting background worker...")
 go w.run()
}

func (w *Worker) Stop() {
 w.logger.Info("Stopping background worker...")
 close(w.stop)
}

func (w *Worker) run() {
 ticker := time.NewTicker(30 * time.Second)
 defer ticker.Stop()

 for {
  select {
  case <-ticker.C:
   w.doWork()
  case <-w.stop:
   return
  }
 }
}

func (w *Worker) doWork() {
 w.logger.Debug("Worker doing periodic task...")
 // Your periodic work here
}
```

Add to `main.go`:

```go
import "mobius/internal/worker"

worker := worker.NewWorker(logger)
worker.Start()
defer worker.Stop()
```

## Summary

The modular structure makes it easy to:

1. ✅ Add new packages in `internal/`
2. ✅ Create deployment manifests in `deployments/`
3. ✅ Wire everything together in `main.go`
4. ✅ Deploy automatically using the `deploy` package
5. ✅ Keep code organized and maintainable

Each component is:

- **Independent** - Can be tested separately
- **Reusable** - Can be used in different contexts
- **Clear** - Single responsibility per package
- **Extensible** - Easy to add features
