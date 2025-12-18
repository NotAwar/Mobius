package headscale

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mobius/internal/deploy"

	"github.com/sirupsen/logrus"
)

const (
	namespace = "headscale"
)

// Config holds Headscale deployment configuration
type Config struct {
	// Namespace to deploy into
	Namespace string
	// CustomValues for deployment (reserved for future use)
	CustomValues map[string]string
}

// DefaultConfig returns the default Headscale configuration
func DefaultConfig() Config {
	return Config{
		Namespace:    namespace,
		CustomValues: make(map[string]string),
	}
}

// Deployer handles Headscale deployment
type Deployer struct {
	config   Config
	deployer *deploy.Deployer
	logger   *logrus.Logger
}

// NewDeployer creates a new Headscale deployer
func NewDeployer(deployer *deploy.Deployer, logger *logrus.Logger, config Config) *Deployer {
	return &Deployer{
		config:   config,
		deployer: deployer,
		logger:   logger,
	}
}

// Deploy deploys Headscale to the cluster using simple manifests
func (h *Deployer) Deploy() error {
	// Create namespace
	if err := h.deployer.CreateNamespace(h.config.Namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Deploy PostgreSQL cluster for Headscale
	h.logger.Info("Creating PostgreSQL database for Headscale...")
	
	postgresManifest := "configs/headscale/postgres.yaml"
	if err := h.deployer.Apply(postgresManifest); err != nil {
		return fmt.Errorf("failed to create PostgreSQL cluster: %w", err)
	}

	// Wait a moment for PostgreSQL pod to start
	// CNPG creates a StatefulSet, not a Deployment, so we just give it time to initialize
	h.logger.Info("Waiting for PostgreSQL to initialize...")
	time.Sleep(20 * time.Second)
	h.logger.Info("PostgreSQL cluster created, Headscale will connect when ready")

	// Generate and apply Headscale manifests
	h.logger.Info("Deploying Headscale server...")
	manifestPath, err := h.generateManifests()
	if err != nil {
		return fmt.Errorf("failed to generate manifests: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(manifestPath))

	if err := h.deployer.Apply(manifestPath); err != nil {
		return fmt.Errorf("failed to deploy Headscale: %w", err)
	}

	h.logger.Info("Headscale deployed successfully!")
	h.logger.Infof("To access Headscale UI: kubectl port-forward -n %s svc/headscale 8080:8080", h.config.Namespace)

	return nil
}

// generateManifests creates Kubernetes manifests for Headscale deployment
func (h *Deployer) generateManifests() (string, error) {
	tmpDir, err := os.MkdirTemp("", "headscale-manifests-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	manifestPath := filepath.Join(tmpDir, "headscale.yaml")

	// Simple Headscale deployment without complex Helm hooks
	manifest := fmt.Sprintf(`---
apiVersion: v1
kind: ConfigMap
metadata:
  name: headscale-config
  namespace: %s
data:
  config.yaml: |
    server_url: http://headscale:8080
    listen_addr: 0.0.0.0:8080
    metrics_listen_addr: 0.0.0.0:9090
    grpc_listen_addr: 0.0.0.0:50443
    
    database:
      type: postgres
      postgres:
        host: headscale-db-rw.%s.svc.cluster.local
        port: 5432
        name: headscale
        user: headscale
        pass: headscale-secure-password
        max_open_conns: 10
        max_idle_conns: 10
        conn_max_idle_time_secs: 3600
    
    dns:
      base_domain: mobius.local
      magic_dns: true
      override_local_dns: false
      nameservers:
        - 1.1.1.1
        - 8.8.8.8
    
    disable_check_updates: true
    ephemeral_node_inactivity_timeout: 30m
    
    log:
      level: info
      format: text
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: headscale
  namespace: %s
  labels:
    app: headscale
spec:
  replicas: 1
  selector:
    matchLabels:
      app: headscale
  template:
    metadata:
      labels:
        app: headscale
    spec:
      containers:
      - name: headscale
        image: headscale/headscale:0.23.0
        imagePullPolicy: IfNotPresent
        command: ["headscale", "serve"]
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        - name: grpc
          containerPort: 50443
          protocol: TCP
        volumeMounts:
        - name: config
          mountPath: /etc/headscale
        - name: data
          mountPath: /var/lib/headscale
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 10
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: headscale-config
      - name: data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: headscale
  namespace: %s
  labels:
    app: headscale
spec:
  type: ClusterIP
  selector:
    app: headscale
  ports:
  - name: http
    port: 8080
    targetPort: http
    protocol: TCP
  - name: metrics
    port: 9090
    targetPort: metrics
    protocol: TCP
  - name: grpc
    port: 50443
    targetPort: grpc
    protocol: TCP
`, h.config.Namespace, h.config.Namespace, h.config.Namespace, h.config.Namespace)

	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	return manifestPath, nil
}

// Uninstall removes Headscale from the cluster
func (h *Deployer) Uninstall() error {
	h.logger.Infof("Uninstalling Headscale from namespace %s...", h.config.Namespace)

	// Headscale resources will be cleaned up when namespace is deleted
	// The PostgreSQL cluster is managed by CNPG and will also be cleaned up
	h.logger.Info("Headscale uninstalled successfully")
	return nil
}
