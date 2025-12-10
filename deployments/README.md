# Mobius Deployments

This directory contains Kubernetes deployment manifests for the Mobius MDM platform.

## Structure

```
deployments/
├── examples/              # Example deployment manifests
│   ├── mdm-server.yaml   # MDM server deployment
│   └── postgres.yaml     # PostgreSQL database
├── Dockerfile            # Container image build
└── score.yaml            # Score specification
```

## Quick Start

### 1. Deploy with Go Code

The easiest way is to use the deployer in your `main.go`:

```go
import "mobius/internal/deploy"

deployer := deploy.NewDeployer(kubeconfigPath, logger)

// Create namespace
deployer.CreateNamespace("mobius-system")

// Deploy database
deployer.Apply("deployments/examples/postgres.yaml")
deployer.WaitForDeployment("mobius-system", "postgres", 2*time.Minute)

// Deploy MDM server
deployer.Apply("deployments/examples/mdm-server.yaml")
deployer.WaitForDeployment("mobius-system", "mdm-server", 2*time.Minute)
```

### 2. Deploy Manually with kubectl

```bash
# Set kubeconfig
export KUBECONFIG=configs/cluster/kubeconfig

# Deploy everything
kubectl apply -f deployments/examples/postgres.yaml
kubectl apply -f deployments/examples/mdm-server.yaml

# Check status
kubectl get pods -n mobius-system

# View logs
kubectl logs -n mobius-system -l app=mdm-server -f
```

## Example Manifests

### postgres.yaml

PostgreSQL database for storing:

- Device inventory
- User accounts
- MDM profiles and policies
- Configuration data
- Audit logs

**Configuration:**

- Single replica (for development)
- 10Gi persistent storage
- Database: `mobius`
- User: `mobius`
- Default password: `changeme` (change in production!)

### mdm-server.yaml

MDM server handling:

- Apple MDM enrollment and management
- Windows MDM enrollment and management
- Device communication
- Policy enforcement

**Components:**

- `Namespace`: mobius-system
- `ConfigMap`: Server configuration
- `Deployment`: MDM server with 1 replica
- `Service`: ClusterIP service (ports 80, 443)
- `Secrets`: Database credentials and TLS certificates

## Customization

### 1. Change Database Password

Edit `deployments/examples/postgres.yaml` and `deployments/examples/mdm-server.yaml`:

```yaml
# In postgres.yaml
env:
- name: POSTGRES_PASSWORD
  value: "your-secure-password"

# In mdm-server.yaml
stringData:
  database-url: "postgresql://mobius:your-secure-password@postgres:5432/mobius?sslmode=disable"
```

### 2. Add TLS Certificates

Replace the placeholder in `mdm-server.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mdm-tls-certs
  namespace: mobius-system
type: kubernetes.io/tls
stringData:
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    <your actual certificate>
    -----END CERTIFICATE-----
  tls.key: |
    -----BEGIN PRIVATE KEY-----
    <your actual private key>
    -----END PRIVATE KEY-----
```

### 3. Scale Replicas

For production, increase replicas:

```yaml
spec:
  replicas: 3  # Change from 1 to 3
```

### 4. Add Resource Limits

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Exposing Services

### Option 1: NodePort (Development)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mdm-server
  namespace: mobius-system
spec:
  type: NodePort
  ports:
  - port: 443
    targetPort: 8443
    nodePort: 30443  # Accessible at https://localhost:30443
```

### Option 2: LoadBalancer (Production)

```yaml
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 8443
```

### Option 3: Ingress

Create `ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mdm-ingress
  namespace: mobius-system
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - mdm.yourdomain.com
    secretName: mdm-tls
  rules:
  - host: mdm.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: mdm-server
            port:
              number: 443
```

## Monitoring

### Check Pod Status

```bash
kubectl get pods -n mobius-system -w
```

### View Logs

```bash
# MDM server logs
kubectl logs -n mobius-system -l app=mdm-server -f

# PostgreSQL logs
kubectl logs -n mobius-system -l app=postgres -f
```

### Execute Commands in Pod

```bash
# Shell into MDM server
kubectl exec -it -n mobius-system deployment/mdm-server -- /bin/sh

# Connect to PostgreSQL
kubectl exec -it -n mobius-system statefulset/postgres -- psql -U mobius -d mobius
```

## Troubleshooting

### Pods Not Starting

```bash
# Describe pod to see events
kubectl describe pod -n mobius-system <pod-name>

# Check logs
kubectl logs -n mobius-system <pod-name>
```

### Database Connection Issues

```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:16-alpine --restart=Never -- psql -h postgres.mobius-system.svc.cluster.local -U mobius -d mobius
```

### Image Pull Errors

If using local images with KIND:

```bash
# Load image into KIND cluster
kind load docker-image mobius/mdm-server:latest --name mobius-cluster
```

## Production Checklist

- [ ] Change all default passwords
- [ ] Add real TLS certificates
- [ ] Configure proper resource limits
- [ ] Set up persistent volumes with backup
- [ ] Enable monitoring and alerting
- [ ] Configure log aggregation
- [ ] Set up ingress with proper domain
- [ ] Enable network policies
- [ ] Configure RBAC properly
- [ ] Set up secrets management (e.g., Vault)

## Next Steps

1. Customize the manifests for your environment
2. Add your own deployment manifests
3. Set up CI/CD for automated deployments
4. Configure monitoring with Prometheus/Grafana
5. Set up log aggregation with ELK/Loki
