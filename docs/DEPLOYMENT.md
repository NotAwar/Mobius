# Mobius Deployment Guide

Complete guide for deploying and testing the Mobius platform.

## Prerequisites

- Linux system with sudo access
- Go 1.21+ installed
- Node.js 20+ and npm installed
- At least 4GB RAM available
- Port 3000 (API) and 8081 (UI) available

## Quick Start

### 1. Build the Server

```bash
cd /home/awar/Desktop/Mobius
go build -o /tmp/mobius-server cmd/server/main.go
```

### 2. Run the Server

```bash
/tmp/mobius-server
```

You'll be prompted for your sudo password. The deployment sequence:

1. **Docker Daemon** - Starts isolated Docker daemon
2. **KIND Cluster** - Creates local Kubernetes cluster
3. **CNPG Operator** - Installs CloudNativePG for PostgreSQL
4. **Headscale** - Deploys Headscale VPN coordinator
5. **Fiber API** - Starts REST API on port 3000
6. **SvelteKit UI** - Builds and deploys web dashboard

### 3. Access the Dashboard

Once deployment completes:

```bash
# API available at:
http://localhost:3000

# UI will be available at (after port-forward):
http://localhost:8081
```

## Development Mode

### Run Web UI in Development

For faster iteration without full deployment:

```bash
cd web
npm run dev
```

Access at `http://localhost:5173` - Features hot module replacement for instant updates.

### API Development

The API runs on port 3000 with the following endpoints:

#### Health & Status

- `GET /api/health` - API health check
- `GET /api/status/cluster` - Kubernetes cluster status
- `GET /api/status/postgres` - PostgreSQL status
- `GET /api/status/headscale` - Headscale status

#### Cluster Management

- `GET /api/cluster/nodes` - List cluster nodes
- `GET /api/cluster/pods` - List all pods

#### PostgreSQL Management

- `GET /api/postgres/databases` - List databases
- `POST /api/postgres/databases` - Create database
- `DELETE /api/postgres/databases/:name` - Delete database

#### Headscale Management

- `GET /api/headscale/users` - List users
- `POST /api/headscale/users` - Create user
- `GET /api/headscale/nodes` - List nodes
- `POST /api/headscale/nodes` - Register node

## Architecture

### Component Stack

```
┌─────────────────────────────────────────────────┐
│            SvelteKit Web Dashboard              │
│         (TypeScript + Tailwind CSS)             │
│              Port: 8081 (prod)                  │
└─────────────────┬───────────────────────────────┘
                  │ HTTP/REST
┌─────────────────▼───────────────────────────────┐
│              Fiber REST API                     │
│         (Go + Fiber v2 Framework)               │
│              Port: 3000                         │
└─────────────────┬───────────────────────────────┘
                  │ kubectl/CLI
┌─────────────────▼───────────────────────────────┐
│          Kubernetes (KIND Cluster)              │
│                                                 │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ CNPG Operator│  │   Headscale  │            │
│  │  (Postgres)  │  │     (VPN)    │            │
│  └──────────────┘  └──────────────┘            │
└─────────────────┬───────────────────────────────┘
                  │ containerd
┌─────────────────▼───────────────────────────────┐
│        Isolated Docker Daemon (VFS)             │
│     /var/lib/mobius-docker (rootless)           │
└─────────────────────────────────────────────────┘
```

### Directory Structure

```
Mobius/
├── cmd/server/main.go          # Main entry point
├── internal/
│   ├── docker/daemon.go        # Docker daemon management
│   ├── kind/cluster.go         # KIND cluster creation
│   ├── cnpg/                   # CNPG deployment
│   ├── headscale/              # Headscale deployment
│   ├── api/server.go           # Fiber API server
│   ├── ui/ui.go                # SvelteKit deployment
│   └── tui/tui.go              # Terminal UI (Bubble Tea)
├── pkg/branding/               # Unified branding system
├── web/                        # SvelteKit frontend
│   ├── src/routes/             # Pages (dashboard, cluster, etc)
│   ├── src/lib/theme.ts        # TypeScript theme
│   └── Dockerfile              # Production container
└── assets/                     # Shared assets (logos, favicons)
    └── (symlinked to web/static/assets)
```

## Branding & Theme

All UIs use the unified branding system from `pkg/branding/`:

### Colors (Logo-based)

- **Primary**: `#1c2f38` (Dark Blue) - Main backgrounds
- **Secondary**: `#31413e` (Teal) - Elevated surfaces
- **Accent**: `#d4af37` (Golden) - Headings, highlights, CTAs

### Typography

- **Headings**: Montserrat Light (300) - Golden color
- **Body**: Ubuntu Regular (400) - White color
- **Fonts loaded from**: Google Fonts CDN

### Assets

- Main logo: `/assets/Mobius_Logo.png`
- Favicon: `/assets/favicon.svg` (SVG) + `/assets/favicon.ico` (fallback)
- Wallpaper: `/assets/mobius_wallpaper.png`

Assets are shared between Go and SvelteKit via symlink at `web/static/assets/`.

## Troubleshooting

### Docker Daemon Issues

If Docker fails to start:

```bash
# Check daemon status
sudo DOCKER_HOST=unix:///var/run/mobius-docker/docker.sock docker info

# Clean restart
sudo rm -rf /var/lib/mobius-docker /var/run/mobius-docker
/tmp/mobius-server
```

### KIND Cluster Issues

```bash
# List clusters
kind get clusters

# Delete and recreate
kind delete cluster --name mobius
/tmp/mobius-server
```

### Port Conflicts

If ports 3000 or 8081 are in use:

```bash
# Find processes using ports
sudo lsof -i :3000
sudo lsof -i :8081

# Kill processes if needed
kill -9 <PID>
```

### Web Build Issues

```bash
cd web

# Clean build
rm -rf .svelte-kit build node_modules
npm install
npm run build
```

### API Not Responding

```bash
# Check API logs (if running in terminal)
# Look for Fiber startup banner on port 3000

# Test health endpoint
curl http://localhost:3000/api/health
```

### UI Not Accessible

```bash
# Check if port-forward is running
kubectl get pods -n default
kubectl port-forward deployment/mobius-ui 8081:3000

# Or access via NodePort
kubectl get svc mobius-ui
```

## Testing

### Manual Testing Checklist

#### Server Deployment

- [ ] Sudo authentication box displays with golden border
- [ ] Docker daemon starts without errors
- [ ] KIND cluster creates successfully
- [ ] CNPG operator installs via Helm
- [ ] Headscale deploys via Helm (not git clone)
- [ ] Fiber API starts on port 3000
- [ ] SvelteKit UI builds and deploys

#### Web Dashboard

- [ ] Dashboard loads at correct port
- [ ] Golden headings display correctly
- [ ] White body text readable on dark background
- [ ] Status cards show cluster/postgres/headscale
- [ ] Real-time updates work (5s refresh)
- [ ] Navigation to /cluster, /postgres, /headscale works

#### API Endpoints

- [ ] Health check returns 200
- [ ] Cluster status endpoints respond
- [ ] PostgreSQL endpoints respond
- [ ] Headscale endpoints respond
- [ ] CORS allows localhost origins

#### Branding Consistency

- [ ] Terminal UI uses golden titles/borders
- [ ] Web headings are golden (#d4af37)
- [ ] Web body text is white (#ffffff)
- [ ] Logo accent color matches theme
- [ ] Fonts load correctly (Montserrat + Ubuntu)

### Automated Testing

```bash
# Run Go tests
go test ./...

# Run web tests
cd web
npm run test

# Linting
cd web
npm run lint
```

## Production Deployment

### Build Optimized Binary

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o mobius-server cmd/server/main.go
```

### Docker Compose (Alternative)

For deploying on existing infrastructure:

```bash
# Build web container
cd web
docker build -t mobius-ui:latest .

# Run API and UI
docker-compose up -d
```

### Kubernetes Deployment (Existing Cluster)

Deploy to existing K8s cluster:

```bash
# Apply CNPG
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm install cnpg cnpg/cloudnative-pg -n cnpg-system --create-namespace

# Apply Headscale
helm repo add headscale https://goodieshq.github.io/headscale-helm
helm install headscale headscale/headscale

# Deploy UI
kubectl apply -f deployments/ui.yaml
```

## Next Steps

### Implement Real API Functionality

Current API returns mock data. To implement real functionality:

1. **Cluster Endpoints** (`internal/api/server.go`)
   - Use `kubectl` commands or client-go library
   - Parse node and pod status
   - Add error handling

2. **PostgreSQL Endpoints**
   - Integrate CNPG CLI (`kubectl-cnpg`)
   - Create/delete databases via CRDs
   - Query database sizes

3. **Headscale Endpoints**
   - Use Headscale CLI in pod
   - Create users and pre-auth keys
   - List nodes and connection status

### Performance Optimization

- Add Redis for caching API responses
- Implement WebSocket for real-time updates
- Add rate limiting to API endpoints
- Enable gzip compression

### Security Hardening

- Add authentication (JWT tokens)
- Implement RBAC for API endpoints
- Enable TLS for API and UI
- Add audit logging

### Monitoring & Observability

- Add Prometheus metrics endpoint
- Implement structured logging
- Add OpenTelemetry tracing
- Create Grafana dashboards

## Support

For issues or questions:

- Check `/docs/` directory for detailed documentation
- Review `pkg/branding/README.md` for branding guidelines
- Check `web/README.md` for frontend architecture
- See `QUICKSTART.md` for basic setup

## License

[Add license information]
