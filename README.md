# Mobius

**Container Orchestration & MDM Platform**

Mobius is an integrated platform for managing containerized workloads, PostgreSQL databases, and VPN connectivity through a unified web interface.

## Features

- 🐳 **Isolated Docker Environment** - Rootless Docker daemon with VFS storage
- ☸️ **Kubernetes Management** - KIND cluster with full kubectl access
- 🐘 **PostgreSQL as a Service** - CloudNativePG operator for managed databases
- 🔒 **VPN Coordination** - Headscale for secure mesh networking
- 🚀 **REST API** - Fiber-based API with 13+ endpoints
- 🎨 **Modern Web Dashboard** - SvelteKit UI with real-time monitoring
- 🎯 **Unified Branding** - Consistent design system across all interfaces

## Quick Start

### Prerequisites

- Linux system with sudo access
- Go 1.21+
- Node.js 20+
- 4GB+ RAM available

### Build & Run

```bash
# Clone the repository
git clone https://github.com/MobiusDM/Mobius.git
cd Mobius

# Build the server
go build -o /tmp/mobius-server cmd/server/main.go

# Run deployment
/tmp/mobius-server
```

Enter your password when prompted. The server will:

1. Start an isolated Docker daemon
2. Create a KIND Kubernetes cluster
3. Install CNPG operator (PostgreSQL)
4. Deploy Headscale (VPN)
5. Launch Fiber REST API (port 3000)
6. Build and deploy SvelteKit UI (port 8081)

### Access

- **API**: <http://localhost:3000>
- **Dashboard**: <http://localhost:8081> (after port-forward)
- **Development UI**: `cd web && npm run dev` → <http://localhost:5173>

## Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide with troubleshooting
- **[QUICKSTART.md](QUICKSTART.md)** - Basic setup instructions
- **[web/README.md](web/README.md)** - Frontend architecture and features
- **[pkg/branding/README.md](pkg/branding/README.md)** - Branding guidelines
- **[docs/](docs/)** - Additional technical documentation

## Architecture

```
┌─────────────────────────────────────┐
│      SvelteKit Web Dashboard        │  TypeScript + Tailwind
│         (Port 8081)                 │
└──────────────┬──────────────────────┘
               │ REST API
┌──────────────▼──────────────────────┐
│         Fiber API Server            │  Go + Fiber v2
│         (Port 3000)                 │
└──────────────┬──────────────────────┘
               │ kubectl/CLI
┌──────────────▼──────────────────────┐
│    Kubernetes (KIND) Cluster        │
│  ┌─────────────┬──────────────┐     │
│  │ CNPG        │ Headscale    │     │  Helm Charts
│  │ (Postgres)  │ (VPN)        │     │
│  └─────────────┴──────────────┘     │
└──────────────┬──────────────────────┘
               │ containerd
┌──────────────▼──────────────────────┐
│  Docker Daemon (Isolated VFS)       │  Rootless
└─────────────────────────────────────┘
```

## Technology Stack

### Backend

- **Language**: Go 1.21+
- **API Framework**: Fiber v2
- **Container Runtime**: Docker (rootless)
- **Orchestration**: KIND (Kubernetes in Docker)
- **Database**: CloudNativePG (PostgreSQL operator)
- **VPN**: Headscale (Tailscale-compatible)
- **TUI**: Bubble Tea + Lipgloss

### Frontend

- **Framework**: SvelteKit 2 (Svelte 5)
- **Language**: TypeScript
- **Styling**: Tailwind CSS 4
- **Build**: Vite 7
- **Deployment**: Node.js adapter (production)

### DevOps

- **Package Manager**: Helm 3
- **CLI**: kubectl
- **Container Build**: Docker multi-stage
- **CI/CD**: GitHub Actions (planned)

## Branding

Mobius uses a unified branding system defined in `pkg/branding/`:

### Colors (Logo-based)

- **Primary**: `#1c2f38` (Dark Blue) - Main brand color
- **Secondary**: `#31413e` (Teal) - Elevated surfaces
- **Accent**: `#d4af37` (Golden Yellow) - Highlights, CTAs

### Typography

- **Headings**: Montserrat Light (300) - Golden color
- **Body**: Ubuntu Regular (400) - White on dark backgrounds

### Assets

All logos, favicons, and images are centralized in `/assets` and shared via symlink to `/web/static/assets`.

See [pkg/branding/README.md](pkg/branding/README.md) for complete guidelines.

## Development

### Project Structure

```
Mobius/
├── cmd/                    # Entry points
│   └── server/            # Main server binary
├── internal/              # Private application code
│   ├── api/              # Fiber REST API
│   ├── docker/           # Docker daemon management
│   ├── kind/             # KIND cluster operations
│   ├── cnpg/             # CNPG deployment
│   ├── headscale/        # Headscale deployment
│   ├── ui/               # SvelteKit deployment
│   └── tui/              # Terminal UI
├── pkg/                   # Public libraries
│   └── branding/         # Unified branding system
├── web/                   # SvelteKit frontend
│   ├── src/routes/       # Pages
│   ├── src/lib/          # Utilities
│   ├── static/           # Static assets
│   └── Dockerfile        # Production container
├── assets/                # Shared assets
├── configs/               # Configuration files
├── deployments/           # Kubernetes manifests
└── docs/                  # Documentation
```

### Running Tests

```bash
# Go tests
go test ./...

# Web tests
cd web
npm run test

# Linting
cd web
npm run lint
```

### Building for Production

```bash
# Optimized binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o mobius-server cmd/server/main.go

# Docker image
cd web
docker build -t mobius-ui:latest .
```

## API Reference

### Health & Status

- `GET /api/health` - API health check
- `GET /api/status/cluster` - Kubernetes status
- `GET /api/status/postgres` - PostgreSQL status
- `GET /api/status/headscale` - Headscale status

### Cluster Management

- `GET /api/cluster/nodes` - List nodes
- `GET /api/cluster/pods` - List pods

### PostgreSQL Management

- `GET /api/postgres/databases` - List databases
- `POST /api/postgres/databases` - Create database
- `DELETE /api/postgres/databases/:name` - Delete database

### Headscale Management

- `GET /api/headscale/users` - List users
- `POST /api/headscale/users` - Create user
- `GET /api/headscale/nodes` - List nodes
- `POST /api/headscale/nodes` - Register node

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete API documentation.

## Roadmap

### Current Status (v1.0.0)

- ✅ Docker daemon management
- ✅ KIND cluster creation
- ✅ CNPG operator installation
- ✅ Headscale deployment
- ✅ Fiber REST API with 13 endpoints
- ✅ SvelteKit dashboard with real-time updates
- ✅ Unified branding system
- ✅ Shared asset management

### Next Steps

- [ ] Implement real API functionality (replace mock data)
- [ ] Add authentication (JWT tokens)
- [ ] WebSocket for real-time updates
- [ ] Prometheus metrics
- [ ] Grafana dashboards
- [ ] CI/CD pipeline
- [ ] Unit and integration tests
- [ ] Performance optimization

### Future Features

- [ ] Multi-cluster management
- [ ] Advanced PostgreSQL operations
- [ ] Backup and restore
- [ ] Role-based access control (RBAC)
- [ ] Custom resource definitions
- [ ] Plugin system
- [ ] CLI tool for remote management

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- **Go**: Follow standard Go conventions (`gofmt`, `golint`)
- **TypeScript**: Use Prettier and ESLint (configs included)
- **Commits**: Use conventional commits format

## Troubleshooting

Common issues and solutions:

### Docker daemon won't start

```bash
# Clean Docker state
sudo rm -rf /var/lib/mobius-docker /var/run/mobius-docker
/tmp/mobius-server
```

### KIND cluster fails

```bash
# Delete and recreate
kind delete cluster --name mobius
/tmp/mobius-server
```

### Port conflicts

```bash
# Find and kill processes
sudo lsof -i :3000
sudo lsof -i :8081
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive troubleshooting.

## License

[Add license information]

## Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: `/docs` directory
- **Email**: [Add contact email]

## Acknowledgments

- [Fiber](https://gofiber.io/) - Web framework
- [SvelteKit](https://kit.svelte.dev/) - Frontend framework
- [CloudNativePG](https://cloudnative-pg.io/) - PostgreSQL operator
- [Headscale](https://github.com/juanfont/headscale) - Tailscale-compatible VPN
- [KIND](https://kind.sigs.k8s.io/) - Kubernetes in Docker
- [Bubble Tea](https://github.com/charmbracelet/bubbletea) - Terminal UI
