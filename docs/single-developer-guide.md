# Mobius Development Guide for Single Developers

## 🚀 Quick Start

### 1. Initial Setup
```bash
# Clone and setup
git clone <repo>
cd mobius
make setup
```

### 2. Start Development
```bash
# Core development (recommended for single dev)
make dev

# Full development (if you need everything)
make dev-full
```

### 3. Access Applications
- **Main App**: http://localhost:8080
- **Frontend**: http://localhost:3000  
- **Website**: http://localhost:1337 (full profile only)

## 📁 Simplified Project Structure

```
mobius/
├── cmd/                    # Application entry points
├── server/                 # Go backend (all MDM features)
├── frontend/               # React frontend (all UI features)
├── database/               # Database schemas
├── config/                 # Configuration files
├── docs/                   # Documentation
├── scripts/                # Build scripts
├── docker/                 # Docker configurations
├── tools/                  # Development tools
└── optional/               # Optional components
    ├── website/            # Marketing site
    ├── ansible-mdm/        # Ansible automation
    ├── terraform/          # Infrastructure
    └── charts/             # Kubernetes
```

## 🔧 Development Profiles

### Core Profile (Default)
- **What it includes**: Backend + Frontend + Database
- **Best for**: Feature development, bug fixes, testing
- **Command**: `make dev`

### Full Profile
- **What it includes**: Everything (current setup)
- **Best for**: Testing integrations, marketing site work
- **Command**: `make dev-full`

### Enterprise Profile  
- **What it includes**: Core + Enterprise features
- **Best for**: Testing SSO, advanced policies
- **Command**: `make dev-enterprise`

## 🛠️ Common Development Tasks

### Backend Development
```bash
# Run backend only
cd server
go run ./cmd/mobius

# Run tests
go test ./...

# Database migrations
go run ./cmd/mobius migrate
```

### Frontend Development
```bash
# Run frontend only
cd frontend
npm start

# Run tests
npm test

# Build for production
npm run build
```

### Database Management
```bash
# Reset database
make db-reset

# Backup database
make db-backup

# Restore database
make db-restore backup.sql
```

## 🧪 Testing

### Unit Tests
```bash
make test                   # All tests
go test ./server/...        # Backend tests
cd frontend && npm test     # Frontend tests
```

### Integration Tests
```bash
make test-integration       # Full integration tests
make test-e2e              # End-to-end tests
```

## 🐳 Docker Development

### Start Services
```bash
# Start all core services
docker-compose -f docker-compose.dev.yml up

# Start specific service
docker-compose -f docker-compose.dev.yml up mysql redis

# Background mode
docker-compose -f docker-compose.dev.yml up -d
```

### Clean Up
```bash
# Stop services
docker-compose -f docker-compose.dev.yml down

# Remove volumes (reset data)
docker-compose -f docker-compose.dev.yml down --volumes
```

## 📦 Building and Deployment

### Local Build
```bash
make build                  # Build everything
make build-server          # Build backend only
make build-frontend        # Build frontend only
```

### Docker Build
```bash
make docker-build          # Build Docker images
make docker-run            # Run in Docker
```

## 🔍 Debugging

### Backend Debugging
```bash
# Run with debugger
dlv debug ./cmd/mobius

# Run with verbose logging
MOBIUS_LOG_LEVEL=debug go run ./cmd/mobius
```

### Frontend Debugging
```bash
# Run with React DevTools
cd frontend && npm start

# Run with debugging
cd frontend && npm run start:debug
```

## 📊 Monitoring

### Development Monitoring
- **Logs**: `docker-compose logs -f mobius-server`
- **Database**: Connect to `localhost:3306`
- **Redis**: Connect to `localhost:6379`

### Health Checks
```bash
# Check server health
curl http://localhost:8080/api/health

# Check frontend
curl http://localhost:3000

# Check database
mysql -h localhost -u mobius -p mobius
```

## 🎯 Single Developer Best Practices

1. **Use Core Profile**: Start with `make dev` for most work
2. **Incremental Testing**: Test features as you build them
3. **Database Snapshots**: Use `make db-backup` before major changes
4. **Clean Slate**: Use `make clean && make setup` to reset everything
5. **Documentation**: Update docs as you modify features

## 🚨 Troubleshooting

### Common Issues

**Database Connection Issues**
```bash
# Check if MySQL is running
docker-compose -f docker-compose.dev.yml ps mysql

# Reset database
make db-reset
```

**Port Conflicts**
```bash
# Check what's using ports
lsof -i :8080
lsof -i :3000

# Kill processes
kill -9 $(lsof -t -i :8080)
```

**Build Issues**
```bash
# Clean everything
make clean

# Rebuild from scratch
make setup
make build
```

## 📞 Getting Help

1. Check the [troubleshooting guide](docs/troubleshooting.md)
2. Review [architecture docs](docs/architecture.md)
3. Look at [API documentation](docs/api.md)
4. Check [deployment guide](docs/deployment.md)
