# Mobius MDM - Single Developer Edition

> **Complete Mobile Device Management platform - optimized for single developer workflow**

## 🚀 Quick Start

```bash
# Get started in 3 commands
git clone <repo>
cd mobius
make setup && make dev
```

**That's it!** Your MDM platform is now running:
- **Main App**: <http://localhost:8080>
- **Frontend**: <http://localhost:3000>

## 🎯 What You Get

### Core MDM Features ✅
- **Device Management**: Track macOS, iOS, Windows, Linux devices
- **osquery Integration**: Query devices in real-time
- **Policy Management**: Deploy and monitor compliance policies
- **Software Management**: Install, update, and remove applications
- **User Authentication**: Secure access control
- **Live Queries**: Interactive device interrogation
- **Vulnerability Scanning**: Security assessment
- **File Carving**: Forensic file collection
- **Script Execution**: Remote command execution

### Advanced Features ✅
- **MDM Enrollment**: iOS and macOS device enrollment
- **App Store Integration**: iOS/macOS app deployment
- **Configuration Profiles**: System settings management
- **Certificate Management**: PKI and certificate deployment
- **Geofencing**: Location-based policies
- **Remote Wipe**: Security breach response
- **Compliance Reporting**: Audit and compliance dashboards

## 📁 Simplified Structure

```
mobius/
├── 🔧 Quick Commands
│   ├── make setup      # Initial setup
│   ├── make dev        # Start development
│   └── make build      # Build application
├── 
├── 💻 Core Application
│   ├── server/         # Go backend (all MDM features)
│   ├── frontend/       # React frontend (all UI)
│   └── database/       # Database schemas
├── 
├── 🧪 Development
│   ├── docker/         # Docker configurations
│   ├── scripts/        # Build scripts
│   └── tools/          # Development tools
└── 
└── 🎨 Optional Components
    ├── website/        # Marketing site
    ├── ansible-mdm/    # Ansible automation
    ├── terraform/      # Infrastructure
    └── charts/         # Kubernetes
```

## 🌐 GitHub-Centric Deployment

### 📦 Container Registry
All Docker images are stored in **GitHub Container Registry**:
- **Backend**: `ghcr.io/yourusername/mobius:latest`
- **Frontend**: `ghcr.io/yourusername/mobius-frontend:latest`
- **No external registries needed** - everything through GitHub

### � CI/CD with GitHub Actions
- **Automatic testing** on every push/PR
- **Automatic building** of Docker images
- **Automatic deployment** to GitHub Container Registry
- **GitHub Pages** for documentation
- **GitHub Releases** for binary distribution

### 🚀 Deployment Options
- **Self-hosted**: Using GitHub Container Registry images
- **Cloud deployment**: Deploy anywhere using GitHub images

```bash
# GitHub integration commands
make github-build      # Build images for GitHub registry
make github-push       # Push to GitHub Container Registry
make github-release    # Create release with binaries
make github-login      # Login to GitHub Container Registry
```

## 🛠️ Common Commands

```bash
# Development
make dev                # Start core development
make dev-full          # Start everything
make test              # Run all tests
make build             # Build application

# Database
make db-reset          # Reset database
make db-backup         # Backup database
make db-restore        # Restore database

# Docker
make docker-build      # Build Docker images
make docker-run        # Run in Docker

# Cleanup
make clean             # Clean build artifacts
```

## 🎨 What's Been Simplified

### For Single Developer Workflow
- **✅ Unified commands**: Single `make dev` command
- **✅ Profile-based development**: Choose what you need
- **✅ Simplified Docker**: Easy containerization
- **✅ Clear documentation**: Step-by-step guides
- **✅ Reduced complexity**: Focus on core features

### What's NOT Removed
- **✅ All MDM features**: Complete device management
- **✅ All integrations**: Cloud, SSO, third-party tools
- **✅ All deployment options**: Docker, Kubernetes, bare metal
- **✅ All platforms**: macOS, iOS, Windows, Linux support
- **✅ All APIs**: Complete REST API surface
- **✅ All security features**: Authentication, authorization, encryption

## 📚 Documentation

- **[Single Developer Guide](docs/single-developer-guide.md)** - Complete development guide
- **[Architecture](docs/architecture.md)** - System architecture
- **[API Documentation](docs/api.md)** - REST API reference
- **[Deployment Guide](docs/deployment.md)** - Production deployment
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues

## 🎯 Development Best Practices

1. **Start with Core**: Use `make dev` for most development
2. **Test Incrementally**: Test features as you build them
3. **Use Profiles**: Switch profiles based on what you're working on
4. **Clean Slate**: Use `make clean && make setup` to reset
5. **Document Changes**: Update docs as you modify features

## 🚨 Need Help?

### Quick Troubleshooting
```bash
# Reset everything
make clean && make setup

# Check services
docker-compose -f docker-compose.dev.yml ps

# View logs
docker-compose -f docker-compose.dev.yml logs -f
```

### Common Issues
- **Port conflicts**: Check what's using ports 8080, 3000
- **Database issues**: Try `make db-reset`
- **Build issues**: Try `make clean && make build`

## 🤝 Contributing

This is optimized for single developer workflow, but contributions welcome:

1. Fork the repository
2. Create feature branch
3. Make changes using `make dev`
4. Test with `make test`
5. Submit pull request

## 📄 License

See [LICENSE](LICENSE) file for details.

---

**🎉 You now have a complete MDM platform with simplified development workflow!**
