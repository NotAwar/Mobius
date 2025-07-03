# Mobius GitHub-Centric Deployment Guide

## 🎯 Overview
This guide covers deploying Mobius using GitHub's ecosystem: Container Registry, Actions, and Releases.

## 🚀 GitHub Container Registry Setup

### 1. Enable GitHub Container Registry
```bash
# Login to GitHub Container Registry
docker login ghcr.io
# Use your GitHub username and a Personal Access Token with packages:write scope
```

### 2. Build and Push Images
```bash
# Build and push to GitHub Container Registry
make github-build
make github-push

# Or manually:
docker build -t ghcr.io/yourusername/mobius:latest .
docker build -t ghcr.io/yourusername/mobius-frontend:latest ./frontend
docker push ghcr.io/yourusername/mobius:latest
docker push ghcr.io/yourusername/mobius-frontend:latest
```

## 🔄 GitHub Actions CI/CD

### 1. Automatic Building
The `.github/workflows/build-and-deploy.yml` workflow will:
- Run tests on every push/PR
- Build Docker images automatically
- Push to GitHub Container Registry
- Deploy documentation to GitHub Pages

### 2. Manual Triggers
```bash
# Trigger a build via GitHub CLI
gh workflow run build-and-deploy.yml

# Or push a tag for release
git tag v1.0.0
git push origin v1.0.0
```

## 📦 GitHub Releases

### 1. Create Release
```bash
# Build release binaries
make github-release

# Create release on GitHub
gh release create v1.0.0 \
  --title "Mobius v1.0.0" \
  --notes "Release notes here" \
  build/mobius-linux-amd64 \
  build/mobius-darwin-amd64 \
  build/mobius-darwin-arm64 \
  build/mobius-windows-amd64.exe
```

### 2. Download Releases
```bash
# Download latest release
gh release download --pattern "mobius-*"

# Or use direct URLs
curl -L https://github.com/yourusername/mobius/releases/latest/download/mobius-linux-amd64 -o mobius
```

## 🌐 Deployment Options

### 1. Self-Hosted (Docker Compose)
```bash
# Create environment file
cat > .env << EOF
GITHUB_USER=yourusername
GITHUB_REPO=mobius
TAG=latest
MYSQL_ROOT_PASSWORD=secure_password
MYSQL_PASSWORD=secure_password
EOF

# Deploy using GitHub images
docker-compose -f docker-compose.prod.yml up -d
```

### 2. Local Development
```bash
# Use the simplified development commands
make setup
make dev
```

### 3. Cloud Deployment
```bash
# Deploy to any cloud provider using GitHub Container Registry
# Examples:

# AWS ECS
aws ecs create-service --service-name mobius --task-definition mobius:1 --cluster default

# Google Cloud Run
gcloud run deploy mobius --image ghcr.io/yourusername/mobius:latest --platform managed

# Azure Container Instances
az container create --resource-group myResourceGroup --name mobius --image ghcr.io/yourusername/mobius:latest
```

## 🔐 Security Best Practices

### 1. Container Registry Access
```bash
# Use fine-grained personal access tokens
# Scope: packages:write, packages:read

# For production, use service accounts
gh auth login --with-token < token.txt
```

### 2. Image Scanning
```bash
# Enable GitHub's built-in security scanning
# Go to Settings > Security & Analysis > Enable all features

# Or use Docker Scout
docker scout cves ghcr.io/yourusername/mobius:latest
```

### 3. Secrets Management
```bash
# Store secrets in GitHub Secrets
gh secret set MYSQL_PASSWORD --body "secure_password"
gh secret set JWT_SECRET --body "jwt_secret_key"
```

## 📊 Monitoring and Logging

### 1. GitHub Container Registry Metrics
- View download statistics in GitHub Packages
- Monitor image vulnerabilities
- Track usage across repositories

### 2. Deployment Monitoring
```bash
# Health check endpoint
curl http://localhost:8080/api/health

# View logs
docker-compose -f docker-compose.prod.yml logs -f mobius-server
```

## 🛠️ Development Workflow

### 1. Feature Development
```bash
# Create feature branch
git checkout -b feature/new-mdm-feature

# Develop using core profile
make dev

# Test changes
make test

# Push for CI/CD
git push origin feature/new-mdm-feature
```

### 2. Release Process
```bash
# Merge to main
git checkout main
git merge feature/new-mdm-feature

# Tag release
git tag v1.0.1
git push origin v1.0.1

# GitHub Actions will automatically:
# - Build and test
# - Create container images
# - Publish to GitHub Container Registry
# - Create GitHub Release with binaries
```

## 🚨 Troubleshooting

### Common Issues

**Authentication to GitHub Container Registry**
```bash
# Check login status
docker system info | grep -i registry

# Re-login if needed
docker logout ghcr.io
docker login ghcr.io
```

**Image Pull Issues**
```bash
# Make sure images are public or you're authenticated
docker pull ghcr.io/yourusername/mobius:latest

# Check image exists
gh api /user/packages/container/mobius/versions
```

**Build Failures**
```bash
# Check GitHub Actions logs
gh run list --workflow=build-and-deploy.yml
gh run view <run-id>

# Local debugging
docker build --no-cache -t test .
```

## 📱 Mobile App Distribution

### 1. iOS App (if applicable)
```bash
# Use GitHub for TestFlight distribution
# Store certificates in GitHub Secrets
# Use GitHub Actions for automated building
```

### 2. Android App (if applicable)
```bash
# Use GitHub for Play Store distribution
# Store signing keys in GitHub Secrets
# Use GitHub Actions for automated building
```

## 🔄 Updates and Maintenance

### 1. Automated Updates
```bash
# Use Dependabot for dependency updates
# Configure in .github/dependabot.yml

# Use GitHub Actions for security updates
# Configure in .github/workflows/security-updates.yml
```

### 2. Backup Strategy
```bash
# Backup database
docker exec mobius_mysql_1 mysqldump -u root -p mobius > backup.sql

# Store backups in GitHub (private repo)
git add backup.sql
git commit -m "Database backup $(date)"
git push origin backups
```

---

**🎉 Your Mobius deployment is now fully integrated with GitHub's ecosystem!**
