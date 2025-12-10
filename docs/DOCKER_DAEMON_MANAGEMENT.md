# Mobius Server - Docker Daemon Management

The Mobius server manages its own isolated Docker daemon to run KIND clusters with **automatic installation and setup**.

## Architecture

```
Mobius Server
├── Auto-installs Docker if not present (Linux only)
├── Creates necessary directories with proper permissions
├── Starts dedicated Docker daemon (dockerd)
│   ├── Socket: /var/run/mobius-docker.sock
│   ├── Data: /var/lib/mobius-docker
│   └── Exec: /var/run/mobius-docker
│
└── Creates KIND cluster using this daemon
    └── Kubernetes nodes run as containers in this daemon
        └── MDM services deployed in the cluster
```

## Features

✨ **Zero-Config Installation** - Automatically installs Docker if not present (Linux)
✨ **Automatic Directory Setup** - Creates and configures all necessary directories
✨ **Permission Handling** - Automatically elevates privileges when needed
✨ **Multi-Distro Support** - Works with Ubuntu, Debian, Fedora, RHEL, CentOS, Arch Linux
✨ **Isolated Daemon** - No conflicts with system Docker installation

## Prerequisites

**None!** The server handles everything automatically. Just run it.

Optional: If you want to manually check if Docker is installed:

```bash
which dockerd
# If not found, Mobius will install it for you
```

## Running

### Simplest Way (Recommended)

```bash
go run cmd/server/server.go
```

The server will:

1. Check if Docker is installed
2. Install Docker automatically if needed (requires sudo)
3. Create necessary directories
4. Set proper permissions
5. Start the daemon and cluster

If elevated privileges are needed, the server will **automatically re-execute itself with sudo**.

### Alternative: Explicitly with sudo

```bash
sudo go run cmd/server/server.go
```

### Option 2: Build and run

```bash
go build -o mobius-server cmd/server/server.go
sudo ./mobius-server
```

## How It Works

1. **Privilege Check** → Detects if elevated privileges are needed
2. **Auto-Elevation** → Re-executes with sudo if Docker needs to be installed
3. **Docker Installation** → Installs Docker automatically on Linux (if needed)
4. **Directory Setup** → Creates `/var/lib/mobius-docker` and `/var/run/mobius-docker`
5. **Permission Setup** → Sets proper ownership and permissions
6. **Daemon Launch** → Starts `dockerd` with custom socket
7. **Health Check** → Waits for daemon to be ready
8. **Cluster Creation** → Creates KIND cluster using `DOCKER_HOST` env var
9. **Ready** → Kubernetes cluster running as containers
10. **Graceful Shutdown** → Cleans up cluster, then stops daemon

## Supported Platforms

| Platform | Auto-Install | Package Manager |
|----------|--------------|-----------------|
| Ubuntu/Debian | ✅ Yes | apt-get |
| Fedora | ✅ Yes | dnf |
| RHEL/CentOS 8+ | ✅ Yes | dnf |
| RHEL/CentOS 7 | ✅ Yes | yum |
| Arch Linux | ✅ Yes | pacman |
| macOS | ❌ Manual | Docker Desktop |
| Windows | ❌ Manual | Docker Desktop |

## Isolation Benefits

- **Zero System Impact** - No conflicts with system Docker daemon
- **Clean State** - Fresh environment each run (optional)
- **Custom Configuration** - Optimized for Mobius needs
- **Easy Cleanup** - Everything contained in `/var/lib/mobius-docker`
- **Security** - Isolated from other Docker workloads

## Troubleshooting

### On macOS or Windows

Docker Desktop installation is required:

```bash
# macOS
brew install --cask docker

# Windows
# Download from: https://www.docker.com/products/docker-desktop
```

### Manual Docker Installation (if auto-install fails)

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y docker.io

# Fedora/RHEL 8+
sudo dnf install -y docker

# Arch Linux
sudo pacman -S --noconfirm docker
```

### "Permission denied" Even with sudo

Check if your user can run Docker commands:

```bash
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

### "Address already in use"

Check if socket exists from previous run:

```bash
sudo rm /var/run/mobius-docker.sock
```

### View Docker daemon logs

The daemon logs are piped to the server's logger (JSON format to stdout).

### Inspect the daemon

While server is running:

```bash
docker --host=unix:///var/run/mobius-docker.sock ps
docker --host=unix:///var/run/mobius-docker.sock images
```

## Next Steps

After the cluster is running, you can:

1. Deploy MDM services to the cluster
2. Configure ingress for device connections
3. Set up certificates for secure communication
4. Deploy your device management APIs

## Configuration

The KIND cluster configuration is at:

- `configs/cluster/config.yaml`

The kubeconfig will be written to:

- `configs/cluster/kubeconfig`

Access your cluster:

```bash
export KUBECONFIG=configs/cluster/kubeconfig
kubectl get nodes
```
