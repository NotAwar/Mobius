# Quick Start Guide

## Running Mobius Server

The Mobius server is **fully automated** - just run it!

```bash
go run cmd/server/main.go
```

That's it! The server will:

1. ✅ Detect your Linux distribution
2. ✅ Install Docker automatically if needed (one-time sudo for installation)
3. ✅ Start its own isolated Docker daemon (no system service needed!)
4. ✅ Create a KIND Kubernetes cluster
5. ✅ Deploy Headscale VPN and UI components
6. ✅ Be ready for device management!

## First Time Running

The very first time you run Mobius, you may be prompted for your sudo password **once** to install Docker (if not already installed).

```bash
go run cmd/server/main.go
# You might see: [sudo] password for user:
# Enter your password - this is the ONLY time you'll need to do this!
```

After Docker is installed, the server manages its own isolated Docker daemon - no more password prompts, no systemd required!

## What You'll See

```text
🚀 Mobius Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[17:30:45] ℹ Checking Docker availability...
[17:30:45] ℹ Docker is already installed
[17:30:45] ℹ Setting up Docker directories...
[17:30:45] ℹ Docker directories ready
[17:30:45] ℹ Starting isolated Docker daemon...
[17:30:45] ℹ Socket: /var/run/mobius-docker/docker.sock
[17:30:45] ℹ Data root: /var/lib/mobius-docker
[17:30:46] ℹ Waiting for Docker daemon to be ready...
[17:30:47] ℹ Docker daemon is responding
[17:30:47] ✓ Docker daemon is ready
[17:30:47] ℹ Creating KIND cluster...
[17:30:52] ✓ Mobius cluster is running. Press Ctrl+C to stop.
```

## What Gets Configured Automatically

When you run Mobius for the first time, it automatically:

1. **Creates isolated Docker directories**
   - `/var/lib/mobius-docker` - Docker data (images, containers)
   - `/var/run/mobius-docker` - Runtime files and socket

2. **Starts its own Docker daemon**
   - Completely isolated from system Docker
   - No systemd dependency
   - No kernel module requirements (iptables-free)

3. **Sets DOCKER_HOST environment variable**
   - Points all docker commands to the custom socket
   - Transparent to the rest of the application

## Platform-Specific Notes

### Linux (Ubuntu, Debian, Fedora, RHEL, Arch)

✅ Fully automatic - no manual steps needed

### macOS

⚠️ Install Docker Desktop first:

```bash
brew install --cask docker
# Then start Docker Desktop from Applications
```

### Windows

⚠️ Install Docker Desktop first:

- Download from: <https://www.docker.com/products/docker-desktop>
- Install and start Docker Desktop

## Stopping the Server

Press `Ctrl+C` - the server will:

1. Delete the KIND cluster
2. Stop the isolated Docker daemon gracefully
3. Clean up resources

## Accessing the Cluster

```bash
# Set kubeconfig
export KUBECONFIG=/home/awar/Desktop/Mobius/configs/cluster/kubeconfig

# Check cluster
kubectl get nodes

# Expected output:
# NAME                           STATUS   ROLES           AGE   VERSION
# mobius-cluster-control-plane   Ready    control-plane   1m    v1.31.0
```

## Troubleshooting

### Port Already in Use

```bash
# Check if there's a stale socket
sudo rm /var/run/mobius-docker.sock
sudo rm /var/run/mobius-docker.pid
```

### Permission Errors

```bash
# Explicitly run with sudo
sudo go run cmd/server/server.go
```

### Can't Find dockerd After Installation

```bash
# Check installation
which dockerd

# If not found, install manually:
sudo apt-get install docker.io  # Ubuntu/Debian
sudo dnf install docker         # Fedora/RHEL
```

## Advanced Usage

### Custom Configuration

Edit `configs/cluster/config.yaml` to customize your KIND cluster:

- Number of nodes
- Kubernetes version
- Network settings
- Port mappings

### Inspect the Isolated Docker Daemon

```bash
# While server is running, in another terminal:
docker --host=unix:///var/run/mobius-docker.sock ps
docker --host=unix:///var/run/mobius-docker.sock images
```

### Clean Everything

```bash
# Remove all Mobius Docker data
sudo rm -rf /var/lib/mobius-docker
sudo rm -rf /var/run/mobius-docker
```

## Next Steps

1. **Deploy MDM Services** - Your device management services run in the cluster
2. **Configure Ingress** - Expose services for device enrollment
3. **Set Up Certificates** - Secure communication with devices
4. **Connect Devices** - Enroll devices to your MDM solution

## Code Organization

The server code is now organized into reusable modules:

- **`cmd/server/main.go`** - Main entry point (add your custom logic here)
- **`internal/docker/`** - Docker daemon management
- **`internal/kind/`** - KIND cluster management
- **`internal/deploy/`** - Kubernetes deployment utilities
- **`internal/privileges/`** - Permission handling

For detailed information, see:

- [DOCKER_DAEMON_MANAGEMENT.md](docs/DOCKER_DAEMON_MANAGEMENT.md)
- [SERVER_ARCHITECTURE.md](docs/SERVER_ARCHITECTURE.md)
- [ADDING_SERVICES.md](docs/ADDING_SERVICES.md)
