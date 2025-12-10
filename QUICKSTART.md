# Quick Start Guide

## Running Mobius Server

The Mobius server is **fully automated** and now **modular** - just run it!

```bash
go run cmd/server/main.go
```

That's it! The server will:

1. ✅ Detect your Linux distribution
2. ✅ Install Docker automatically if needed (will prompt for sudo)
3. ✅ Create necessary directories
4. ✅ Set proper permissions
5. ✅ Start an isolated Docker daemon
6. ✅ Create a KIND Kubernetes cluster
7. ✅ Be ready for device management!

## What You'll See

```
INFO[0000] Docker is already installed                  
INFO[0000] Ensuring directory exists: /var/lib/mobius-docker 
INFO[0000] Ensuring directory exists: /var/run/mobius-docker 
INFO[0000] Directories are ready                        
INFO[0000] Using dockerd at: /usr/bin/dockerd           
INFO[0000] Starting Docker daemon...                    
INFO[0000] Waiting for Docker daemon to be ready...    
INFO[0001] Docker daemon is ready                       
INFO[0001] Creating KIND cluster...                     
INFO[0005] Mobius cluster is running. Press Ctrl+C to stop.
```

## First Time Running?

If Docker is not installed:

```bash
go run cmd/server/server.go
# If you see "Docker not installed and not running as root"
# The server will automatically re-execute with sudo
# You'll be prompted: [sudo] password for user:
# Enter your password and it will install Docker
```

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
2. Stop the Docker daemon gracefully
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
