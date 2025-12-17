# Docker Daemon Refactor - Isolated Daemon Approach

## Overview

Refactored the Docker daemon management from using systemd/D-Bus to starting an isolated dockerd process managed entirely by the application.

## Changes Made

### 1. Removed Dependencies

- **go-systemd/v22/dbus**: No longer needed since we don't interact with systemd
- **PolicyKit integration**: Removed all PolicyKit setup code and embedded rule files
- **System Docker service**: No dependency on docker.service or system daemon

### 2. New Architecture

#### Isolated Docker Daemon

- Starts its own `dockerd` process with custom configuration
- Uses dedicated directories:
  - Socket: `/var/run/mobius-docker/docker.sock`
  - Data root: `/var/lib/mobius-docker`
  - Exec root: `/var/run/mobius-docker`

#### Key Features

- **No kernel modules**: Uses `--iptables=false` and `--bridge=none` flags to avoid iptables kernel module requirements
- **Custom socket**: All docker commands automatically use `DOCKER_HOST` environment variable pointing to our socket
- **Process management**: Direct control over dockerd lifecycle (start/stop)
- **No sudo required**: Daemon runs as current user with appropriate permissions

### 3. Code Structure

#### Main Functions

**`Start(logger Logger) (*Daemon, error)`**

- Entry point for Docker daemon management
- Ensures Docker is installed
- Sets up required directories
- Starts isolated dockerd process
- Waits for daemon to be ready
- Returns Daemon instance for lifecycle management

**`setupDirectories(logger Logger) error`**

- Creates `/var/lib/mobius-docker` and `/var/run/mobius-docker`
- Sets appropriate permissions (0755)

**`startIsolatedDaemon(logger Logger) (*Daemon, error)`**

- Locates dockerd executable
- Starts dockerd with custom flags:

  ```
  --host unix:///var/run/mobius-docker/docker.sock
  --data-root /var/lib/mobius-docker
  --exec-root /var/run/mobius-docker
  --pidfile /var/run/mobius-docker/docker.pid
  --iptables=false
  --ip-forward=false
  --bridge=none
  ```

- Sets `DOCKER_HOST` environment variable
- Returns Daemon struct with command handle

**`waitForDaemonReady(logger Logger, socketPath string) error`**

- Polls daemon with `docker info` command
- 30-second timeout with 500ms intervals
- Verifies daemon is responding before proceeding

**`Stop() error`**

- Gracefully shuts down dockerd process
- Uses cmd.Stop() for clean termination
- 2-second grace period

### 4. Benefits

✅ **No authentication prompts**: No sudo/pkexec required since daemon runs as user
✅ **No system dependencies**: Doesn't rely on systemd or system Docker service
✅ **Full control**: Direct process management of dockerd
✅ **Isolated environment**: Separate data and runtime directories prevent conflicts
✅ **Kernel module independence**: Avoids iptables/netfilter kernel modules with simplified networking
✅ **Portable**: Works on any Linux system with dockerd installed

### 5. Testing

Build successfully:

```bash
go build ./cmd/server
```

Run the server:

```bash
./server
```

Expected behavior:

1. Checks if Docker is installed
2. Creates isolated directories
3. Starts dockerd with custom socket
4. Waits for daemon to respond
5. Proceeds with KIND cluster setup

### 6. Cleanup Recommendations

The following files/directories are now obsolete and can be removed:

- `/home/awar/Desktop/Mobius/configs/polkit/` - PolicyKit rules no longer needed
- `/home/awar/Desktop/Mobius/internal/docker/polkit-rule.js` - Embedded rule file
- System-level PolicyKit rule (if installed): `/etc/polkit-1/rules.d/10-docker-nopasswd.rules`

To clean up system-level PolicyKit rule:

```bash
sudo rm /etc/polkit-1/rules.d/10-docker-nopasswd.rules
sudo systemctl restart polkit
```

Note: The docker group membership that was added is harmless and can remain, but is no longer required for this implementation.

## Architecture Diagram

```
┌─────────────────────────────────────┐
│   Mobius Server (Go Application)   │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  internal/docker/daemon.go   │  │
│  │                              │  │
│  │  - setupDirectories()        │  │
│  │  - startIsolatedDaemon()     │  │
│  │  - waitForDaemonReady()      │  │
│  │  - Stop()                    │  │
│  └────────────┬─────────────────┘  │
│               │                     │
│               │ spawns              │
│               ▼                     │
│  ┌──────────────────────────────┐  │
│  │   dockerd process            │  │
│  │                              │  │
│  │   --host unix://...sock      │  │
│  │   --data-root /var/lib/...   │  │
│  │   --exec-root /var/run/...   │  │
│  │   --iptables=false           │  │
│  │   --bridge=none              │  │
│  └────────────┬─────────────────┘  │
└────────────────┼─────────────────────┘
                 │
                 │ listens on
                 ▼
    /var/run/mobius-docker/docker.sock
                 │
                 │ DOCKER_HOST
                 ▼
         All docker commands
    (docker info, docker ps, etc.)
```

## Migration Notes

If you previously ran the application with the systemd approach:

1. The system Docker service may still be running - you can stop it if desired:

   ```bash
   sudo systemctl stop docker
   ```

2. System Docker data remains at `/var/lib/docker` - this is separate from our isolated daemon

3. The application now creates its own Docker environment at:
   - `/var/lib/mobius-docker`
   - `/var/run/mobius-docker`

4. Any containers/images created previously won't be visible to the new isolated daemon (they're in different data roots)
