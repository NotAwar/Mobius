# Mobius Client Service Documentation

## Overview

The Mobius client is a lightweight, kernel-level service that runs on managed devices. It provides:

- **Client enrollment and onboarding**
- **Automated check-ins with the server**
- **OSQuery integration for system queries**
- **Event reporting to the server**
- **SSH-based remote management**
- **System information collection**

## Design Principles

### 1. **Lightweight & Efficient**

- Maximum 50MB memory usage
- Maximum 5% CPU usage
- Minimal disk I/O
- Efficient network communication

### 2. **Secure by Default**

- TLS encryption for all communication
- Certificate verification
- Authenticated requests (client ID + key)
- SSH for secure remote access

### 3. **Resilient**

- Automatic reconnection on network failures
- Graceful degradation
- Health monitoring
- Resource limit enforcement

### 4. **Observable**

- Structured logging (JSON)
- Health status reporting
- Performance metrics

## Architecture

```
┌─────────────────────────────────────────┐
│         Mobius Client Service           │
├─────────────────────────────────────────┤
│  ┌────────────┐  ┌──────────────────┐  │
│  │  Reporter  │  │  System Info     │  │
│  │            │  │  Collector       │  │
│  └────────────┘  └──────────────────┘  │
│                                          │
│  ┌────────────┐  ┌──────────────────┐  │
│  │  OSQuery   │  │  SSH Manager     │  │
│  │  Manager   │  │                  │  │
│  └────────────┘  └──────────────────┘  │
│                                          │
│  ┌────────────┐  ┌──────────────────┐  │
│  │  Health    │  │  Config Manager  │  │
│  │  Monitor   │  │                  │  │
│  └────────────┘  └──────────────────┘  │
└─────────────────────────────────────────┘
           │                  │
           │                  │
           ▼                  ▼
    ┌──────────┐      ┌─────────────┐
    │  Server  │      │   OSQuery   │
    │   API    │      │   Daemon    │
    └──────────┘      └─────────────┘
```

## Components

### 1. Service (`service.go`)

Main service coordinator:

- Manages all sub-components
- Handles lifecycle (start/stop)
- Coordinates check-ins
- Monitors resource usage
- Enforces resource limits

### 2. Reporter (`reporter.go`)

Handles server communication:

- Check-in requests
- Hardware info reporting
- OSQuery results submission
- Event reporting
- Configuration fetching

### 3. OSQuery Manager (`osquery.go`)

Manages OSQuery integration:

- Executes scheduled queries
- Collects results
- Handles custom queries from server
- Monitors OSQuery daemon

### 4. System Info Collector (`sysinfo.go`)

Collects system information:

- Basic info (OS, CPU, memory, disk)
- Detailed hardware inventory
- Network interfaces
- Performance metrics

### 5. SSH Manager (`ssh.go`)

Provides secure remote access:

- SSH server on custom port (default: 2222)
- Command execution
- Interactive shell sessions
- Authorized key validation

### 6. Health Monitor (`health.go`)

Monitors client health:

- Resource usage tracking
- Service status
- Health status reporting
- Automatic degradation detection

### 7. Config Manager (`config.go`)

Manages configuration:

- YAML-based configuration
- Default values
- Validation
- Dynamic reloading

### 8. Enrollment (`enroll.go`)

Handles client onboarding:

- Initial enrollment with server
- Client ID/key generation
- Configuration creation
- Certificate exchange

## Installation

### Prerequisites

- Go 1.21 or higher
- OSQuery installed (optional, for full functionality)
- Root/admin access (for system-level operations)

### Building

```bash
# Build for current platform
go build -o mobius-client ./cmd/client

# Build for Linux (from macOS)
GOOS=linux GOARCH=amd64 go build -o mobius-client-linux ./cmd/client

# Build for Windows (from macOS)
GOOS=windows GOARCH=amd64 go build -o mobius-client.exe ./cmd/client

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o mobius-client-macos ./cmd/client
```

### Installation Steps

#### Linux (systemd)

1. **Build and install binary:**

```bash
sudo cp mobius-client /usr/local/bin/
sudo chmod +x /usr/local/bin/mobius-client
```

2. **Create directories:**

```bash
sudo mkdir -p /etc/mobius
sudo mkdir -p /var/log/mobius
```

3. **Enroll client:**

```bash
sudo mobius-client \
  --server https://mobius.example.com \
  --enroll-key YOUR_ENROLLMENT_KEY \
  --config /etc/mobius/client.yaml
```

4. **Create systemd service:**

```bash
sudo tee /etc/systemd/system/mobius-client.service > /dev/null <<EOF
[Unit]
Description=Mobius Client Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mobius-client --config /etc/mobius/client.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
MemoryMax=100M
CPUQuota=10%

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/mobius /var/log/mobius

[Install]
WantedBy=multi-user.target
EOF
```

5. **Start service:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable mobius-client
sudo systemctl start mobius-client
sudo systemctl status mobius-client
```

#### macOS (launchd)

1. **Build and install binary:**

```bash
sudo cp mobius-client /usr/local/bin/
sudo chmod +x /usr/local/bin/mobius-client
```

2. **Create directories:**

```bash
sudo mkdir -p /etc/mobius
sudo mkdir -p /var/log/mobius
```

3. **Enroll client:**

```bash
sudo mobius-client \
  --server https://mobius.example.com \
  --enroll-key YOUR_ENROLLMENT_KEY \
  --config /etc/mobius/client.yaml
```

4. **Create launchd plist:**

```bash
sudo tee /Library/LaunchDaemons/com.mobius.client.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mobius.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/mobius-client</string>
        <string>--config</string>
        <string>/etc/mobius/client.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/mobius/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/mobius/stderr.log</string>
</dict>
</plist>
EOF
```

5. **Start service:**

```bash
sudo launchctl load /Library/LaunchDaemons/com.mobius.client.plist
sudo launchctl start com.mobius.client
```

#### Windows (NSSM or sc)

1. **Install binary:**

```cmd
mkdir C:\Program Files\Mobius
copy mobius-client.exe "C:\Program Files\Mobius\"
```

2. **Create directories:**

```cmd
mkdir C:\ProgramData\Mobius
mkdir C:\ProgramData\Mobius\logs
```

3. **Enroll client:**

```cmd
"C:\Program Files\Mobius\mobius-client.exe" ^
  --server https://mobius.example.com ^
  --enroll-key YOUR_ENROLLMENT_KEY ^
  --config C:\ProgramData\Mobius\client.yaml
```

4. **Install as Windows service (using sc):**

```cmd
sc create MobiusClient binPath= "C:\Program Files\Mobius\mobius-client.exe --config C:\ProgramData\Mobius\client.yaml" start= auto
sc description MobiusClient "Mobius Device Management Client"
sc start MobiusClient
```

## Usage

### Enrollment

Enroll a new client with the server:

```bash
mobius-client \
  --server https://mobius.example.com \
  --enroll-key <ENROLLMENT_KEY>
```

The enrollment key is generated by the server administrator.

### Running the Service

After enrollment, start the service:

```bash
mobius-client --config /etc/mobius/client.yaml
```

### Command-Line Options

```
--config <path>       Configuration file path (default: /etc/mobius/client.yaml)
--server <url>        Server URL for enrollment
--enroll-key <key>    Enrollment key
--debug               Enable debug logging
--version             Show version and exit
```

### Configuration

Example configuration (`/etc/mobius/client.yaml`):

```yaml
server_url: "https://mobius.example.com"
client_id: "generated-during-enrollment"
client_key: "generated-during-enrollment"

check_in_interval: 5m
heartbeat_timeout: 30s

enable_osquery: true
osquery_socket: "/var/osquery/osquery.sock"
osquery_interval: 60s

enable_ssh: true
ssh_port: 2222

tls_verify: true
log_level: "info"
log_format: "json"

max_memory_mb: 50
max_cpu_pct: 5
```

## Server-Side Management

### Remote Command Execution

Execute commands on clients via SSH:

```bash
ssh -p 2222 admin@client-ip "osqueryi 'SELECT * FROM processes;'"
```

### Query Execution

The server can push OSQuery queries to clients through the API:

```bash
POST /api/v1/osquery/queries/:id/execute
{
  "client_ids": ["client-id-1", "client-id-2"],
  "query": "SELECT * FROM system_info;"
}
```

### Configuration Updates

Update client configuration remotely:

```bash
PUT /api/v1/clients/:id/configuration
{
  "check_in_interval": "10m",
  "osquery_interval": "120s"
}
```

## Monitoring

### Check Client Status

```bash
GET /api/v1/clients/:id
```

Returns:

```json
{
  "id": "client-id",
  "hostname": "web-server-01",
  "status": "online",
  "last_seen": "2025-12-18T10:30:00Z",
  "health_status": {
    "status": "healthy",
    "cpu_usage_percent": 2.5,
    "memory_usage_mb": 45,
    "memory_limit_mb": 50
  }
}
```

### View Check-In History

```bash
GET /api/v1/clients/:id/check-ins?limit=10
```

### View OSQuery Results

```bash
GET /api/v1/osquery/results?client_id=:id&limit=50
```

## Troubleshooting

### Client Not Checking In

1. Check service status:

```bash
systemctl status mobius-client  # Linux
launchctl list | grep mobius    # macOS
sc query MobiusClient           # Windows
```

2. Check logs:

```bash
tail -f /var/log/mobius/client.log
journalctl -u mobius-client -f  # Linux
```

3. Verify network connectivity:

```bash
curl https://mobius.example.com/api/v1/health
```

### High Resource Usage

If client exceeds resource limits:

- Check `max_memory_mb` and `max_cpu_pct` settings
- Review OSQuery query frequency
- Disable unnecessary features

### OSQuery Not Working

1. Verify OSQuery installation:

```bash
osqueryi --version
```

2. Check OSQuery socket:

```bash
ls -l /var/osquery/osquery.sock
```

3. Test query manually:

```bash
osqueryi "SELECT * FROM system_info;"
```

## Security Considerations

### Network Security

- Always use TLS (HTTPS) for server communication
- Verify server certificates
- Use firewall rules to restrict SSH access

### Authentication

- Client credentials (ID + key) are generated during enrollment
- Store credentials securely (file permissions 0600)
- Rotate keys periodically

### SSH Access

- Use SSH key authentication (not passwords)
- Restrict authorized keys
- Use custom port (not 22)
- Monitor SSH access logs

### Resource Limits

- Enforce memory and CPU limits
- Monitor resource usage
- Alert on limit violations

## Performance

### Typical Resource Usage

- Memory: 20-30 MB (idle)
- CPU: 1-2% (average)
- Network: ~1 KB/min (check-ins)
- Disk: Minimal (logs only)

### Scaling

- Supports 10,000+ clients per server
- Check-in intervals can be adjusted
- Query execution is asynchronous
- Results are batched for efficiency

## Development

### Building from Source

```bash
git clone https://github.com/MobiusDM/Mobius.git
cd Mobius
go build -o mobius-client ./cmd/client
```

### Running Tests

```bash
go test ./internal/client/...
```

### Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](../LICENSE) for details.
