# Mobius Client (Load Testing Tool)

This is a **load testing client** that simulates multiple device connections to a Mobius server for performance testing and validation.

## Purpose

The Mobius Client is **not a real device agent** - it's a testing tool that:

- Simulates multiple osquery agents connecting to the server
- Tests enrollment and configuration endpoints
- Validates server performance under load
- Provides realistic client behavior patterns

## Real Device Management

In a production Mobius deployment, device management happens through:

- **osquery agents** installed on devices that connect to the Mobius server
- **Native MDM protocols** for Apple and Microsoft device management
- **Standard OS tools** - no custom agent is required

## Usage

```bash
# Build the client
go build ./cmd/client

# Run load test with 100 simulated devices
./client -server_url https://your-mobius-server.com -enroll_secret your_secret -host_count 100

# Run with custom intervals
./client -server_url https://localhost:8080 -enroll_secret test123 -host_count 50 -interval 30s
```

## Options

- `-server_url`: URL of the Mobius server to test
- `-enroll_secret`: Enrollment secret from the server
- `-host_count`: Number of simulated devices (default: 10)
- `-interval`: Interval between configuration requests (default: 1m)

## How It Works

1. Creates multiple goroutines, each representing a simulated device
2. Each device enrolls with the server using the provided secret
3. Devices continuously request configuration updates at the specified interval
4. Provides logging of enrollment status and request success/failure

This tool is essential for:
- Performance testing before production deployment
- Validating server capacity and response times
- Testing enrollment and configuration distribution at scale
