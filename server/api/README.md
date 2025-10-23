# Mobius Server

The Mobius server is the core backend that provides device management,
osquery orchestration, and MDM functionality.

## Components

- **Core Server**: HTTP/HTTPS server with REST API endpoints
- **MDM Support**: Apple, Microsoft, and Android device management
- **osquery Integration**: Query orchestration and result processing
- **Vulnerability Management**: Security scanning and compliance
- **Background Jobs**: Cron scheduling and async processing

## Building

```bash
# Build the server
go build -o ../build/mobius ./cmd/mobius

# Run the server
../build/mobius serve
```

## Architecture

The server is organized into:

- `cmd/mobius/` - Main application entry point
- `server/` - Core server implementation (HTTP handlers, services, middleware)
- `api/` - API schema definitions
- `tools/` - Server-specific utilities

## Dependencies

- `../shared` - Shared libraries with mobius-cli
- External dependencies as defined in go.mod

## Licensing endpoints

- GET /api/_version_/mobius/license/status — returns license info.
- PUT /api/_version_/mobius/license — admin-only; OSS builds return config guidance.

### CLI usage

You can view license status using the CLI:

- mobiuscli license status (use --json for JSON output; default is YAML)
