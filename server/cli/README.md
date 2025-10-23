# Mobius CLI

The Mobius command-line interface for interacting with Mobius servers and managing configurations.

## Features

- **Server Management**: Connect to and manage Mobius servers
- **Configuration**: Apply policies, queries, and teams via YAML
- **GitOps Support**: Version-controlled device management
- **Scripts**: Execute scripts on managed devices
- **Data Export**: Extract and analyze device data

## Building

```bash
# Build the CLI
go build -o ../build/mobiuscli ./cmd/mobiuscli

# Use the CLI
../build/mobiuscli --help
```

## Commands

Key mobiuscli commands include:

- `login` - Authenticate with a Mobius server
- `apply` - Apply configuration from YAML files
- `get` - Retrieve information from the server
- `generate` - Generate configuration templates
- `query` - Execute ad-hoc queries

## Dependencies

- `../shared` - Shared libraries with mobius-server
- External dependencies as defined in go.mod
