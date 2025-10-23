# Shared Libraries

Common utilities and libraries shared between Mobius server and CLI.

## Packages

### Core Utilities

- `pkg/certificate/` - X.509 certificate handling
- `pkg/file/` - File system operations
- `pkg/open/` - Cross-platform file/URL opening
- `pkg/secure/` - Cryptographic utilities

### Network & HTTP

- `pkg/mobiushttp/` - HTTP client for Mobius APIs  
- `pkg/download/` - File downloading with progress

### System Integration

- `pkg/scripts/` - Cross-platform script execution
- `pkg/optjson/` - Optional JSON handling
- `pkg/rawjson/` - Raw JSON processing

### Build Tools

- `pkg/buildpkg/` - Package building utilities

## Design

These packages are designed to be:

- **Platform-agnostic**: Work across Windows, macOS, and Linux
- **Reusable**: Can be imported by both server and CLI
- **Well-tested**: Include comprehensive test coverage
- **Minimal dependencies**: Avoid heavy external dependencies

## Usage

Import packages using the shared module:

```go
import (
    "github.com/notawar/mobius/shared/pkg/certificate"
    "github.com/notawar/mobius/shared/pkg/mobiushttp"
)
```
