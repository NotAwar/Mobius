# Standalone Tools

This document describes the standalone Go tools in `server/api/tools/` that
have their own `go.mod` files and are **not** part of the main Go workspace.

These tools are maintained separately to:

- Avoid dependency conflicts with the main platform
- Allow independent development and testing
- Provide specialized utilities that may use different Go versions or libraries

## Tools Overview

### 1. Snapshot Tool

**Location:** `server/api/tools/snapshot/`

**Purpose:** Interactive tool for creating and managing database snapshots for
testing and development.

**Module:** `github.com/notawar/mobius/v4/tools/snapshot`

**Key Dependencies:**

- `github.com/manifoldco/promptui` - Interactive CLI prompts
- `golang.org/x/sys` - System utilities

**Usage:**

```bash
cd server/api/tools/snapshot
go run snapshot.go
```

**When to use:**

- Creating test database snapshots
- Capturing database state for debugging
- Setting up test fixtures

---

### 2. BitLocker Tool

**Location:** `server/api/tools/mdm/windows/bitlocker/`

**Purpose:** Windows BitLocker encryption management utilities for MDM.

**Module:** `bitlocker`

**Key Dependencies:**

- `github.com/go-ole/go-ole` - COM/OLE automation
- `github.com/iamacarpet/go-win64api` - Windows API access
- `github.com/google/deck` - Windows management

**Usage:**

```bash
cd server/api/tools/mdm/windows/bitlocker
go build
./bitlocker [options]
```

**When to use:**

- Managing BitLocker encryption on Windows devices
- Retrieving encryption keys
- Enforcing encryption policies via MDM

**Platform:** Windows only

---

### 3. Windows MDM POC Server

**Location:** `server/api/tools/mdm/windows/poc-mdm-server/`

**Purpose:** Proof-of-concept implementation of Windows MDM enrollment and
management protocols for testing and development.

**Module:** `github.com/oscartbeaumont/windows_mdm`

**Key Dependencies:**

- `github.com/go-xmlfmt/xmlfmt` - XML formatting
- `github.com/gorilla/mux` - HTTP routing

**Protocols Implemented:**

- MS-MDE (enrollment)
- MS-MDM (management)
- MS-WSTEP (certificate enrollment)
- MS-XCEP (certificate enrollment)
- OMA Device Management Protocol

**Usage:**

```bash
cd server/api/tools/mdm/windows/poc-mdm-server
go run main.go
```

**When to use:**

- Testing Windows MDM enrollment flows
- Developing Windows MDM features
- Understanding Windows MDM protocols
- Integration testing

**Documentation:** See `README.md` in the tool directory for detailed setup
and usage instructions.

---

## Why Standalone?

These tools are **not** in `go.work` because:

1. **Dependency Isolation**: They use specific versions of libraries that may
   conflict with the main platform dependencies.

2. **Platform-Specific**: Some tools (BitLocker, POC server) are
   Windows-specific and may not be relevant for all developers.

3. **Development Independence**: They can be developed, tested, and versioned
   independently from the main platform.

4. **Build Flexibility**: They can use different Go versions or build flags
   without affecting the main platform build.

## Building

Each tool can be built independently:

```bash
# Snapshot tool
cd server/api/tools/snapshot
go mod download
go build -o snapshot snapshot.go

# BitLocker tool (Windows only)
cd server/api/tools/mdm/windows/bitlocker
go mod download
go build

# Windows MDM POC Server
cd server/api/tools/mdm/windows/poc-mdm-server
go mod download
go build
```

## Maintenance

When updating these tools:

1. **Update Go Version**: Each tool specifies `go 1.25.3` - keep synchronized
   with the main platform when possible.

2. **Update Dependencies**: Run `go mod tidy` in each tool directory after
   dependency changes.

3. **Test Independently**: Build and test each tool separately from the main
   platform.

4. **Document Changes**: Update this file and individual tool READMEs when
   adding new tools or changing existing ones.

## Adding New Standalone Tools

To add a new standalone tool:

1. Create a new directory under appropriate location (e.g.,
   `server/api/tools/your-tool/`)

2. Initialize with `go mod init`:

   ```bash
   cd server/api/tools/your-tool
   go mod init github.com/notawar/mobius/tools/your-tool
   ```

3. Add a README.md explaining the tool's purpose

4. Update this document with the new tool information

5. **Do not** add to `go.work` unless it needs to be part of the main
   workspace

## See Also

- [Main Platform Documentation](../../../../README.md)
- [MDM Tools Overview](../mdm/README.md)
- [Windows MDM POC Server](../mdm/windows/poc-mdm-server/README.md)
