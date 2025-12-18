# Mobius Build System

.PHONY: all clean build-client build-server build docker-server test lint help

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Directories
DIST_DIR := dist
CLIENT_DIR := $(DIST_DIR)/client
SERVER_DIR := $(DIST_DIR)/server

# Default target
all: build

# Help target
help:
	@echo "Mobius Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build everything (client + server)"
	@echo "  build          - Build everything (client + server)"
	@echo "  build-client   - Build client binaries for all platforms"
	@echo "  build-server   - Build server binary"
	@echo "  docker-server  - Build server Docker image"
	@echo "  clean          - Remove build artifacts"
	@echo "  test           - Run tests"
	@echo "  lint           - Run linters"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION        - Build version (default: git describe)"
	@echo "  GIT_COMMIT     - Git commit hash (default: git rev-parse)"
	@echo "  BUILD_TIME     - Build timestamp (default: current time)"
	@echo ""

# Build everything
build: build-client build-server
	@echo "✅ All builds complete!"

# Build client binaries
build-client:
	@echo "Building client binaries..."
	@chmod +x scripts/build-client.sh
	@VERSION=$(VERSION) GIT_COMMIT=$(GIT_COMMIT) BUILD_TIME=$(BUILD_TIME) \
		./scripts/build-client.sh

# Build server binary
build-server:
	@echo "Building server binary..."
	@chmod +x scripts/build-server.sh
	@VERSION=$(VERSION) GIT_COMMIT=$(GIT_COMMIT) BUILD_TIME=$(BUILD_TIME) \
		./scripts/build-server.sh

# Build Docker image for server
docker-server: build-server
	@echo "Building Docker image..."
	docker build -t mobius-server:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-f Dockerfile.server .
	@echo "✅ Docker image built: mobius-server:$(VERSION)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(DIST_DIR)
	@echo "✅ Clean complete!"

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@echo "✅ Tests complete!"

# Run linters
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed, skipping..."; \
		echo "   Install: https://golangci-lint.run/usage/install/"; \
	fi
	@echo "✅ Lint complete!"

# Go mod tidy
tidy:
	@echo "Running go mod tidy..."
	@go mod tidy
	@echo "✅ go mod tidy complete!"

# Install client locally (for testing)
install-client: build-client
	@echo "Installing client locally..."
	@if [ "$(shell uname -s)" = "Darwin" ]; then \
		if [ "$(shell uname -m)" = "arm64" ]; then \
			sudo cp $(CLIENT_DIR)/mobius-client-darwin-arm64 /usr/local/bin/mobius-client; \
		else \
			sudo cp $(CLIENT_DIR)/mobius-client-darwin-amd64 /usr/local/bin/mobius-client; \
		fi \
	elif [ "$(shell uname -s)" = "Linux" ]; then \
		if [ "$(shell uname -m)" = "aarch64" ]; then \
			sudo cp $(CLIENT_DIR)/mobius-client-linux-arm64 /usr/local/bin/mobius-client; \
		else \
			sudo cp $(CLIENT_DIR)/mobius-client-linux-amd64 /usr/local/bin/mobius-client; \
		fi \
	else \
		echo "❌ Unsupported platform for auto-install"; \
		exit 1; \
	fi
	@sudo chmod +x /usr/local/bin/mobius-client
	@echo "✅ Client installed to /usr/local/bin/mobius-client"

# Uninstall client
uninstall-client:
	@echo "Uninstalling client..."
	@sudo rm -f /usr/local/bin/mobius-client
	@echo "✅ Client uninstalled"

# Development server (run locally)
dev-server:
	@echo "Starting development server..."
	@go run cmd/server/main.go

# Development client (run locally)
dev-client:
	@echo "Starting development client..."
	@go run cmd/client/main.go --config=dev-config.yaml

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✅ Format complete!"

# Vet code
vet:
	@echo "Vetting code..."
	@go vet ./...
	@echo "✅ Vet complete!"

# Check everything before commit
pre-commit: fmt vet lint test
	@echo "✅ Pre-commit checks passed!"

# Show version info
version:
	@echo "Version:    $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
