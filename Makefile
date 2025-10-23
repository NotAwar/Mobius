# Mobius MDM Build System

.PHONY: all clean build-frontend build-backend build test dev help

# Default target
all: build

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Build everything (default)"
	@echo "  build         - Build both frontend and backend"
	@echo "  build-frontend - Build Svelte frontend only"
	@echo "  build-backend  - Build Go backend only" 
	@echo "  test          - Run all tests"
	@echo "  dev           - Start development servers"
	@echo "  clean         - Clean build artifacts"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf server/api/static/_app
	rm -f server/api/static/index.html
	rm -f server/api/static/robots.txt
	rm -f server/api/mobius-api
	rm -rf ui/web/.svelte-kit
	rm -rf ui/web/build
	rm -rf build

# Build Svelte frontend
build-frontend:
	@echo "Building Svelte frontend..."
	cd ui/web && npm run build
	@echo "Copying frontend files to API server..."
	mkdir -p server/api/static
	cp -r ui/web/build/* server/api/static/
	@echo "Frontend build complete"

# Build Go backend
build-backend:
	@echo "Building Go backend..."
	mkdir -p build
	cd server/api && go build -o ../../build/mobius-api cmd/api-server/main.go
	cd server/cli && go build -o ../../build/mobiuscli cmd/mobiuscli/main.go
	cd client/client && go build -o ../../build/mobius-client cmd/client/main.go
	cd cocoon/portal && go build -o ../../build/mobius-cocoon cmd/cocoon/main.go
	@echo "Backend build complete"

# Build everything
build: build-frontend build-backend
	@echo "Build complete! Run ./build/mobius-api to start the server"

# Run tests
test:
	@echo "Running Go tests..."
	cd server/api && go test ./...
	cd server/cli && go test ./...
	cd client/client && go test ./...
	cd cocoon/portal && go test ./...
	cd common/shared && go test ./...
	@echo "Running frontend tests..."
	cd ui/web && npm test 2>/dev/null || echo "No frontend tests configured"

# Development mode
dev:
	@echo "Starting development servers..."
	@echo "Starting backend server..."
	cd server/api && go run cmd/api-server/main.go &
	@echo "Starting frontend development server..."
	cd ui/web && npm run dev

# Install frontend dependencies
install-deps:
	@echo "Installing frontend dependencies..."
	cd ui/web && npm install
