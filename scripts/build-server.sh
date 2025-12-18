#!/bin/bash
set -e

# Mobius Server Build Script
# Builds server binary

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

DIST_DIR="dist/server"
SOURCE_DIR="cmd/server"

echo "================================================"
echo "  Building Mobius Server"
echo "================================================"
echo "Version:     $VERSION"
echo "Git Commit:  $GIT_COMMIT"
echo "Build Time:  $BUILD_TIME"
echo "================================================"
echo ""

# Create dist directory
mkdir -p "$DIST_DIR"

# Build flags
LDFLAGS="-w -s \
  -X 'main.Version=$VERSION' \
  -X 'main.GitCommit=$GIT_COMMIT' \
  -X 'main.BuildTime=$BUILD_TIME'"

# Build server binary (Linux only for deployment)
echo "→ Building server binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="$LDFLAGS" \
  -o "$DIST_DIR/mobius-server" \
  "./$SOURCE_DIR"
echo "  ✓ $DIST_DIR/mobius-server"

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""

# Show file size
if command -v ls &> /dev/null; then
  echo "Binary size:"
  ls -lh "$DIST_DIR/mobius-server"
fi

echo ""
echo "Server binary available at: $DIST_DIR/mobius-server"
echo ""
echo "✅ Server build complete!"
echo ""
