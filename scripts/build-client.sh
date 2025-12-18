#!/bin/bash
set -e

# Mobius Client Build Script
# Builds client binaries for multiple platforms

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

DIST_DIR="dist/client"
SOURCE_DIR="cmd/client"

echo "================================================"
echo "  Building Mobius Client"
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

# Build for Linux AMD64
echo "→ Building for Linux AMD64..."
GOOS=linux GOARCH=amd64 go build \
  -ldflags="$LDFLAGS" \
  -o "$DIST_DIR/mobius-client-linux-amd64" \
  "./$SOURCE_DIR"
echo "  ✓ $DIST_DIR/mobius-client-linux-amd64"

# Build for Linux ARM64
echo "→ Building for Linux ARM64..."
GOOS=linux GOARCH=arm64 go build \
  -ldflags="$LDFLAGS" \
  -o "$DIST_DIR/mobius-client-linux-arm64" \
  "./$SOURCE_DIR"
echo "  ✓ $DIST_DIR/mobius-client-linux-arm64"

# Build for macOS AMD64
echo "→ Building for macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build \
  -ldflags="$LDFLAGS" \
  -o "$DIST_DIR/mobius-client-darwin-amd64" \
  "./$SOURCE_DIR"
echo "  ✓ $DIST_DIR/mobius-client-darwin-amd64"

# Build for macOS ARM64 (Apple Silicon)
echo "→ Building for macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build \
  -ldflags="$LDFLAGS" \
  -o "$DIST_DIR/mobius-client-darwin-arm64" \
  "./$SOURCE_DIR"
echo "  ✓ $DIST_DIR/mobius-client-darwin-arm64"

# Build for Windows AMD64
echo "→ Building for Windows AMD64..."
GOOS=windows GOARCH=amd64 go build \
  -ldflags="$LDFLAGS" \
  -o "$DIST_DIR/mobius-client-windows-amd64.exe" \
  "./$SOURCE_DIR"
echo "  ✓ $DIST_DIR/mobius-client-windows-amd64.exe"

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""

# Show file sizes
if command -v ls &> /dev/null; then
  echo "Binary sizes:"
  ls -lh "$DIST_DIR"
fi

echo ""
echo "Binaries available in: $DIST_DIR"
echo ""

# Create archives
if command -v tar &> /dev/null && command -v gzip &> /dev/null; then
  echo "Creating release archives..."
  cd "$DIST_DIR"
  
  tar czf "mobius-client-${VERSION}-linux-amd64.tar.gz" mobius-client-linux-amd64
  echo "  ✓ mobius-client-${VERSION}-linux-amd64.tar.gz"
  
  tar czf "mobius-client-${VERSION}-linux-arm64.tar.gz" mobius-client-linux-arm64
  echo "  ✓ mobius-client-${VERSION}-linux-arm64.tar.gz"
  
  tar czf "mobius-client-${VERSION}-darwin-amd64.tar.gz" mobius-client-darwin-amd64
  echo "  ✓ mobius-client-${VERSION}-darwin-amd64.tar.gz"
  
  tar czf "mobius-client-${VERSION}-darwin-arm64.tar.gz" mobius-client-darwin-arm64
  echo "  ✓ mobius-client-${VERSION}-darwin-arm64.tar.gz"
  
  if command -v zip &> /dev/null; then
    zip -q "mobius-client-${VERSION}-windows-amd64.zip" mobius-client-windows-amd64.exe
    echo "  ✓ mobius-client-${VERSION}-windows-amd64.zip"
  fi
  
  cd - > /dev/null
  echo ""
fi

# Generate checksums
if command -v sha256sum &> /dev/null; then
  echo "Generating checksums..."
  cd "$DIST_DIR"
  sha256sum mobius-client-* > checksums.txt 2>/dev/null || true
  echo "  ✓ checksums.txt"
  cd - > /dev/null
elif command -v shasum &> /dev/null; then
  echo "Generating checksums..."
  cd "$DIST_DIR"
  shasum -a 256 mobius-client-* > checksums.txt 2>/dev/null || true
  echo "  ✓ checksums.txt"
  cd - > /dev/null
fi

echo ""
echo "✅ Client build complete!"
echo ""
