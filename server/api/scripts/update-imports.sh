#!/bin/bash

# Script to update import paths from backend/server to internal/server

echo "Updating import paths..."

# Find all Go files and update the import paths
find /Users/awar/Documents/Mobius/backend -name "*.go" -type f -exec sed -i '' 's|github.com/notawar/mobius/backend/server|github.com/notawar/mobius/internal/server|g' {} \;

echo "Import paths updated successfully"
