#!/bin/bash

# Script to update import paths from backend/ to root level

echo "Updating pkg import paths..."

# Update backend/pkg to just pkg
find /Users/awar/Documents/Mobius/backend -name "*.go" -type f -exec sed -i '' 's|github.com/notawar/mobius/backend/pkg|github.com/notawar/mobius/pkg|g' {} \;

echo "Pkg import paths updated successfully"
