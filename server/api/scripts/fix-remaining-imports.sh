#!/bin/bash

echo "Fixing remaining import paths..."

# Fix goose imports
find /Users/awar/Documents/Mobius/backend -name "*.go" -type f -exec sed -i '' 's|github.com/notawar/mobius/server/goose|github.com/notawar/mobius/internal/server/goose|g' {} \;

echo "Fixed goose imports"

# Check for legacy agent references that need to be removed or made external
echo "Legacy agent references found (these may need manual review):"
grep -r "backend/orbit" /Users/awar/Documents/Mobius/backend || echo "No legacy agent references found"
