#!/bin/bash
# Version Update Helper Script for Mobius
# This script helps maintain version consistency across all Mobius components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Check if version is provided
if [ -z "$1" ]; then
    print_error "Usage: $0 <version>"
    print_error "Example: $0 1.2.0"
    exit 1
fi

NEW_VERSION="$1"

# Validate version format (semantic versioning)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    print_error "Version must follow semantic versioning format (e.g., 1.2.0)"
    exit 1
fi

print_header "Mobius Version Update Tool"
print_status "Updating to version: $NEW_VERSION"

# Files to update
declare -a VERSION_FILES=(
    "package.json"
    "tools/mobiuscli-npm/package.json"
    "charts/mobius/values.yaml"
    "charts/mobius/Chart.yaml"
    "infrastructure/dogfood/terraform/aws/variables.tf"
    "infrastructure/dogfood/terraform/gcp/variables.tf"
)

print_header "Updating Version Files"

for file in "${VERSION_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_status "Updating $file"
        case "$file" in
            *.json)
                # Update JSON files
                if command -v jq >/dev/null 2>&1; then
                    jq ".version = \"$NEW_VERSION\"" "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
                else
                    sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" "$file"
                    rm -f "${file}.bak"
                fi
                ;;
            *.yaml|*.yml)
                # Update YAML files
                if [[ "$file" == *"values.yaml"* ]]; then
                    sed -i.bak "s/imageTag: v[0-9]\+\.[0-9]\+\.[0-9]\+/imageTag: v$NEW_VERSION/" "$file"
                elif [[ "$file" == *"Chart.yaml"* ]]; then
                    sed -i.bak "s/appVersion: v[0-9]\+\.[0-9]\+\.[0-9]\+/appVersion: v$NEW_VERSION/" "$file"
                fi
                rm -f "${file}.bak"
                ;;
            *.tf)
                # Update Terraform files
                sed -i.bak "s/mobiusmdm\/mobius:v[0-9]\+\.[0-9]\+\.[0-9]\+/mobiusmdm\/mobius:v$NEW_VERSION/" "$file"
                rm -f "${file}.bak"
                ;;
        esac
    else
        print_warning "File not found: $file"
    fi
done

print_header "Validation"

# Validate updates
print_status "Validating version updates..."

for file in "${VERSION_FILES[@]}"; do
    if [ -f "$file" ]; then
        if grep -q "$NEW_VERSION" "$file"; then
            print_status "✓ $file updated successfully"
        else
            print_warning "✗ $file may not have been updated correctly"
        fi
    fi
done

print_header "Next Steps"
print_status "Version files have been updated to $NEW_VERSION"
print_status ""
print_status "Recommended next steps:"
print_status "1. Review the changes: git diff"
print_status "2. Run tests: make test"
print_status "3. Update CHANGELOG.md with release notes"
print_status "4. Commit changes: git add . && git commit -m \"chore: bump version to $NEW_VERSION\""
print_status "5. Create release: git tag v$NEW_VERSION && git push origin v$NEW_VERSION"
print_status ""
print_status "For creating release candidates:"
print_status "git checkout -b rc-minor-mobius-v$NEW_VERSION"

print_header "Version Update Complete"
print_status "Mobius version updated to $NEW_VERSION successfully!"
