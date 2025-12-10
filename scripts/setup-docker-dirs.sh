#!/bin/bash

# Setup directories for Mobius Docker daemon
# This script is OPTIONAL - Mobius server handles this automatically
# Use this only if you want to pre-create directories with specific permissions

set -e

echo "Setting up directories for Mobius Docker daemon..."
echo "Note: The Mobius server does this automatically, so this script is optional."
echo ""

# Create directories
sudo mkdir -p /var/lib/mobius-docker
sudo mkdir -p /var/run/mobius-docker

# Set permissions (adjust based on your user)
sudo chown -R $USER:$USER /var/lib/mobius-docker
sudo chown -R $USER:$USER /var/run/mobius-docker
sudo chmod 755 /var/lib/mobius-docker
sudo chmod 755 /var/run/mobius-docker

echo "✓ Directories created successfully:"
echo "  - /var/lib/mobius-docker (data directory)"
echo "  - /var/run/mobius-docker (runtime directory)"
echo ""
echo "✓ Permissions set for user: $USER"
echo ""
echo "You can now run: go run cmd/server/server.go"
