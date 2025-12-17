#!/usr/bin/env bash
# Test script for Mobius API endpoints

API_BASE="http://localhost:3000"

echo "=== Testing Mobius API ==="
echo ""

# Test health endpoint
echo "1. Testing health endpoint..."
curl -s "$API_BASE/api/v1/health" | jq '.' 2>/dev/null || echo "  ❌ Health endpoint failed"
echo ""

# Test cluster status
echo "2. Testing cluster status..."
curl -s "$API_BASE/api/v1/status/cluster" | jq '.' 2>/dev/null || echo "  ❌ Cluster status failed"
echo ""

# Test postgres status
echo "3. Testing PostgreSQL status..."
curl -s "$API_BASE/api/v1/status/postgres" | jq '.' 2>/dev/null || echo "  ❌ Postgres status failed"
echo ""

# Test headscale status
echo "4. Testing Headscale status..."
curl -s "$API_BASE/api/v1/status/headscale" | jq '.' 2>/dev/null || echo "  ❌ Headscale status failed"
echo ""

# Test cluster nodes
echo "5. Testing cluster nodes..."
curl -s "$API_BASE/api/v1/cluster/nodes" | jq '.' 2>/dev/null || echo "  ❌ Cluster nodes failed"
echo ""

# Test cluster pods
echo "6. Testing cluster pods..."
curl -s "$API_BASE/api/v1/cluster/pods" | jq '.' 2>/dev/null || echo "  ❌ Cluster pods failed"
echo ""

echo "=== API Test Complete ==="
