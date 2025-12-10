#!/bin/bash

# Simple Workflow Verification Test
echo "🔧 GitHub Workflows Verification Test"
echo "======================================"

# Test 1: Check key workflow files exist
echo -e "\n📁 Checking workflow files..."
WORKFLOWS=(
    ".github/workflows/golangci-lint.yml"
    ".github/workflows/unit-tests.yml" 
    ".github/workflows/build-and-deploy.yml"
    ".github/workflows/trivy-scan.yml"
    ".github/workflows/dependency-review.yml"
)

for workflow in "${WORKFLOWS[@]}"; do
    if [ -f "$workflow" ]; then
        echo "✅ $workflow exists"
    else
        echo "❌ $workflow missing"
    fi
done

# Test 2: Check builds work
echo -e "\n🔨 Testing builds..."
if (cd mobius-server && go build ./cmd/api-server >/dev/null 2>&1); then
    echo "✅ mobius-server builds successfully"
else
    echo "❌ mobius-server build failed"
fi

if (cd mobius-cli && go build ./cmd/mobiuscli >/dev/null 2>&1); then
    echo "✅ mobius-cli builds successfully"
else
    echo "❌ mobius-cli build failed"
fi

# Test 3: Check configuration files
echo -e "\n⚙️ Checking configuration files..."
if [ -f ".golangci.yml" ]; then
    echo "✅ .golangci.yml exists"
else
    echo "❌ .golangci.yml missing"
fi

if [ -f "go.work" ]; then
    echo "✅ go.work exists"
else
    echo "❌ go.work missing"
fi

# Test 4: Count workflows and check structure
echo -e "\n📊 Workflow summary..."
WORKFLOW_COUNT=$(find .github/workflows -name "*.yml" -o -name "*.yaml" | wc -l)
echo "Total workflows: $WORKFLOW_COUNT"

CONCURRENCY_COUNT=$(grep -l "concurrency:" .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | wc -l)
echo "Workflows with concurrency control: $CONCURRENCY_COUNT"

echo -e "\n✅ Workflow verification complete!"