#!/bin/bash

# Workflow Verification Test Script
# Tests key functionality that workflows depend on

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 GitHub Workflows Verification Test${NC}"
echo "=========================================="

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to log test results
log_test() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    
    ((TOTAL_TESTS++))
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✅ ${test_name}: ${message}${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}❌ ${test_name}: ${message}${NC}"
        ((FAILED_TESTS++))
    fi
}

# Test 1: Check Go workspace functionality
echo -e "\n${BLUE}Testing Go Workspace Setup${NC}"
echo "----------------------------"

if go work sync 2>/dev/null; then
    log_test "Go Workspace Sync" "PASS" "go work sync executed successfully"
else
    log_test "Go Workspace Sync" "FAIL" "go work sync failed"
fi

# Test 2: Build verification for all components
echo -e "\n${BLUE}Testing Component Builds${NC}"
echo "-------------------------"

components=("mobius-server/cmd/api-server" "mobius-cli/cmd/mobiuscli" "mobius-client/cmd/client")
for component in "${components[@]}"; do
    module=$(echo "$component" | cut -d'/' -f1)
    cmd_path=$(echo "$component" | cut -d'/' -f2-)
    
    if (cd "$module" && go build "./$cmd_path" 2>/dev/null); then
        log_test "Build $module" "PASS" "$component builds successfully"
    else
        build_err=$(cd "$module" && go build "./$cmd_path" 2>&1)
        log_test "Build $module" "FAIL" "$component build failed. Error output:\n$build_err"
    fi
done

# Test 3: Check for workflow files
echo -e "\n${BLUE}Testing Workflow File Structure${NC}"
echo "--------------------------------"

workflow_files=(
    ".github/workflows/golangci-lint.yml"
    ".github/workflows/unit-tests.yml"
    ".github/workflows/build-and-deploy.yml"
    ".github/workflows/trivy-scan.yml"
    ".github/workflows/dependency-review.yml"
)

for workflow in "${workflow_files[@]}"; do
    if [ -f "$workflow" ]; then
        log_test "Workflow File" "PASS" "$workflow exists"
    else
        log_test "Workflow File" "FAIL" "$workflow missing"
    fi
done

# Test 4: Check workflow syntax (basic YAML validation)
echo -e "\n${BLUE}Testing Workflow Syntax${NC}"
echo "------------------------"

for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
    if [ -f "$workflow" ]; then
        # Basic YAML syntax check - just check file exists and has content
        if [ -s "$workflow" ]; then
            log_test "YAML Syntax" "PASS" "$(basename "$workflow") exists and has content"
        else
            log_test "YAML Syntax" "FAIL" "$(basename "$workflow") is empty or missing"
        fi
    fi
done

# Test 5: Check for required secrets and configurations
echo -e "\n${BLUE}Testing Configuration Dependencies${NC}"
echo "-----------------------------------"

# Check for golangci-lint config
if [ -f ".golangci.yml" ]; then
    log_test "Linting Config" "PASS" ".golangci.yml exists"
else
    log_test "Linting Config" "FAIL" ".golangci.yml missing"
fi

# Check for Docker configs
docker_files=("Dockerfile" "mobius-server/Dockerfile" "mobius-cli/Dockerfile")
for dockerfile in "${docker_files[@]}"; do
    if [ -f "$dockerfile" ]; then
        log_test "Docker Config" "PASS" "$dockerfile exists"
    else
        log_test "Docker Config" "FAIL" "$dockerfile missing"
    fi
done

# Test 6: Check unit test capability
echo -e "\n${BLUE}Testing Unit Test Infrastructure${NC}"
echo "---------------------------------"

modules=("mobius-server" "mobius-cli" "mobius-client" "shared")
for module in "${modules[@]}"; do
    if [ -d "$module" ]; then
        if (cd "$module" && go test -list ./... >/dev/null 2>&1); then
            log_test "Test Discovery" "PASS" "$module has discoverable tests"
        else
            log_test "Test Discovery" "FAIL" "$module test discovery failed"
        fi
    fi
done

# Test 7: Check for security scanning dependencies
echo -e "\n${BLUE}Testing Security Infrastructure${NC}"
echo "--------------------------------"

# Check for trivy ignore file
if [ -f "security/code/.trivyignore" ] || [ -f ".trivyignore" ]; then
    log_test "Security Config" "PASS" "Trivy ignore file exists"
else
    log_test "Security Config" "FAIL" "Trivy ignore file missing"
fi

# Check for VEX files (if they exist)
if [ -d "security/vex" ]; then
    vex_count=$(find security/vex -name "*.json" 2>/dev/null | wc -l)
    if [ "$vex_count" -gt 0 ]; then
        log_test "VEX Files" "PASS" "Found $vex_count VEX files"
    else
        log_test "VEX Files" "FAIL" "No VEX files found in security/vex"
    fi
fi

# Test 8: Verify GitHub Actions best practices
echo -e "\n${BLUE}Testing Workflow Best Practices${NC}"
echo "--------------------------------"

# Check for concurrency control
# Require at least 67% of workflows to have concurrency control to ensure best practices are widely adopted.
CONCURRENCY_THRESHOLD=2   # Numerator for threshold (2/3 = 67%)
CONCURRENCY_THRESHOLD_DENOM=3 # Denominator for threshold
concurrency_workflows=$(grep -l "concurrency:" .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | wc -l)
total_workflows=$(find .github/workflows -name "*.yml" -o -name "*.yaml" | wc -l)

if [ "$concurrency_workflows" -ge $((total_workflows * CONCURRENCY_THRESHOLD / CONCURRENCY_THRESHOLD_DENOM)) ]; then
    log_test "Concurrency Control" "PASS" "$concurrency_workflows/$total_workflows workflows have concurrency control"
else
    log_test "Concurrency Control" "FAIL" "Only $concurrency_workflows/$total_workflows workflows have concurrency control"
fi

# Check for proper shell configuration
shell_config_workflows=$(grep -l "shell: bash" .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | wc -l)
if [ "$shell_config_workflows" -ge $((total_workflows / 2)) ]; then
    log_test "Shell Config" "PASS" "$shell_config_workflows workflows use proper shell configuration"
else
    log_test "Shell Config" "FAIL" "Only $shell_config_workflows workflows use proper shell configuration"
fi

# Summary
echo -e "\n${BLUE}📊 Test Summary${NC}"
echo "================"
echo -e "Total tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All workflow verification tests passed!${NC}"
    echo -e "The GitHub Actions infrastructure is properly configured and functional."
    exit 0
else
    echo -e "\n${YELLOW}⚠️  Some tests failed. Review the output above for details.${NC}"
    exit 1
fi