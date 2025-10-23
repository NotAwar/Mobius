#!/bin/bash

# MDM Platform Functionality Test Script
# This script comprehensively tests all MDM features

set -e

echo "🧪 Starting MDM Platform Functionality Tests"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Function to log test results
log_test() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✅ $test_name${NC}: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}❌ $test_name${NC}: $message"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo -e "${YELLOW}⚠️  $test_name${NC}: $message"
    fi
}

# Check if server is running (we'll start it if needed)
start_server() {
    echo "🚀 Starting Mobius Test Server..."
    cd /Users/awar/Documents/Mobius/mobius-server
    
    # Build the test server
    go build ./cmd/test-server
    if [ $? -eq 0 ]; then
        log_test "Test Server Build" "PASS" "Mobius test server built successfully"
    else
        log_test "Test Server Build" "FAIL" "Failed to build Mobius test server"
        return 1
    fi
    
    # Start test server in background (redirect output to log)
    ./test-server > test-server.log 2>&1 &
    SERVER_PID=$!
    echo "Test server started with PID: $SERVER_PID"
    
    # Wait for server to be ready
    echo "⏳ Waiting for test server to start..."
    for i in {1..30}; do
        if curl -s http://localhost:8081/api/v1/health > /dev/null 2>&1; then
            log_test "Test Server Startup" "PASS" "Test server is responding to health checks"
            return 0
        fi
        sleep 1
    done
    
    log_test "Test Server Startup" "FAIL" "Test server failed to start within 30 seconds"
    return 1
}

# Stop server
stop_server() {
    if [ ! -z "$SERVER_PID" ]; then
        echo "🛑 Stopping server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}

# Trap to ensure server is stopped on exit
trap stop_server EXIT

# Test functions
test_health_endpoint() {
    echo -e "\n📋 Testing Health Endpoint"
    echo "----------------------------"
    
    response=$(curl -s -w "%{http_code}" http://localhost:8081/api/v1/health -o /tmp/health_response.json)
    http_code="${response: -3}"
    
    if [ "$http_code" = "200" ]; then
        log_test "Health Endpoint" "PASS" "Returns HTTP 200"
        
        # Check response content
        if grep -q "healthy" /tmp/health_response.json; then
            log_test "Health Content" "PASS" "Response contains health status"
        else
            log_test "Health Content" "FAIL" "Response does not contain expected health status"
        fi
    else
        log_test "Health Endpoint" "FAIL" "Returns HTTP $http_code instead of 200"
    fi
}

test_authentication() {
    echo -e "\n🔐 Testing Authentication"
    echo "-------------------------"
    
    # Test login with valid credentials
    login_response=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"admin@mobius.local","password":"admin123"}' \
        -w "%{http_code}" \
        -o /tmp/login_response.json)
    
    http_code="${login_response: -3}"
    
    if [ "$http_code" = "200" ]; then
        log_test "Login Endpoint" "PASS" "Accepts valid credentials"
        
        # Extract token
        if command -v jq > /dev/null; then
            TOKEN=$(jq -r '.token' /tmp/login_response.json)
            if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
                log_test "JWT Token" "PASS" "JWT token generated successfully"
            else
                log_test "JWT Token" "FAIL" "No JWT token in response"
                TOKEN=""
            fi
        else
            log_test "JWT Token" "WARN" "jq not available, cannot parse token"
            TOKEN=""
        fi
    else
        log_test "Login Endpoint" "FAIL" "Returns HTTP $http_code instead of 200"
        TOKEN=""
    fi
    
    # Test invalid credentials
    invalid_login=$(curl -s -X POST http://localhost:8081/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"wrong@example.com","password":"wrong"}' \
        -w "%{http_code}" \
        -o /dev/null)
    
    invalid_code="${invalid_login: -3}"
    if [ "$invalid_code" = "401" ]; then
        log_test "Invalid Login" "PASS" "Rejects invalid credentials with HTTP 401"
    else
        log_test "Invalid Login" "FAIL" "Returns HTTP $invalid_code instead of 401"
    fi
}

test_license_management() {
    echo -e "\n📜 Testing License Management"
    echo "-----------------------------"
    
    if [ -z "$TOKEN" ]; then
        log_test "License Tests" "WARN" "Skipping - no authentication token"
        return
    fi
    
    # Test get license status
    license_response=$(curl -s -X GET http://localhost:8081/api/v1/license/status \
        -H "Authorization: Bearer $TOKEN" \
        -w "%{http_code}" \
        -o /tmp/license_response.json)
    
    http_code="${license_response: -3}"
    if [ "$http_code" = "200" ]; then
        log_test "License Status" "PASS" "Returns current license information"
    else
        log_test "License Status" "FAIL" "Returns HTTP $http_code instead of 200"
    fi
    
    # Test license update
    update_response=$(curl -s -X PUT http://localhost:8081/api/v1/license \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"key":"professional-license"}' \
        -w "%{http_code}" \
        -o /dev/null)
    
    update_code="${update_response: -3}"
    if [ "$update_code" = "200" ] || [ "$update_code" = "201" ]; then
        log_test "License Update" "PASS" "License updated successfully"
    else
        log_test "License Update" "FAIL" "Returns HTTP $update_code"
    fi
}

test_device_management() {
    echo -e "\n📱 Testing Device Management"
    echo "----------------------------"
    
    if [ -z "$TOKEN" ]; then
        log_test "Device Tests" "WARN" "Skipping - no authentication token"
        return
    fi
    
    # Test device enrollment
    enroll_response=$(curl -s -X POST http://localhost:8081/api/v1/devices \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "uuid": "test-device-001",
            "hostname": "test-laptop",
            "platform": "macos", 
            "os_version": "14.0",
            "enrollment_secret": "test-secret"
        }' \
        -w "%{http_code}" \
        -o /tmp/enroll_response.json)
    
    enroll_code="${enroll_response: -3}"
    if [ "$enroll_code" = "200" ] || [ "$enroll_code" = "201" ]; then
        log_test "Device Enrollment" "PASS" "Device enrolled successfully"
        
        # Extract device ID for further tests
        if command -v jq > /dev/null; then
            DEVICE_ID=$(jq -r '.id' /tmp/enroll_response.json)
        fi
    else
        log_test "Device Enrollment" "FAIL" "Returns HTTP $enroll_code"
    fi
    
    # Test device listing
    list_response=$(curl -s -X GET http://localhost:8081/api/v1/devices \
        -H "Authorization: Bearer $TOKEN" \
        -w "%{http_code}" \
        -o /tmp/devices_list.json)
    
    list_code="${list_response: -3}"
    if [ "$list_code" = "200" ]; then
        log_test "Device Listing" "PASS" "Devices listed successfully"
        
        # Check if our enrolled device is in the list
        if command -v jq > /dev/null && [ -n "$DEVICE_ID" ]; then
            device_found=$(jq --arg id "$DEVICE_ID" '.devices[] | select(.id == $id)' /tmp/devices_list.json)
            if [ -n "$device_found" ]; then
                log_test "Device Persistence" "PASS" "Enrolled device appears in device list"
            else
                log_test "Device Persistence" "FAIL" "Enrolled device not found in list"
            fi
        fi
    else
        log_test "Device Listing" "FAIL" "Returns HTTP $list_code"
    fi
    
    # Test device search
    search_response=$(curl -s -X GET "http://localhost:8081/api/v1/devices?search=test-laptop" \
        -H "Authorization: Bearer $TOKEN" \
        -w "%{http_code}" \
        -o /tmp/search_response.json)
    
    search_code="${search_response: -3}"
    if [ "$search_code" = "200" ]; then
        log_test "Device Search" "PASS" "Device search works"
    else
        log_test "Device Search" "FAIL" "Returns HTTP $search_code"
    fi
    
    # Test device command execution (if device ID available)
    if [ -n "$DEVICE_ID" ]; then
        command_response=$(curl -s -X POST "http://localhost:8081/api/v1/devices/$DEVICE_ID/commands" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"command": "restart", "parameters": {}}' \
            -w "%{http_code}" \
            -o /tmp/command_response.json)
        
        command_code="${command_response: -3}"
        if [ "$command_code" = "200" ]; then
            log_test "Device Commands" "PASS" "Command execution works"
        else
            log_test "Device Commands" "FAIL" "Returns HTTP $command_code"
        fi
        
        # Test OSQuery execution
        osquery_response=$(curl -s -X POST "http://localhost:8081/api/v1/devices/$DEVICE_ID/osquery" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"query": "SELECT name, version, platform FROM osquery_info;"}' \
            -w "%{http_code}" \
            -o /tmp/osquery_response.json)
        
        osquery_code="${osquery_response: -3}"
        if [ "$osquery_code" = "200" ]; then
            log_test "OSQuery Execution" "PASS" "OSQuery execution works"
        else
            log_test "OSQuery Execution" "FAIL" "Returns HTTP $osquery_code"
        fi
    fi
}

test_device_groups() {
    echo -e "\n👥 Testing Device Groups"
    echo "----------------------------"
    
    if [ -z "$TOKEN" ]; then
        log_test "Device Group Tests" "WARN" "Skipping - no authentication token"
        return
    fi
    
    # Test device group creation
    group_response=$(curl -s -X POST http://localhost:8081/api/v1/device-groups \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "MacOS Devices",
            "description": "All macOS devices in the organization",
            "filters": {
                "platform": "macos"
            },
            "labels": {
                "department": "engineering"
            }
        }' \
        -w "%{http_code}" \
        -o /tmp/group_response.json)
    
    group_code="${group_response: -3}"
    if [ "$group_code" = "200" ] || [ "$group_code" = "201" ]; then
        log_test "Device Group Creation" "PASS" "Device group created successfully"
        
        if command -v jq > /dev/null; then
            GROUP_ID=$(jq -r '.id' /tmp/group_response.json)
        fi
    else
        log_test "Device Group Creation" "FAIL" "Returns HTTP $group_code"
    fi
    
    # Test device group listing
    groups_response=$(curl -s -X GET http://localhost:8081/api/v1/device-groups \
        -H "Authorization: Bearer $TOKEN" \
        -w "%{http_code}" \
        -o /tmp/groups_list.json)
    
    groups_code="${groups_response: -3}"
    if [ "$groups_code" = "200" ]; then
        log_test "Device Group Listing" "PASS" "Device groups listed successfully"
    else
        log_test "Device Group Listing" "FAIL" "Returns HTTP $groups_code"
    fi
    
    # Test adding device to group (if both group and device exist)
    if [ -n "$GROUP_ID" ] && [ -n "$DEVICE_ID" ]; then
        add_device_response=$(curl -s -X POST "http://localhost:8081/api/v1/device-groups/$GROUP_ID/devices/$DEVICE_ID" \
            -H "Authorization: Bearer $TOKEN" \
            -w "%{http_code}" \
            -o /tmp/add_device_response.json)
        
        add_device_code="${add_device_response: -3}"
        if [ "$add_device_code" = "200" ]; then
            log_test "Add Device to Group" "PASS" "Device added to group successfully"
        else
            log_test "Add Device to Group" "FAIL" "Returns HTTP $add_device_code"
        fi
        
        # Test getting group devices
        group_devices_response=$(curl -s -X GET "http://localhost:8081/api/v1/device-groups/$GROUP_ID/devices" \
            -H "Authorization: Bearer $TOKEN" \
            -w "%{http_code}" \
            -o /tmp/group_devices.json)
        
        group_devices_code="${group_devices_response: -3}"
        if [ "$group_devices_code" = "200" ]; then
            log_test "Get Group Devices" "PASS" "Group devices listed successfully"
        else
            log_test "Get Group Devices" "FAIL" "Returns HTTP $group_devices_code"
        fi
    fi
}

test_policy_management() {
    echo -e "\n📋 Testing Policy Management"
    echo "----------------------------"
    
    if [ -z "$TOKEN" ]; then
        log_test "Policy Tests" "WARN" "Skipping - no authentication token"
        return
    fi
    
    # Test policy creation
    policy_response=$(curl -s -X POST http://localhost:8081/api/v1/policies \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Test Security Policy",
            "description": "A test policy for security compliance",
            "platform": "macos",
            "configuration": {
                "firewall_enabled": true,
                "encryption_required": true
            }
        }' \
        -w "%{http_code}" \
        -o /tmp/policy_response.json)
    
    policy_code="${policy_response: -3}"
    if [ "$policy_code" = "200" ] || [ "$policy_code" = "201" ]; then
        log_test "Policy Creation" "PASS" "Policy created successfully"
        
        if command -v jq > /dev/null; then
            POLICY_ID=$(jq -r '.id' /tmp/policy_response.json)
        fi
    else
        log_test "Policy Creation" "FAIL" "Returns HTTP $policy_code"
    fi
    
    # Test policy listing
    policies_response=$(curl -s -X GET http://localhost:8081/api/v1/policies \
        -H "Authorization: Bearer $TOKEN" \
        -w "%{http_code}" \
        -o /tmp/policies_list.json)
    
    policies_code="${policies_response: -3}"
    if [ "$policies_code" = "200" ]; then
        log_test "Policy Listing" "PASS" "Policies listed successfully"
    else
        log_test "Policy Listing" "FAIL" "Returns HTTP $policies_code"
    fi
    
    # Test policy assignment (if both policy and device exist)
    if [ -n "$POLICY_ID" ] && [ -n "$DEVICE_ID" ]; then
        assign_response=$(curl -s -X POST "http://localhost:8081/api/v1/policies/$POLICY_ID/devices/$DEVICE_ID" \
            -H "Authorization: Bearer $TOKEN" \
            -w "%{http_code}" \
            -o /tmp/assign_response.json)
        
        assign_code="${assign_response: -3}"
        if [ "$assign_code" = "200" ]; then
            log_test "Policy Assignment to Device" "PASS" "Policy assigned to device successfully"
        else
            log_test "Policy Assignment to Device" "FAIL" "Returns HTTP $assign_code"
        fi
        
        # Test getting policy devices
        policy_devices_response=$(curl -s -X GET "http://localhost:8081/api/v1/policies/$POLICY_ID/devices" \
            -H "Authorization: Bearer $TOKEN" \
            -w "%{http_code}" \
            -o /tmp/policy_devices.json)
        
        policy_devices_code="${policy_devices_response: -3}"
        if [ "$policy_devices_code" = "200" ]; then
            log_test "Get Policy Devices" "PASS" "Policy devices listed successfully"
        else
            log_test "Get Policy Devices" "FAIL" "Returns HTTP $policy_devices_code"
        fi
    fi
    
    # Test policy assignment to group (if both policy and group exist)
    if [ -n "$POLICY_ID" ] && [ -n "$GROUP_ID" ]; then
        assign_group_response=$(curl -s -X POST "http://localhost:8081/api/v1/policies/$POLICY_ID/groups/$GROUP_ID" \
            -H "Authorization: Bearer $TOKEN" \
            -w "%{http_code}" \
            -o /tmp/assign_group_response.json)
        
        assign_group_code="${assign_group_response: -3}"
        if [ "$assign_group_code" = "200" ]; then
            log_test "Policy Assignment to Group" "PASS" "Policy assigned to group successfully"
        else
            log_test "Policy Assignment to Group" "FAIL" "Returns HTTP $assign_group_code"
        fi
        
        # Test getting policy groups
        policy_groups_response=$(curl -s -X GET "http://localhost:8081/api/v1/policies/$POLICY_ID/groups" \
            -H "Authorization: Bearer $TOKEN" \
            -w "%{http_code}" \
            -o /tmp/policy_groups.json)
        
        policy_groups_code="${policy_groups_response: -3}"
        if [ "$policy_groups_code" = "200" ]; then
            log_test "Get Policy Groups" "PASS" "Policy groups listed successfully"
        else
            log_test "Get Policy Groups" "FAIL" "Returns HTTP $policy_groups_code"
        fi
    fi
}

test_application_management() {
    echo -e "\n📦 Testing Application Management"
    echo "---------------------------------"
    
    if [ -z "$TOKEN" ]; then
        log_test "Application Tests" "WARN" "Skipping - no authentication token"
        return
    fi
    
    # Test application listing (might be empty initially)
    apps_response=$(curl -s -X GET http://localhost:8081/api/v1/applications \
        -H "Authorization: Bearer $TOKEN" \
        -w "%{http_code}" \
        -o /tmp/apps_response.json)
    
    apps_code="${apps_response: -3}"
    if [ "$apps_code" = "200" ]; then
        log_test "Application Listing" "PASS" "Applications endpoint responds"
    else
        log_test "Application Listing" "FAIL" "Returns HTTP $apps_code"
    fi
}

test_build_components() {
    echo -e "\n🔨 Testing Component Builds"
    echo "----------------------------"
    
    # Test each component build
    cd /Users/awar/Documents/Mobius
    
    echo "Building CLI..."
    cd mobius-cli
    if go build ./cmd/mobiuscli; then
        log_test "CLI Build" "PASS" "Mobius CLI builds successfully"
    else
        log_test "CLI Build" "FAIL" "CLI build failed"
    fi
    
    echo "Building Client..."
    cd ../mobius-client
    if go build ./cmd/client; then
        log_test "Client Build" "PASS" "Mobius Client builds successfully"
    else
        log_test "Client Build" "FAIL" "Client build failed"
    fi
    
    echo "Building Cocoon..."
    cd ../mobius-cocoon
    if go build ./cmd/cocoon; then
        log_test "Cocoon Build" "PASS" "Mobius Cocoon builds successfully"
    else
        log_test "Cocoon Build" "FAIL" "Cocoon build failed"
    fi
    
    cd ..
}

# Main test execution
main() {
    echo "Starting comprehensive MDM platform testing..."
    
    # Test builds first (no server needed)
    test_build_components
    
    # Start the server for API tests
    if start_server; then
        # Give server a moment to fully initialize
        sleep 2
        
        # Run API tests
        test_health_endpoint
        test_authentication
        test_license_management
        test_device_management
        test_device_groups
        test_policy_management
        test_application_management
    else
        echo "❌ Cannot run API tests - server failed to start"
    fi
    
    # Print summary
    echo -e "\n📊 Test Summary"
    echo "==============="
    echo -e "Total tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed! The MDM platform is working correctly.${NC}"
        exit 0
    else
        echo -e "\n${RED}⚠️  Some tests failed. Check the output above for details.${NC}"
        exit 1
    fi
}

# Run the main function
main
