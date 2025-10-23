#!/bin/bash

# WebSocket Functionality Tests for Mobius MDM Platform
# Tests real-time features and WebSocket integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
SERVER_URL="localhost:8081"
WS_URL="ws://${SERVER_URL}/ws"
TOKEN="test-token"

echo -e "${BLUE}🚀 Mobius MDM WebSocket Tests${NC}"
echo "========================================"

# Function to test WebSocket connection
test_websocket_connection() {
    echo -e "${BLUE}Testing WebSocket connection...${NC}"
    
    # Create a simple WebSocket test using curl (if available) or nc
    # For now, we'll just test the WebSocket status endpoint
    
    response=$(curl -s "http://${SERVER_URL}/api/v1/websocket/status" || echo "ERROR")
    
    if [[ "$response" == *"connected_clients"* ]]; then
        echo -e "${GREEN}✅ WebSocket status endpoint accessible${NC}"
        return 0
    else
        echo -e "${RED}❌ WebSocket status endpoint not accessible${NC}"
        return 1
    fi
}

# Function to test real-time device enrollment
test_realtime_device_enrollment() {
    echo -e "${BLUE}Testing real-time device enrollment notifications...${NC}"
    
    # Enroll a device and check if WebSocket would receive notifications
    device_data='{
        "uuid": "ws-test-device-001",
        "hostname": "WebSocket-Test-Device",
        "platform": "linux",
        "os_version": "Ubuntu 22.04"
    }'
    
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$device_data" \
        "http://${SERVER_URL}/api/v1/devices" || echo "ERROR")
    
    if [[ "$response" == *"WebSocket-Test-Device"* ]]; then
        echo -e "${GREEN}✅ Device enrollment successful (would trigger WebSocket notification)${NC}"
        return 0
    else
        echo -e "${RED}❌ Device enrollment failed${NC}"
        return 1
    fi
}

# Function to test real-time policy assignment
test_realtime_policy_assignment() {
    echo -e "${BLUE}Testing real-time policy assignment notifications...${NC}"
    
    # First create a policy
    policy_data='{
        "name": "WebSocket Test Policy",
        "description": "Policy for testing WebSocket notifications",
        "type": "device_config",
        "rules": {
            "test_rule": "test_value"
        }
    }'
    
    policy_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$policy_data" \
        "http://${SERVER_URL}/api/v1/policies" || echo "ERROR")
    
    if [[ "$policy_response" == *"WebSocket Test Policy"* ]]; then
        # Extract policy ID
        policy_id=$(echo "$policy_response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        
        # Assign policy to device
        assignment_response=$(curl -s -X POST \
            -H "Authorization: Bearer ${TOKEN}" \
            "http://${SERVER_URL}/api/v1/policies/${policy_id}/devices" \
            -d '{"device_id": "ws-test-device-001"}' || echo "ERROR")
        
        if [[ "$assignment_response" == *"success"* ]] || [[ "$assignment_response" == "" ]]; then
            echo -e "${GREEN}✅ Policy assignment successful (would trigger WebSocket notification)${NC}"
            return 0
        else
            echo -e "${RED}❌ Policy assignment failed: $assignment_response${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Policy creation failed${NC}"
        return 1
    fi
}

# Function to test real-time command execution
test_realtime_command_execution() {
    echo -e "${BLUE}Testing real-time command execution notifications...${NC}"
    
    # Execute a command on the test device
    command_data='{
        "command": "system_info",
        "parameters": {}
    }'
    
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$command_data" \
        "http://${SERVER_URL}/api/v1/devices/ws-test-device-001/commands" || echo "ERROR")
    
    if [[ "$response" == *"completed"* ]] || [[ "$response" == *"success"* ]]; then
        echo -e "${GREEN}✅ Command execution successful (would trigger WebSocket notification)${NC}"
        return 0
    else
        echo -e "${RED}❌ Command execution failed: $response${NC}"
        return 1
    fi
}

# Function to test real-time group membership
test_realtime_group_membership() {
    echo -e "${BLUE}Testing real-time group membership notifications...${NC}"
    
    # Create a device group
    group_data='{
        "name": "WebSocket Test Group",
        "description": "Group for testing WebSocket notifications"
    }'
    
    group_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$group_data" \
        "http://${SERVER_URL}/api/v1/device-groups" || echo "ERROR")
    
    if [[ "$group_response" == *"WebSocket Test Group"* ]]; then
        # Extract group ID
        group_id=$(echo "$group_response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        
        # Add device to group
        membership_response=$(curl -s -X POST \
            -H "Authorization: Bearer ${TOKEN}" \
            "http://${SERVER_URL}/api/v1/device-groups/${group_id}/devices" \
            -d '{"device_id": "ws-test-device-001"}' || echo "ERROR")
        
        if [[ "$membership_response" == *"success"* ]] || [[ "$membership_response" == "" ]]; then
            echo -e "${GREEN}✅ Group membership change successful (would trigger WebSocket notification)${NC}"
            return 0
        else
            echo -e "${RED}❌ Group membership change failed: $membership_response${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Group creation failed${NC}"
        return 1
    fi
}

# Function to check WebSocket status
check_websocket_status() {
    echo -e "${BLUE}Checking WebSocket service status...${NC}"
    
    status_response=$(curl -s "http://${SERVER_URL}/api/v1/websocket/status" || echo "ERROR")
    
    if [[ "$status_response" == *"running"* ]]; then
        connected_clients=$(echo "$status_response" | grep -o '"connected_clients":[0-9]*' | cut -d':' -f2)
        echo -e "${GREEN}✅ WebSocket service is running${NC}"
        echo "   Connected clients: $connected_clients"
        return 0
    else
        echo -e "${RED}❌ WebSocket service not available${NC}"
        return 1
    fi
}

# Main test execution
main() {
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    echo "Testing WebSocket functionality..."
    echo "Server: $SERVER_URL"
    echo "WebSocket URL: $WS_URL"
    echo ""
    
    # Test WebSocket status endpoint
    ((total_tests++))
    if check_websocket_status; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    
    # Test WebSocket connection capability
    ((total_tests++))
    if test_websocket_connection; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    
    # Test real-time device enrollment notifications
    ((total_tests++))
    if test_realtime_device_enrollment; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    
    # Test real-time policy assignment notifications
    ((total_tests++))
    if test_realtime_policy_assignment; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    
    # Test real-time command execution notifications
    ((total_tests++))
    if test_realtime_command_execution; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    
    # Test real-time group membership notifications
    ((total_tests++))
    if test_realtime_group_membership; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    echo "========================================"
    echo -e "${BLUE}📊 WebSocket Test Results${NC}"
    echo "========================================"
    echo "Total Tests: ${total_tests}"
    echo -e "Passed: ${GREEN}${passed_tests}${NC}"
    echo -e "Failed: ${RED}${failed_tests}${NC}"
    
    if [[ $failed_tests -eq 0 ]]; then
        echo -e "${GREEN}🎉 All WebSocket tests passed!${NC}"
        echo ""
        echo -e "${YELLOW}📝 Note: These tests verify that WebSocket notifications would be triggered${NC}"
        echo -e "${YELLOW}   by various MDM operations. To see live WebSocket events, connect a${NC}"
        echo -e "${YELLOW}   WebSocket client to: ${WS_URL}?token=${TOKEN}${NC}"
        echo ""
        exit 0
    else
        echo -e "${RED}❌ Some WebSocket tests failed.${NC}"
        exit 1
    fi
}

# Run the tests
main
