#!/bin/bash

# Mobius MDM Test Runner - Centralized test execution
# Runs all test suites and provides comprehensive reporting

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_SERVER_PORT=8081
TEST_RESULTS_FILE="test_results.log"

echo -e "${BLUE}🧪 Mobius MDM Platform - Test Suite Runner${NC}"
echo "=================================================="

# Function to run individual test script
run_test_script() {
    local script_name="$1"
    local description="$2"
    
    echo -e "${BLUE}Running: ${description}${NC}"
    echo "Script: ${script_name}"
    echo "------------------------------------------"
    
    if [[ -f "$script_name" ]]; then
        if bash "$script_name"; then
            echo -e "${GREEN}✅ ${description} - PASSED${NC}"
            return 0
        else
            echo -e "${RED}❌ ${description} - FAILED${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠️  ${description} - SCRIPT NOT FOUND${NC}"
        return 1
    fi
}

# Function to check if test server is running
check_test_server() {
    echo -e "${BLUE}Checking test server status...${NC}"
    if curl -s "http://localhost:${TEST_SERVER_PORT}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Test server is running on port ${TEST_SERVER_PORT}${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Test server not running on port ${TEST_SERVER_PORT}${NC}"
        echo "Please start the test server first:"
        echo "cd ../mobius-server && go run cmd/mobius/main.go serve --port ${TEST_SERVER_PORT}"
        return 1
    fi
}

# Main test execution
main() {
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    echo -e "${BLUE}Starting test execution...${NC}"
    echo "Timestamp: $(date)"
    echo ""
    
    # Check prerequisites
    if ! check_test_server; then
        echo -e "${RED}❌ Prerequisites not met. Exiting.${NC}"
        exit 1
    fi
    
    echo ""
    
    # Run comprehensive MDM functionality tests
    ((total_tests++))
    if run_test_script "test_mdm_functionality.sh" "Comprehensive MDM Functionality Tests"; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    
    # Run WebSocket functionality tests
    ((total_tests++))
    if run_test_script "test_websocket_functionality.sh" "WebSocket Real-time Features Tests"; then
        ((passed_tests++))
    else
        ((failed_tests++))
    fi
    
    echo ""
    echo "=================================================="
    echo -e "${BLUE}📊 Test Execution Summary${NC}"
    echo "=================================================="
    echo "Total Test Suites: ${total_tests}"
    echo -e "Passed: ${GREEN}${passed_tests}${NC}"
    echo -e "Failed: ${RED}${failed_tests}${NC}"
    
    if [[ $failed_tests -eq 0 ]]; then
        echo -e "${GREEN}🎉 All test suites passed successfully!${NC}"
        exit 0
    else
        echo -e "${RED}❌ Some test suites failed. Check the output above.${NC}"
        exit 1
    fi
}

# Help function
show_help() {
    echo "Mobius MDM Test Runner"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  run       Run all test suites (default)"
    echo "  help      Show this help message"
    echo ""
    echo "Prerequisites:"
    echo "  - Test server running on port ${TEST_SERVER_PORT}"
    echo "  - Start with: cd ../mobius-server && go run cmd/mobius/main.go serve --port ${TEST_SERVER_PORT}"
    echo ""
    echo "Test suites included:"
    echo "  - Comprehensive MDM Functionality Tests (29 scenarios)"
    echo "  - WebSocket Real-time Features Tests (6 scenarios)"
    echo ""
}

# Command line argument handling
case "${1:-run}" in
    "run")
        main
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Use '$0 help' for usage information."
        exit 1
        ;;
esac
