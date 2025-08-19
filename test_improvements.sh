#!/bin/bash

# Test script for the improved Inkan Key Management Module
# This script tests the new features and endpoints

set -e

BASE_URL="http://localhost:3002"
echo "🧪 Testing Inkan Key Management Module at $BASE_URL"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to run tests
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_status="$3"
    
    echo -e "${BLUE}Running: $test_name${NC}"
    
    if eval "$command" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✅ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "  ${RED}❌ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

# Wait for service to be ready
wait_for_service() {
    echo -e "${YELLOW}Waiting for service to be ready...${NC}"
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$BASE_URL/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Service is ready!${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 1
        ((attempt++))
    done
    
    echo -e "${RED}Service failed to start within $max_attempts seconds${NC}"
    return 1
}

# Test health endpoint
test_health() {
    run_test "Health Check" \
        "curl -s '$BASE_URL/health' | grep -q 'OK'" \
        0
}

# Test key generation
test_key_generation() {
    run_test "Generate Key Pair (Unencrypted)" \
        "curl -s -X POST '$BASE_URL/keys/generate' \
            -H 'Content-Type: application/json' \
            -d '{\"name\": \"Test Key\", \"description\": \"Test key for testing\"}' \
            | grep -q 'success.*true'" \
        0
    
    run_test "Generate Key Pair (Encrypted)" \
        "curl -s -X POST '$BASE_URL/keys/generate' \
            -H 'Content-Type: application/json' \
            -d '{\"name\": \"Encrypted Test Key\", \"password\": \"test123\", \"tags\": [\"test\", \"encrypted\"]}' \
            | grep -q 'success.*true'" \
        0
}

# Test key listing
test_key_listing() {
    run_test "List All Keys" \
        "curl -s '$BASE_URL/keys' | grep -q 'success.*true'" \
        0
    
    run_test "List Active Keys Only" \
        "curl -s '$BASE_URL/keys?active_only=true' | grep -q 'success.*true'" \
        0
    
    run_test "Search Keys" \
        "curl -s '$BASE_URL/keys/search?search=test' | grep -q 'success.*true'" \
        0
}

# Test key statistics
test_key_statistics() {
    run_test "Get Key Statistics" \
        "curl -s '$BASE_URL/keys/stats' | grep -q 'success.*true'" \
        0
}

# Test document signing and verification
test_signing_verification() {
    # First, get a key ID from the list
    local key_response=$(curl -s "$BASE_URL/keys")
    local key_id=$(echo "$key_response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -n "$key_id" ]; then
        run_test "Sign Document" \
            "curl -s -X POST '$BASE_URL/sign' \
                -H 'Content-Type: application/json' \
                -d '{\"key_id\": \"$key_id\", \"document_content\": \"Test document content\"}' \
                | grep -q 'success.*true'" \
            0
        
        # Get the signature for verification
        local sign_response=$(curl -s -X POST "$BASE_URL/sign" \
            -H "Content-Type: application/json" \
            -d "{\"key_id\": \"$key_id\", \"document_content\": \"Test document content\"}")
        
        local signature=$(echo "$sign_response" | grep -o '"signature":"[^"]*"' | cut -d'"' -f4)
        local public_key=$(echo "$key_response" | grep -o '"public_key":"[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ -n "$signature" ] && [ -n "$public_key" ]; then
            run_test "Verify Signature" \
                "curl -s -X POST '$BASE_URL/verify' \
                    -H 'Content-Type: application/json' \
                    -d '{\"public_key\": \"$public_key\", \"document_content\": \"Test document content\", \"signature\": \"$signature\"}' \
                    | grep -q 'is_valid.*true'" \
                0
        fi
    fi
}

# Test key management operations
test_key_management() {
    # Get a key ID for testing
    local key_response=$(curl -s "$BASE_URL/keys")
    local key_id=$(echo "$key_response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -n "$key_id" ]; then
        run_test "Update Key" \
            "curl -s -X PUT '$BASE_URL/keys/$key_id' \
                -H 'Content-Type: application/json' \
                -d '{\"name\": \"Updated Test Key\"}' \
                | grep -q 'success.*true'" \
            0
        
        run_test "Get Key Information" \
            "curl -s '$BASE_URL/keys/$key_id' | grep -q 'success.*true'" \
            0
    fi
}

# Main test execution
main() {
    echo -e "${YELLOW}Starting Inkan Key Management Module Tests${NC}"
    echo "=================================================="
    
    # Wait for service
    if ! wait_for_service; then
        echo -e "${RED}❌ Service is not available. Please start the service first.${NC}"
        echo "You can start it with: cargo run"
        exit 1
    fi
    
    echo ""
    echo -e "${YELLOW}Running Tests...${NC}"
    echo "========================"
    
    # Run all tests
    test_health
    test_key_generation
    test_key_listing
    test_key_statistics
    test_signing_verification
    test_key_management
    
    echo ""
    echo -e "${YELLOW}Test Results${NC}"
    echo "============="
    echo -e "${GREEN}✅ Tests Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}❌ Tests Failed: $TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}💥 Some tests failed.${NC}"
        exit 1
    fi
}

# Run main function
main "$@"
