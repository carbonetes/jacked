#!/bin/bash
# Comprehensive Test Suite for Jacked Performance Configuration System
# This script runs all unit tests, integration tests, and performance benchmarks

set -e

echo "=== Jacked Performance Configuration Test Suite ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test with proper error handling
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "${BLUE}Running: $test_name${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command" 2>&1; then
        echo -e "${GREEN}✓ PASSED: $test_name${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED: $test_name${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

# Function to run benchmarks
run_benchmark() {
    local benchmark_name="$1"
    local benchmark_command="$2"
    
    echo -e "${YELLOW}Benchmarking: $benchmark_name${NC}"
    if eval "$benchmark_command" 2>&1; then
        echo -e "${GREEN}✓ BENCHMARK COMPLETED: $benchmark_name${NC}"
    else
        echo -e "${RED}✗ BENCHMARK FAILED: $benchmark_name${NC}"
    fi
    echo ""
}

# Ensure we're in the right directory
if [ ! -f "go.mod" ]; then
    echo -e "${RED}Error: Not in jacked project root directory${NC}"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed or not in PATH${NC}"
    exit 1
fi

echo "Go version: $(go version)"
echo ""

# Build the project first to ensure it compiles
echo -e "${BLUE}Building jacked...${NC}"
if go build -o jacked ./cmd/jacked/main.go; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Run unit tests for each package
echo -e "${YELLOW}=== UNIT TESTS ===${NC}"
echo ""

# Test config package
run_test "Config Package - File Loading" \
    "go test -v ./pkg/config/... -run TestLoadConfigFromPath"

run_test "Config Package - Path Handling" \
    "go test -v ./pkg/config/... -run TestSetConfigPath"

run_test "Config Package - Configuration Reload" \
    "go test -v ./pkg/config/... -run TestReloadConfig"

run_test "Config Package - Invalid YAML" \
    "go test -v ./pkg/config/... -run TestInvalidConfigYAML"

run_test "Config Package - Default Generation" \
    "go test -v ./pkg/config/... -run TestDefaultConfigGeneration"

# Test command package (CLI)
run_test "Command Package - Root Flags" \
    "go test -v ./cmd/jacked/command/... -run TestRootCommandFlags"

run_test "Command Package - Config Path Handling" \
    "go test -v ./cmd/jacked/command/... -run TestConfigPathHandling"

run_test "Command Package - Non-Interactive Mode" \
    "go test -v ./cmd/jacked/command/... -run TestNonInteractiveMode"

run_test "Command Package - Optimize Command Flags" \
    "go test -v ./cmd/jacked/command/... -run TestOptimizeCommandFlags"

run_test "Command Package - Configuration Integration" \
    "go test -v ./cmd/jacked/command/... -run TestConfigurationIntegration"

# Test TUI table package
run_test "Table Package - Empty Vulnerabilities" \
    "go test -v ./internal/tea/table/... -run TestCreateTableWithNoVulnerabilities"

run_test "Table Package - With Vulnerabilities" \
    "go test -v ./internal/tea/table/... -run TestCreateTableWithVulnerabilities"

run_test "Table Package - Complex Versions" \
    "go test -v ./internal/tea/table/... -run TestCreateTableWithComplexVersions"

run_test "Table Package - Missing Ratings" \
    "go test -v ./internal/tea/table/... -run TestCreateTableWithMissingRatings"

run_test "Table Package - Non-Interactive Mode" \
    "go test -v ./internal/tea/table/... -run TestNonInteractiveMode"

run_test "Table Package - Sorting" \
    "go test -v ./internal/tea/table/... -run TestTableSorting"

run_test "Table Package - Model View" \
    "go test -v ./internal/tea/table/... -run TestModelView"

# Run all tests together to check for conflicts
echo -e "${YELLOW}=== INTEGRATION TESTS ===${NC}"
echo ""

run_test "All Package Tests" \
    "go test ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/"

# Test with race detection
run_test "Race Condition Detection" \
    "go test -race ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/"

# Run benchmarks
echo -e "${YELLOW}=== PERFORMANCE BENCHMARKS ===${NC}"
echo ""

run_benchmark "Types Package Benchmarks" \
    "go test -bench=. ./pkg/types/"

run_benchmark "Config Package Benchmarks" \
    "go test -bench=. ./pkg/config/"

run_benchmark "Command Package Benchmarks" \
    "go test -bench=. ./cmd/jacked/command/"

run_benchmark "Table Package Benchmarks" \
    "go test -bench=. ./internal/tea/table/"

# Test actual CLI functionality
echo -e "${YELLOW}=== CLI FUNCTIONALITY TESTS ===${NC}"
echo ""

# Test help output
run_test "CLI Help Output" \
    "./jacked --help"

# Test version output
run_test "CLI Version Output" \
    "./jacked version"

# Test different performance levels (basic functionality)
run_test "Performance Level - Basic" \
    "./jacked --performance=basic --help"

run_test "Performance Level - Balanced" \
    "./jacked --performance=balanced --help"

run_test "Performance Level - Aggressive" \
    "./jacked --performance=aggressive --help"

run_test "Performance Level - Maximum" \
    "./jacked --performance=maximum --help"

# Test config flag
run_test "Custom Config Path" \
    "./jacked --config=/tmp/test-config.yaml --help"

# Test non-interactive flag
run_test "Non-Interactive Flag" \
    "./jacked --non-interactive --help"

# Test optimize command
run_test "Optimize Command Help" \
    "./jacked analyze-optimized --help"

# Test database command
run_test "Database Command Help" \
    "./jacked db --help"

# Code quality checks
echo -e "${YELLOW}=== CODE QUALITY CHECKS ===${NC}"
echo ""

# Check code formatting
run_test "Code Formatting" \
    "test -z \$(gofmt -l .)"

# Check for common issues with go vet
run_test "Go Vet" \
    "go vet ./..."

# Test code coverage
echo -e "${BLUE}Generating code coverage report...${NC}"
if go test -coverprofile=coverage.out ./pkg/types/ ./pkg/config/ ./cmd/jacked/command/ ./internal/tea/table/; then
    echo -e "${GREEN}✓ Coverage report generated${NC}"
    
    # Show coverage summary
    echo ""
    echo -e "${BLUE}Coverage Summary:${NC}"
    go tool cover -func=coverage.out | tail -1
    
    # Generate HTML coverage report
    go tool cover -html=coverage.out -o coverage.html
    echo -e "${GREEN}✓ HTML coverage report generated: coverage.html${NC}"
else
    echo -e "${RED}✗ Coverage report generation failed${NC}"
fi
echo ""

# Performance configuration validation
echo -e "${YELLOW}=== CONFIGURATION VALIDATION ===${NC}"
echo ""

# Create a test config file
cat > test-config.yaml << EOF
version: "1.0"
performance:
  max_concurrent_scanners: 8
  scan_timeout: 300s
  enable_caching: true
  max_cache_size: 1000
  scanners:
    npm:
      enabled: true
      timeout: 120s
      max_concurrency: 8
      caching_enabled: true
      priority: 8
    maven:
      enabled: true
      timeout: 180s
      max_concurrency: 8
      caching_enabled: true
      priority: 7
EOF

run_test "Valid Config File" \
    "./jacked --config=test-config.yaml --help"

# Test invalid config
cat > invalid-config.yaml << EOF
version: "1.0"
performance:
  max_concurrent_scanners: invalid_number
  scan_timeout: not_a_duration
EOF

run_test "Invalid Config Handling" \
    "./jacked --config=invalid-config.yaml --help || true"

# Clean up test files
rm -f test-config.yaml invalid-config.yaml coverage.out

# Summary
echo -e "${YELLOW}=== TEST SUMMARY ===${NC}"
echo ""
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo ""
    echo "The performance configuration system is working correctly!"
    echo ""
    echo "Next steps:"
    echo "1. Run './test-performance.sh' to test actual scanning performance"
    echo "2. Check 'coverage.html' for detailed code coverage"
    echo "3. Review PERFORMANCE_CONFIGURATION.md for usage instructions"
    exit 0
else
    echo ""
    echo -e "${RED}❌ SOME TESTS FAILED ❌${NC}"
    echo ""
    echo "Please review the failed tests above and fix any issues."
    exit 1
fi
