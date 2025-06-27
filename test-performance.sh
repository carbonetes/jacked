#!/bin/bash
# Jacked Performance Testing Script
# This script demonstrates the different performance optimization levels

echo "=== Jacked Performance Configuration Demo ==="
echo ""

# Check if jacked is available
if ! command -v jacked &> /dev/null; then
    echo "Error: jacked is not installed or not in PATH"
    exit 1
fi

# Test image
TEST_IMAGE="alpine:latest"

echo "Testing different performance optimization levels with $TEST_IMAGE"
echo ""

# Basic performance test
echo "1. Testing BASIC performance optimization..."
echo "   - Minimal resource usage"
echo "   - Safe for resource-constrained environments"
echo ""
time jacked --performance=basic --non-interactive $TEST_IMAGE
echo ""

# Balanced performance test
echo "2. Testing BALANCED performance optimization (default)..."
echo "   - Good balance of speed and resource usage"
echo "   - Recommended for most use cases"
echo ""
time jacked --performance=balanced --non-interactive $TEST_IMAGE
echo ""

# Aggressive performance test
echo "3. Testing AGGRESSIVE performance optimization..."
echo "   - Higher resource usage for better performance"
echo "   - Advanced features enabled"
echo ""
time jacked --performance=aggressive --non-interactive $TEST_IMAGE
echo ""

# Maximum performance test
echo "4. Testing MAXIMUM performance optimization..."
echo "   - Experimental optimizations"
echo "   - Best performance but highest resource usage"
echo ""
time jacked --performance=maximum --non-interactive $TEST_IMAGE
echo ""

echo "=== Advanced Optimized Scanning Demo ==="
echo ""

# Advanced optimization with metrics
echo "5. Testing ADVANCED OPTIMIZED scanning with metrics..."
echo "   - Uses the analyze-optimized command"
echo "   - Shows performance metrics"
echo ""
jacked analyze-optimized --optimization=balanced --show-metrics --enable-metrics $TEST_IMAGE
echo ""

echo "=== Performance Test Complete ==="
echo ""
echo "Check your ~/.jacked.yaml file to see the performance configuration:"
echo "cat ~/.jacked.yaml"
echo ""
echo "For more information, see PERFORMANCE_CONFIGURATION.md"
