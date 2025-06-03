#!/bin/bash
# Batched test runner for Noise Protocol Framework
# This script runs tests in smaller batches to avoid resource exhaustion

set -e

echo "🧪 Running Noise Protocol Framework Tests in Batches..."
echo "📊 Test suite: 103 tests (cryptographic, fuzz, async, and integration)"
echo "🔄 Running in batches to prevent resource exhaustion"
echo ""

# Track overall success
OVERALL_SUCCESS=0
TOTAL_TESTS=0
PASSED_TESTS=0

# Define test suites to run in batches
SUITES=(
    "HandshakePatternTests"
    "CryptographicTests"
    "ErrorHandlingTests"
    "PSKTests"
    "TestVectorTests"
    "RekeyingTests"
    "AsyncTests"
    "ActorAsyncTests"
    "FuzzTests"
    "AdvancedFailureTests"
)

echo "📦 Running test suites in batches..."

for suite in "${SUITES[@]}"; do
    echo ""
    echo "🔍 Running suite: $suite"
    
    if swift test --parallel --filter "$suite" 2>/dev/null; then
        echo "✅ $suite passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ $suite failed"
        OVERALL_SUCCESS=1
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Small delay between batches to prevent resource issues
    sleep 0.1
done

echo ""
echo "📈 Results Summary:"
echo "   Passed: $PASSED_TESTS/$TOTAL_TESTS suites"

if [ $OVERALL_SUCCESS -eq 0 ]; then
    echo "✅ All test suites completed successfully!"
    echo "🔒 Noise Protocol Framework is ready for secure communication."
else
    echo "❌ Some test suites failed."
    exit 1
fi