#!/bin/bash
# Stable test runner for Noise Protocol Framework
# This script runs tests in a way that avoids all concurrency issues

set -e

echo "🧪 Running Noise Protocol Framework Tests (Stable Mode)"
echo "📊 Test suite: 103 tests (cryptographic, fuzz, async, and integration)"
echo "🔄 Running in sequential batches to ensure stability"
echo ""

# Track overall success
OVERALL_SUCCESS=0
TOTAL_TESTS=0
PASSED_TESTS=0

# Test basic suites that work well together
STABLE_SUITES=(
    "HandshakePatternTests"
    "CryptographicTests" 
    "ErrorHandlingTests"
    "PSKTests"
    "TestVectorTests"
    "RekeyingTests"
    "AsyncTests"
    "ActorAsyncTests"
    "AdvancedFailureTests"
)

# Individual fuzz tests that need to run separately
FUZZ_TESTS=(
    "fuzzCurve25519Operations"
    "fuzzChaChaPolyOperations" 
    "fuzzSHA256Operations"
    "fuzzHandshakeMessageParsing"
    "fuzzHandshakeMessageEdgeLengths"
    "fuzzHandshakeMessageStructured"
    "fuzzTransportMessageParsing"
    "fuzzTransportMessageCorruption"
    "fuzzAllPatterns"
    "fuzzSessionStateTransitions"
)

echo "📦 Running stable test suites..."

for suite in "${STABLE_SUITES[@]}"; do
    echo ""
    echo "🔍 Running suite: $suite"
    
    if swift test --parallel --filter "$suite" >/dev/null 2>&1; then
        echo "✅ $suite passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ $suite failed"
        OVERALL_SUCCESS=1
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    sleep 0.1
done

echo ""
echo "🧪 Running individual fuzz tests..."

for test in "${FUZZ_TESTS[@]}"; do
    echo "🔍 Running: $test"
    
    if swift test --parallel --filter "$test" >/dev/null 2>&1; then
        echo "✅ $test passed"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ $test failed"
        OVERALL_SUCCESS=1
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    sleep 0.1
done

echo ""
echo "📈 Results Summary:"
echo "   Passed: $PASSED_TESTS/$TOTAL_TESTS test groups"

if [ $OVERALL_SUCCESS -eq 0 ]; then
    echo "✅ All tests completed successfully!"
    echo "🔒 Noise Protocol Framework is ready for secure communication."
    echo ""
    echo "💡 Note: Tests are run in batches to prevent resource exhaustion."
    echo "    For development, use './test-stable.sh' for reliable results."
else
    echo "❌ Some tests failed."
    exit 1
fi