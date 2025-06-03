#!/bin/bash
# Test runner script for Noise Protocol Framework
# This script ensures reliable test execution by using proper parallelization

set -e

echo "🧪 Running Noise Protocol Framework Tests..."
echo "📊 Test suite: 103 tests (cryptographic, fuzz, async, and integration)"
echo ""

# Run tests with parallel execution to avoid resource exhaustion
swift test --parallel "$@"

echo ""
echo "✅ All tests completed successfully!"
echo "🔒 Noise Protocol Framework is ready for secure communication."