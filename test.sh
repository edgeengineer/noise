#!/bin/bash
# Test runner script for Noise Protocol Framework
# This script ensures reliable test execution

set -e

echo "🧪 Running Noise Protocol Framework Tests..."
echo "📊 Test suite: 103 tests (cryptographic, fuzz, async, and integration)"
echo ""

# Check if user wants to force full parallel execution (risky)
if [[ "$1" == "--force-parallel" ]]; then
    echo "⚠️  Running all tests in parallel (may be unstable)"
    shift
    swift test --parallel "$@"
else
    echo "🛡️  Running in stable mode (batched execution)"
    echo "    Use --force-parallel to run all tests concurrently (risky)"
    echo ""
    ./test-stable.sh
fi