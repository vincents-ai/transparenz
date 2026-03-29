#!/bin/sh

set -e

CLI="../transparenz"
TESTDATA="./testdata"
PASSED=0
FAILED=0

echo "========================================="
echo "CLI Integration Tests"
echo "========================================="
echo ""

test_cmd() {
    name="$1"
    shift
    echo -n "Testing: $name ... "
    if "$CLI" "$@" > /dev/null 2>&1; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

test_cmd_fail() {
    name="$1"
    shift
    echo -n "Testing: $name (should fail) ... "
    if "$CLI" "$@" > /dev/null 2>&1; then
        echo "FAIL"
        FAILED=$((FAILED + 1))
    else
        echo "PASS"
        PASSED=$((PASSED + 1))
    fi
}

test_output() {
    name="$1"
    expected="$2"
    shift 2
    echo -n "Testing: $name ... "
    output=$("$CLI" "$@" 2>&1)
    if echo "$output" | grep -q "$expected"; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (expected: $expected)"
        FAILED=$((FAILED + 1))
    fi
}

test_output_fail() {
    name="$1"
    expected="$2"
    shift 2
    echo -n "Testing: $name (should fail) ... "
    output=$("$CLI" "$@" 2>&1) || true
    if echo "$output" | grep -qi "$expected"; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (expected error containing: $expected, got: $output)"
        FAILED=$((FAILED + 1))
    fi
}

test_output "version" "0.1.0" --version
test_output "help" "SBOM" --help

test_cmd "generate SPDX" generate "$TESTDATA" -f spdx
test_cmd "generate CycloneDX" generate "$TESTDATA" -f cyclonedx

echo -n "Testing: generate with output file ... "
OUTPUT_FILE="$TESTDATA/sbom_test_output.json"
rm -f "$OUTPUT_FILE"
if "$CLI" generate "$TESTDATA" -o "$OUTPUT_FILE" > /dev/null 2>&1 && [ -f "$OUTPUT_FILE" ]; then
    echo "PASS"
    PASSED=$((PASSED + 1))
    rm -f "$OUTPUT_FILE"
else
    echo "FAIL"
    FAILED=$((FAILED + 1))
fi

test_cmd "bsi-check SPDX" bsi-check "$TESTDATA/sbom.spdx.json"
test_cmd "bsi-check CycloneDX" bsi-check "$TESTDATA/sbom.cyclonedx.json"

test_cmd_fail "scan non-existent" scan nonexistent.json

test_output_fail "scan SPDX (no db)" "database" scan "$TESTDATA/sbom.spdx.json" -f json

test_cmd_fail "db migrate (no db)" db migrate

echo ""
echo "========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "========================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
