#!/usr/bin/env bash
# SBOM Generation Integration Test Script
# Tests transparenz CLI SBOM generation with various formats

set -e

TEST_DIR="/tmp/transparenz-sbom-test"
SBOM_OUTPUT_DIR="$TEST_DIR/output"

setup() {
    echo "=== Setting up test environment ==="
    mkdir -p "$SBOM_OUTPUT_DIR"
    cd "$TEST_DIR"
}

cleanup() {
    echo "=== Cleaning up test artifacts ==="
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

test_help_command() {
    echo "=== Test: CLI help command ==="
    if transparenz --help | grep -q "SBOM generator"; then
        echo "PASS: Help command works"
        return 0
    else
        echo "FAIL: Help command failed"
        return 1
    fi
}

test_version_command() {
    echo "=== Test: CLI version command ==="
    if transparenz version | grep -q "0.1.0"; then
        echo "PASS: Version command works"
        return 0
    else
        echo "FAIL: Version command failed"
        return 1
    fi
}

test_generate_spdx() {
    echo "=== Test: Generate SPDX SBOM ==="
    local output_file="$SBOM_OUTPUT_DIR/sbom-spdx.json"
    
    if transparenz generate . --format spdx --output "$output_file" 2>&1; then
        if [ -f "$output_file" ] && jq -e '.spdxVersion' "$output_file" > /dev/null 2>&1; then
            echo "PASS: SPDX generation successful"
            return 0
        else
            echo "FAIL: SPDX output invalid"
            return 1
        fi
    else
        echo "FAIL: SPDX generation failed"
        return 1
    fi
}

test_generate_cyclonedx() {
    echo "=== Test: Generate CycloneDX SBOM ==="
    local output_file="$SBOM_OUTPUT_DIR/sbom-cyclonedx.json"
    
    if transparenz generate . --format cyclonedx --output "$output_file" 2>&1; then
        if [ -f "$output_file" ] && jq -e '.bomFormat' "$output_file" > /dev/null 2>&1; then
            echo "PASS: CycloneDX generation successful"
            return 0
        else
            echo "FAIL: CycloneDX output invalid"
            return 1
        fi
    else
        echo "FAIL: CycloneDX generation failed"
        return 1
    fi
}

test_bsi_compliant() {
    echo "=== Test: BSI TR-03183 compliant generation ==="
    local output_file="$SBOM_OUTPUT_DIR/sbom-bsi.json"
    
    if transparenz generate . --bsi-compliant --format cyclonedx --output "$output_file" 2>&1; then
        if [ -f "$output_file" ]; then
            if jq -e '.metadata.component.properties' "$output_file" > /dev/null 2>&1; then
                echo "PASS: BSI compliant generation successful"
                return 0
            else
                echo "FAIL: BSI output missing properties"
                return 1
            fi
        else
            echo "FAIL: BSI output file not created"
            return 1
        fi
    else
        echo "FAIL: BSI compliant generation failed"
        return 1
    fi
}

test_verbose_mode() {
    echo "=== Test: Verbose mode ==="
    
    if transparenz --verbose generate . --format spdx --output "$SBOM_OUTPUT_DIR/sbom-verbose.json" 2>&1 | grep -q "Generating SBOM"; then
        echo "PASS: Verbose mode works"
        return 0
    else
        echo "FAIL: Verbose mode failed"
        return 1
    fi
}

run_all_tests() {
    setup
    
    local failed=0
    
    test_help_command || ((failed++))
    test_version_command || ((failed++))
    test_generate_spdx || ((failed++))
    test_generate_cyclonedx || ((failed++))
    test_bsi_compliant || ((failed++))
    test_verbose_mode || ((failed++))
    
    echo ""
    echo "=== Test Summary ==="
    if [ $failed -eq 0 ]; then
        echo "All tests passed!"
        return 0
    else
        echo "$failed test(s) failed"
        return 1
    fi
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: $0"
    echo ""
    echo "Tests the transparenz CLI SBOM generation functionality"
    echo ""
    echo "The script creates a temporary test directory and generates SBOMs"
    echo "in various formats (SPDX, CycloneDX) and validates the output."
    exit 0
fi

run_all_tests
