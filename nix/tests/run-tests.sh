#!/usr/bin/env bash
# Test runner for Transparenz Go NixOS integration tests

set -e

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE_DIR="$(dirname "$TESTS_DIR")"

show_help() {
    cat << EOF
Transparenz Go NixOS Integration Test Runner

Usage: $0 [OPTIONS] [TEST]

OPTIONS:
    -h, --help          Show this help message
    -l, --list          List available tests
    -v, --verbose       Enable verbose output

TESTS:
    cli                 CLI integration tests
    database            Database integration tests (PostgreSQL)
    bsi                 BSI TR-03183-2 compliance tests
    vulnz               Vulnerability database sync tests
    e2e                 End-to-end tests
    all                 Run all tests (default)

EXAMPLES:
    $0                  # Run all tests
    $0 cli              # Run CLI tests only
    $0 -l              # List available tests
    $0 database bsi     # Run database and BSI tests

EOF
}

list_tests() {
    echo "Available NixOS Integration Tests:"
    echo ""
    echo "  cli       - CLI integration tests"
    echo "  database  - Database integration tests (PostgreSQL)"
    echo "  bsi       - BSI TR-03183-2 compliance tests"
    echo "  vulnz     - Vulnerability database sync tests"
    echo "  e2e       - End-to-end tests"
    echo ""
}

run_test() {
    local test_name=$1
    local test_path=".#hydraJobs.tests.transparenz-go-${test_name}.x86_64-linux"
    
    echo "Running ${test_name} tests..."
    echo "Command: nix run ${test_path}"
    echo ""
    
    cd "$FLAKE_DIR"
    nix run "$test_path"
}

run_all_tests() {
    echo "Running all NixOS integration tests..."
    echo ""
    
    cd "$FLAKE_DIR"
    
    for test in cli database bsi vulnz e2e; do
        echo "=========================================="
        echo "Running: ${test}"
        echo "=========================================="
        nix run ".#hydraJobs.tests.transparenz-go-${test}.x86_64-linux"
        echo ""
        echo ""
    done
    
    echo "=========================================="
    echo "All tests completed!"
    echo "=========================================="
}

VERBOSE=false
TESTS=("all")

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            list_tests
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        cli|database|bsi|vulnz|e2e|all)
            TESTS=("$1")
            shift
            ;;
        *)
            echo "Unknown test: $1"
            show_help
            exit 1
            ;;
    esac
done

if [[ "${TESTS[0]}" == "all" ]]; then
    run_all_tests
else
    for test in "${TESTS[@]}"; do
        run_test "$test"
    done
fi
