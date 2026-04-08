#!/usr/bin/env bash
set -euo pipefail

# Usage: run-bdd-tests.sh [feature files...]
# Runs Godog BDD tests against the compiled transparenz binary.
# Designed for GitLab CI and local development.

BINARY="${TRANSPARENZ_BINARY:-./transparenz}"
FEATURE_FILES="${*:-features/*.feature}"
RESULTS_DIR="${RESULTS_DIR:-test-results}"

if [ ! -f "$BINARY" ]; then
  echo "ERROR: binary $BINARY not found. Build first: go build -o transparenz ."
  exit 1
fi

mkdir -p "$RESULTS_DIR"

echo "Running BDD tests: $FEATURE_FILES"
go test ./tests/... -v -tags bdd -args -godog.format=pretty -godog.paths="$FEATURE_FILES" 2>&1 | tee "$RESULTS_DIR/bdd-output.txt"
