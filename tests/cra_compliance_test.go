// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

// Package bdd contains the BDD test entry point for CRA/BSI TR-03183-2 compliance.
// Step definitions are organised by domain in the steps/ sub-package.
package bdd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/shift/transparenz/tests/steps"
)

var prebuiltBinary string

// TestMain builds the transparenz binary once and creates a minimal test project
// for all BDD scenarios to reuse.
func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "cra-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	prebuiltBinary = filepath.Join(tmpDir, "transparenz")
	cmd := exec.Command("go", "build", "-o", prebuiltBinary, "..")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build binary: %v\n", err)
		os.Exit(1)
	}

	// Minimal Go project — used as the generate target in SBOM scenarios.
	testProject := filepath.Join(tmpDir, "test-project")
	os.MkdirAll(testProject, 0755)
	os.WriteFile(filepath.Join(testProject, "go.mod"), []byte(
		"module example.com/test\ngo 1.22.0\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgithub.com/spf13/cobra v1.10.2\n\tgolang.org/x/text v0.14.0\n)\n",
	), 0644)
	os.WriteFile(filepath.Join(testProject, "main.go"), []byte(
		"package main\n\nimport _ \"github.com/google/uuid\"\nimport _ \"github.com/spf13/cobra\"\n\nfunc main() {}\n",
	), 0644)

	os.Exit(m.Run())
}

// TestCRACompliance is the godog entry point.
func TestCRACompliance(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(s *godog.ScenarioContext) {
			s.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
				ctx = context.WithValue(ctx, steps.KeyTmpDir, t.TempDir())
				return ctx, nil
			})
			InitializeScenario(s)
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

// InitializeScenario registers all step definitions across domain packages.
func InitializeScenario(s *godog.ScenarioContext) {
	// Common/runner steps defined in this file.
	s.Step(`^the transparenz binary is built$`, theTransparenzBinaryIsBuilt)
	s.Step(`^I run "([^"]*)"$`, iRun)
	s.Step(`^the command succeeds$`, theCommandSucceeds)
	s.Step(`^the command fails$`, theCommandFails)

	// Domain step sets.
	steps.RegisterSBOMSteps(s)
	steps.RegisterBSISteps(s)
	steps.RegisterEnrichmentSteps(s)
}

// ─── Common runner steps ──────────────────────────────────────────────────────

func theTransparenzBinaryIsBuilt(_ context.Context) error {
	if _, err := os.Stat(prebuiltBinary); err != nil {
		return fmt.Errorf("prebuilt binary not found: %w", err)
	}
	return nil
}

func iRun(ctx context.Context, command string) (context.Context, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ctx, fmt.Errorf("empty command")
	}

	if parts[0] == "transparenz" {
		parts[0] = prebuiltBinary
	}

	for i, p := range parts {
		if (p == "." || p == "/test-project") && i > 0 {
			parts[i] = getTestProject()
		}
	}

	tmpDir := getTmpDir(ctx)
	for i, p := range parts {
		if p == "-o" || p == "--output" || p == "--artifacts" || p == "--binary" {
			if i+1 < len(parts) && !filepath.IsAbs(parts[i+1]) {
				parts[i+1] = filepath.Join(tmpDir, parts[i+1])
			}
		}
		if p == "sbom.json" {
			parts[i] = filepath.Join(tmpDir, "sbom.json")
		}
		if p == "artifacts/" || p == "artifacts" {
			parts[i] = filepath.Join(tmpDir, "artifacts")
		}
		if strings.HasPrefix(p, "artifacts/") {
			parts[i] = filepath.Join(tmpDir, p)
		}
	}

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Dir = getTestProject()

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	outBytes := []byte(stdout.String())
	ctx = context.WithValue(ctx, steps.KeyCmdOut, string(outBytes))
	ctx = context.WithValue(ctx, steps.KeyCmdErr, err)

	var data interface{}
	if json.Unmarshal(outBytes, &data) == nil {
		ctx = context.WithValue(ctx, steps.KeyJSON, data)
	}

	for i, p := range parts {
		if (p == "-o" || p == "--output") && i+1 < len(parts) {
			if fileData, readErr := os.ReadFile(parts[i+1]); readErr == nil {
				var fileJSON interface{}
				if json.Unmarshal(fileData, &fileJSON) == nil {
					ctx = context.WithValue(ctx, steps.KeyJSON, fileJSON)
				}
				ctx = context.WithValue(ctx, steps.KeyReportJSON, fileJSON)
			}
			break
		}
	}

	if strings.Contains(command, "bsi-check") {
		var reportData interface{}
		if json.Unmarshal(outBytes, &reportData) == nil {
			ctx = context.WithValue(ctx, steps.KeyReportJSON, reportData)
		}
	}

	return ctx, nil
}

func theCommandSucceeds(ctx context.Context) error {
	if err, ok := ctx.Value(steps.KeyCmdErr).(error); ok && err != nil {
		out, _ := ctx.Value(steps.KeyCmdOut).(string)
		return fmt.Errorf("command failed: %w\nOutput: %s", err, out)
	}
	return nil
}

func theCommandFails(ctx context.Context) error {
	err, ok := ctx.Value(steps.KeyCmdErr).(error)
	if !ok || err == nil {
		return fmt.Errorf("expected command to fail but it succeeded")
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func getTmpDir(ctx context.Context) string {
	if d, ok := ctx.Value(steps.KeyTmpDir).(string); ok {
		return d
	}
	return os.TempDir()
}

// getTestProject returns the path to the pre-created minimal test project.
func getTestProject() string {
	if prebuiltBinary == "" {
		return "."
	}
	return filepath.Join(filepath.Dir(prebuiltBinary), "test-project")
}
