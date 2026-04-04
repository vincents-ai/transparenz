// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cucumber/godog"
)

// RegisterEnrichmentSteps registers SBOM enrichment and hash-related step definitions.
func RegisterEnrichmentSteps(s *godog.ScenarioContext) {
	s.Step(`^a test binary exists in the artifacts directory$`, aTestBinaryExistsInTheArtifactsDirectory)
	s.Step(`^the enriched SBOM has SHA-512 hashes$`, theEnrichedSBOMHasSHA512Hashes)
	s.Step(`^an SBOM file exists with SHA-256 only hashes$`, anSBOMFileExistsWithSHA256OnlyHashes)
	s.Step(`^the report flags SHA-256-only as non-compliant$`, theReportFlagsSHA256OnlyAsNonCompliant)
}

// ─── Step implementations ─────────────────────────────────────────────────────

func aTestBinaryExistsInTheArtifactsDirectory(ctx context.Context) error {
	artDir := filepath.Join(getTmpDir(ctx), "artifacts")
	if err := os.MkdirAll(artDir, 0755); err != nil {
		return err
	}
	testBin := filepath.Join(artDir, "test-binary")
	return os.WriteFile(testBin, []byte("test binary content for SHA-512"), 0755)
}

func theEnrichedSBOMHasSHA512Hashes(ctx context.Context) error {
	sbomPath := filepath.Join(getTmpDir(ctx), "sbom-enriched.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		out, _ := ctx.Value(KeyCmdOut).(string)
		if out != "" {
			data = []byte(out)
		} else {
			return fmt.Errorf("no enriched SBOM found")
		}
	}
	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("enriched SBOM is not valid JSON: %w", err)
	}
	components, ok := sbom["components"].([]interface{})
	if !ok {
		return fmt.Errorf("no components in enriched SBOM")
	}
	for _, c := range components {
		comp, _ := c.(map[string]interface{})
		if comp == nil {
			continue
		}
		if hashes, ok := comp["hashes"].([]interface{}); ok {
			for _, h := range hashes {
				hMap, _ := h.(map[string]interface{})
				if hMap != nil && hMap["alg"] == "SHA-512" {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("no SHA-512 hashes found in enriched SBOM")
}

func anSBOMFileExistsWithSHA256OnlyHashes(ctx context.Context) error {
	sbom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata":    map[string]interface{}{},
		"components": []interface{}{
			map[string]interface{}{
				"name":    "test-component",
				"version": "1.0.0",
				"type":    "library",
				"hashes": []interface{}{
					map[string]interface{}{
						"alg":     "SHA-256",
						"content": "abc123",
					},
				},
			},
		},
	}
	data, _ := json.Marshal(sbom)
	return os.WriteFile(filepath.Join(getTmpDir(ctx), "sbom.json"), data, 0644)
}

func theReportFlagsSHA256OnlyAsNonCompliant(ctx context.Context) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON not available")
	}
	if hashSha256Only, ok := m["hash_sha256_only"].(float64); ok && hashSha256Only > 0 {
		return nil
	}
	if hashCoverage, ok := m["hash_coverage"].(float64); ok && hashCoverage < 100 {
		return nil
	}
	return fmt.Errorf("SHA-256-only components not flagged as non-compliant")
}

// getTmpDir retrieves the per-scenario temp directory from context.
func getTmpDir(ctx context.Context) string {
	if d, ok := ctx.Value(KeyTmpDir).(string); ok {
		return d
	}
	return os.TempDir()
}
