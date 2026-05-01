// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package pbt_test

import (
	"testing"

	"github.com/vincents-ai/transparenz/cmd"
	"github.com/vincents-ai/transparenz/pkg/sbom"
)

func FuzzParseSBOM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		parser := sbom.NewParser(false)
		_, _ = parser.ParseFile(data)
	})
}

func FuzzBSICheck(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = cmd.RunBSICheck(string(data))
	})
}
