// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package steps

// ContextKey is the type for BDD scenario context keys.
// Using a named type prevents collisions with other packages.
type ContextKey string

const (
	KeyTmpDir     ContextKey = "tmpDir"
	KeyCmdOut     ContextKey = "cmdOut"
	KeyCmdErr     ContextKey = "cmdErr"
	KeyJSON       ContextKey = "json"
	KeyReportJSON ContextKey = "reportJSON"
	KeySBOMPath   ContextKey = "sbomPath"
)
