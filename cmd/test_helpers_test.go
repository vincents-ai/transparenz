package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testdata = "./testdata"

func getTestDir(t *testing.T) string {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	if filepath.Base(cwd) == "cmd" {
		return filepath.Dir(cwd)
	}

	if filepath.Base(cwd) == "transparenz-go" {
		return cwd
	}

	return cwd
}

func getCLIBinary(t *testing.T) string {
	return filepath.Join(getTestDir(t), "transparenz")
}

func requireCLIBinary(t *testing.T) string {
	t.Helper()
	cliBin := getCLIBinary(t)
	if _, err := os.Stat(cliBin); os.IsNotExist(err) {
		t.Skipf("transparenz binary not found at %s; run 'go build -o transparenz .' first", cliBin)
	}
	return cliBin
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
