package depfetch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// writeTempFile creates a file with the given name inside dir and returns the path.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	return p
}

// TestDirMatchesFetcher_Go checks go.mod detection.
func TestDirMatchesFetcher_Go(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.21\n")

	goFetcher := allFetchers[0] // Go is first in the list
	if goFetcher.name != "Go" {
		t.Fatalf("expected Go fetcher at index 0, got %q", goFetcher.name)
	}

	if !dirMatchesFetcher(dir, goFetcher) {
		t.Error("expected go.mod to match Go fetcher")
	}
}

// TestDirMatchesFetcher_NoMatch verifies empty dirs don't match.
func TestDirMatchesFetcher_NoMatch(t *testing.T) {
	dir := t.TempDir()

	for _, f := range allFetchers {
		if dirMatchesFetcher(dir, f) {
			t.Errorf("empty dir should not match fetcher %q", f.name)
		}
	}
}

// TestDirMatchesFetcher_NodeJS checks package.json detection.
func TestDirMatchesFetcher_NodeJS(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "package.json", `{"name":"test"}`)

	var nodeFetcher *fetcher
	for i := range allFetchers {
		if allFetchers[i].name == "Node.js" {
			nodeFetcher = &allFetchers[i]
			break
		}
	}
	if nodeFetcher == nil {
		t.Fatal("Node.js fetcher not found")
	}
	if !dirMatchesFetcher(dir, *nodeFetcher) {
		t.Error("expected package.json to match Node.js fetcher")
	}
}

// TestDiscoverJobs_SingleGoMod ensures a directory with go.mod produces exactly
// one Go job.
func TestDiscoverJobs_SingleGoMod(t *testing.T) {
	root := t.TempDir()
	writeTempFile(t, root, "go.mod", "module example.com/test\n\ngo 1.21\n")

	jobs := discoverJobs(root)
	if len(jobs) == 0 {
		t.Fatal("expected at least one job for go.mod")
	}

	var found bool
	for _, j := range jobs {
		if j.fetcher.name == "Go" && j.dir == root {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a Go job for %s, got: %v", root, jobs)
	}
}

// TestDiscoverJobs_Nested verifies sub-directories are discovered recursively.
func TestDiscoverJobs_Nested(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, sub, "go.mod", "module example.com/sub\n\ngo 1.21\n")

	jobs := discoverJobs(root)
	var found bool
	for _, j := range jobs {
		if j.fetcher.name == "Go" && j.dir == sub {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Go job for nested sub, got: %v", jobs)
	}
}

// TestDiscoverJobs_SkipsNodeModules ensures node_modules is not descended into.
func TestDiscoverJobs_SkipsNodeModules(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	if err := os.Mkdir(nm, 0755); err != nil {
		t.Fatal(err)
	}
	// Place a go.mod inside node_modules – should NOT be discovered.
	writeTempFile(t, nm, "go.mod", "module example.com/nm\n\ngo 1.21\n")

	jobs := discoverJobs(root)
	for _, j := range jobs {
		if j.dir == nm {
			t.Errorf("job inside node_modules should be skipped: %v", j)
		}
	}
}

// TestDiscoverJobs_SkipsVendor ensures vendor/ is not descended into.
func TestDiscoverJobs_SkipsVendor(t *testing.T) {
	root := t.TempDir()
	v := filepath.Join(root, "vendor")
	if err := os.Mkdir(v, 0755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, v, "go.mod", "module example.com/vendor\n\ngo 1.21\n")

	jobs := discoverJobs(root)
	for _, j := range jobs {
		if j.dir == v {
			t.Errorf("job inside vendor/ should be skipped: %v", j)
		}
	}
}

// TestRunJob_ToolNotFound checks that a missing tool sets skipped=true.
func TestRunJob_ToolNotFound(t *testing.T) {
	dir := t.TempDir()
	j := job{
		dir: dir,
		fetcher: fetcher{
			name:      "FakeTool",
			manifests: []string{"fake.manifest"},
			cmd:       []string{"this-tool-definitely-does-not-exist-abc123"},
		},
	}

	r := runJob(context.Background(), j, false)
	if !r.skipped {
		t.Errorf("expected skipped=true for missing tool, got err=%v", r.err)
	}
}

// TestFetch_EmptyPath verifies Fetch does not panic on empty sourcePath.
func TestFetch_EmptyPath(t *testing.T) {
	// Should be a no-op without panicking.
	Fetch(context.Background(), "", false)
}

// TestFetch_NonExistentPath verifies Fetch handles a non-existent directory.
func TestFetch_NonExistentPath(t *testing.T) {
	Fetch(context.Background(), "/this/path/does/not/exist/abc123", false)
}

// TestFetch_GoModDownload runs Fetch on a temp dir with a go.mod file and
// verifies it does not return an error on a machine that has 'go' on PATH.
// The module has no dependencies so 'go mod download' is a no-op that exits 0.
func TestFetch_GoModDownload(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}

	root := t.TempDir()
	writeTempFile(t, root, "go.mod", "module example.com/test\n\ngo 1.21\n")

	// Should complete without error.
	Fetch(context.Background(), root, true)
	// No assertion needed – if it panics or logs a fatal error, the test fails.
}
