// Package depfetch pre-fetches dependencies for all supported ecosystems before
// SBOM generation so that the license classifier can locate license files in
// the local package/module cache.
//
// Without a warm dependency cache many dependencies lack license information
// (e.g. argo-cd scores 21% instead of ~80%) because the classifier cannot open
// the license file from the on-disk module cache that does not yet exist.
//
// Fetch is deliberately best-effort: a missing ecosystem tool (go, npm, cargo,
// etc.) is a warning, not a fatal error.  The SBOM generation continues with
// whatever is already cached.
package depfetch

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// fetcher holds the configuration for a single ecosystem fetch operation.
type fetcher struct {
	// name is a human-readable label used in log output.
	name string

	// manifests is the list of filename patterns that indicate this ecosystem
	// is present in a directory.  Any match triggers the fetch.
	manifests []string

	// cmd is the primary command to run in the matched directory.
	cmd []string

	// fallbacks are alternative commands tried in order if the primary tool is
	// not on PATH (e.g. yarn/pnpm as fallbacks for npm).
	fallbacks [][]string
}

// allFetchers is the ordered list of all supported ecosystem fetchers.
var allFetchers = []fetcher{
	{
		name:      "Go",
		manifests: []string{"go.mod"},
		cmd:       []string{"go", "mod", "download"},
	},
	{
		name:      "Node.js",
		manifests: []string{"package.json"},
		cmd:       []string{"npm", "ci", "--ignore-scripts", "--prefer-offline"},
		fallbacks: [][]string{
			{"yarn", "install", "--frozen-lockfile", "--ignore-scripts"},
			{"pnpm", "install", "--frozen-lockfile", "--ignore-scripts"},
		},
	},
	{
		name:      "Python",
		manifests: []string{"requirements.txt"},
		cmd:       []string{"pip", "install", "--quiet", "-r", "requirements.txt"},
	},
	{
		name:      "Python (pyproject)",
		manifests: []string{"pyproject.toml"},
		cmd:       []string{"pip", "install", "--quiet", "."},
	},
	{
		name:      "Python (setup.py)",
		manifests: []string{"setup.py"},
		cmd:       []string{"pip", "install", "--quiet", "."},
	},
	{
		name:      "Rust",
		manifests: []string{"Cargo.toml"},
		cmd:       []string{"cargo", "fetch"},
	},
	{
		name:      "Maven",
		manifests: []string{"pom.xml"},
		cmd:       []string{"mvn", "dependency:resolve", "-q", "--batch-mode"},
	},
	{
		name:      "Gradle",
		manifests: []string{"build.gradle", "build.gradle.kts"},
		cmd:       []string{"gradle", "dependencies", "-q"},
	},
	{
		name:      "Ruby",
		manifests: []string{"Gemfile"},
		cmd:       []string{"bundle", "install"},
	},
	{
		name:      "PHP",
		manifests: []string{"composer.json"},
		cmd:       []string{"composer", "install", "--no-scripts", "--no-interaction", "-q"},
	},
	{
		name:      ".NET",
		manifests: []string{"*.csproj", "*.sln"},
		cmd:       []string{"dotnet", "restore"},
	},
}

// result holds the outcome of a single fetch operation.
type result struct {
	dir     string
	fetcher string
	err     error
	skipped bool // tool not found on PATH
}

// Fetch walks sourcePath, detects ecosystem manifest files, and runs the
// appropriate dependency-fetch command for each detected ecosystem directory.
// All fetches run concurrently.  Errors from individual fetchers are printed
// as warnings to stderr (when verbose=true) but never abort execution.
//
// Fetch is a no-op when sourcePath is empty or does not exist.
func Fetch(ctx context.Context, sourcePath string, verbose bool) {
	if sourcePath == "" {
		return
	}
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return
	}

	jobs := discoverJobs(sourcePath)
	if len(jobs) == 0 {
		return
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[depfetch] discovered %d fetch job(s) in %s\n", len(jobs), sourcePath)
	}

	results := runJobs(ctx, jobs, verbose)

	for _, r := range results {
		if r.skipped {
			if verbose {
				fmt.Fprintf(os.Stderr, "[depfetch] skipped %s in %s: tool not found on PATH\n", r.fetcher, r.dir)
			}
			continue
		}
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "[depfetch] warning: %s fetch failed in %s: %v\n", r.fetcher, r.dir, r.err)
			continue
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[depfetch] %s dependencies fetched in %s\n", r.fetcher, r.dir)
		}
	}
}

// job represents a single (directory, fetcher) pair to execute.
type job struct {
	dir     string
	fetcher fetcher
}

// discoverJobs walks the directory tree and builds the list of fetch jobs.
// Each directory is checked against every fetcher's manifest list.
// A directory that matches multiple fetchers (e.g. both go.mod and
// Cargo.toml) produces one job per fetcher.
func discoverJobs(root string) []job {
	var jobs []job

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !d.IsDir() {
			return nil
		}
		// Skip hidden directories (e.g. .git, .cache).
		if len(d.Name()) > 1 && d.Name()[0] == '.' {
			return filepath.SkipDir
		}
		// Skip common vendored / generated directories.
		switch d.Name() {
		case "vendor", "node_modules", "target", ".gradle":
			return filepath.SkipDir
		}

		for _, f := range allFetchers {
			if dirMatchesFetcher(path, f) {
				jobs = append(jobs, job{dir: path, fetcher: f})
			}
		}
		return nil
	})

	return jobs
}

// dirMatchesFetcher returns true if the directory contains at least one file
// matching any of the fetcher's manifest patterns.
func dirMatchesFetcher(dir string, f fetcher) bool {
	for _, pattern := range f.manifests {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

// runJobs executes all jobs concurrently and collects results.
func runJobs(ctx context.Context, jobs []job, verbose bool) []result {
	results := make([]result, len(jobs))
	var wg sync.WaitGroup

	for i, j := range jobs {
		wg.Add(1)
		go func(idx int, j job) {
			defer wg.Done()
			results[idx] = runJob(ctx, j, verbose)
		}(i, j)
	}

	wg.Wait()
	return results
}

// runJob executes the fetch command for a single job, trying fallbacks when
// the primary tool is absent from PATH.
func runJob(ctx context.Context, j job, verbose bool) result {
	r := result{dir: j.dir, fetcher: j.fetcher.name}

	commands := [][]string{j.fetcher.cmd}
	commands = append(commands, j.fetcher.fallbacks...)

	for _, args := range commands {
		tool := args[0]
		if _, err := exec.LookPath(tool); err != nil {
			// This specific tool is not on PATH; try next fallback.
			continue
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "[depfetch] running: %v in %s\n", args, j.dir)
		}

		cmd := exec.CommandContext(ctx, tool, args[1:]...)
		cmd.Dir = j.dir
		// Discard stdout; forward stderr only when verbose.
		cmd.Stdout = nil
		if verbose {
			cmd.Stderr = os.Stderr
		} else {
			cmd.Stderr = nil
		}

		r.err = cmd.Run()
		return r
	}

	// No tool found on PATH for any variant.
	r.skipped = true
	return r
}
