// Command build-manifest generates the web client integrity manifest
// It is invoked from the release workflow after `pnpm run build` / `go generate`
// The resulting file is signed with cosign and embedded in the server binary
//
//nolint:forbidigo
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/italypaleale/revaulter/pkg/integrity"
)

func main() {
	var (
		distDir   string
		outPath   string
		version   string
		commit    string
		buildDate string
	)

	flag.StringVar(&distDir, "dist", "", "Path to the dist directory to hash (required)")
	flag.StringVar(&outPath, "out", "", "Output file path (required)")
	flag.StringVar(&version, "version", "", "Build version (empty for commit-only manifest)")
	flag.StringVar(&commit, "commit", "", "Commit hash (required)")
	flag.StringVar(&buildDate, "build-date", "", "Build date in RFC3339 (required)")
	flag.Parse()

	err := run(distDir, outPath, version, commit, buildDate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build-manifest:", err)
		os.Exit(1)
	}
}

func run(distDir, outPath, version, commit, buildDate string) error {
	if distDir == "" {
		return errors.New("--dist is required")
	}
	if outPath == "" {
		return errors.New("--out is required")
	}

	// BuildFromFS expects the root path to be reachable inside the fs.FS
	// We use os.DirFS rooted at distDir and walk "." (the whole tree)
	fsys := os.DirFS(distDir)

	manifest, err := integrity.BuildFromFS(fsys, ".", version, commit, buildDate)
	if err != nil {
		return fmt.Errorf("build manifest: %w", err)
	}

	// Permissions 0644 are appropriate here
	//nolint:gosec
	err = os.WriteFile(outPath, manifest.Marshal(), 0o644)
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "build-manifest: wrote %d files, %d bytes, to %s\n", len(manifest.Files), len(manifest.Marshal()), outPath)
	return nil
}
