// Package integrity provides shared types and helpers for the web client asset integrity manifest
// The manifest lists every file under client/web/dist/ with its sha256 and size, plus version / commit / build-date metadata
// It is emitted at release time, signed with cosign keyless, embedded in the server binary, and verified by `revaulter-cli check`
package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Manifest describes the contents of a web client `dist/` directory at a specific build
// Its serialized form (see Marshal) is what gets signed
type Manifest struct {
	// Build version (may be empty for dev builds where no version is available)
	Version string
	// Commit hash (short, as set by the build pipeline)
	Commit string
	// Build date in RFC3339
	BuildDate string
	// One entry per file, sorted ascending by Path (byte comparison)
	Files []FileEntry
}

// FileEntry describes a single file in the manifest
type FileEntry struct {
	// POSIX-style path relative to dist/, no leading slash
	Path string
	// File size in bytes
	Size int64
	// Lowercase hex SHA-256 of the file contents
	Sha256 string
}

// Marshal returns the canonical textual representation of the manifest
// The output is what gets signed: plain ASCII, LF line terminators, pipe-separated fields, final LF included
func (m Manifest) Marshal() []byte {
	var b bytes.Buffer

	// Line 1: `version|commit` or just `commit` if version is empty
	if m.Version != "" {
		b.WriteString(m.Version)
		b.WriteByte('|')
	}
	b.WriteString(m.Commit)
	b.WriteByte('\n')

	// Line 2: build date
	b.WriteString(m.BuildDate)
	b.WriteByte('\n')

	// Lines 3..N: file entries
	for _, f := range m.Files {
		b.WriteString(f.Path)
		b.WriteByte('|')
		b.WriteString(strconv.FormatInt(f.Size, 10))
		b.WriteByte('|')
		b.WriteString(f.Sha256)
		b.WriteByte('\n')
	}

	return b.Bytes()
}

// Parse decodes a canonical manifest produced by Marshal
// It is strict: any malformed line or unexpected field count returns an error
func Parse(b []byte) (Manifest, error) {
	if len(b) == 0 {
		return Manifest{}, errors.New("empty manifest")
	}

	// Reject CRLF and other line-ending quirks before splitting
	if bytes.ContainsRune(b, '\r') {
		return Manifest{}, errors.New("manifest contains CR (CRLF line endings not allowed)")
	}
	if b[len(b)-1] != '\n' {
		return Manifest{}, errors.New("manifest does not end with LF")
	}

	// Trim the final LF so Split doesn't produce an empty trailing element
	lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
	if len(lines) < 2 {
		return Manifest{}, errors.New("manifest has fewer than 2 header lines")
	}

	m := Manifest{}

	// Line 1: version|commit or commit
	headerLine := string(lines[0])
	pipes := strings.Count(headerLine, "|")
	switch pipes {
	case 0:
		if headerLine == "" {
			return Manifest{}, errors.New("manifest header line is empty")
		}
		m.Commit = headerLine
	case 1:
		parts := strings.SplitN(headerLine, "|", 2)
		if parts[0] == "" || parts[1] == "" {
			return Manifest{}, errors.New("manifest header has empty version or commit")
		}
		m.Version = parts[0]
		m.Commit = parts[1]
	default:
		return Manifest{}, fmt.Errorf("manifest header line has %d pipes, expected 0 or 1", pipes)
	}

	// Line 2: build date
	buildDate := string(lines[1])
	if buildDate == "" {
		return Manifest{}, errors.New("manifest build-date line is empty")
	}
	m.BuildDate = buildDate

	// Lines 3..N: file entries
	for i := 2; i < len(lines); i++ {
		line := lines[i]
		if len(line) == 0 {
			return Manifest{}, fmt.Errorf("manifest has empty line at position %d", i+1)
		}

		parts := bytes.SplitN(line, []byte{'|'}, 3)
		if len(parts) != 3 {
			return Manifest{}, fmt.Errorf("manifest file entry at line %d has %d fields, expected 3", i+1, len(parts))
		}

		size, err := strconv.ParseInt(string(parts[1]), 10, 64)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest file entry at line %d: invalid size: %w", i+1, err)
		}
		if size < 0 {
			return Manifest{}, fmt.Errorf("manifest file entry at line %d: negative size", i+1)
		}

		hashHex := string(parts[2])
		err = validateSha256Hex(hashHex)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest file entry at line %d: invalid sha256: %w", i+1, err)
		}

		m.Files = append(m.Files, FileEntry{
			Path:   string(parts[0]),
			Size:   size,
			Sha256: hashHex,
		})
	}

	return m, nil
}

// BuildFromFS walks fsys under root, hashes every regular file, and returns a sorted Manifest
// All paths are recorded relative to root using POSIX separators
func BuildFromFS(fsys fs.FS, root, version, commit, buildDate string) (Manifest, error) {
	if commit == "" {
		return Manifest{}, errors.New("commit must not be empty")
	}
	if buildDate == "" {
		return Manifest{}, errors.New("build-date must not be empty")
	}

	var files []FileEntry

	walkErr := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := relPath(root, p)
		if err != nil {
			return err
		}

		if strings.ContainsAny(rel, "|\n\r") {
			return fmt.Errorf("file path contains disallowed character: %q", rel)
		}

		f, err := fsys.Open(p)
		if err != nil {
			return fmt.Errorf("open %s: %w", p, err)
		}
		defer f.Close()

		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return fmt.Errorf("hash %s: %w", p, err)
		}

		files = append(files, FileEntry{
			Path:   rel,
			Size:   n,
			Sha256: hex.EncodeToString(h.Sum(nil)),
		})

		return nil
	})
	if walkErr != nil {
		return Manifest{}, walkErr
	}

	slices.SortFunc(files, func(a, b FileEntry) int {
		return strings.Compare(a.Path, b.Path)
	})

	return Manifest{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		Files:     files,
	}, nil
}

// relPath returns the POSIX-style relative path of p under root
// Both root and p are expected to use forward slashes (fs.FS convention)
func relPath(root, p string) (string, error) {
	root = path.Clean(root)
	p = path.Clean(p)

	if root == "." {
		return p, nil
	}

	prefix := root + "/"
	if !strings.HasPrefix(p, prefix) {
		return "", fmt.Errorf("path %q is not under root %q", p, root)
	}

	return p[len(prefix):], nil
}

// validateSha256Hex returns an error if s is not a valid lowercase hex-encoded SHA-256
func validateSha256Hex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("expected 64 hex chars, got %d", len(s))
	}
	for i := range len(s) {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fmt.Errorf("non-lowercase-hex char %q at position %d", c, i)
	}
	return nil
}
