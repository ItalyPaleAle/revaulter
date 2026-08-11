package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManifest_MarshalParse_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		manifest Manifest
		want     string
	}{
		{
			name: "with version",
			manifest: Manifest{
				Version:   "v1.9.0",
				Commit:    "abc1234",
				BuildDate: "2026-04-16T00:00:00Z",
				Files: []FileEntry{
					{Path: "index.html", Size: 10, Sha256: strings.Repeat("a", 64)},
					{Path: "js/app.js", Size: 1234, Sha256: strings.Repeat("b", 64)},
				},
			},
			want: "v1.9.0|abc1234\n2026-04-16T00:00:00Z\nindex.html|10|" + strings.Repeat("a", 64) + "\njs/app.js|1234|" + strings.Repeat("b", 64) + "\n",
		},
		{
			name: "commit only",
			manifest: Manifest{
				Commit:    "def5678",
				BuildDate: "2026-04-16T00:00:00Z",
				Files:     []FileEntry{{Path: "a.txt", Size: 0, Sha256: strings.Repeat("0", 64)}},
			},
			want: "def5678\n2026-04-16T00:00:00Z\na.txt|0|" + strings.Repeat("0", 64) + "\n",
		},
		{
			name: "empty files list",
			manifest: Manifest{
				Version:   "edge",
				Commit:    "ffff",
				BuildDate: "2026-04-16T00:00:00Z",
			},
			want: "edge|ffff\n2026-04-16T00:00:00Z\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.manifest.Marshal()
			assert.Equal(t, tt.want, string(got))

			parsed, err := Parse(got)
			require.NoError(t, err)
			assert.Equal(t, tt.manifest, parsed)
		})
	}
}

func TestParse_Errors(t *testing.T) {
	hash := strings.Repeat("a", 64)

	tests := []struct {
		name  string
		input string
		err   string
	}{
		{name: "empty input", input: "", err: "empty manifest"},
		{name: "missing trailing LF", input: "v1|abc\n2026-04-16T00:00:00Z", err: "does not end with LF"},
		{name: "CRLF line endings", input: "v1|abc\r\n2026-04-16T00:00:00Z\r\n", err: "CR"},
		{name: "too few lines", input: "v1|abc\n", err: "fewer than 2 header lines"},
		{name: "empty header", input: "\n2026-04-16T00:00:00Z\n", err: "header line is empty"},
		{name: "header has two pipes", input: "v1|abc|extra\n2026-04-16T00:00:00Z\n", err: "expected 0 or 1"},
		{name: "empty version", input: "|abc\n2026-04-16T00:00:00Z\n", err: "empty version or commit"},
		{name: "empty commit", input: "v1|\n2026-04-16T00:00:00Z\n", err: "empty version or commit"},
		{name: "empty build-date", input: "v1|abc\n\n", err: "build-date line is empty"},
		{name: "file entry wrong field count", input: "v1|abc\n2026-04-16T00:00:00Z\nfoo|10\n", err: "expected 3"},
		{name: "file entry bad size", input: "v1|abc\n2026-04-16T00:00:00Z\nfoo|abc|" + hash + "\n", err: "invalid size"},
		{name: "file entry negative size", input: "v1|abc\n2026-04-16T00:00:00Z\nfoo|-1|" + hash + "\n", err: "negative size"},
		{name: "file entry short hash", input: "v1|abc\n2026-04-16T00:00:00Z\nfoo|10|abc\n", err: "expected 64 hex"},
		{name: "file entry uppercase hash", input: "v1|abc\n2026-04-16T00:00:00Z\nfoo|10|" + strings.ToUpper(hash) + "\n", err: "non-lowercase-hex"},
		{name: "empty file line", input: "v1|abc\n2026-04-16T00:00:00Z\n\n", err: "empty line"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.input))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestBuildFromFS_SortingAndHashing(t *testing.T) {
	// Deliberately unsorted input
	fsys := fstest.MapFS{
		"dist/zeta.txt":         {Data: []byte("zeta")},
		"dist/alpha/nested.txt": {Data: []byte("nested")},
		"dist/alpha.txt":        {Data: []byte("alpha")},
	}

	m, err := BuildFromFS(fsys, "dist", "v1", "abc1234", "2026-04-16T00:00:00Z")
	require.NoError(t, err)

	assert.Equal(t, "v1", m.Version)
	assert.Equal(t, "abc1234", m.Commit)

	// Sorted ascending by byte comparison
	require.Len(t, m.Files, 3)
	assert.Equal(t, "alpha.txt", m.Files[0].Path)
	assert.Equal(t, "alpha/nested.txt", m.Files[1].Path)
	assert.Equal(t, "zeta.txt", m.Files[2].Path)

	// Hashes + sizes match expected
	sum := sha256.Sum256([]byte("alpha"))
	assert.Equal(t, hex.EncodeToString(sum[:]), m.Files[0].Sha256)
	assert.Equal(t, int64(5), m.Files[0].Size)
}

func TestBuildFromFS_RejectsBadPaths(t *testing.T) {
	fsys := fstest.MapFS{
		"dist/has|pipe.txt": {Data: []byte("x")},
	}
	_, err := BuildFromFS(fsys, "dist", "v1", "abc", "2026-04-16T00:00:00Z")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed character")
}

func TestBuildFromFS_MissingInputs(t *testing.T) {
	fsys := fstest.MapFS{"dist/a.txt": {Data: []byte("a")}}

	_, err := BuildFromFS(fsys, "dist", "v1", "", "2026-04-16T00:00:00Z")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit")

	_, err = BuildFromFS(fsys, "dist", "v1", "abc", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build-date")
}

func TestBuildFromFS_MarshalRoundTrip(t *testing.T) {
	fsys := fstest.MapFS{
		"dist/index.html": {Data: []byte("<html></html>")},
		"dist/app.js":     {Data: []byte("console.log(1)")},
	}

	m, err := BuildFromFS(fsys, "dist", "v1", "abc1234", "2026-04-16T00:00:00Z")
	require.NoError(t, err)

	bytes := m.Marshal()
	parsed, err := Parse(bytes)
	require.NoError(t, err)

	assert.Equal(t, m, parsed)
}
