package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveEditor(t *testing.T) {
	t.Run("prefers the flag", func(t *testing.T) {
		t.Setenv("VISUAL", "visual-editor")
		t.Setenv("EDITOR", "env-editor")

		editor, err := resolveEditor("flag-editor")
		require.NoError(t, err)
		require.Equal(t, "flag-editor", editor)
	})

	t.Run("falls back to VISUAL, then EDITOR", func(t *testing.T) {
		t.Setenv("VISUAL", "visual-editor")
		t.Setenv("EDITOR", "env-editor")

		editor, err := resolveEditor("")
		require.NoError(t, err)
		require.Equal(t, "visual-editor", editor)

		t.Setenv("VISUAL", "")
		editor, err = resolveEditor("")
		require.NoError(t, err)
		require.Equal(t, "env-editor", editor)
	})

	t.Run("fails when no editor is configured", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "")

		_, err := resolveEditor("")
		require.ErrorContains(t, err, "no editor configured")
	})
}

func TestEditorFileName(t *testing.T) {
	tests := map[string]string{
		"/home/alice/notes.txt":      "notes.txt",
		"/home/alice/notes.md.jwe":   "notes.md",
		"/home/alice/secrets.enc":    "secrets",
		"/home/alice/data.ENCRYPTED": "data",
		"notes":                      "notes",
		"/":                          "revaulter-edit.txt",
	}

	for path, expect := range tests {
		t.Run(path, func(t *testing.T) {
			require.Equal(t, expect, editorFileName(path))
		})
	}
}

func TestNeedsWaitFlag(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		expect bool
	}{
		{name: "code", args: []string{"code"}, expect: true},
		{name: "subl", args: []string{"subl"}, expect: true},
		{name: "full path", args: []string{"/usr/local/bin/code"}, expect: true},
		{name: "windows executable", args: []string{"Code.exe"}, expect: true},
		{name: "with other arguments", args: []string{"code", "--new-window"}, expect: true},
		{name: "already waiting", args: []string{"code", "--wait"}, expect: false},
		{name: "already waiting with the short flag", args: []string{"subl", "-w"}, expect: false},
		{name: "editor that blocks", args: []string{"vim"}, expect: false},
		{name: "editor whose name contains code", args: []string{"codepad"}, expect: false},
		{name: "no arguments", args: nil, expect: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, needsWaitFlag(tc.args))
		})
	}
}

func TestSplitCommand(t *testing.T) {
	tests := []struct {
		in     string
		expect []string
	}{
		{in: "vim", expect: []string{"vim"}},
		{in: "code --wait", expect: []string{"code", "--wait"}},
		{in: "  code   --wait  ", expect: []string{"code", "--wait"}},
		{in: `"/path/with spaces/editor" -f`, expect: []string{"/path/with spaces/editor", "-f"}},
		{in: `sh -c 'printf hi > "$0"'`, expect: []string{"sh", "-c", `printf hi > "$0"`}},
		{in: "", expect: nil},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.expect, splitCommand(tc.in))
		})
	}
}

func TestWipeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plaintext.txt")
	err := os.WriteFile(path, []byte("secret contents"), 0o600)
	require.NoError(t, err)

	err = wipeFile(path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, make([]byte, len("secret contents")), data)
}

func TestNewPrivateTempDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	dir, err := newPrivateTempDir()
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	require.Equal(t, base, filepath.Dir(dir), "the directory must be created inside XDG_RUNTIME_DIR when it exists")

	st, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), st.Mode().Perm())
}
