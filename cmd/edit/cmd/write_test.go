package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// withStdin replaces stdin with a file holding the given contents, for the duration of the test
func withStdin(t *testing.T, contents string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stdin")
	err := os.WriteFile(path, []byte(contents), 0o600)
	require.NoError(t, err)

	f, err := os.Open(path) // #nosec G304 -- this is the file the test just created
	require.NoError(t, err)

	orig := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = orig
		_ = f.Close()
	})
}

func TestReadContents(t *testing.T) {
	t.Run("reads everything from stdin", func(t *testing.T) {
		withStdin(t, "first line\nsecond line\n")

		got, err := readContents(testLogger())
		require.NoError(t, err)
		require.Equal(t, "first line\nsecond line\n", string(got))
	})

	t.Run("reads empty input", func(t *testing.T) {
		withStdin(t, "")

		got, err := readContents(testLogger())
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestWriteRefusesEmptyContents(t *testing.T) {
	// The command must not reach the server, so the flags and their environment variables are left unset on purpose
	t.Setenv(envServer, "")
	t.Setenv(envRequestKey, "")

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())

	t.Run("refuses empty contents", func(t *testing.T) {
		withStdin(t, "")
		allowEmptyFlag = false

		err := runWrite(cmd, []string{"notes.txt"})
		require.ErrorContains(t, err, "refusing to write empty contents")
	})

	t.Run("accepts empty contents with --allow-empty", func(t *testing.T) {
		withStdin(t, "")
		allowEmptyFlag = true
		t.Cleanup(func() {
			allowEmptyFlag = false
		})

		// Getting as far as the flags means the guard let it through
		err := runWrite(cmd, []string{"notes.txt"})
		require.ErrorContains(t, err, "--server is required")
	})

	t.Run("requires a file", func(t *testing.T) {
		withStdin(t, "contents")

		err := runWrite(cmd, nil)
		require.ErrorContains(t, err, "the path of a file is required")
	})
}
