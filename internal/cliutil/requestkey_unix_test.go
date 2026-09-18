//go:build unix

package cliutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadRequestKeyFilePermissions(t *testing.T) {
	t.Run("rejects a file readable by group or others", func(t *testing.T) {
		for _, perm := range []os.FileMode{0o640, 0o604, 0o644, 0o666, 0o660} {
			path := filepath.Join(t.TempDir(), "request-key")
			err := os.WriteFile(path, []byte("rvk_key"), perm)
			require.NoError(t, err)

			// os.WriteFile applies the umask, so set the permissions explicitly
			err = os.Chmod(path, perm)
			require.NoError(t, err)

			_, err = ReadRequestKeyFile(path)
			require.ErrorContains(t, err, "too open")
		}
	})

	t.Run("accepts a file only the owner can access", func(t *testing.T) {
		for _, perm := range []os.FileMode{0o400, 0o600, 0o700} {
			path := filepath.Join(t.TempDir(), "request-key")
			err := os.WriteFile(path, []byte("rvk_key"), perm)
			require.NoError(t, err)

			err = os.Chmod(path, perm)
			require.NoError(t, err)

			key, err := ReadRequestKeyFile(path)
			require.NoError(t, err)
			require.Equal(t, "rvk_key", key)
		}
	})
}
