package cliutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeRequestKeyFile writes content to a file in a temporary directory, with owner-only permissions, and returns its path
func writeRequestKeyFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "request-key")
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)

	return path
}

func TestReadRequestKeyFile(t *testing.T) {
	t.Run("reads the key", func(t *testing.T) {
		key, err := ReadRequestKeyFile(writeRequestKeyFile(t, "rvk_abcdef0123456789"))
		require.NoError(t, err)
		require.Equal(t, "rvk_abcdef0123456789", key)
	})

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		for _, content := range []string{"rvk_key\n", "rvk_key\r\n", "  rvk_key  ", "\n\nrvk_key\n\n"} {
			key, err := ReadRequestKeyFile(writeRequestKeyFile(t, content))
			require.NoError(t, err)
			require.Equal(t, "rvk_key", key)
		}
	})

	t.Run("accepts a file at the size limit", func(t *testing.T) {
		content := strings.Repeat("k", MaxRequestKeyFileSize)
		key, err := ReadRequestKeyFile(writeRequestKeyFile(t, content))
		require.NoError(t, err)
		require.Equal(t, content, key)
	})

	t.Run("rejects an empty path", func(t *testing.T) {
		_, err := ReadRequestKeyFile("")
		require.ErrorContains(t, err, "path is empty")
	})

	t.Run("rejects a file that does not exist", func(t *testing.T) {
		_, err := ReadRequestKeyFile(filepath.Join(t.TempDir(), "missing"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("rejects a directory", func(t *testing.T) {
		_, err := ReadRequestKeyFile(t.TempDir())
		require.ErrorContains(t, err, "not a regular file")
	})

	t.Run("rejects an empty file", func(t *testing.T) {
		for _, content := range []string{"", "\n", "   \n\t "} {
			_, err := ReadRequestKeyFile(writeRequestKeyFile(t, content))
			require.ErrorContains(t, err, "file is empty")
		}
	})

	t.Run("rejects a file larger than the limit", func(t *testing.T) {
		_, err := ReadRequestKeyFile(writeRequestKeyFile(t, strings.Repeat("k", MaxRequestKeyFileSize+1)))
		require.ErrorContains(t, err, "larger than the maximum allowed size")
	})

	t.Run("rejects content that is not a single key", func(t *testing.T) {
		for _, content := range []string{"rvk_one rvk_two", "rvk_one\nrvk_two", "rvk_\x00key", "rvk\tkey"} {
			_, err := ReadRequestKeyFile(writeRequestKeyFile(t, content))
			require.ErrorContains(t, err, "does not contain a single request key")
		}
	})

	t.Run("follows a symlink to a regular file", func(t *testing.T) {
		target := writeRequestKeyFile(t, "rvk_linked")
		link := filepath.Join(t.TempDir(), "link")
		err := os.Symlink(target, link)
		require.NoError(t, err)

		key, err := ReadRequestKeyFile(link)
		require.NoError(t, err)
		require.Equal(t, "rvk_linked", key)
	})
}
