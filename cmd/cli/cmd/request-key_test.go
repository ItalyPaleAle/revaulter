package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// writeRequestKeyFile writes a request key to a file with owner-only permissions and returns its path
func writeRequestKeyFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "request-key")
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)

	err = os.Chmod(path, 0o600)
	require.NoError(t, err)

	return path
}

func TestResolveRequestKey(t *testing.T) {
	t.Run("returns the inline key", func(t *testing.T) {
		key, err := resolveRequestKey("rvk_inline", "")
		require.NoError(t, err)
		require.Equal(t, "rvk_inline", key)
	})

	t.Run("reads the key from the file", func(t *testing.T) {
		key, err := resolveRequestKey("", writeRequestKeyFile(t, "rvk_from_file\n"))
		require.NoError(t, err)
		require.Equal(t, "rvk_from_file", key)
	})

	t.Run("rejects both", func(t *testing.T) {
		_, err := resolveRequestKey("rvk_inline", writeRequestKeyFile(t, "rvk_from_file"))
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("rejects neither", func(t *testing.T) {
		_, err := resolveRequestKey("", "")
		require.ErrorContains(t, err, "one of --request-key or --request-key-file is required")
	})

	t.Run("wraps the error from an unusable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		_, err := resolveRequestKey("", path)
		require.ErrorContains(t, err, "invalid --request-key-file")
		require.ErrorContains(t, err, path)
	})
}

func TestEncryptValidateResolvesRequestKeyFile(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	f.RequestKey = ""
	f.RequestKeyFile = writeRequestKeyFile(t, "rvk_from_file\n")

	err := f.Validate()
	require.NoError(t, err)
	require.Equal(t, "rvk_from_file", f.GetRequestKey(), "the key read from the file must replace the empty --request-key")
}

func TestEncryptValidateRejectsUnusableRequestKeyFile(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	f.RequestKey = ""
	f.RequestKeyFile = t.TempDir()

	err := f.Validate()
	require.ErrorContains(t, err, "not a regular file")
}

func TestTrustResolvesRequestKeyFile(t *testing.T) {
	c := &trustCmd{
		Server:         "https://example.invalid",
		RequestKeyFile: writeRequestKeyFile(t, "rvk_from_file\n"),
	}

	key, err := resolveRequestKey(c.RequestKey, c.RequestKeyFile)
	require.NoError(t, err)
	c.RequestKey = key
	require.Equal(t, "rvk_from_file", c.GetRequestKey())
}

// parseFlagGroups parses args on cmd and runs the flag-group checks cobra applies before RunE
// Only the group checks are run: the other required flags of each command are not what these tests are about
func parseFlagGroups(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()

	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	return cmd.ValidateFlagGroups()
}

func TestRequestKeyFlagGroups(t *testing.T) {
	// Every command that connects to a server must accept either flag, but not both and not neither
	cmds := map[string]func() *cobra.Command{
		"encrypt": func() *cobra.Command {
			return newV2OperationCmd("encrypt", "Encrypt data", func() v2OperationFlags { return &v2OperationFlagsEncrypt{} })
		},
		"decrypt": func() *cobra.Command {
			return newV2OperationCmd("decrypt", "Decrypt data", func() v2OperationFlags { return &v2OperationFlagsDecrypt{} })
		},
		"sign": func() *cobra.Command {
			return newV2OperationCmd("sign", "Sign data", func() v2OperationFlags { return &v2OperationFlagsSign{} })
		},
		"trust": newTrustCmd,
	}

	for name, newCmd := range cmds {
		t.Run(name, func(t *testing.T) {
			path := writeRequestKeyFile(t, "rvk_from_file")

			t.Run("accepts --request-key", func(t *testing.T) {
				err := parseFlagGroups(t, newCmd(), "--server", "https://example.invalid", "--request-key", "rvk_inline")
				require.NoError(t, err)
			})

			t.Run("accepts --request-key-file", func(t *testing.T) {
				err := parseFlagGroups(t, newCmd(), "--server", "https://example.invalid", "--request-key-file", path)
				require.NoError(t, err)
			})

			t.Run("rejects both", func(t *testing.T) {
				err := parseFlagGroups(t, newCmd(), "--server", "https://example.invalid", "--request-key", "rvk_inline", "--request-key-file", path)
				require.ErrorContains(t, err, "none of the others can be")
			})

			t.Run("rejects neither", func(t *testing.T) {
				err := parseFlagGroups(t, newCmd(), "--server", "https://example.invalid")
				require.ErrorContains(t, err, "at least one of the flags in the group [request-key request-key-file] is required")
			})
		})
	}
}
