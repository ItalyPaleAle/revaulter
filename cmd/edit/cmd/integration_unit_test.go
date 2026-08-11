package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/clienttest"
	"github.com/italypaleale/revaulter/pkg/revaulter"
)

// newTestKeyWrapper returns a key wrapper backed by a simulated Revaulter server
func newTestKeyWrapper(t *testing.T) (*clienttest.Server, keyWrapper) {
	t.Helper()

	srv := clienttest.NewServer(t)
	client, err := revaulter.New(revaulter.Options{
		Server:       srv.URL,
		RequestKey:   clienttest.RequestKey,
		HTTPClient:   srv.HTTPClient(),
		UserAgent:    userAgent,
		NoTrustStore: true,
	})
	require.NoError(t, err)

	return srv, &revaulterKeyWrapper{client: client}
}

// TestFileRoundTripThroughRevaulter covers the whole path a file takes: a new content encryption key is wrapped by Revaulter, the contents are encrypted with it locally, and reopening the file unwraps the key again
func TestFileRoundTripThroughRevaulter(t *testing.T) {
	srv, wrapper := newTestKeyWrapper(t)
	path := filepath.Join(t.TempDir(), "notes.txt")
	ctx := t.Context()

	opts := openOptions{
		Path:      path,
		Server:    srv.URL,
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmA256GCM,
		Note:      requestNote("", path),
		Create:    true,
	}

	file, plaintext, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	require.Empty(t, plaintext)
	require.Equal(t, "revaulter-edit notes.txt", srv.LastNote())

	contents := []byte("api-key = hunter2\n")
	err = file.Save(contents)
	require.NoError(t, err)

	// The file on disk is a JWE that carries the wrapped key, and none of the contents in the clear
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "hunter2")

	header, err := parseHeader(data)
	require.NoError(t, err)
	require.Equal(t, "notes", header.Revaulter.KeyLabel)
	require.Equal(t, revaulter.AlgorithmA256GCM, header.Revaulter.Algorithm)
	require.Equal(t, srv.URL, header.Revaulter.Server)
	require.NotEmpty(t, header.Revaulter.WrappedKeyNonce)
	require.NotEmpty(t, header.Revaulter.WrappedKeyTag)

	// Reopening asks Revaulter to unwrap the key, and returns the same contents
	_, got, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	require.Equal(t, contents, got)
}

// TestFileWithChaCha20Poly1305WrappedKey checks that the key wrapping algorithm is not hardcoded
func TestFileWithChaCha20Poly1305WrappedKey(t *testing.T) {
	srv, wrapper := newTestKeyWrapper(t)
	path := filepath.Join(t.TempDir(), "notes.txt")
	ctx := t.Context()

	opts := openOptions{
		Path:      path,
		Server:    srv.URL,
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmC20P,
		Create:    true,
	}

	file, _, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	err = file.Save([]byte("hello"))
	require.NoError(t, err)

	header, err := parseHeader(mustReadFile(t, path))
	require.NoError(t, err)
	require.Equal(t, revaulter.AlgorithmC20P, header.Revaulter.Algorithm)

	_, got, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), got)
}

// TestFileKeyLabelComesFromTheFile checks that an existing file is opened with the label recorded in its header, not with the one passed on the command line
func TestFileKeyLabelComesFromTheFile(t *testing.T) {
	srv, wrapper := newTestKeyWrapper(t)
	path := filepath.Join(t.TempDir(), "notes.txt")
	ctx := t.Context()

	file, _, err := openFile(ctx, testLogger(), wrapper, openOptions{
		Path:      path,
		Server:    srv.URL,
		KeyLabel:  "first-label",
		Algorithm: revaulter.AlgorithmA256GCM,
		Create:    true,
	})
	require.NoError(t, err)
	err = file.Save([]byte("contents"))
	require.NoError(t, err)

	reopened, got, err := openFile(ctx, testLogger(), wrapper, openOptions{
		Path:      path,
		Server:    srv.URL,
		KeyLabel:  "another-label",
		Algorithm: revaulter.AlgorithmA256GCM,
		Create:    true,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("contents"), got)
	require.Equal(t, "first-label", reopened.keyInfo.KeyLabel)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return data
}

// TestWriteReplacesContentsAndReusesTheKey covers what the "write" command does: an existing file has its own key unwrapped and reused, so only its contents change
func TestWriteReplacesContentsAndReusesTheKey(t *testing.T) {
	srv, wrapper := newTestKeyWrapper(t)
	path := filepath.Join(t.TempDir(), "notes.txt")
	ctx := t.Context()

	opts := openOptions{
		Path:      path,
		Server:    srv.URL,
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmA256GCM,
		Create:    true,
	}

	file, _, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	err = file.Save([]byte("first contents"))
	require.NoError(t, err)

	headerBefore, err := parseHeader(mustReadFile(t, path))
	require.NoError(t, err)

	// Writing new contents opens the file first, which is what unwraps its key
	file, _, err = openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	err = file.Save([]byte("replaced contents"))
	require.NoError(t, err)

	headerAfter, err := parseHeader(mustReadFile(t, path))
	require.NoError(t, err)
	require.Equal(t, headerBefore.Revaulter, headerAfter.Revaulter, "the wrapped key must be reused, not replaced")

	_, got, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	require.Equal(t, []byte("replaced contents"), got)
}
