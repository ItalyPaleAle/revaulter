package cmd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/revaulter"
)

// fakeWrapper stands in for Revaulter, wrapping keys with a local AES-256-GCM key
type fakeWrapper struct {
	key []byte

	wrapCalls   int
	unwrapCalls int
	lastNote    string
	unwrapErr   error
	returnKey   []byte
}

func newFakeWrapper(t *testing.T) *fakeWrapper {
	t.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	return &fakeWrapper{key: key}
}

func (w *fakeWrapper) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func (w *fakeWrapper) Wrap(_ context.Context, keyLabel string, algorithm string, key []byte, note string) (*wrappedKey, error) {
	w.wrapCalls++
	w.lastNote = note

	aead, err := w.aead()
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	combined := aead.Seal(nil, nonce, key, nil)

	return &wrappedKey{
		KeyLabel:   keyLabel,
		Algorithm:  algorithm,
		Ciphertext: combined[:len(combined)-16],
		Nonce:      nonce,
		Tag:        combined[len(combined)-16:],
	}, nil
}

func (w *fakeWrapper) Unwrap(_ context.Context, wk *wrappedKey, note string) ([]byte, error) {
	w.unwrapCalls++
	w.lastNote = note

	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}
	if w.returnKey != nil {
		return w.returnKey, nil
	}

	aead, err := w.aead()
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, wk.Nonce, append(append([]byte{}, wk.Ciphertext...), wk.Tag...), nil)
}

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestOpenFileCreatesAndReopens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	wrapper := newFakeWrapper(t)
	ctx := t.Context()

	opts := openOptions{
		Path:      path,
		Server:    "https://revaulter.example.com",
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmA256GCM,
		Note:      "revaulter-edit notes.txt",
		Create:    true,
	}

	file, plaintext, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	require.Empty(t, plaintext, "a new file starts empty")
	require.Equal(t, 1, wrapper.wrapCalls)
	require.Equal(t, "revaulter-edit notes.txt", wrapper.lastNote)
	require.NoFileExists(t, path, "nothing is written until the contents are saved")

	// Save some contents, then open the file again
	contents := []byte("some secret notes\n")
	require.NoError(t, file.Save(contents))

	reopened, got, err := openFile(ctx, testLogger(), wrapper, opts)
	require.NoError(t, err)
	require.Equal(t, contents, got)
	require.Equal(t, 1, wrapper.unwrapCalls)
	require.Equal(t, "notes", reopened.keyInfo.KeyLabel)
	require.Equal(t, "https://revaulter.example.com", reopened.keyInfo.Server)
}

func TestOpenFileRequiresAnExistingFileWithoutCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	wrapper := newFakeWrapper(t)

	_, _, err := openFile(t.Context(), testLogger(), wrapper, openOptions{
		Path:      path,
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmA256GCM,
	})
	require.ErrorContains(t, err, "does not exist")
	require.Equal(t, 0, wrapper.wrapCalls)
	require.Equal(t, 0, wrapper.unwrapCalls)
}

func TestOpenFileRequiresAKeyLabelForNewFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")

	_, _, err := openFile(t.Context(), testLogger(), newFakeWrapper(t), openOptions{
		Path:      path,
		Algorithm: revaulter.AlgorithmA256GCM,
		Create:    true,
	})
	require.ErrorContains(t, err, "--key-label is required")
}

func TestOpenFileRejectsAnInvalidContentKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	wrapper := newFakeWrapper(t)
	opts := openOptions{
		Path:      path,
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmA256GCM,
		Create:    true,
	}

	file, _, err := openFile(t.Context(), testLogger(), wrapper, opts)
	require.NoError(t, err)
	err = file.Save([]byte("hello"))
	require.NoError(t, err)

	// A server that returns a key of the wrong size must not be trusted to be the file's key
	wrapper.returnKey = []byte("too-short")
	_, _, err = openFile(t.Context(), testLogger(), wrapper, opts)
	require.ErrorContains(t, err, "encryption key is 9 bytes, expected 32")
}

func TestOpenFilePropagatesUnwrapErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	wrapper := newFakeWrapper(t)
	opts := openOptions{
		Path:      path,
		KeyLabel:  "notes",
		Algorithm: revaulter.AlgorithmA256GCM,
		Create:    true,
	}

	file, _, err := openFile(t.Context(), testLogger(), wrapper, opts)
	require.NoError(t, err)
	err = file.Save([]byte("hello"))
	require.NoError(t, err)

	wrapper.unwrapErr = errors.New("operation is canceled, denied, or failed")
	_, _, err = openFile(t.Context(), testLogger(), wrapper, opts)
	require.ErrorContains(t, err, "failed to unwrap the file's encryption key")
	require.ErrorContains(t, err, "denied")
}

func TestOpenFileRejectsAnUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	err := os.WriteFile(path, []byte("this is not a JWE"), 0o600)
	require.NoError(t, err)

	_, _, err = openFile(t.Context(), testLogger(), newFakeWrapper(t), openOptions{
		Path:     path,
		KeyLabel: "notes",
		Create:   true,
	})
	require.ErrorContains(t, err, "failed to parse")
}

func TestRequestNote(t *testing.T) {
	t.Run("uses the file name", func(t *testing.T) {
		require.Equal(t, "revaulter-edit notes.txt", requestNote("", "/home/alice/notes.txt"))
	})

	t.Run("keeps a user-supplied note", func(t *testing.T) {
		require.Equal(t, "my note", requestNote("my note", "/home/alice/notes.txt"))
	})

	t.Run("replaces characters the server does not allow", func(t *testing.T) {
		require.Equal(t, "revaulter-edit my-notes-2-.txt", requestNote("", "/home/alice/my:notes(2).txt"))
	})

	t.Run("fits within the server's limit", func(t *testing.T) {
		note := requestNote("", "/home/alice/"+strings.Repeat("a", 200)+".txt")
		require.LessOrEqual(t, len(note), revaulter.MaxNoteLength)
		require.True(t, strings.HasSuffix(note, ".txt"))
	})
}
