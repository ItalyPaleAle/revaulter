package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestFile returns an encrypted file backed by a random content encryption key
func newTestFile(t *testing.T, path string) *encryptedFile {
	t.Helper()

	key, err := generateContentKey()
	require.NoError(t, err)
	require.Len(t, key, 32)

	return newEncryptedFile(path, "https://revaulter.example.com", &wrappedKey{
		KeyLabel:   "notes",
		Algorithm:  "A256GCM",
		Ciphertext: []byte("wrapped-key-ciphertext"),
		Nonce:      []byte("nonce-123456"),
		Tag:        []byte("tag-0123456789ab"),
	}, key)
}

func TestSerializeAndDecrypt(t *testing.T) {
	file := newTestFile(t, filepath.Join(t.TempDir(), "notes.txt"))
	plaintext := []byte("the file's secret contents\n")

	data, err := file.Serialize(plaintext)
	require.NoError(t, err)

	// The result is a JWE in compact serialization, with an empty encrypted key segment
	segments := strings.Split(strings.TrimSpace(string(data)), ".")
	require.Len(t, segments, 5)
	require.Empty(t, segments[1], "the encrypted key segment must be empty with 'alg':'dir'")
	require.NotContains(t, string(data), "secret contents")

	got, err := file.Decrypt(data)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestSerializeEmptyContents(t *testing.T) {
	file := newTestFile(t, filepath.Join(t.TempDir(), "notes.txt"))

	data, err := file.Serialize(nil)
	require.NoError(t, err)

	got, err := file.Decrypt(data)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestParseHeader(t *testing.T) {
	file := newTestFile(t, filepath.Join(t.TempDir(), "notes.txt"))
	data, err := file.Serialize([]byte("hello"))
	require.NoError(t, err)

	header, err := parseHeader(data)
	require.NoError(t, err)
	require.Equal(t, joseAlg, header.Alg)
	require.Equal(t, joseEnc, header.Enc)
	require.Equal(t, headerFormatVersion, header.Revaulter.V)
	require.Equal(t, "https://revaulter.example.com", header.Revaulter.Server)
	require.Equal(t, "notes", header.Revaulter.KeyLabel)
	require.Equal(t, "A256GCM", header.Revaulter.Algorithm)

	wk, err := header.WrappedKey()
	require.NoError(t, err)
	require.Equal(t, []byte("wrapped-key-ciphertext"), wk.Ciphertext)
	require.Equal(t, []byte("nonce-123456"), wk.Nonce)
	require.Equal(t, []byte("tag-0123456789ab"), wk.Tag)
	require.Equal(t, "notes", wk.KeyLabel)
}

func TestParseHeaderRejectsInvalidFiles(t *testing.T) {
	tests := []struct {
		name string
		data string
		err  string
	}{
		{name: "not a JWE", data: "hello world", err: "expected 5 segments"},
		{name: "too few segments", data: "aaa.bbb.ccc", err: "expected 5 segments"},
		{name: "invalid header encoding", data: "!!!....", err: "invalid protected header encoding"},
		{name: "invalid header JSON", data: base64.RawURLEncoding.EncodeToString([]byte("not json")) + "....", err: "invalid protected header"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseHeader([]byte(tc.data))
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestParseHeaderRejectsUnsupportedValues(t *testing.T) {
	makeFile := func(t *testing.T, header jweHeader) []byte {
		t.Helper()
		b, err := json.Marshal(header)
		require.NoError(t, err)
		return []byte(base64.RawURLEncoding.EncodeToString(b) + "....")
	}

	validKeyInfo := revaulterKeyInfo{
		V:          headerFormatVersion,
		KeyLabel:   "notes",
		Algorithm:  "A256GCM",
		WrappedKey: "AAAA",
	}

	t.Run("rejects an unsupported alg", func(t *testing.T) {
		_, err := parseHeader(makeFile(t, jweHeader{Alg: "RSA-OAEP", Enc: joseEnc, Revaulter: validKeyInfo}))
		require.ErrorContains(t, err, "unsupported JWE 'alg'")
	})

	t.Run("rejects an unsupported enc", func(t *testing.T) {
		_, err := parseHeader(makeFile(t, jweHeader{Alg: joseAlg, Enc: "A128GCM", Revaulter: validKeyInfo}))
		require.ErrorContains(t, err, "unsupported JWE 'enc'")
	})

	t.Run("rejects a newer header version", func(t *testing.T) {
		keyInfo := validKeyInfo
		keyInfo.V = headerFormatVersion + 1
		_, err := parseHeader(makeFile(t, jweHeader{Alg: joseAlg, Enc: joseEnc, Revaulter: keyInfo}))
		require.ErrorContains(t, err, "unsupported Revaulter header version")
	})

	t.Run("rejects a header without a wrapped key", func(t *testing.T) {
		keyInfo := validKeyInfo
		keyInfo.WrappedKey = ""
		_, err := parseHeader(makeFile(t, jweHeader{Alg: joseAlg, Enc: joseEnc, Revaulter: keyInfo}))
		require.ErrorContains(t, err, "does not carry a wrapped key")
	})
}

func TestDecryptRejectsTamperedFiles(t *testing.T) {
	file := newTestFile(t, filepath.Join(t.TempDir(), "notes.txt"))
	data, err := file.Serialize([]byte("hello"))
	require.NoError(t, err)
	segments := strings.Split(strings.TrimSpace(string(data)), ".")

	t.Run("rejects a tampered protected header", func(t *testing.T) {
		// Swapping the wrapped key information out invalidates the authentication tag, because the header is the AEAD's additional data
		header, err := parseHeader(data)
		require.NoError(t, err)
		header.Revaulter.KeyLabel = "another-label"
		headerJSON, err := json.Marshal(header)
		require.NoError(t, err)

		tampered := strings.Join(append([]string{base64.RawURLEncoding.EncodeToString(headerJSON)}, segments[1:]...), ".")
		_, err = file.Decrypt([]byte(tampered))
		require.ErrorContains(t, err, "failed to decrypt the file")
	})

	t.Run("rejects a tampered ciphertext", func(t *testing.T) {
		ciphertext, err := base64.RawURLEncoding.DecodeString(segments[3])
		require.NoError(t, err)
		ciphertext[0] ^= 0xFF

		tampered := strings.Join([]string{segments[0], segments[1], segments[2], base64.RawURLEncoding.EncodeToString(ciphertext), segments[4]}, ".")
		_, err = file.Decrypt([]byte(tampered))
		require.ErrorContains(t, err, "failed to decrypt the file")
	})

	t.Run("rejects a non-empty encrypted key segment", func(t *testing.T) {
		tampered := strings.Join([]string{segments[0], "AAAA", segments[2], segments[3], segments[4]}, ".")
		_, err := file.Decrypt([]byte(tampered))
		require.ErrorContains(t, err, "unexpected encrypted key segment")
	})

	t.Run("rejects a file encrypted with a different key", func(t *testing.T) {
		other := newTestFile(t, filepath.Join(t.TempDir(), "notes.txt"))
		_, err := other.Decrypt(data)
		require.ErrorContains(t, err, "failed to decrypt the file")
	})
}

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	file := newTestFile(t, path)

	err := file.Save([]byte("first"))
	require.NoError(t, err)

	st, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	// Saving again replaces the contents, and leaves no temporary file behind
	err = file.Save([]byte("second"))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got, err := file.Decrypt(data)
	require.NoError(t, err)
	require.Equal(t, []byte("second"), got)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestSaveRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.WriteFile(target, []byte("existing"), 0o600))
	require.NoError(t, os.Symlink(target, link))

	file := newTestFile(t, link)
	err := file.Save([]byte("hello"))
	require.ErrorContains(t, err, "refusing to write through symlink")
}
