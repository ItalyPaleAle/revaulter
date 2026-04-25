package utils

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func TestIsTruthy(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
		name     string
	}{
		{input: "1", expected: true, name: "Numeric 1"},
		{input: "true", expected: true, name: "Lower true"},
		{input: "TRUE", expected: true, name: "Upper true"},
		{input: "True", expected: true, name: "Title true"},
		{input: "t", expected: true, name: "Single t"},
		{input: "T", expected: true, name: "Single T"},
		{input: "on", expected: true, name: "Lower on"},
		{input: "ON", expected: true, name: "Upper on"},
		{input: "yes", expected: true, name: "Lower yes"},
		{input: "YES", expected: true, name: "Upper yes"},
		{input: "y", expected: true, name: "Single y"},
		{input: "Y", expected: true, name: "Single Y"},

		{input: "0", expected: false, name: "Numeric 0"},
		{input: "false", expected: false, name: "Lower false"},
		{input: "FALSE", expected: false, name: "Upper false"},
		{input: "no", expected: false, name: "No"},
		{input: "off", expected: false, name: "Off"},
		{input: "n", expected: false, name: "Single n"},
		{input: "", expected: false, name: "Empty string"},
		{input: "something else", expected: false, name: "Long string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsTruthy(test.input)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestRandomString(t *testing.T) {
	t.Run("returns empty string for zero length", func(t *testing.T) {
		result, err := RandomString(0)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("returns requested length using base62 alphabet", func(t *testing.T) {
		result, err := RandomString(128)
		require.NoError(t, err)
		require.Len(t, result, 128)

		for _, char := range result {
			require.True(t, strings.ContainsRune(base62Alphabet, char))
		}
	})

	t.Run("skips bytes rejected by rejection sampling", func(t *testing.T) {
		previousReader := rand.Reader
		// 248 and 251 are above the base62 rejection threshold (256 - 256%62 = 248) and must be skipped
		rand.Reader = bytes.NewReader([]byte{248, 0, 61, 62, 248, 251, 1, 2})
		t.Cleanup(func() {
			rand.Reader = previousReader
		})

		result, err := RandomString(4)
		require.NoError(t, err)
		require.Equal(t, "0z01", result)
	})

	t.Run("returns wrapped error when random reader fails", func(t *testing.T) {
		expectedErr := errors.New("boom")
		previousReader := rand.Reader
		rand.Reader = errorReader{err: expectedErr}
		t.Cleanup(func() {
			rand.Reader = previousReader
		})

		result, err := RandomString(8)
		require.Empty(t, result)
		require.Error(t, err)
		require.ErrorContains(t, err, "error reading random bytes")
		require.ErrorIs(t, err, expectedErr)
	})
}
