//go:build unit

package server

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildWrappedAnchorFromBody wraps a literal newline body in base64url to form a full envelope
func buildWrappedAnchorFromBody(body string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(body))
}

// validWrappedAnchorBody returns the canonical newline body for a well-formed envelope
func validWrappedAnchorBody() string {
	return strings.Join([]string{
		"ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")),
		"nonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)),
		"v=1",
	}, "\n")
}

func TestValidateWrappedAnchorEnvelope_Accepts(t *testing.T) {
	err := validateWrappedAnchorEnvelope(buildWrappedAnchorFromBody(validWrappedAnchorBody()))
	require.NoError(t, err)
}

func TestValidateWrappedAnchorEnvelope_Rejects(t *testing.T) {
	cases := []struct {
		name    string
		wrapped string
		wantSub string
	}{
		{
			name:    "empty string",
			wrapped: "",
			wantSub: "empty",
		},
		{
			name:    "not base64url",
			wrapped: "not*valid*base64",
			wantSub: "base64url",
		},
		{
			name:    "too few lines",
			wrapped: buildWrappedAnchorFromBody("ciphertext=AA\nv=1"),
			wantSub: "expected 3 lines",
		},
		{
			name:    "too many lines",
			wrapped: buildWrappedAnchorFromBody(validWrappedAnchorBody() + "\nextra=x"),
			wantSub: "expected 3 lines",
		},
		{
			name:    "wrong order",
			wrapped: buildWrappedAnchorFromBody("nonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nv=1"),
			wantSub: "expected key",
		},
		{
			name:    "unknown field replacing v",
			wrapped: buildWrappedAnchorFromBody("ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nversion=1"),
			wantSub: "expected key",
		},
		{
			name:    "duplicate key",
			wrapped: buildWrappedAnchorFromBody("ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize))),
			wantSub: "expected key",
		},
		{
			name:    "missing equals",
			wrapped: buildWrappedAnchorFromBody("ciphertext" + "\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nv=1"),
			wantSub: "missing '='",
		},
		{
			name:    "unsupported version",
			wrapped: buildWrappedAnchorFromBody("ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nv=2"),
			wantSub: "unsupported version",
		},
		{
			name:    "empty ciphertext",
			wrapped: buildWrappedAnchorFromBody("ciphertext=\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nv=1"),
			wantSub: "ciphertext",
		},
		{
			name:    "empty nonce",
			wrapped: buildWrappedAnchorFromBody("ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nnonce=\nv=1"),
			wantSub: "nonce",
		},
		{
			name:    "nonce wrong size",
			wrapped: buildWrappedAnchorFromBody("ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, 10)) + "\nv=1"),
			wantSub: "nonce must be 12 bytes",
		},
		{
			name:    "nonce not base64url",
			wrapped: buildWrappedAnchorFromBody("ciphertext=" + base64.RawURLEncoding.EncodeToString([]byte("ct")) + "\nnonce=***\nv=1"),
			wantSub: "nonce",
		},
		{
			name:    "ciphertext not base64url",
			wrapped: buildWrappedAnchorFromBody("ciphertext=***\nnonce=" + base64.RawURLEncoding.EncodeToString(make([]byte, wrappedAnchorNonceSize)) + "\nv=1"),
			wantSub: "ciphertext",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWrappedAnchorEnvelope(tc.wrapped)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantSub)
		})
	}
}
