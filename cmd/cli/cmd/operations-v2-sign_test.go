package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

// newSignFlagsWithRequired builds a v2OperationFlagsSign bound to a cobra command and populated with the required base flags
// Validate then only has to focus on sign-specific behavior
func newSignFlagsWithRequired(t *testing.T) *v2OperationFlagsSign {
	t.Helper()
	f := &v2OperationFlagsSign{}
	cmd := &cobra.Command{Use: "sign"}
	f.BindToCommand(cmd)
	f.Server = "https://example.invalid"
	f.RequestKey = "rk-test"
	f.KeyLabel = "label-test"
	f.Algorithm = protocolv2.SigningAlgES256
	return f
}

func TestSignValidateRejectsUnsupportedAlgorithm(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Algorithm = "ES384"
	f.Digest = strings.Repeat("aa", 32)

	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signing algorithm")
}

func TestSignValidateRequiresExactlyOneInput(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		f := newSignFlagsWithRequired(t)
		err := f.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "one of --input")
	})

	t.Run("input and digest", func(t *testing.T) {
		f := newSignFlagsWithRequired(t)
		f.Input = "-"
		f.Digest = strings.Repeat("aa", 32)
		err := f.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "mutually exclusive")
	})
}

func TestSignValidateDigestAcceptsHexAndBase64url(t *testing.T) {
	raw := sha256.Sum256([]byte("hello"))

	t.Run("hex", func(t *testing.T) {
		f := newSignFlagsWithRequired(t)
		f.Digest = hex.EncodeToString(raw[:])
		err := f.Validate()
		require.NoError(t, err)
		require.Equal(t, base64.RawURLEncoding.EncodeToString(raw[:]), f.digestB64)
	})

	t.Run("base64url", func(t *testing.T) {
		f := newSignFlagsWithRequired(t)
		f.Digest = base64.RawURLEncoding.EncodeToString(raw[:])
		err := f.Validate()
		require.NoError(t, err)
		require.Equal(t, base64.RawURLEncoding.EncodeToString(raw[:]), f.digestB64)
	})
}

func TestSignValidateDigestRejectsWrongLength(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	// 31 bytes of hex — one short of 32
	f.Digest = strings.Repeat("aa", 31)
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "digest length")
}

func TestSignValidateDigestRejectsInvalidEncoding(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = "not@hex@or@base64"
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not valid hex or base64url")
}

func TestSignValidateInputFileComputesDigest(t *testing.T) {
	dir := t.TempDir()
	msg := []byte("the quick brown fox")
	path := filepath.Join(dir, "msg.bin")
	require.NoError(t, os.WriteFile(path, msg, 0o600))

	f := newSignFlagsWithRequired(t)
	f.Input = path
	err := f.Validate()
	require.NoError(t, err)

	expected := sha256.Sum256(msg)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(expected[:]), f.digestB64)
	// No JWS requested, so the JWS segments must remain empty
	require.Empty(t, f.jwsHeaderSegment)
	require.Empty(t, f.jwsPayloadSegment)
}

func TestSignValidateFormatJwsWithInputBuildsSegments(t *testing.T) {
	dir := t.TempDir()
	msg := []byte("jws-payload")
	path := filepath.Join(dir, "msg.bin")
	require.NoError(t, os.WriteFile(path, msg, 0o600))

	f := newSignFlagsWithRequired(t)
	f.Input = path
	f.Format = "jws"
	err := f.Validate()
	require.NoError(t, err)

	// Payload segment must be the base64url of the raw file bytes (no hash)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(msg), f.jwsPayloadSegment)

	// Default header must be {"alg":"ES256"}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(f.jwsHeaderSegment)
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(hdrJSON, &hdr))
	require.Equal(t, "ES256", hdr["alg"])

	// Digest must be SHA-256 of "<header>.<payload>"
	expected := sha256.Sum256([]byte(f.jwsHeaderSegment + "." + f.jwsPayloadSegment))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(expected[:]), f.digestB64)
}

func TestSignValidateFormatJwsMergesUserHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.bin")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	f := newSignFlagsWithRequired(t)
	f.Input = path
	f.Format = "jws"
	f.JwsHeader = `{"kid":"my-kid","typ":"JWT","alg":"ES384"}`
	err := f.Validate()
	require.NoError(t, err)

	hdrJSON, err := base64.RawURLEncoding.DecodeString(f.jwsHeaderSegment)
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(hdrJSON, &hdr))
	require.Equal(t, "my-kid", hdr["kid"])
	require.Equal(t, "JWT", hdr["typ"])
	// User-supplied alg must be ignored and forced back to ES256
	require.Equal(t, "ES256", hdr["alg"])
}

func TestSignValidateFormatJwsRejectsInvalidHeaderJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.bin")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	f := newSignFlagsWithRequired(t)
	f.Input = path
	f.Format = "jws"
	f.JwsHeader = `{not valid`
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --jws-header")
}

func TestSignValidateFormatJwsRejectsDigest(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("aa", 32)
	f.Format = "jws"
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires --input")
}

func TestSignValidateFormatUnknownRejected(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("aa", 32)
	f.Format = "bogus"
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --format")
}

func TestSignInnerPayloadCarriesOnlyDigestAndTransportKeys(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("00", 32)
	require.NoError(t, f.Validate())

	transportJWK := protocolv2.ECP256PublicJWK{Kty: "EC", Crv: "P-256", X: "x", Y: "y"}
	inner := f.InnerPayload(transportJWK, "mlkem-ct")

	require.Equal(t, f.digestB64, inner.Value)
	require.Empty(t, inner.Nonce, "sign payloads must leave nonce empty")
	require.Empty(t, inner.Tag, "sign payloads must leave tag empty")
	require.Empty(t, inner.AdditionalData, "sign payloads must leave additionalData empty")
	require.Equal(t, transportJWK, inner.ClientTransportEcdhKey)
	require.Equal(t, "mlkem-ct", inner.ClientTransportMlkemKey)
}

// --- FormatResult ---

func newSignResponse(t *testing.T, state, keyLabel string, sig []byte) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"state":     state,
		"operation": protocolv2.OperationSign,
		"algorithm": protocolv2.SigningAlgES256,
		"keyLabel":  keyLabel,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	require.NoError(t, err)
	return b
}

func TestSignFormatResultRawEmitsRawBytes(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("00", 32)
	require.NoError(t, f.Validate())

	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	plain := newSignResponse(t, "state-1", f.KeyLabel, sig)
	out, err := f.FormatResult("state-1", plain, "raw")
	require.NoError(t, err)
	require.Equal(t, sig, out, "--format raw must emit the 64 r||s bytes verbatim")
}

func TestSignFormatResultJSONEmitsIndentedEnvelope(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("00", 32)
	require.NoError(t, f.Validate())

	sig := make([]byte, 64)
	plain := newSignResponse(t, "state-1", f.KeyLabel, sig)
	out, err := f.FormatResult("state-1", plain, "json")
	require.NoError(t, err)
	require.Contains(t, string(out), "\n \"state\": \"state-1\"")
	require.True(t, strings.HasSuffix(string(out), "\n"), "default output must end with newline")
}

func TestSignFormatResultJwsEmitsCompactJWS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.bin")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))

	f := newSignFlagsWithRequired(t)
	f.Input = path
	f.Format = "jws"
	require.NoError(t, f.Validate())
	origHeader := f.jwsHeaderSegment
	origPayload := f.jwsPayloadSegment

	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 1)
	}
	plain := newSignResponse(t, "state-jws", f.KeyLabel, sig)
	out, err := f.FormatResult("state-jws", plain, "jws")
	require.NoError(t, err)

	line := strings.TrimRight(string(out), "\n")
	parts := strings.Split(line, ".")
	require.Len(t, parts, 3)
	require.Equal(t, origHeader, parts[0], "JWS header segment must be verbatim")
	require.Equal(t, origPayload, parts[1], "JWS payload segment must be verbatim")
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Equal(t, sig, sigBytes)
}

func TestSignFormatResultUnknownFormat(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("00", 32)
	require.NoError(t, f.Validate())

	plain := newSignResponse(t, "state-x", f.KeyLabel, make([]byte, 64))
	_, err := f.FormatResult("state-x", plain, "bogus")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported format")
}

func TestSignFormatResultValidatesResponseFields(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Digest = strings.Repeat("00", 32)
	require.NoError(t, f.Validate())

	sig := make([]byte, 64)

	t.Run("state mismatch", func(t *testing.T) {
		plain := newSignResponse(t, "state-b", f.KeyLabel, sig)
		_, err := f.FormatResult("state-a", plain, "json")
		require.Error(t, err)
		require.Contains(t, err.Error(), "state mismatch")
	})

	t.Run("operation mismatch", func(t *testing.T) {
		b, err := json.Marshal(map[string]any{
			"state":     "state-x",
			"operation": "encrypt",
			"algorithm": protocolv2.SigningAlgES256,
			"keyLabel":  f.KeyLabel,
			"signature": base64.RawURLEncoding.EncodeToString(sig),
		})
		require.NoError(t, err)
		_, err = f.FormatResult("state-x", b, "json")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected operation")
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		b, err := json.Marshal(map[string]any{
			"state":     "state-x",
			"operation": protocolv2.OperationSign,
			"algorithm": "ES384",
			"keyLabel":  f.KeyLabel,
			"signature": base64.RawURLEncoding.EncodeToString(sig),
		})
		require.NoError(t, err)
		_, err = f.FormatResult("state-x", b, "json")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected algorithm")
	})

	t.Run("keyLabel mismatch", func(t *testing.T) {
		plain := newSignResponse(t, "state-x", "other-label", sig)
		_, err := f.FormatResult("state-x", plain, "json")
		require.Error(t, err)
		require.Contains(t, err.Error(), "keyLabel")
	})

	t.Run("signature wrong length", func(t *testing.T) {
		plain := newSignResponse(t, "state-x", f.KeyLabel, make([]byte, 63))
		_, err := f.FormatResult("state-x", plain, "json")
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature length")
	})

	t.Run("missing signature", func(t *testing.T) {
		b, err := json.Marshal(map[string]any{
			"state":     "state-x",
			"operation": protocolv2.OperationSign,
			"algorithm": protocolv2.SigningAlgES256,
			"keyLabel":  f.KeyLabel,
		})
		require.NoError(t, err)
		_, err = f.FormatResult("state-x", b, "json")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signature")
	})
}
