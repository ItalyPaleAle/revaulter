package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

// newEncryptFlagsWithRequired binds an encrypt flag set to a fresh cobra command and pre-fills the required base flags so Validate can focus on encrypt-specific behavior
// The caller is responsible for choosing one of --message, --input, or --json before calling Validate
func newEncryptFlagsWithRequired(t *testing.T) *v2OperationFlagsEncrypt {
	t.Helper()
	f := &v2OperationFlagsEncrypt{}
	cmd := &cobra.Command{Use: "encrypt"}
	f.BindToCommand(cmd)
	f.Server = "https://example.invalid"
	f.RequestKey = "rk-test"
	f.KeyLabel = "label-test"
	f.Algorithm = "A256GCM"
	f.Message = "hello world"
	return f
}

func newDecryptFlagsWithRequired(t *testing.T) *v2OperationFlagsDecrypt {
	t.Helper()
	f := &v2OperationFlagsDecrypt{}
	cmd := &cobra.Command{Use: "decrypt"}
	f.BindToCommand(cmd)
	f.Server = "https://example.invalid"
	f.RequestKey = "rk-test"
	f.KeyLabel = "label-test"
	f.Algorithm = "A256GCM"
	f.Value = "dGVzdA"
	return f
}

func TestEncryptFormatDefaultsToJSON(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	require.Equal(t, "json", f.Format, "encrypt --format must default to json")
	require.NoError(t, f.Validate())
}

func TestEncryptFormatRejectsNonJSON(t *testing.T) {
	for _, bad := range []string{"raw", "jws", "bogus"} {
		t.Run(bad, func(t *testing.T) {
			f := newEncryptFlagsWithRequired(t)
			f.Format = bad
			err := f.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "encrypt only supports 'json'")
		})
	}
}

func TestDecryptFormatDefaultsToJSON(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	require.Equal(t, "json", f.Format, "decrypt --format must default to json")
	require.NoError(t, f.Validate())
}

func TestDecryptFormatAcceptsRaw(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	f.Format = "raw"
	require.NoError(t, f.Validate())
}

func TestDecryptFormatRejectsJWSAndUnknown(t *testing.T) {
	for _, bad := range []string{"jws", "bogus"} {
		t.Run(bad, func(t *testing.T) {
			f := newDecryptFlagsWithRequired(t)
			f.Format = bad
			err := f.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "decrypt supports 'json' or 'raw'")
		})
	}
}

func TestSignFormatDefaultsToJSON(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	require.Equal(t, "json", f.Format, "sign --format must default to json")
	// Provide a digest so Validate doesn't fail on the "one of input/digest is required" check
	f.Digest = "00000000000000000000000000000000000000000000000000000000000000aa"
	require.NoError(t, f.Validate())
	require.False(t, f.jwsOutput, "default format must not emit JWS")
}

func TestSignFormatAcceptsRaw(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Format = "raw"
	f.Digest = "00000000000000000000000000000000000000000000000000000000000000aa"
	require.NoError(t, f.Validate())
	require.False(t, f.jwsOutput, "raw must not emit JWS")
}

func TestSignFormatAcceptsJSON(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Format = "json"
	f.Digest = "00000000000000000000000000000000000000000000000000000000000000aa"
	require.NoError(t, f.Validate())
	require.False(t, f.jwsOutput)
}

func TestSignFormatAlgorithmStillEnforced(t *testing.T) {
	f := newSignFlagsWithRequired(t)
	f.Format = "raw"
	f.Algorithm = "ES384"
	f.Digest = "00000000000000000000000000000000000000000000000000000000000000aa"
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signing algorithm")

	// Reference protocolv2 to keep the import alive in case the test is later split off
	require.Equal(t, "ES256", protocolv2.SigningAlgES256)
}

func TestEncryptInputSourceMutuallyExclusiveAtValidate(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		f := newEncryptFlagsWithRequired(t)
		f.Message = ""
		err := f.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "one of --message, --input, or --json is required")
	})
}

func TestEncryptMessageEncodesAsBase64UrlUTF8(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	f.Message = "héllo"
	require.NoError(t, f.Validate())

	expected := base64.RawURLEncoding.EncodeToString([]byte("héllo"))
	require.Equal(t, expected, f.resolvedValueB64, "--message bytes must travel as base64url to the inner payload")
	require.Empty(t, f.resolvedAADB64, "no --aad supplied")
}

func TestEncryptInputReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.bin")
	body := []byte{0x00, 0x01, 0xff, 0xfe}
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newEncryptFlagsWithRequired(t)
	f.Message = ""
	f.Input = path
	require.NoError(t, f.Validate())

	require.Equal(t, base64.RawURLEncoding.EncodeToString(body), f.resolvedValueB64)
}

func TestEncryptJSONReadsValueAndAad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.json")
	body := []byte(`{"value":"aGVsbG8","additionalData":"YWFk"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newEncryptFlagsWithRequired(t)
	f.Message = ""
	f.JSON = path
	require.NoError(t, f.Validate())

	require.Equal(t, "aGVsbG8", f.resolvedValueB64, "JSON value must travel through verbatim")
	require.Equal(t, "YWFk", f.resolvedAADB64, "JSON additionalData must travel through verbatim")
}

func TestEncryptJSONRejectsMissingValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0o600))

	f := newEncryptFlagsWithRequired(t)
	f.Message = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "'value' field is required")
}

func TestDecryptJSONReadsAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"state":"s","operation":"encrypt","algorithm":"A256GCM","value":"dmFs","tag":"dGFn","nonce":"bm9u","additionalData":"YWFk"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Value = ""
	f.JSON = path
	require.NoError(t, f.Validate())

	require.Equal(t, "dmFs", f.resolvedValueB64)
	require.Equal(t, "dGFn", f.resolvedTagB64)
	require.Equal(t, "bm9u", f.resolvedNonceB64)
	require.Equal(t, "YWFk", f.resolvedAADB64)
}

func TestDecryptRequiresValueOrJSON(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	f.Value = ""
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "either --value or --json is required")
}
