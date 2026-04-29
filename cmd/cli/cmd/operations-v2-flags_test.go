package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
			require.ErrorContains(t, err, "encrypt only supports 'json'")
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
			require.ErrorContains(t, err, "decrypt supports 'json' or 'raw'")
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
	require.ErrorContains(t, err, "unsupported signing algorithm")

	// Reference protocolv2 to keep the import alive in case the test is later split off
	require.Equal(t, "ES256", protocolv2.SigningAlgES256)
}

func TestEncryptInputSourceMutuallyExclusiveAtValidate(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		f := newEncryptFlagsWithRequired(t)
		f.Message = ""
		err := f.Validate()
		require.Error(t, err)
		require.ErrorContains(t, err, "one of --message, --input, or --json is required")
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
	require.ErrorContains(t, err, "'value' field is required")
}

func TestDecryptJSONReadsAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"kind":"revaulter/1","algorithm":"A256GCM","keyLabel":"label-test","value":"dmFs","tag":"dGFn","nonce":"bm9u","additionalData":"YWFk"}`)
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
	require.ErrorContains(t, err, "either --value or --json is required")
}

func TestDecryptJSONAlgorithmPopulatesFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"kind":"revaulter/1","algorithm":"A256GCM","keyLabel":"label-test","value":"dmFs","tag":"dGFn","nonce":"bm9u","additionalData":"YWFk"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Algorithm = ""
	f.KeyLabel = ""
	f.Value = ""
	f.JSON = path
	require.NoError(t, f.Validate())
	require.Equal(t, "A256GCM", f.Algorithm, "algorithm from --json must populate the flag")
	require.Equal(t, "label-test", f.KeyLabel, "keyLabel from --json must populate the flag")
}

func TestDecryptJSONKindIsRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"algorithm":"A256GCM","keyLabel":"label-test","value":"dmFs"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Algorithm = ""
	f.KeyLabel = ""
	f.Value = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, `unsupported 'kind' "" (expected "revaulter/1")`)
}

func TestDecryptJSONRejectsUnsupportedKind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"kind":"revaulter/99","algorithm":"A256GCM","keyLabel":"label-test","value":"dmFs"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Algorithm = ""
	f.KeyLabel = ""
	f.Value = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, `unsupported 'kind' "revaulter/99"`)
}

func TestDecryptJSONAlgorithmIsRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"kind":"revaulter/1","keyLabel":"label-test","value":"dmFs"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Algorithm = ""
	f.KeyLabel = ""
	f.Value = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "'algorithm' field is required")
}

func TestDecryptJSONKeyLabelIsRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.json")
	body := []byte(`{"kind":"revaulter/1","algorithm":"A256GCM","value":"dmFs"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Algorithm = ""
	f.KeyLabel = ""
	f.Value = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "'keyLabel' field is required")
}

func TestDecryptValueModeRequiresAlgorithm(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	f.Algorithm = ""
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--algorithm is required")
}

func TestEncryptMessageRejectsOversizeInput(t *testing.T) {
	// One byte over the limit: keeps the test fast and cheap while still tripping the size guard
	oversize := make([]byte, maxInputBytes+1)
	for i := range oversize {
		oversize[i] = 'a'
	}

	f := newEncryptFlagsWithRequired(t)
	f.Message = string(oversize)
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--message exceeds the maximum allowed size")
}

func TestEncryptMessageAcceptsExactlyMaxSize(t *testing.T) {
	// Exactly maxInputBytes is allowed; only strictly greater trips the guard
	exact := make([]byte, maxInputBytes)
	for i := range exact {
		exact[i] = 'a'
	}

	f := newEncryptFlagsWithRequired(t)
	f.Message = string(exact)
	require.NoError(t, f.Validate())
}

func TestEncryptInputRejectsOversizeFile(t *testing.T) {
	oversize := make([]byte, maxInputBytes+1)
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	require.NoError(t, os.WriteFile(path, oversize, 0o600))

	f := newEncryptFlagsWithRequired(t)
	f.Message = ""
	f.Input = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--input exceeds the maximum allowed size")
}

func TestEncryptJSONRejectsOversizeValue(t *testing.T) {
	// 200 KiB of base64 decodes to ~150 KiB, which is over the 100 KiB cap
	oversizeB64 := base64.StdEncoding.EncodeToString(make([]byte, maxInputBytes+1))
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	body := []byte(`{"value":"` + oversizeB64 + `"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newEncryptFlagsWithRequired(t)
	f.Message = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--json value exceeds the maximum allowed size")
}

func TestEncryptAADRejectsOversize(t *testing.T) {
	// Use a 1 KiB margin so the size check trips even after stringValue.Set re-encodes as RawURLEncoding (no padding) and the StdEncoding-based DecodedLen rounds down
	oversizeB64 := base64.StdEncoding.EncodeToString(make([]byte, maxInputBytes+1024))

	f := newEncryptFlagsWithRequired(t)
	require.NoError(t, f.AdditionalData.Set(oversizeB64))
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--aad exceeds the maximum allowed size")
}

func TestDecryptValueRejectsOversize(t *testing.T) {
	oversizeB64 := base64.StdEncoding.EncodeToString(make([]byte, maxInputBytes+1024))

	f := newDecryptFlagsWithRequired(t)
	require.NoError(t, f.Value.Set(oversizeB64))
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--value exceeds the maximum allowed size")
}

func TestDecryptJSONRejectsOversizeValue(t *testing.T) {
	oversizeB64 := base64.StdEncoding.EncodeToString(make([]byte, maxInputBytes+1))
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	body := []byte(`{"kind":"revaulter/1","algorithm":"A256GCM","keyLabel":"label-test","value":"` + oversizeB64 + `"}`)
	require.NoError(t, os.WriteFile(path, body, 0o600))

	f := newDecryptFlagsWithRequired(t)
	f.Value = ""
	f.JSON = path
	err := f.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "--json value exceeds the maximum allowed size")
}

// newEncryptResponse builds the JSON envelope the browser produces after an `encrypt` operation
func newEncryptResponse(t *testing.T, state, alg string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"state":          state,
		"operation":      protocolv2.OperationEncrypt,
		"algorithm":      alg,
		"value":          "dmFs",
		"nonce":          "bm9u",
		"tag":            "dGFn",
		"additionalData": "YWFk",
	})
	require.NoError(t, err)
	return body
}

func TestEncryptFormatResultRewritesEnvelope(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plain := newEncryptResponse(t, "state-1", "A256GCM")
	out, err := f.FormatResult("state-1", plain, "json")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	require.Equal(t, "revaulter/1", got["kind"])
	require.Equal(t, "A256GCM", got["algorithm"])
	require.Equal(t, "label-test", got["keyLabel"])
	require.Equal(t, "dmFs", got["value"])
	require.Equal(t, "bm9u", got["nonce"])
	require.Equal(t, "dGFn", got["tag"])
	require.Equal(t, "YWFk", got["additionalData"])
	_, hasState := got["state"]
	require.False(t, hasState, "state must be stripped from encrypt JSON output")
	_, hasOp := got["operation"]
	require.False(t, hasOp, "operation must be stripped from encrypt JSON output")
	require.True(t, strings.HasSuffix(string(out), "\n"), "output must end with newline")
}

func TestEncryptFormatResultOmitsEmptyAdditionalData(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	body, err := json.Marshal(map[string]any{
		"state":     "state-1",
		"operation": protocolv2.OperationEncrypt,
		"algorithm": "A256GCM",
		"value":     "dmFs",
		"nonce":     "bm9u",
		"tag":       "dGFn",
	})
	require.NoError(t, err)
	out, err := f.FormatResult("state-1", body, "json")
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	_, has := got["additionalData"]
	require.False(t, has, "additionalData must be omitted when empty")
}

func TestEncryptFormatResultRejectsStateMismatch(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plain := newEncryptResponse(t, "other", "A256GCM")
	_, err := f.FormatResult("state-1", plain, "json")
	require.Error(t, err)
	require.ErrorContains(t, err, "state mismatch")
}

func TestEncryptFormatResultRejectsAlgorithmMismatch(t *testing.T) {
	f := newEncryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plain := newEncryptResponse(t, "state-1", "ChaCha20-Poly1305")
	_, err := f.FormatResult("state-1", plain, "json")
	require.Error(t, err)
	require.ErrorContains(t, err, "does not match requested")
}

// newDecryptResponse builds the JSON envelope the browser produces after a `decrypt` operation
func newDecryptResponse(t *testing.T, state, alg, valueB64 string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"state":     state,
		"operation": protocolv2.OperationDecrypt,
		"algorithm": alg,
		"value":     valueB64,
	})
	require.NoError(t, err)
	return body
}

func TestDecryptFormatResultRawEmitsRawBytes(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plaintext := []byte("hello world\x00\xff")
	plain := newDecryptResponse(t, "state-1", "A256GCM", base64.RawURLEncoding.EncodeToString(plaintext))
	out, err := f.FormatResult("state-1", plain, "raw")
	require.NoError(t, err)
	require.Equal(t, plaintext, out, "--format raw must emit the decrypted bytes verbatim with no JSON wrapping")
}

func TestDecryptFormatResultJSONIndentsEnvelope(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plain := newDecryptResponse(t, "state-1", "A256GCM", "aGVsbG8")
	out, err := f.FormatResult("state-1", plain, "json")
	require.NoError(t, err)
	require.Contains(t, string(out), "\n \"state\": \"state-1\"")
	require.True(t, strings.HasSuffix(string(out), "\n"), "default output must end with newline")
}

func TestDecryptFormatResultRejectsStateMismatch(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plain := newDecryptResponse(t, "other", "A256GCM", "aGVsbG8")
	_, err := f.FormatResult("state-1", plain, "raw")
	require.Error(t, err)
	require.ErrorContains(t, err, "state mismatch")
}

func TestDecryptFormatResultRejectsAlgorithmMismatch(t *testing.T) {
	f := newDecryptFlagsWithRequired(t)
	require.NoError(t, f.Validate())

	plain := newDecryptResponse(t, "state-1", "ChaCha20-Poly1305", "aGVsbG8")
	_, err := f.FormatResult("state-1", plain, "raw")
	require.Error(t, err)
	require.ErrorContains(t, err, "does not match requested")
}
