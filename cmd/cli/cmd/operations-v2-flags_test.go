package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

// newEncryptFlagsWithRequired binds an encrypt flag set to a fresh cobra command and pre-fills the required base flags so Validate can focus on encrypt-specific behavior
func newEncryptFlagsWithRequired(t *testing.T) *v2OperationFlagsEncrypt {
	t.Helper()
	f := &v2OperationFlagsEncrypt{}
	cmd := &cobra.Command{Use: "encrypt"}
	f.BindToCommand(cmd)
	f.Server = "https://example.invalid"
	f.RequestKey = "rk-test"
	f.KeyLabel = "label-test"
	f.Algorithm = "A256GCM"
	f.Value = "dGVzdA"
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
