package server

import (
	"testing"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

func TestRequirePRFSupport(t *testing.T) {
	t.Run("accepts confirmed PRF support", func(t *testing.T) {
		enabled := true
		cred := &webauthnlib.Credential{
			Extensions: webauthnlib.CredentialExtensions{PRFEnabled: &enabled},
		}
		err := requirePRFSupport(cred)
		require.NoError(t, err)
	})

	for _, tc := range []struct {
		name string
		cred *webauthnlib.Credential
	}{
		{name: "nil credential"},
		{name: "missing PRF result", cred: &webauthnlib.Credential{}},
		{name: "PRF unavailable", cred: credentialWithPRFSupport(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requirePRFSupport(tc.cred)
			require.Error(t, err)
		})
	}
}

func credentialWithPRFSupport(enabled bool) *webauthnlib.Credential {
	return &webauthnlib.Credential{
		Extensions: webauthnlib.CredentialExtensions{PRFEnabled: &enabled},
	}
}
