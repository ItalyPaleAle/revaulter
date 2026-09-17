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
		require.NoError(t, requirePRFSupport(cred))
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
			require.Error(t, requirePRFSupport(tc.cred))
		})
	}
}

func credentialWithPRFSupport(enabled bool) *webauthnlib.Credential {
	return &webauthnlib.Credential{
		Extensions: webauthnlib.CredentialExtensions{PRFEnabled: &enabled},
	}
}
