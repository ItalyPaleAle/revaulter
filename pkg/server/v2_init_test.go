//go:build unit

package server

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
)

func TestInitWebAuthnAddsRelatedOriginRequestsFromConfiguredOrigins(t *testing.T) {
	t.Cleanup(config.SetTestConfig(map[string]any{
		"baseUrl":         "https://auth.example.com",
		"webauthnRpId":    "example.com",
		"webauthnRpName":  "Revaulter",
		"webauthnOrigins": []string{"https://auth.example.com"},
		"origins": []string{
			"https://console.example.com",
			"https://console.example.com/",
			"https://admin.example.com",
		},
	}))

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	require.NotNil(t, wa)
	require.Equal(t, []string{
		"https://auth.example.com",
		"https://console.example.com",
		"https://admin.example.com",
	}, wa.Config.RPOrigins)
	require.Equal(t, []string{
		"https://console.example.com",
		"https://admin.example.com",
	}, wa.Config.RPTopOrigins)
	require.Equal(t, protocol.TopOriginExplicitVerificationMode, wa.Config.RPTopOriginVerificationMode)
}

func TestInitWebAuthnIgnoresWildcardOriginsForRelatedOriginRequests(t *testing.T) {
	t.Cleanup(config.SetTestConfig(map[string]any{
		"baseUrl":        "https://auth.example.com",
		"webauthnRpId":   "example.com",
		"webauthnRpName": "Revaulter",
		"origins":        []string{"*"},
	}))

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	require.NotNil(t, wa)
	require.Equal(t, []string{"https://auth.example.com"}, wa.Config.RPOrigins)
	require.Empty(t, wa.Config.RPTopOrigins)
	require.Equal(t, protocol.TopOriginIgnoreVerificationMode, wa.Config.RPTopOriginVerificationMode)
}
