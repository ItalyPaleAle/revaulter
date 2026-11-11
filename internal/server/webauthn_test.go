package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

func TestInitWebAuthnAddsRelatedOriginRequestsFromConfiguredOrigins(t *testing.T) {
	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"baseUrl":        "https://auth.example.com",
			"webauthnRpId":   "example.com",
			"webauthnRpName": "Revaulter",
			"webauthnOrigins": []string{
				"https://auth.example.com",
				"https://console.example.com",
				"https://console.example.com/",
				"https://admin.example.com",
			},
		}),
	)

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	require.NotNil(t, wa)

	require.Equal(t, []string{
		"https://auth.example.com",
		"https://console.example.com",
		"https://admin.example.com",
	}, wa.Config.RPOrigins)
	assert.Equal(t, []string{
		"https://auth.example.com",
		"https://console.example.com",
		"https://admin.example.com",
	}, wa.Config.RPTopOrigins)
	assert.Equal(t, protocol.TopOriginExplicitVerificationMode, wa.Config.RPTopOriginVerificationMode)
}

func TestInitWebAuthnIgnoresWildcardOriginsForRelatedOriginRequests(t *testing.T) {
	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"baseUrl":        "https://auth.example.com",
			"webauthnRpId":   "example.com",
			"webauthnRpName": "Revaulter",
			"webauthnOrigins": []string{
				"*",
			},
		}),
	)

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	require.NotNil(t, wa)

	assert.Equal(t, []string{"https://auth.example.com"}, wa.Config.RPOrigins)
	assert.Empty(t, wa.Config.RPTopOrigins)
	assert.Equal(t, protocol.TopOriginExplicitVerificationMode, wa.Config.RPTopOriginVerificationMode)
}

func TestLogWebAuthnErrorIncludesConciseStructuredDiagnostic(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	ctx := logging.LogToContext(t.Context(), logger)
	protocolErr := protocol.ErrBadRequest.
		WithDetails("Parse error for Assertion").
		WithInfo("sensitive debug details")

	logWebAuthnError(ctx, "login", protocolErr)

	logOutput := output.String()
	assert.Contains(t, logOutput, "WebAuthn ceremony failed")
	assert.Contains(t, logOutput, "ceremony=login")
	assert.Contains(t, logOutput, "webauthn_error_type=invalid_request")
	assert.Contains(t, logOutput, `webauthn_error_details="Parse error for Assertion"`)
	assert.NotContains(t, logOutput, "webauthn_debug=")
	assert.NotContains(t, logOutput, "webauthn_cause=")
	assert.NotContains(t, logOutput, "webauthn_field_types=")
	assert.NotContains(t, logOutput, "sensitive debug details")
}

func TestStripWebAuthnPRFResults(t *testing.T) {
	t.Run("removes PRF results and keeps every other member", func(t *testing.T) {
		credential := json.RawMessage(`{"id":"credential","response":{"signature":"AQID"},"clientExtensionResults":{"appid":false,"prf":{"enabled":true,"results":{"first":"c2VjcmV0","second":"b3RoZXI"}}}}`)

		stripped, err := stripWebAuthnPRFResults(credential)
		require.NoError(t, err)
		assert.JSONEq(t, `{"id":"credential","response":{"signature":"AQID"},"clientExtensionResults":{"appid":false,"prf":{"enabled":true}}}`, string(stripped))
		assert.NotContains(t, string(stripped), "c2VjcmV0")
		assert.NotContains(t, string(stripped), "b3RoZXI")
	})

	// Older clients encoded the PRF output in several shapes, and all of them must be removed without being parsed
	for name, results := range map[string]string{
		"byte array":         `{"first":[251,255,0]}`,
		"empty object":       `{"first":{}}`,
		"invalid byte array": `{"first":[256]}`,
		"null":               `null`,
	} {
		t.Run("removes PRF results encoded as "+name, func(t *testing.T) {
			credential := json.RawMessage(`{"clientExtensionResults":{"prf":{"results":` + results + `}}}`)

			stripped, err := stripWebAuthnPRFResults(credential)
			require.NoError(t, err)
			assert.JSONEq(t, `{"clientExtensionResults":{"prf":{}}}`, string(stripped))
		})
	}

	for name, credential := range map[string]string{
		"no extension results":   `{"id":"credential"}`,
		"null extension results": `{"id":"credential","clientExtensionResults":null}`,
		"no PRF output":          `{"id":"credential","clientExtensionResults":{"appid":false}}`,
		"null PRF output":        `{"id":"credential","clientExtensionResults":{"prf":null}}`,
		"no PRF results":         `{"id":"credential","clientExtensionResults":{"prf":{"enabled":true}}}`,
	} {
		t.Run("returns a credential with "+name+" unchanged", func(t *testing.T) {
			stripped, err := stripWebAuthnPRFResults(json.RawMessage(credential))
			require.NoError(t, err)
			assert.Equal(t, credential, string(stripped))
		})
	}

	for name, credential := range map[string]string{
		"a top-level value that is not an object": `"credential"`,
		"invalid JSON": `{"id":`,
		"extension results that are not an object": `{"clientExtensionResults":"prf"}`,
		"a PRF output that is not an object":       `{"clientExtensionResults":{"prf":[1,2,3]}}`,
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := stripWebAuthnPRFResults(json.RawMessage(credential))
			require.Error(t, err)
		})
	}
}

func TestCredentialCreationWithoutExclusionsRemovesBrowserExclusionList(t *testing.T) {
	creation := &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: protocol.URLEncodedBase64("challenge"),
			CredentialExcludeList: []protocol.CredentialDescriptor{
				{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: protocol.URLEncodedBase64("existing-credential"),
				},
			},
		},
	}

	res, ok := credentialCreationWithoutExclusions(creation).(*protocol.CredentialCreation)
	require.True(t, ok)
	require.NotSame(t, creation, res)
	assert.Empty(t, res.Response.CredentialExcludeList)
	assert.Len(t, creation.Response.CredentialExcludeList, 1)
}
