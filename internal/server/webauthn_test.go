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

func TestNormalizeWebAuthnPRFResultsEncodesBrowserByteArrays(t *testing.T) {
	credential := json.RawMessage(`{"id":"credential","clientExtensionResults":{"prf":{"results":{"first":[251,255,0],"second":"AQID"}}}}`)

	normalized, err := normalizeWebAuthnPRFResults(credential)
	require.NoError(t, err)

	var value struct {
		ClientExtensionResults struct {
			PRF struct {
				Results struct {
					First  string `json:"first"`
					Second string `json:"second"`
				} `json:"results"`
			} `json:"prf"`
		} `json:"clientExtensionResults"`
	}
	err = json.Unmarshal(normalized, &value)
	require.NoError(t, err)
	assert.Equal(t, "-_8A", value.ClientExtensionResults.PRF.Results.First)
	assert.Equal(t, "AQID", value.ClientExtensionResults.PRF.Results.Second)
}

func TestNormalizeWebAuthnPRFResultsRejectsInvalidBytes(t *testing.T) {
	credential := json.RawMessage(`{"clientExtensionResults":{"prf":{"results":{"first":[256]}}}}`)

	_, err := normalizeWebAuthnPRFResults(credential)
	require.ErrorContains(t, err, "invalid byte")
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
