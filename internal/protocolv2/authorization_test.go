package protocolv2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testJWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"

func TestParseAuthorization(t *testing.T) {
	tests := []struct {
		header        string
		expectedKind  CredentialKind
		expectedValue string
	}{
		{header: "", expectedKind: CredentialNone},
		{header: "   ", expectedKind: CredentialNone},
		{header: "RequestKey ", expectedKind: CredentialNone},
		{header: "RequestKey rvk_abc", expectedKind: CredentialRequestKey, expectedValue: "rvk_abc"},
		{header: "requestkey rvk_abc", expectedKind: CredentialRequestKey, expectedValue: "rvk_abc"},
		// Legacy forms of request keys
		{header: "Bearer rvk_abc", expectedKind: CredentialRequestKey, expectedValue: "rvk_abc"},
		{header: "rvk_abc", expectedKind: CredentialRequestKey, expectedValue: "rvk_abc"},
		{header: "AbCdEf0123456789GhIj", expectedKind: CredentialRequestKey, expectedValue: "AbCdEf0123456789GhIj"},
		// JWTs are only recognized with the Bearer scheme
		{header: "Bearer " + testJWT, expectedKind: CredentialJWT, expectedValue: testJWT},
		{header: "bearer " + testJWT, expectedKind: CredentialJWT, expectedValue: testJWT},
		{header: "RequestKey " + testJWT, expectedKind: CredentialRequestKey, expectedValue: testJWT},
		{header: testJWT, expectedKind: CredentialRequestKey, expectedValue: testJWT},
		{header: "ResultToken rvr_abc", expectedKind: CredentialResultToken, expectedValue: "rvr_abc"},
		{header: "Basic dXNlcjpwYXNz", expectedKind: CredentialUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			kind, value := ParseAuthorization(tt.header)
			assert.Equal(t, tt.expectedKind, kind)
			assert.Equal(t, tt.expectedValue, value)
		})
	}
}

func TestAuthSchemeLowercaseNames(t *testing.T) {
	assert.Equal(t, authSchemeRequestKeyLC, strings.ToLower(AuthSchemeRequestKey))
	assert.Equal(t, authSchemeBearerLC, strings.ToLower(AuthSchemeBearer))
	assert.Equal(t, authSchemeResultTokenLC, strings.ToLower(AuthSchemeResultToken))
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{value: testJWT, expected: true},
		{value: "a.b", expected: true},
		{value: "rvk_AbCdEf0123456789GhIj", expected: false},
		{value: "AbCdEf0123456789GhIj", expected: false},
		{value: "rvr_abc", expected: false},
		{value: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			assert.Equal(t, tt.expected, LooksLikeJWT(tt.value))
		})
	}
}
