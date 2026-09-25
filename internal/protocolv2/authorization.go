package protocolv2

import (
	"strings"
)

// UserIDHeader is the HTTP header that carries the ID of the user a CLI request is for
// It's required when the request credential is a JWT, which on its own doesn't identify a Revaulter user
// With other credentials it's optional, but when set it must match the user the credential belongs to
const UserIDHeader = "X-Revaulter-User"

// Authentication schemes used in the Authorization header of requests to the /v2/request endpoints
const (
	// AuthSchemeRequestKey carries a static request key
	AuthSchemeRequestKey   = "RequestKey"
	authSchemeRequestKeyLC = "requestkey"
	// AuthSchemeBearer carries a JWT from a trusted OIDC issuer
	AuthSchemeBearer   = "Bearer"
	authSchemeBearerLC = "bearer"
	// AuthSchemeResultToken carries the token returned when a request is created, and is only accepted when retrieving the request's result
	AuthSchemeResultToken   = "ResultToken"
	authSchemeResultTokenLC = "resulttoken"
)

// CredentialKind is the kind of credential in the Authorization header of a request to the /v2/request endpoints
type CredentialKind int

const (
	// CredentialNone means the Authorization header is missing or empty
	CredentialNone CredentialKind = iota
	// CredentialRequestKey is a static request key
	CredentialRequestKey
	// CredentialJWT is a JWT from a trusted OIDC issuer
	CredentialJWT
	// CredentialResultToken is the result token of a request
	CredentialResultToken
	// CredentialUnsupported means the header uses an authentication scheme that isn't supported
	CredentialUnsupported
)

// ParseAuthorization returns the kind and value of the credential in the Authorization header
func ParseAuthorization(header string) (CredentialKind, string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return CredentialNone, ""
	}

	scheme, value, found := strings.Cut(header, " ")
	if !found {
		if isKnownAuthScheme(header) {
			// A scheme name on its own carries no credential
			return CredentialNone, ""
		}

		// For backwards compatibility, assume this is a request key
		return CredentialRequestKey, header
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return CredentialNone, ""
	}

	// Scheme names are case-insensitive
	switch strings.ToLower(scheme) {
	case authSchemeRequestKeyLC:
		return CredentialRequestKey, value
	case authSchemeResultTokenLC:
		return CredentialResultToken, value
	case authSchemeBearerLC:
		// For backwards compatibility, a request key can be passed as bearer token
		if LooksLikeJWT(value) {
			return CredentialJWT, value
		}
		return CredentialRequestKey, value
	default:
		return CredentialUnsupported, ""
	}
}

func isKnownAuthScheme(s string) bool {
	switch strings.ToLower(s) {
	case authSchemeRequestKeyLC, authSchemeBearerLC, authSchemeResultTokenLC:
		return true
	default:
		return false
	}
}

// LooksLikeJWT returns true if the value could be a JWT, which is the case when it contains a dot
func LooksLikeJWT(value string) bool {
	return strings.IndexByte(value, '.') >= 0
}
