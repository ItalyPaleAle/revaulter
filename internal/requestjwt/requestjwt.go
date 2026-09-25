// Package requestjwt authenticates CLI requests carrying short-lived JWTs issued by a trusted third party, such as a CI provider's OIDC tokens
package requestjwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// MaxTokenSize is the maximum size of a JWT accepted as a request credential, in bytes
const MaxTokenSize = 8 << 10

// Limits for the fields of a trusted issuer
const (
	MaxIssuerLength      = 512
	MaxAudienceLength    = 512
	MaxSubjectLength     = 512
	MaxJWKSURLLength     = 2048
	MaxDisplayNameLength = 100
)

// clockSkew is the tolerance applied when validating the time-based claims
const clockSkew = time.Minute

var (
	// ErrInvalidToken is returned when a token is malformed, has an invalid signature, or fails claim validation
	ErrInvalidToken = errors.New("invalid token")
	// ErrKeyFetch is returned when the issuer's signing keys cannot be retrieved
	ErrKeyFetch = errors.New("failed to retrieve the issuer's signing keys")
)

// IssuerConfig is a trusted issuer, with the audience and subject a token must carry
type IssuerConfig struct {
	// Value of the "iss" claim, matched exactly
	Issuer string
	// Value that must appear in the "aud" claim
	Audience string
	// Pattern the "sub" claim must match, where "*" matches any sequence of characters
	Subject string
	// URL of the issuer's JWKS
	// When empty, it is resolved with OIDC discovery from the issuer URL
	JWKSURL string
}

// Claims are the registered claims of a token that the server uses
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	JwtID     string
	ExpiresAt time.Time
}

// PeekClaims parses the claims of a token without verifying its signature
// The result is untrusted, and must only be used to pick the issuers the token is then verified against
func PeekClaims(token string) (*Claims, error) {
	if len(token) > MaxTokenSize {
		return nil, fmt.Errorf("%w: token is larger than %d bytes", ErrInvalidToken, MaxTokenSize)
	}

	tok, err := jwt.ParseInsecure([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	return claimsFromToken(tok), nil
}

// peekKeyID returns the "kid" header of a compact JWS, without verifying it
func peekKeyID(token string) string {
	header, _, ok := strings.Cut(token, ".")
	if !ok {
		return ""
	}

	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return ""
	}

	var h struct {
		KeyID string `json:"kid"`
	}
	err = json.Unmarshal(decoded, &h)
	if err != nil {
		return ""
	}

	return h.KeyID
}

func claimsFromToken(tok jwt.Token) *Claims {
	c := &Claims{}
	c.Issuer, _ = tok.Issuer()
	c.Subject, _ = tok.Subject()
	c.Audience, _ = tok.Audience()
	c.JwtID, _ = tok.JwtID()
	c.ExpiresAt, _ = tok.Expiration()
	return c
}

// MatchSubject reports whether the subject matches the pattern
// The only special character in the pattern is "*", which matches any sequence of characters (including an empty one)
func MatchSubject(pattern string, subject string) bool {
	// Iterative wildcard matching: on mismatch, backtrack to the most recent "*" and let it consume one more character
	var p, s, starMatch int
	star := -1
	for s < len(subject) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star = p
			starMatch = s
			p++
		case p < len(pattern) && pattern[p] == subject[s]:
			p++
			s++
		case star >= 0:
			p = star + 1
			starMatch++
			s = starMatch
		default:
			return false
		}
	}

	// Any remaining pattern characters must all be "*"
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}

// NormalizeIssuerConfig trims the fields of cfg and validates them
func NormalizeIssuerConfig(cfg *IssuerConfig) error {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	cfg.Subject = strings.TrimSpace(cfg.Subject)
	cfg.JWKSURL = strings.TrimSpace(cfg.JWKSURL)

	err := validateClaimValue("issuer", cfg.Issuer, MaxIssuerLength)
	if err != nil {
		return err
	}

	err = validateClaimValue("audience", cfg.Audience, MaxAudienceLength)
	if err != nil {
		return err
	}

	err = validateClaimValue("subject", cfg.Subject, MaxSubjectLength)
	if err != nil {
		return err
	}

	// A pattern made only of wildcards would accept every token the issuer signs for this audience
	// For shared issuers such as GitHub Actions, that includes tokens minted by anyone's workflows
	if strings.Trim(cfg.Subject, "*") == "" {
		return errors.New("subject must not consist only of wildcards")
	}

	if cfg.JWKSURL != "" {
		if len(cfg.JWKSURL) > MaxJWKSURLLength {
			return fmt.Errorf("JWKS URL must be at most %d characters", MaxJWKSURLLength)
		}

		err = validateHTTPSURL(cfg.JWKSURL)
		if err != nil {
			return fmt.Errorf("JWKS URL is invalid: %w", err)
		}

		return nil
	}

	// Without an explicit JWKS URL, the issuer must be a URL that supports OIDC discovery
	err = validateHTTPSURL(cfg.Issuer)
	if err != nil {
		return fmt.Errorf("issuer must be an HTTPS URL that supports OpenID Connect discovery, or a JWKS URL must be set: %w", err)
	}

	issuerURL, _ := url.Parse(cfg.Issuer)
	if issuerURL.RawQuery != "" || issuerURL.ForceQuery {
		return errors.New("issuer URL must not contain a query string")
	}

	return nil
}

func validateClaimValue(name string, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}

	if len(value) > maxLen {
		return fmt.Errorf("%s must be at most %d characters", name, maxLen)
	}

	invalid := strings.ContainsFunc(value, func(r rune) bool {
		return !unicode.IsPrint(r)
	})
	if invalid {
		return fmt.Errorf("%s contains invalid characters", name)
	}

	return nil
}

// validateHTTPSURL checks that u is an absolute HTTPS URL
// Userinfo is rejected because fetch errors include the URL verbatim, which would leak credentials into logs
func validateHTTPSURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}

	if parsed.Scheme != "https" {
		return errors.New("scheme must be https")
	}

	if parsed.Host == "" {
		return errors.New("host is missing")
	}

	if parsed.User != nil {
		return errors.New("URL must not contain credentials")
	}

	if parsed.Fragment != "" {
		return errors.New("URL must not contain a fragment")
	}

	return nil
}
