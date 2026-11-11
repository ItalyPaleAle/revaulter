package server

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/italypaleale/revaulter/internal/config"
)

// initWebAuthn builds the relying-party configuration used for all WebAuthn registration and login ceremonies
// It derives the RP ID from config when needed, normalizes the allowed origins, and enables related-origin requests when extra WebAuthn origins are explicitly configured
func (s *Server) initWebAuthn() (*webauthnlib.WebAuthn, error) {
	cfg := config.Get()

	// Prefer an explicit RP ID, otherwise derive it from the configured base URL hostname
	rpID := strings.ToLower(strings.TrimSpace(cfg.WebAuthnRPID))
	if rpID == "" {
		base, err := url.Parse(cfg.BaseUrl)
		if err != nil {
			return nil, fmt.Errorf("invalid baseUrl for WebAuthn RP: %w", err)
		}
		rpID = strings.ToLower(base.Hostname())
	}

	if rpID == "" {
		return nil, errors.New("cannot determine WebAuthn RP ID: configuration values for 'webauthnRpId' and 'baseUrl' are both empty")
	}

	// The base URL is always a valid relying-party origin when present
	origins := make([]string, 0, 1+len(cfg.WebAuthnOrigins))
	if strings.TrimSpace(cfg.BaseUrl) != "" {
		origins = append(origins, strings.TrimRight(cfg.BaseUrl, "/"))
	}

	// Additional configured WebAuthn origins are accepted both as RP origins and as related top-level origins for related-origin requests
	topOrigins := make([]string, 0, len(cfg.WebAuthnOrigins))
	for _, origin := range cfg.WebAuthnOrigins {
		origin = strings.TrimSpace(origin)
		// Ignore wildcards
		if origin == "" || origin == "*" {
			continue
		}
		origin = strings.TrimRight(origin, "/")
		origins = append(origins, origin)
		topOrigins = append(topOrigins, origin)
	}

	// Remove duplicates after normalization so the WebAuthn library receives a clean list
	filtered := dedupeOrigins(origins)
	if len(filtered) == 0 {
		return nil, errors.New("no valid WebAuthn origins configured")
	}

	// RPOrigins controls the normal origin checks for WebAuthn ceremonies
	waCfg := &webauthnlib.Config{
		RPID:                              rpID,
		RPDisplayName:                     cfg.WebAuthnRPName,
		RPOrigins:                         filtered,
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	}

	// Enable explicit top-origin verification for Related Origin Requests when extra WebAuthn origins are configured
	filteredTopOrigins := dedupeOrigins(topOrigins)
	if len(filteredTopOrigins) > 0 {
		waCfg.RPTopOrigins = filteredTopOrigins
		waCfg.RPTopOriginVerificationMode = protocol.TopOriginExplicitVerificationMode
	}

	return webauthnlib.New(waCfg)
}

func dedupeOrigins(origins []string) []string {
	seen := make(map[string]struct{}, len(origins))
	filtered := make([]string, 0, len(origins))
	for _, origin := range origins {
		_, ok := seen[origin]
		if ok {
			continue
		}

		seen[origin] = struct{}{}
		filtered = append(filtered, origin)
	}
	return filtered
}

// cookieSecurityForOrigins decides whether session cookies must always be Secure, based on the configured WebAuthn origins
// alwaysSecure is true when no origin uses http://, because browsers can then only use the web client over HTTPS
// An http:// origin is only usable on localhost (WebAuthn doesn't work on non-HTTPS pages outside of localhost), so it signals local development, where cookies follow the scheme of each request instead
// mixed is true when both https:// and http:// origins are configured
// Origins with other schemes, such as Android app origins, don't load the web client and are ignored
func cookieSecurityForOrigins(origins []string) (alwaysSecure bool, mixed bool) {
	var hasHTTPS, hasHTTP bool
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil {
			continue
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
			hasHTTPS = true
		case "http":
			hasHTTP = true
		}
	}

	return hasHTTPS && !hasHTTP, hasHTTPS && hasHTTP
}
