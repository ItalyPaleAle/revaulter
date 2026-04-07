package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/v2db"
)

func (s *Server) initStore(log *slog.Logger) error {
	cfg := config.Get()
	if cfg.DatabaseDSN == "" {
		return nil
	}

	key := cfg.GetSecretKey()
	if len(key) == 0 {
		return errors.New("databaseDSN configured but secretKey was not parsed")
	}

	connCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	db, err := v2db.Open(connCtx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	err = v2db.RunMigrations(context.Background(), db, log)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to run database migrations: %w", err)
	}

	authStore, err := v2db.NewAuthStore(db, log)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to initialize auth store: %w", err)
	}

	store, err := v2db.NewRequestStore(db, key, log)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to initialize request store: %w", err)
	}

	s.db = db
	s.authStore = authStore
	s.requestStore = store

	s.webAuthn, err = s.initWebAuthn()
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to initialize WebAuthn config: %w", err)
	}

	return nil
}

// initWebAuthn builds the relying-party configuration used for all v2 WebAuthn registration and login ceremonies
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
		RPID:          rpID,
		RPDisplayName: cfg.WebAuthnRPName,
		RPOrigins:     filtered,
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
