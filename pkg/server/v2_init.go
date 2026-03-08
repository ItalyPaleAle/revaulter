package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/v2db"
)

func (s *Server) initV2Store(log *slog.Logger) error {
	cfg := config.Get()
	if cfg.DatabaseDSN == "" {
		return nil
	}
	key := cfg.GetDBPayloadEncryptionKey()
	if len(key) == 0 {
		return fmt.Errorf("databaseDSN configured but dbPayloadEncryptionKey was not parsed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	db, _, err := v2db.Open(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("failed to open v2 database: %w", err)
	}
	authStore, err := v2db.NewAuthStoreWithPayloadKey(ctx, db, key, log)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to initialize v2 auth store: %w", err)
	}
	store, err := v2db.NewRequestStore(ctx, db, key, log)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to initialize v2 request store: %w", err)
	}

	s.v2DB = db
	s.v2AuthStore = authStore
	s.v2RequestStore = store
	if wa, err := s.initV2WebAuthn(); err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to initialize v2 WebAuthn config: %w", err)
	} else {
		s.v2WebAuthn = wa
	}
	return nil
}

func (s *Server) initV2WebAuthn() (*webauthnlib.WebAuthn, error) {
	cfg := config.Get()
	rpID := strings.ToLower(strings.TrimSpace(cfg.WebAuthnRPID))
	if rpID == "" {
		base, err := url.Parse(cfg.BaseUrl)
		if err != nil {
			return nil, fmt.Errorf("invalid baseUrl for WebAuthn RP: %w", err)
		}
		rpID = strings.ToLower(base.Hostname())
	}
	if rpID == "" {
		return nil, fmt.Errorf("invalid WebAuthn RP ID")
	}

	origins := make([]string, 0, 1+len(cfg.Origins)+len(cfg.WebAuthnOrigins))
	if strings.TrimSpace(cfg.BaseUrl) != "" {
		origins = append(origins, strings.TrimRight(cfg.BaseUrl, "/"))
	}
	for _, origin := range cfg.WebAuthnOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		origins = append(origins, strings.TrimRight(origin, "/"))
	}
	for _, origin := range cfg.Origins {
		origin = strings.TrimSpace(origin)
		if origin == "" || origin == "*" {
			continue
		}
		origins = append(origins, strings.TrimRight(origin, "/"))
	}

	seen := map[string]struct{}{}
	filtered := make([]string, 0, len(origins))
	for _, o := range origins {
		if _, ok := seen[o]; ok {
			continue
		}
		seen[o] = struct{}{}
		filtered = append(filtered, o)
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no valid WebAuthn origins configured")
	}
	rpName := strings.TrimSpace(cfg.WebAuthnRPName)
	if rpName == "" {
		rpName = "Revaulter v2"
	}

	return webauthnlib.New(&webauthnlib.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     filtered,
	})
}
