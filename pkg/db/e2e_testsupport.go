//go:build e2e

// This file includes helpers for the e2e tests, and it's only built with the "e2e" tag

package db

import (
	"context"
	"fmt"
	"time"
)

// ResetAllForTests removes all v2 rows in dependency order.
// This is only intended for deterministic test harness setup.
func (db *DB) ResetAllForTests(ctx context.Context) error {
	if db == nil || db.DatabaseConn == nil {
		return fmt.Errorf("db is not initialized")
	}

	tables := []string{
		"v2_auth_challenge_payloads",
		"v2_auth_challenges",
		"v2_user_sessions",
		"v2_user_credentials",
		"v2_requests",
		"v2_users",
	}
	for _, table := range tables {
		_, err := db.Exec(ctx, "DELETE FROM "+table)
		if err != nil {
			return fmt.Errorf("failed to reset table %s: %w", table, err)
		}
	}

	return nil
}

// ForceExpireRequestForTests sets the request expiry in the past for deterministic test setup.
func (s *RequestStore) ForceExpireRequestForTests(ctx context.Context, state string, expiresAt time.Time) error {
	if s == nil || s.db == nil || s.db.DatabaseConn == nil {
		return fmt.Errorf("request store is not initialized")
	}

	_, err := s.db.Exec(ctx, `UPDATE v2_requests SET expires_at = $1 WHERE state = $2`, expiresAt.Unix(), state)
	if err != nil {
		return fmt.Errorf("failed to force-expire request %s: %w", state, err)
	}

	return nil
}
