//go:build e2e

// This file includes helpers for the e2e tests, and it's only built with the "e2e" tag

package db

import (
	"context"
	"fmt"
	"time"
)

// ResetAllForTests removes all v2 rows in dependency order
// This is only intended for deterministic test harness setup
func (db *DB) ResetAllForTests(ctx context.Context) error {
	if db == nil || db.DatabaseConn == nil {
		return fmt.Errorf("db is not initialized")
	}

	_, err := ExecuteInTransaction(ctx, db, 30*time.Second, func(ctx context.Context, tx *DbTx) (struct{}, error) {
		tables := []string{
			"v2_published_signing_keys",
			"v2_auth_challenge_payloads",
			"v2_auth_challenges",
			"v2_user_credentials",
			"v2_request_payloads",
			"v2_users",
		}
		for _, table := range tables {
			_, err := tx.Exec(ctx, "DELETE FROM "+table)
			if err != nil {
				return struct{}{}, fmt.Errorf("failed to reset table %s: %w", table, err)
			}
		}

		return struct{}{}, nil
	})

	return err
}

// GetRequestPayloadOwnerForTests returns the ID of the user who owns a request, or an empty string if the request has no payload row
func (s *RequestPayloadStore) GetRequestPayloadOwnerForTests(ctx context.Context, state string) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("request payload store is not initialized")
	}

	var userID string
	err := s.db.QueryRow(ctx, `SELECT user_id FROM v2_request_payloads WHERE state = $1`, state).Scan(&userID)
	if s.db.IsNoRowsError(err) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("failed to read owner of request %s: %w", state, err)
	}

	return userID, nil
}
