package db

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

func TestRequestStoreLifecycle(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-1",
				DisplayName:    "Alice",
				WebAuthnUserID: "webauthn-user-1",
				CredentialID:   "cred-1",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			now := time.Now().UTC().Truncate(time.Second)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-1",
				UserID:           "user-1",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "boot-disk",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			// Returns all pending
			list, err := rs.ListPending(ctx, "")
			require.NoError(t, err)
			require.Len(t, list, 1)
			require.Equal(t, "state-1", list[0].State)

			// Filtering by the owner returns the same record
			list, err = rs.ListPending(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, list, 1)
			require.Equal(t, "state-1", list[0].State)

			// Filtering by a different user returns nothing
			list, err = rs.ListPending(ctx, "user-other")
			require.NoError(t, err)
			require.Empty(t, list)

			rec, err := rs.GetRequest(ctx, "state-1")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusPending, rec.Status)
			require.Equal(t, "user-1", rec.UserID)
			require.Contains(t, rec.EncryptedRequest, "cliEphemeralPublicKey")
			require.Nil(t, rec.ResponseEnvelope)

			completed, err := rs.CompleteRequest(ctx, "state-1", "user-1", protocolv2.ResponseEnvelope{
				TransportAlg: protocolv2.TransportAlg,
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Nonce:      "bm9uY2U",
				Ciphertext: "Y2lwaGVy",
			})
			require.NoError(t, err)
			require.NotNil(t, completed)
			require.Equal(t, V2RequestStatusCompleted, completed.Status)
			require.NotNil(t, completed.ResponseEnvelope)

			rec, err = rs.GetRequest(ctx, "state-1")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusCompleted, rec.Status)
			require.NotNil(t, rec.ResponseEnvelope)
			require.Equal(t, protocolv2.TransportAlg, rec.ResponseEnvelope.TransportAlg)

			return nil, nil
		})
	})
}

func TestRequestStoreCancel(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-2",
				DisplayName:    "Bob",
				WebAuthnUserID: "webauthn-user-2",
				CredentialID:   "cred-2",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-2",
				UserID:           "user-2",
				Operation:        "decrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "x",
				Algorithm:        "A256GCM",
				CreatedAt:        time.Now(),
				ExpiresAt:        time.Now().Add(time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"t","y":"t"},"nonce":"n","ciphertext":"c"}`,
			})
			require.NoError(t, err)

			canceled, err := rs.CancelRequest(ctx, "state-2", "user-2")
			require.NoError(t, err)
			require.NotNil(t, canceled)
			require.Equal(t, V2RequestStatusCanceled, canceled.Status)

			rec, err := rs.GetRequest(ctx, "state-2")
			require.NoError(t, err)
			require.Equal(t, V2RequestStatusCanceled, rec.Status)

			return nil, nil
		})
	})
}

func TestRequestStoreGetAndDeleteTerminalRequest(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-get-delete",
				DisplayName:    "Get Delete User",
				WebAuthnUserID: "webauthn-user-get-delete",
				CredentialID:   "cred-get-delete",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			now := time.Now().UTC().Truncate(time.Second)
			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-terminal",
				UserID:           "user-get-delete",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "terminal-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			_, err = rs.CompleteRequest(ctx, "state-terminal", "user-get-delete", protocolv2.ResponseEnvelope{
				TransportAlg: protocolv2.TransportAlg,
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Nonce:      "bm9uY2U",
				Ciphertext: "Y2lwaGVy",
			})
			require.NoError(t, err)

			rec, err := rs.GetAndDeleteTerminalRequest(ctx, "state-terminal")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusCompleted, rec.Status)

			rec, err = rs.GetRequest(ctx, "state-terminal")
			require.NoError(t, err)
			require.Nil(t, rec)

			return nil, nil
		})
	})
}

func TestRequestStoreGetAndDeleteTerminalRequestExpiresPending(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			// #nosec G101 - Hardcoded credentials are test ones
			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-get-delete-expired",
				DisplayName:    "Get Delete Expired User",
				WebAuthnUserID: "webauthn-user-get-delete-expired",
				CredentialID:   "cred-get-delete-expired",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			now := time.Now().UTC().Truncate(time.Second)
			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-expired-terminal",
				UserID:           "user-get-delete-expired",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "expired-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now.Add(-2 * time.Minute),
				ExpiresAt:        now.Add(-1 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			rec, err := rs.GetAndDeleteTerminalRequest(ctx, "state-expired-terminal")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusExpired, rec.Status)

			rec, err = rs.GetRequest(ctx, "state-expired-terminal")
			require.NoError(t, err)
			require.Nil(t, rec)

			return nil, nil
		})
	})
}

func TestRequestStoreMarkExpired(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-expire",
				DisplayName:    "Expire User",
				WebAuthnUserID: "webauthn-user-expire",
				CredentialID:   "cred-expire",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			now := time.Now().UTC().Truncate(time.Second)
			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-expired",
				UserID:           "user-expire",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "expired-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now.Add(-2 * time.Minute),
				ExpiresAt:        now.Add(-1 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-fresh",
				UserID:           "user-expire",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "fresh-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-completed",
				UserID:           "user-expire",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "completed-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			completed, err := rs.CompleteRequest(ctx, "state-completed", "user-expire", protocolv2.ResponseEnvelope{
				TransportAlg: protocolv2.TransportAlg,
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Nonce:      "bm9uY2U",
				Ciphertext: "Y2lwaGVy",
			})
			require.NoError(t, err)
			require.NotNil(t, completed)

			expired, err := rs.MarkExpired(ctx, "state-expired")
			require.NoError(t, err)
			require.NotNil(t, expired)
			require.Equal(t, "state-expired", expired.State)
			require.Equal(t, "user-expire", expired.UserID)
			require.Equal(t, V2RequestStatusExpired, expired.Status)

			rec, err := rs.GetRequest(ctx, "state-expired")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusExpired, rec.Status)

			expired, err = rs.MarkExpired(ctx, "state-fresh")
			require.NoError(t, err)
			require.Nil(t, expired)

			expired, err = rs.MarkExpired(ctx, "state-completed")
			require.NoError(t, err)
			require.Nil(t, expired)

			return nil, nil
		})
	})
}

func TestRequestStoreDeleteTerminalRequestWithCutoff(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-delete",
				DisplayName:    "Delete User",
				WebAuthnUserID: "webauthn-user-delete",
				CredentialID:   "cred-delete",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			now := time.Now().UTC().Truncate(time.Second)
			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-old-terminal",
				UserID:           "user-delete",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "old-terminal",
				Algorithm:        "A256GCM",
				CreatedAt:        now.Add(-25 * time.Minute),
				ExpiresAt:        now.Add(-20 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			canceled, err := rs.CancelRequest(ctx, "state-old-terminal", "user-delete")
			require.NoError(t, err)
			require.NotNil(t, canceled)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-pending",
				UserID:           "user-delete",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "pending",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(30 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-recent-terminal",
				UserID:           "user-delete",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "recent-terminal",
				Algorithm:        "A256GCM",
				CreatedAt:        now.Add(-5 * time.Minute),
				ExpiresAt:        now.Add(-2 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			canceled, err = rs.CancelRequest(ctx, "state-recent-terminal", "user-delete")
			require.NoError(t, err)
			require.NotNil(t, canceled)

			err = rs.DeleteTerminalRequest(ctx, "state-old-terminal", &now)
			require.NoError(t, err)
			err = rs.DeleteTerminalRequest(ctx, "state-pending", &now)
			require.NoError(t, err)
			err = rs.DeleteTerminalRequest(ctx, "state-recent-terminal", &now)
			require.NoError(t, err)

			rec, err := rs.GetRequest(ctx, "state-old-terminal")
			require.NoError(t, err)
			require.Nil(t, rec)

			rec, err = rs.GetRequest(ctx, "state-pending")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusPending, rec.Status)

			rec, err = rs.GetRequest(ctx, "state-recent-terminal")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusCanceled, rec.Status)

			return nil, nil
		})
	})
}

func TestRequestStoreDeleteTerminalRequest(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-delete-now",
				DisplayName:    "Delete Now User",
				WebAuthnUserID: "webauthn-user-delete-now",
				CredentialID:   "cred-delete-now",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			now := time.Now().UTC().Truncate(time.Second)
			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-terminal-delete",
				UserID:           "user-delete-now",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "terminal-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			err = rs.CreateRequest(ctx, CreateRequestInput{
				State:            "state-pending-keep",
				UserID:           "user-delete-now",
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "pending-key",
				Algorithm:        "A256GCM",
				CreatedAt:        now,
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			_, err = rs.CompleteRequest(ctx, "state-terminal-delete", "user-delete-now", protocolv2.ResponseEnvelope{
				TransportAlg: protocolv2.TransportAlg,
				BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
					Kty: "EC", Crv: "P-256",
					X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Nonce:      "bm9uY2U",
				Ciphertext: "Y2lwaGVy",
			})
			require.NoError(t, err)

			err = rs.DeleteTerminalRequest(ctx, "state-terminal-delete", nil)
			require.NoError(t, err)

			rec, err := rs.GetRequest(ctx, "state-terminal-delete")
			require.NoError(t, err)
			require.Nil(t, rec)

			err = rs.DeleteTerminalRequest(ctx, "state-pending-keep", nil)
			require.NoError(t, err)

			rec, err = rs.GetRequest(ctx, "state-pending-keep")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusPending, rec.Status)

			return nil, nil
		})
	})
}

func TestRequestStoreListPendingByUser(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			rs := tx.RequestStore()

			var err error
			for _, id := range []string{"user-list-alice", "user-list-bob"} {
				_, err = as.RegisterUser(ctx, RegisterUserInput{
					UserID:         id,
					DisplayName:    id,
					WebAuthnUserID: "webauthn-" + id,
					CredentialID:   "cred-" + id,
					PublicKey:      `{"kty":"EC"}`,
					SignCount:      1,
					SessionTTL:     time.Minute,
				})
				require.NoError(t, err)
			}

			now := time.Now().UTC().Truncate(time.Second)
			mkReq := func(state, userID, label string, createdOffset time.Duration) {
				err = rs.CreateRequest(ctx, CreateRequestInput{
					State:            state,
					UserID:           userID,
					Operation:        "encrypt",
					RequestorIP:      "127.0.0.1",
					KeyLabel:         label,
					Algorithm:        "A256GCM",
					CreatedAt:        now.Add(createdOffset),
					ExpiresAt:        now.Add(5 * time.Minute),
					EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
				})
				require.NoError(t, err)
			}

			// Offsets keep ASC ordering deterministic without relying on insertion time
			mkReq("state-alice-1", "user-list-alice", "alice-1", 0)
			mkReq("state-alice-2", "user-list-alice", "alice-2", time.Second)
			mkReq("state-bob-1", "user-list-bob", "bob-1", 2*time.Second)

			// Empty userID returns every pending row
			list, err := rs.ListPending(ctx, "")
			require.NoError(t, err)
			require.Len(t, list, 3)

			// Filter by Alice returns only her two rows and no cross-user leakage
			list, err = rs.ListPending(ctx, "user-list-alice")
			require.NoError(t, err)
			require.Len(t, list, 2)
			states := []string{list[0].State, list[1].State}
			require.ElementsMatch(t, []string{"state-alice-1", "state-alice-2"}, states)
			for _, item := range list {
				require.Equal(t, "user-list-alice", item.UserID)
			}

			// Filter by Bob returns only his row
			list, err = rs.ListPending(ctx, "user-list-bob")
			require.NoError(t, err)
			require.Len(t, list, 1)
			require.Equal(t, "state-bob-1", list[0].State)
			require.Equal(t, "user-list-bob", list[0].UserID)

			// A userID that owns no rows yields an empty slice, not an error
			list, err = rs.ListPending(ctx, "user-list-nobody")
			require.NoError(t, err)
			require.Empty(t, list)

			// Terminal rows never appear in the pending list, regardless of filter
			_, err = rs.CancelRequest(ctx, "state-alice-1", "user-list-alice")
			require.NoError(t, err)
			list, err = rs.ListPending(ctx, "user-list-alice")
			require.NoError(t, err)
			require.Len(t, list, 1)
			require.Equal(t, "state-alice-2", list[0].State)

			return nil, nil
		})
	})
}

func TestRequestStoreExpiryWritesAuditEvents(t *testing.T) {
	// Seeds a user with one pending request per state, all past their deadline unless listed in fresh
	seed := func(t *testing.T, conn *DB, userID string, states []string, fresh ...string) {
		t.Helper()

		_, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			_, rErr := tx.AuthStore().RegisterUser(ctx, RegisterUserInput{
				UserID:         userID,
				DisplayName:    "Expiry Audit User",
				WebAuthnUserID: "webauthn-" + userID,
				CredentialID:   "cred-" + userID,
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			if rErr != nil {
				return nil, rErr
			}

			now := time.Now().UTC().Truncate(time.Second)
			for _, state := range states {
				expiresAt := now.Add(-1 * time.Minute)
				if slices.Contains(fresh, state) {
					expiresAt = now.Add(5 * time.Minute)
				}

				rErr = tx.RequestStore().CreateRequest(ctx, CreateRequestInput{
					State:            state,
					UserID:           userID,
					Operation:        "encrypt",
					RequestorIP:      "127.0.0.1",
					KeyLabel:         "expiry-key",
					Algorithm:        "A256GCM",
					Note:             "expiry note",
					CreatedAt:        now.Add(-2 * time.Minute),
					ExpiresAt:        expiresAt,
					EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
				})
				if rErr != nil {
					return nil, rErr
				}
			}

			return nil, nil
		})
		require.NoError(t, err)
	}

	// Returns the request states that have a request.expire audit event, in any order
	expireAuditStates := func(t *testing.T, conn *DB) []string {
		t.Helper()

		events, _, err := conn.AuditStore().List(t.Context(), AuditFilter{EventType: AuditRequestExpire}, 500, "")
		require.NoError(t, err)

		states := make([]string, 0, len(events))
		for _, ev := range events {
			require.Equal(t, AuditOutcomeSuccess, ev.Outcome)
			require.Equal(t, AuditAuthMethodSystem, ev.AuthMethod)
			require.NotNil(t, ev.ActorUserID)
			require.NotNil(t, ev.TargetUserID)
			require.Equal(t, *ev.ActorUserID, *ev.TargetUserID)
			require.NotNil(t, ev.RequestState)
			require.JSONEq(t, `{"operation":"encrypt","algorithm":"A256GCM","keyLabel":"expiry-key","note":"expiry note"}`, string(ev.Metadata))
			states = append(states, *ev.RequestState)
		}
		return states
	}

	t.Run("MarkExpired", func(t *testing.T) {
		runDBTest(t, func(t *testing.T, conn *DB) {
			require.NoError(t, RunMigrations(t.Context(), conn, nil))
			seed(t, conn, "user-expiry-mark", []string{"mark-expired", "mark-fresh"}, "mark-fresh")

			rs := conn.RequestStore()
			rec, err := rs.MarkExpired(t.Context(), "mark-expired")
			require.NoError(t, err)
			require.NotNil(t, rec)

			// A second transition, or one on a request that isn't past its deadline, is a no-op and must not write another event
			rec, err = rs.MarkExpired(t.Context(), "mark-expired")
			require.NoError(t, err)
			require.Nil(t, rec)
			rec, err = rs.MarkExpired(t.Context(), "mark-fresh")
			require.NoError(t, err)
			require.Nil(t, rec)

			require.Equal(t, []string{"mark-expired"}, expireAuditStates(t, conn))
		})
	})

	t.Run("ExpirePending", func(t *testing.T) {
		runDBTest(t, func(t *testing.T, conn *DB) {
			require.NoError(t, RunMigrations(t.Context(), conn, nil))
			seed(t, conn, "user-expiry-bulk", []string{"bulk-1", "bulk-2", "bulk-fresh"}, "bulk-fresh")

			rs := conn.RequestStore()
			expired, err := rs.ExpirePending(t.Context(), time.Now())
			require.NoError(t, err)
			require.Len(t, expired, 2)
			for _, rec := range expired {
				require.Equal(t, V2RequestStatusExpired, rec.Status)
			}

			// Running again finds nothing left to expire
			expired, err = rs.ExpirePending(t.Context(), time.Now())
			require.NoError(t, err)
			require.Empty(t, expired)

			require.ElementsMatch(t, []string{"bulk-1", "bulk-2"}, expireAuditStates(t, conn))
		})
	})

	t.Run("ExpirePending across batches", func(t *testing.T) {
		runDBTest(t, func(t *testing.T, conn *DB) {
			require.NoError(t, RunMigrations(t.Context(), conn, nil))

			// More requests than fit in a single audit INSERT statement
			states := make([]string, 2*auditInsertBatchSize+1)
			for i := range states {
				states[i] = "many-" + strconv.Itoa(i)
			}
			seed(t, conn, "user-expiry-many", states)

			expired, err := conn.RequestStore().ExpirePending(t.Context(), time.Now())
			require.NoError(t, err)
			require.Len(t, expired, len(states))

			require.ElementsMatch(t, states, expireAuditStates(t, conn))
		})
	})

	t.Run("ListPending", func(t *testing.T) {
		runDBTest(t, func(t *testing.T, conn *DB) {
			require.NoError(t, RunMigrations(t.Context(), conn, nil))
			seed(t, conn, "user-expiry-list", []string{"list-expired", "list-fresh"}, "list-fresh")

			list, err := conn.RequestStore().ListPending(t.Context(), "user-expiry-list")
			require.NoError(t, err)
			require.Len(t, list, 1)
			require.Equal(t, "list-fresh", list[0].State)

			require.Equal(t, []string{"list-expired"}, expireAuditStates(t, conn))
		})
	})

	t.Run("GetRequest", func(t *testing.T) {
		runDBTest(t, func(t *testing.T, conn *DB) {
			require.NoError(t, RunMigrations(t.Context(), conn, nil))
			seed(t, conn, "user-expiry-get", []string{"get-expired"})

			rec, err := conn.RequestStore().GetRequest(t.Context(), "get-expired")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusExpired, rec.Status)

			require.Equal(t, []string{"get-expired"}, expireAuditStates(t, conn))
		})
	})

	t.Run("GetAndDeleteTerminalRequest", func(t *testing.T) {
		runDBTest(t, func(t *testing.T, conn *DB) {
			require.NoError(t, RunMigrations(t.Context(), conn, nil))
			seed(t, conn, "user-expiry-delete", []string{"delete-expired", "delete-canceled", "delete-fresh"}, "delete-canceled", "delete-fresh")

			rs := conn.RequestStore()
			_, err := rs.CancelRequest(t.Context(), "delete-canceled", "user-expiry-delete")
			require.NoError(t, err)

			// A pending request past its deadline is expired, audited, and deleted
			rec, err := rs.GetAndDeleteTerminalRequest(t.Context(), "delete-expired")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusExpired, rec.Status)

			// A request that was already terminal is deleted without an expiry event
			rec, err = rs.GetAndDeleteTerminalRequest(t.Context(), "delete-canceled")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusCanceled, rec.Status)

			// A request that is still pending is left alone
			rec, err = rs.GetAndDeleteTerminalRequest(t.Context(), "delete-fresh")
			require.NoError(t, err)
			require.Nil(t, rec)
			rec, err = rs.GetRequest(t.Context(), "delete-fresh")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, V2RequestStatusPending, rec.Status)

			require.Equal(t, []string{"delete-expired"}, expireAuditStates(t, conn))
		})
	})
}
