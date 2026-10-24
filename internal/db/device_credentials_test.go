package db

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// seedReadyUser registers a user with one passkey and completes signup, so the account is active and ready
func seedReadyUser(t *testing.T, conn *DB, userID string) {
	t.Helper()

	_, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (struct{}, error) {
		as := tx.AuthStore()

		_, rErr := as.RegisterUser(ctx, RegisterUserInput{
			UserID:         userID,
			DisplayName:    "Alice",
			WebAuthnUserID: "webauthn-" + userID,
			CredentialID:   "passkey-" + userID,
			PublicKey:      `{"kty":"EC"}`,
			SignCount:      1,
			SessionTTL:     time.Minute,
		})
		if rErr != nil {
			return struct{}{}, rErr
		}

		_, rErr = as.FinalizeSignup(ctx, FinalizeSignupInput{
			UserID:              userID,
			WrappedPrimaryKey:   "wrapped",
			PubkeyBundleVersion: protocolv2.PubkeyBundleVersion2,
		})
		return struct{}{}, rErr
	})
	require.NoError(t, err)
}

func addTestCredential(t *testing.T, conn *DB, in AddCredentialInput) {
	t.Helper()

	_, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (struct{}, error) {
		return struct{}{}, tx.AuthStore().AddCredential(ctx, in)
	})
	require.NoError(t, err)
}

func credentialIDsByCredentialID(t *testing.T, conn *DB, userID string) map[string]AuthCredentialRecord {
	t.Helper()

	creds, err := conn.AuthStore().ListCredentials(t.Context(), userID)
	require.NoError(t, err)

	out := make(map[string]AuthCredentialRecord, len(creds))
	for _, c := range creds {
		out[c.CredentialID] = c
	}

	return out
}

func TestAuthStoreDeviceCredentials(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)
		seedReadyUser(t, conn, "user-1")

		// A device envelope with its ML-KEM ciphertext is much larger than the passkey limit used to be
		largeWrapped := strings.Repeat("a", 2500)
		addTestCredential(t, conn, AddCredentialInput{
			UserID:            "user-1",
			CredentialID:      "device-1",
			DisplayName:       "iPhone",
			CredentialType:    protocolv2.CredentialTypeDevice,
			PublicKey:         `{"signP256":"a","kaP256":"b","signMldsa65":"c","kemMlkem768":"d"}`,
			WrappedPrimaryKey: largeWrapped,
		})

		creds := credentialIDsByCredentialID(t, conn, "user-1")
		require.Len(t, creds, 2)
		require.Equal(t, protocolv2.CredentialTypePasskey, creds["passkey-user-1"].CredentialType)
		require.Equal(t, protocolv2.CredentialTypeDevice, creds["device-1"].CredentialType)
		require.Equal(t, largeWrapped, creds["device-1"].WrappedPrimaryKey)

		as := conn.AuthStore()

		rec, err := as.GetCredentialForUser(t.Context(), "user-1", "device-1")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, protocolv2.CredentialTypeDevice, rec.CredentialType)

		rec, err = as.GetCredentialByCredentialID(t.Context(), "device-1", "user-1")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.Equal(t, protocolv2.CredentialTypeDevice, rec.CredentialType)

		t.Run("rejects an unknown type", func(t *testing.T) {
			err := as.AddCredential(t.Context(), AddCredentialInput{
				UserID:         "user-1",
				CredentialID:   "other",
				CredentialType: "security-key",
				PublicKey:      `{}`,
			})
			require.Error(t, err)
		})

		t.Run("rejects a duplicate credential ID", func(t *testing.T) {
			err := as.AddCredential(t.Context(), AddCredentialInput{
				UserID:         "user-1",
				CredentialID:   "device-1",
				CredentialType: protocolv2.CredentialTypeDevice,
				PublicKey:      `{}`,
			})
			require.ErrorIs(t, err, ErrCredentialAlreadyExists)
		})

		t.Run("rejects an oversized wrapped key", func(t *testing.T) {
			err := as.AddCredential(t.Context(), AddCredentialInput{
				UserID:            "user-1",
				CredentialID:      "device-2",
				CredentialType:    protocolv2.CredentialTypeDevice,
				PublicKey:         `{}`,
				WrappedPrimaryKey: strings.Repeat("a", protocolv2.MaxWrappedPrimaryKeyLength+1),
			})
			require.Error(t, err)
		})

		t.Run("uses the given record ID", func(t *testing.T) {
			err := as.AddCredential(t.Context(), AddCredentialInput{
				ID:             "record-3",
				UserID:         "user-1",
				CredentialID:   "device-3",
				CredentialType: protocolv2.CredentialTypeDevice,
				PublicKey:      `{}`,
			})
			require.NoError(t, err)

			rec, err := as.GetCredentialForUser(t.Context(), "user-1", "device-3")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, "record-3", rec.ID)
		})
	})
}

func TestAuthStoreDeleteKeepsAPasskey(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)
		seedReadyUser(t, conn, "user-1")

		addTestCredential(t, conn, AddCredentialInput{UserID: "user-1", CredentialID: "device-1", CredentialType: protocolv2.CredentialTypeDevice, PublicKey: `{}`})
		addTestCredential(t, conn, AddCredentialInput{UserID: "user-1", CredentialID: "device-2", CredentialType: protocolv2.CredentialTypeDevice, PublicKey: `{}`})

		as := conn.AuthStore()
		creds := credentialIDsByCredentialID(t, conn, "user-1")

		// The only passkey can't go while devices remain
		err = as.DeleteCredential(t.Context(), creds["passkey-user-1"].ID, "user-1")
		require.ErrorIs(t, err, ErrLastPasskey)

		// Devices can go
		err = as.DeleteCredential(t.Context(), creds["device-1"].ID, "user-1")
		require.NoError(t, err)

		// A second passkey makes the first one removable
		addTestCredential(t, conn, AddCredentialInput{UserID: "user-1", CredentialID: "passkey-2", PublicKey: `{}`})
		err = as.DeleteCredential(t.Context(), creds["passkey-user-1"].ID, "user-1")
		require.NoError(t, err)

		// Now passkey-2 is the last passkey
		creds = credentialIDsByCredentialID(t, conn, "user-1")
		err = as.DeleteCredential(t.Context(), creds["passkey-2"].ID, "user-1")
		require.ErrorIs(t, err, ErrLastPasskey)

		// Once the last device goes, the passkey is the last credential
		err = as.DeleteCredential(t.Context(), creds["device-2"].ID, "user-1")
		require.NoError(t, err)
		err = as.DeleteCredential(t.Context(), creds["passkey-2"].ID, "user-1")
		require.ErrorIs(t, err, ErrLastCredential)

		err = as.DeleteCredential(t.Context(), "nonexistent", "user-1")
		require.ErrorIs(t, err, ErrCredentialNotFound)
	})
}

func TestAuthStoreDeleteKeepsAPasskeyConcurrently(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)
		seedReadyUser(t, conn, "user-1")

		addTestCredential(t, conn, AddCredentialInput{UserID: "user-1", CredentialID: "passkey-2", PublicKey: `{}`})
		addTestCredential(t, conn, AddCredentialInput{UserID: "user-1", CredentialID: "device-1", CredentialType: protocolv2.CredentialTypeDevice, PublicKey: `{}`})
		creds := credentialIDsByCredentialID(t, conn, "user-1")

		// Delete both passkeys at once: exactly one may succeed
		targets := []string{creds["passkey-user-1"].ID, creds["passkey-2"].ID}
		errs := make([]error, len(targets))
		var wg sync.WaitGroup
		for i, id := range targets {
			wg.Go(func() {
				_, errs[i] = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (struct{}, error) {
					return struct{}{}, tx.AuthStore().DeleteCredential(ctx, id, "user-1")
				})
			})
		}
		wg.Wait()

		var ok, refused int
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrLastPasskey):
				refused++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		require.Equal(t, 1, ok)
		require.Equal(t, 1, refused)

		remaining := credentialIDsByCredentialID(t, conn, "user-1")
		require.Len(t, remaining, 2)
		require.Contains(t, remaining, "device-1")
	})
}

func TestAuthStorePairingSessions(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)
		seedReadyUser(t, conn, "user-1")
		seedReadyUser(t, conn, "user-2")

		as := conn.AuthStore()
		createSession := func(t *testing.T, userID string, ttl time.Duration) *PairingSession {
			t.Helper()

			p, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (*PairingSession, error) {
				return tx.AuthStore().CreatePairingSession(ctx, userID, "https://vault.example.com", ttl)
			})
			require.NoError(t, err)

			return p
		}
		completeSession := func(t *testing.T, id string, credential AddCredentialInput) error {
			t.Helper()

			_, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (struct{}, error) {
				return struct{}{}, tx.AuthStore().CompletePairing(ctx, id, credential, time.Now())
			})
			return err
		}
		deviceCredential := func(userID string, credentialID string) AddCredentialInput {
			return AddCredentialInput{
				UserID:         userID,
				CredentialID:   credentialID,
				DisplayName:    "iPhone",
				CredentialType: protocolv2.CredentialTypeDevice,
				PublicKey:      `{}`,
			}
		}

		t.Run("full flow", func(t *testing.T) {
			now := time.Now()
			p := createSession(t, "user-1", protocolv2.PairingTTL)
			require.Equal(t, protocolv2.PairingStatusCreated, p.Status)
			require.Len(t, p.ID, 22)

			open, err := as.HasOpenPairingSession(t.Context(), "user-1", now)
			require.NoError(t, err)
			require.True(t, open)

			// The nonce can't come before the hello, and completion can't come before the nonce
			err = as.SetPairingNonce(t.Context(), p.ID, "user-1", "nonce", "mac", now)
			require.ErrorIs(t, err, ErrPairingSessionState)
			err = completeSession(t, p.ID, deviceCredential("user-1", "device-early"))
			require.ErrorIs(t, err, ErrPairingSessionState)

			err = as.SetPairingHello(t.Context(), p.ID, `{"deviceName":"iPhone"}`, now)
			require.NoError(t, err)

			// A second hello is refused
			err = as.SetPairingHello(t.Context(), p.ID, `{"deviceName":"Other"}`, now)
			require.ErrorIs(t, err, ErrPairingSessionState)

			// Another user can't send the nonce
			err = as.SetPairingNonce(t.Context(), p.ID, "user-2", "nonce", "mac", now)
			require.ErrorIs(t, err, ErrPairingSessionState)

			err = as.SetPairingNonce(t.Context(), p.ID, "user-1", "nonce", "mac", now)
			require.NoError(t, err)

			got, err := as.GetPairingSession(t.Context(), p.ID)
			require.NoError(t, err)
			require.Equal(t, protocolv2.PairingStatusNonce, got.Status)
			require.JSONEq(t, `{"deviceName":"iPhone"}`, got.Hello)
			require.Equal(t, "nonce", got.Nonce)
			require.Equal(t, "mac", got.NonceMAC)
			require.Equal(t, "https://vault.example.com", got.Server)

			// Another user can't complete it, and pairing only adds devices
			err = completeSession(t, p.ID, deviceCredential("user-2", "device-wrong-user"))
			require.ErrorIs(t, err, ErrPairingSessionState)
			passkey := deviceCredential("user-1", "device-passkey")
			passkey.CredentialType = protocolv2.CredentialTypePasskey
			err = completeSession(t, p.ID, passkey)
			require.Error(t, err)

			err = completeSession(t, p.ID, deviceCredential("user-1", "device-1"))
			require.NoError(t, err)

			got, err = as.GetPairingSession(t.Context(), p.ID)
			require.NoError(t, err)
			require.Equal(t, protocolv2.PairingStatusCompleted, got.Status)
			require.False(t, got.IsOpen(now))

			creds := credentialIDsByCredentialID(t, conn, "user-1")
			require.Equal(t, protocolv2.CredentialTypeDevice, creds["device-1"].CredentialType)

			// A completed session can't be completed or canceled again
			err = completeSession(t, p.ID, deviceCredential("user-1", "device-again"))
			require.ErrorIs(t, err, ErrPairingSessionState)
			err = as.CancelPairingSession(t.Context(), p.ID, "user-1", now)
			require.ErrorIs(t, err, ErrPairingSessionState)

			open, err = as.HasOpenPairingSession(t.Context(), "user-1", now)
			require.NoError(t, err)
			require.False(t, open)
		})

		t.Run("a failed completion leaves the session open", func(t *testing.T) {
			now := time.Now()
			p := createSession(t, "user-1", protocolv2.PairingTTL)
			err := as.SetPairingHello(t.Context(), p.ID, `{}`, now)
			require.NoError(t, err)
			err = as.SetPairingNonce(t.Context(), p.ID, "user-1", "nonce", "mac", now)
			require.NoError(t, err)

			// device-1 already exists, so the insert fails and the status change rolls back with it
			err = completeSession(t, p.ID, deviceCredential("user-1", "device-1"))
			require.ErrorIs(t, err, ErrCredentialAlreadyExists)

			got, err := as.GetPairingSession(t.Context(), p.ID)
			require.NoError(t, err)
			require.Equal(t, protocolv2.PairingStatusNonce, got.Status)
		})

		t.Run("a new session cancels the open one", func(t *testing.T) {
			first := createSession(t, "user-1", protocolv2.PairingTTL)
			second := createSession(t, "user-1", protocolv2.PairingTTL)

			got, err := as.GetPairingSession(t.Context(), first.ID)
			require.NoError(t, err)
			require.Equal(t, protocolv2.PairingStatusCanceled, got.Status)

			err = as.SetPairingHello(t.Context(), first.ID, `{}`, time.Now())
			require.ErrorIs(t, err, ErrPairingSessionState)

			err = as.CancelPairingSession(t.Context(), second.ID, "user-2", time.Now())
			require.ErrorIs(t, err, ErrPairingSessionState)
			err = as.CancelPairingSession(t.Context(), second.ID, "user-1", time.Now())
			require.NoError(t, err)
		})

		t.Run("expired sessions refuse changes and are cleaned up", func(t *testing.T) {
			p := createSession(t, "user-1", protocolv2.PairingTTL)
			later := time.Now().Add(protocolv2.PairingTTL + time.Minute)

			err := as.SetPairingHello(t.Context(), p.ID, `{}`, later)
			require.ErrorIs(t, err, ErrPairingSessionState)

			open, err := as.HasOpenPairingSession(t.Context(), "user-1", later)
			require.NoError(t, err)
			require.False(t, open)

			// Not deleted until 10 minutes after expiry
			err = as.DeleteExpiredPairingSession(t.Context(), p.ID, later)
			require.NoError(t, err)
			_, err = as.GetPairingSession(t.Context(), p.ID)
			require.NoError(t, err)

			err = as.CleanupExpired(t.Context(), later.Add(10*time.Minute))
			require.NoError(t, err)
			_, err = as.GetPairingSession(t.Context(), p.ID)
			require.ErrorIs(t, err, ErrPairingSessionNotFound)
		})

		t.Run("deleting one expired session", func(t *testing.T) {
			p := createSession(t, "user-1", protocolv2.PairingTTL)

			err := as.DeleteExpiredPairingSession(t.Context(), p.ID, time.Now().Add(protocolv2.PairingTTL+11*time.Minute))
			require.NoError(t, err)
			_, err = as.GetPairingSession(t.Context(), p.ID)
			require.ErrorIs(t, err, ErrPairingSessionNotFound)
		})

		t.Run("requires a ready user", func(t *testing.T) {
			_, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (*PairingSession, error) {
				return tx.AuthStore().CreatePairingSession(ctx, "missing-user", "https://vault.example.com", protocolv2.PairingTTL)
			})
			require.ErrorIs(t, err, ErrUserNotFound)
		})
	})
}

func TestMigrationGivesExistingCredentialsThePasskeyType(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrationsUpTo(t.Context(), conn, nil, 4)
		require.NoError(t, err)

		_, err = conn.Exec(t.Context(),
			`INSERT INTO v2_users (id, display_name, status, webauthn_user_id, request_key, created_at, updated_at) VALUES ('user-1', 'Alice', 'active', 'w-1', 'rk-1', 1, 1)`,
		)
		require.NoError(t, err)
		_, err = conn.Exec(t.Context(),
			`INSERT INTO v2_user_credentials (id, user_id, credential_id, public_key, sign_count, created_at, last_used_at) VALUES ('rec-1', 'user-1', 'cred-1', '{}', 1, 1, 1)`,
		)
		require.NoError(t, err)

		err = RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)

		creds, err := conn.AuthStore().ListCredentials(t.Context(), "user-1")
		require.NoError(t, err)
		require.Len(t, creds, 1)
		require.Equal(t, protocolv2.CredentialTypePasskey, creds[0].CredentialType)
	})
}
