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

// addTestCredential adds a credential at the user's initial wrapped key epoch, unless the input sets another one
func addTestCredential(t *testing.T, conn *DB, in AddCredentialInput) {
	t.Helper()

	if in.WrappedKeyEpoch == 0 {
		in.WrappedKeyEpoch = 1
	}

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
				UserID:          "user-1",
				CredentialID:    "device-1",
				CredentialType:  protocolv2.CredentialTypeDevice,
				PublicKey:       `{}`,
				WrappedKeyEpoch: 1,
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
				ID:              "record-3",
				UserID:          "user-1",
				CredentialID:    "device-3",
				CredentialType:  protocolv2.CredentialTypeDevice,
				PublicKey:       `{}`,
				WrappedKeyEpoch: 1,
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

func TestMigrationGivesExistingCredentialsThePasskeyType(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrationsUpTo(t.Context(), conn, nil, 5)
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
