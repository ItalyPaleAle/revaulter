package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthStoreRegisterUserAndLogin(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			n, err := as.CountUsers(ctx)
			require.NoError(t, err)
			require.Equal(t, 0, n)

			sess, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-1",
				DisplayName:    "Alice",
				WebAuthnUserID: "webauthn-user-1",
				CredentialID:   "cred-1",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)
			require.NotNil(t, sess)
			require.Equal(t, "user-1", sess.ID)
			require.Equal(t, "Alice", sess.DisplayName)
			require.True(t, strings.HasPrefix(sess.RequestKey, RequestKeyPrefix))
			require.Len(t, sess.RequestKey, len(RequestKeyPrefix)+20)
			require.Empty(t, sess.AllowedIPs)

			gotUser, err := as.GetUserByRequestKey(ctx, sess.RequestKey)
			require.NoError(t, err)
			require.NotNil(t, gotUser)
			require.Equal(t, "user-1", gotUser.ID)

			err = as.Login(ctx, LoginInput{
				UserID:       "user-1",
				CredentialID: "cred-1",
				SignCount:    2,
				SessionTTL:   time.Minute,
			})
			require.NoError(t, err)

			loginSess, err := as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.NotNil(t, loginSess)
			require.Equal(t, sess.RequestKey, loginSess.RequestKey)

			creds, err := as.ListCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, creds, 1)
			require.EqualValues(t, 2, creds[0].SignCount)

			return nil, nil
		})
	})
}

func TestAuthStoreLoginCounter(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)

		tests := []struct {
			name        string
			firstCount  int64
			secondCount int64
			wantCount   int64
			wantError   bool
		}{
			{name: "out of order", firstCount: 3, secondCount: 2, wantCount: 3, wantError: true},
			{name: "duplicate", firstCount: 3, secondCount: 3, wantCount: 3, wantError: true},
			{name: "increasing", firstCount: 3, secondCount: 4, wantCount: 4},
			{name: "counterless", firstCount: 0, secondCount: 0, wantCount: 0},
			{name: "starts counting", firstCount: 0, secondCount: 2, wantCount: 2},
			{name: "stops counting", firstCount: 3, secondCount: 0, wantCount: 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				credentialID := "credential-" + tt.name
				_, err := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (struct{}, error) {
					_, rErr := tx.AuthStore().RegisterUser(ctx, RegisterUserInput{
						UserID:         tt.name,
						WebAuthnUserID: "webauthn-" + tt.name,
						CredentialID:   credentialID,
						PublicKey:      `{}`,
						SignCount:      1,
					})
					return struct{}{}, rErr
				})
				require.NoError(t, err)

				as := conn.AuthStore()
				err = as.Login(t.Context(), LoginInput{UserID: tt.name, CredentialID: credentialID, SignCount: tt.firstCount})
				require.NoError(t, err)

				// A login verified against an earlier snapshot must still pass the current counter check at write time
				err = as.Login(t.Context(), LoginInput{UserID: tt.name, CredentialID: credentialID, SignCount: tt.secondCount})
				if tt.wantError {
					require.ErrorIs(t, err, ErrInvalidLogin)
				} else {
					require.NoError(t, err)
				}

				creds, err := as.ListCredentials(t.Context(), tt.name)
				require.NoError(t, err)
				require.Len(t, creds, 1)
				require.Equal(t, tt.wantCount, creds[0].SignCount)
			})
		}
	})
}

func TestAuthStorePasswordCanaryAndAllowedIPs(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-1",
				DisplayName:    "",
				WebAuthnUserID: "webauthn-user-1",
				CredentialID:   "cred-1",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
				UserID:                "user-1",
				WrappedPrimaryKey:     "canary-1",
				RequestEncEcdhPubkey:  `{"kty":"EC","crv":"P-256","x":"test","y":"test"}`,
				RequestEncMlkemPubkey: "dGVzdC1tbGtlbS1wdWJrZXk",
				PubkeyBundleVersion:   2,
			})
			require.NoError(t, err)

			_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
				UserID:                "user-1",
				WrappedPrimaryKey:     "canary-2",
				RequestEncEcdhPubkey:  `{"kty":"EC"}`,
				RequestEncMlkemPubkey: "dGVzdA",
				PubkeyBundleVersion:   2,
			})
			require.ErrorIs(t, err, ErrAlreadyFinalized)

			allowed, err := as.UpdateAllowedIPs(ctx, "user-1", []string{"127.0.0.1", " 10.0.0.0/8 ", "::1", "127.0.0.1"})
			require.NoError(t, err)
			require.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "::1"}, allowed)

			user, err := as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.Equal(t, []string{"127.0.0.1", "10.0.0.0/8", "::1"}, user.AllowedIPs)

			allowed, err = as.UpdateAllowedIPs(ctx, "user-1", []string{})
			require.NoError(t, err)
			require.Empty(t, allowed)

			return nil, nil
		})
	})
}

func TestAuthStoreRegenerateRequestKey(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			sess, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:         "user-1",
				DisplayName:    "Alice",
				WebAuthnUserID: "webauthn-user-1",
				CredentialID:   "cred-1",
				PublicKey:      `{"kty":"EC"}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			require.NoError(t, err)

			// RegenerateRequestKey requires the account to be active and ready;
			// finalize the signup first.
			_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
				UserID:                "user-1",
				RequestEncEcdhPubkey:  `{"kty":"EC"}`,
				RequestEncMlkemPubkey: "mlkem-pub",
				PubkeyBundleVersion:   2,
			})
			require.NoError(t, err)

			newKey, err := as.RegenerateRequestKey(ctx, "user-1")
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(newKey, RequestKeyPrefix))
			require.Len(t, newKey, len(RequestKeyPrefix)+20)
			require.NotEqual(t, sess.RequestKey, newKey)

			user, err := as.GetUserByRequestKey(ctx, newKey)
			require.NoError(t, err)
			require.NotNil(t, user)
			require.Equal(t, "user-1", user.ID)

			oldUser, err := as.GetUserByRequestKey(ctx, sess.RequestKey)
			require.NoError(t, err)
			require.Nil(t, oldUser)

			return nil, nil
		})
	})
}

func TestParseAllowedIPsCSV(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{name: "empty string", input: "", expected: nil},
		{name: "whitespace only", input: "  \t  ", expected: nil},
		{name: "single value", input: "127.0.0.1", expected: []string{"127.0.0.1"}},
		{name: "trims and drops empty entries", input: " 127.0.0.1 , , 10.0.0.0/8,   ::1  ", expected: []string{"127.0.0.1", "10.0.0.0/8", "::1"}},
		{name: "all empty entries", input: ", , ,", expected: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := parseAllowedIPsCSV(test.input)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestNormalizeAllowedIPsEmptyInputs(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{name: "nil input", input: nil},
		{name: "blank entries only", input: []string{"", "  ", "\t", "\n"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NormalizeAllowedIPs(test.input)
			require.NoError(t, err)
			require.Empty(t, result)
		})
	}
}

func TestNormalizeAllowedIPsNormalizesCanonicalizesDeduplicatesAndPreservesOrder(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{
		" 127.0.0.1 ",
		"10.123.45.67/8",
		"2001:DB8::1",
		"2001:db8::abcd/64",
		"10.0.0.0/8",
		"2001:db8::1",
		"2001:db8::/64",
		"",
		"   ",
		"127.0.0.1",
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"127.0.0.1",
		"10.0.0.0/8",
		"2001:db8::1",
		"2001:db8::/64",
	}, result)
}

func TestNormalizeAllowedIPsInvalidIP(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{"127.0.0.1", "not-an-ip"})
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrInvalidIP)
	require.EqualError(t, err, "invalid IP: not-an-ip")
}

func TestNormalizeAllowedIPsInvalidCIDR(t *testing.T) {
	result, err := NormalizeAllowedIPs([]string{" 10.0.0.0/33 "})
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrInvalidCIDR)
	require.EqualError(t, err, "invalid CIDR: 10.0.0.0/33")
}

func TestAuthStoreUpdateDisplayName(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

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

			_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
				UserID:                "user-1",
				RequestEncEcdhPubkey:  `{"kty":"EC"}`,
				RequestEncMlkemPubkey: "mlkem-pub",
				PubkeyBundleVersion:   2,
			})
			require.NoError(t, err)

			// Successful update
			err = as.UpdateDisplayName(ctx, "user-1", "Bob")
			require.NoError(t, err)
			user, err := as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.Equal(t, "Bob", user.DisplayName)

			// Empty display name is valid
			err = as.UpdateDisplayName(ctx, "user-1", "")
			require.NoError(t, err)
			user, err = as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.Empty(t, user.DisplayName)

			// Too-long display name
			err = as.UpdateDisplayName(ctx, "user-1", strings.Repeat("a", 101))
			require.ErrorIs(t, err, ErrDisplayNameTooLong)

			// Non-existent user
			err = as.UpdateDisplayName(ctx, "no-such-user", "Test")
			require.ErrorIs(t, err, ErrUserNotFound)

			return nil, nil
		})
	})
}

func TestAuthStoreUpdateCredentialWrappedKey(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

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

			_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
				UserID:                "user-1",
				WrappedPrimaryKey:     "initial-key",
				RequestEncEcdhPubkey:  `{"kty":"EC"}`,
				RequestEncMlkemPubkey: "mlkem-pub",
				PubkeyBundleVersion:   2,
			})
			require.NoError(t, err)

			// The initial wrapped primary key was set on the single credential via FinalizeSignup
			rec, err := as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.Equal(t, "initial-key", rec.WrappedPrimaryKey)

			// Successful update
			err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "new-wrapped-key", "new-anchor-key")
			require.NoError(t, err)
			rec, err = as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
			require.NoError(t, err)
			require.Equal(t, "new-wrapped-key", rec.WrappedPrimaryKey)
			require.Equal(t, "new-anchor-key", rec.WrappedAnchorKey)

			// Empty string is valid (removes password)
			err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "", "")
			require.NoError(t, err)
			rec, err = as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
			require.NoError(t, err)
			require.Empty(t, rec.WrappedPrimaryKey)

			// Oversized values return a sentinel, so the server can tell them apart from database errors
			err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", strings.Repeat("x", 513), "anchor")
			require.ErrorIs(t, err, ErrWrappedKeyTooLarge)
			require.ErrorContains(t, err, "wrappedPrimaryKey")

			err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "key", strings.Repeat("x", (32<<10)+1))
			require.ErrorIs(t, err, ErrWrappedKeyTooLarge)
			require.ErrorContains(t, err, "wrappedAnchorKey")

			// Non-existent credential
			err = as.UpdateCredentialWrappedKey(ctx, "no-such-cred", "user-1", "key", "anchor")
			require.ErrorIs(t, err, ErrCredentialNotFound)

			// Credential belonging to a different user
			err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "other-user", "key", "anchor")
			require.ErrorIs(t, err, ErrCredentialNotFound)

			return nil, nil
		})
	})
}

func TestAuthStoreCredentialWrappedKeyEpochRotation(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

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

			_, err = as.FinalizeSignup(ctx, FinalizeSignupInput{
				UserID:                "user-1",
				WrappedPrimaryKey:     "wrapped-1-v1",
				RequestEncEcdhPubkey:  `{"kty":"EC"}`,
				RequestEncMlkemPubkey: "mlkem-pub",
				PubkeyBundleVersion:   2,
			})
			require.NoError(t, err)

			err = as.AddCredential(ctx, AddCredentialInput{
				UserID:            "user-1",
				CredentialID:      "cred-2",
				DisplayName:       "Second",
				PublicKey:         `{"kty":"EC"}`,
				SignCount:         1,
				WrappedPrimaryKey: "wrapped-2-v1",
				WrappedKeyEpoch:   1,
			})
			require.NoError(t, err)

			rec1, err := as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
			require.NoError(t, err)
			rec2, err := as.GetCredentialByCredentialID(ctx, "cred-2", "user-1")
			require.NoError(t, err)
			require.EqualValues(t, 1, rec1.WrappedKeyEpoch)
			require.EqualValues(t, 1, rec2.WrappedKeyEpoch)

			newEpoch, err := as.AdvanceWrappedKeyEpoch(ctx, "user-1")
			require.NoError(t, err)
			require.EqualValues(t, 2, newEpoch)

			err = as.UpdateCredentialWrappedKey(ctx, "cred-1", "user-1", "wrapped-1-v2", "anchor-1-v2")
			require.NoError(t, err)

			rec1, err = as.GetCredentialByCredentialID(ctx, "cred-1", "user-1")
			require.NoError(t, err)
			rec2, err = as.GetCredentialByCredentialID(ctx, "cred-2", "user-1")
			require.NoError(t, err)
			require.Equal(t, "wrapped-1-v2", rec1.WrappedPrimaryKey)
			require.Equal(t, "wrapped-2-v1", rec2.WrappedPrimaryKey)
			require.EqualValues(t, 2, rec1.WrappedKeyEpoch)
			require.EqualValues(t, 1, rec2.WrappedKeyEpoch)

			err = as.UpdateCredentialWrappedKey(ctx, "cred-2", "user-1", "wrapped-2-v2", "anchor-2-v2")
			require.NoError(t, err)

			rec2, err = as.GetCredentialByCredentialID(ctx, "cred-2", "user-1")
			require.NoError(t, err)
			require.Equal(t, "wrapped-2-v2", rec2.WrappedPrimaryKey)
			require.EqualValues(t, 2, rec2.WrappedKeyEpoch)

			return nil, nil
		})
	})
}

func TestAuthStoreCredentialCRUD(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			_, err := as.RegisterUser(ctx, RegisterUserInput{
				UserID:                "user-1",
				DisplayName:           "Alice",
				WebAuthnUserID:        "webauthn-user-1",
				CredentialID:          "cred-1",
				CredentialDisplayName: "My Laptop",
				PublicKey:             `{"kty":"EC"}`,
				SignCount:             1,
				SessionTTL:            time.Minute,
			})
			require.NoError(t, err)

			// List — should have 1 credential with display name and timestamps
			creds, err := as.ListCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, creds, 1)
			require.NotEmpty(t, creds[0].ID)
			require.Equal(t, "cred-1", creds[0].CredentialID)
			require.Equal(t, "My Laptop", creds[0].DisplayName)
			require.NotZero(t, creds[0].CreatedAt)
			require.NotZero(t, creds[0].LastUsedAt)

			firstCredID := creds[0].ID

			// Add a second credential
			err = as.AddCredential(ctx, AddCredentialInput{
				UserID:          "user-1",
				CredentialID:    "cred-2",
				DisplayName:     "My Phone",
				PublicKey:       `{"kty":"EC","crv":"P-256"}`,
				SignCount:       0,
				WrappedKeyEpoch: 1,
			})
			require.NoError(t, err)

			creds, err = as.ListCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, creds, 2)

			secondCredID := creds[1].ID
			require.Equal(t, "My Phone", creds[1].DisplayName)

			// Rename second credential
			err = as.RenameCredential(ctx, secondCredID, "user-1", "Work Phone")
			require.NoError(t, err)
			creds, err = as.ListCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Equal(t, "Work Phone", creds[1].DisplayName)

			// Rename with too-long name
			err = as.RenameCredential(ctx, secondCredID, "user-1", strings.Repeat("a", 101))
			require.ErrorIs(t, err, ErrDisplayNameTooLong)

			// Rename nonexistent credential
			err = as.RenameCredential(ctx, "nonexistent-id", "user-1", "test")
			require.ErrorIs(t, err, ErrCredentialNotFound)

			// Rename credential belonging to different user
			err = as.RenameCredential(ctx, secondCredID, "other-user", "test")
			require.ErrorIs(t, err, ErrCredentialNotFound)

			// Delete second credential — should succeed
			err = as.DeleteCredential(ctx, secondCredID, "user-1")
			require.NoError(t, err)
			creds, err = as.ListCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, creds, 1)
			require.Equal(t, firstCredID, creds[0].ID)

			// Delete last credential — should fail
			err = as.DeleteCredential(ctx, firstCredID, "user-1")
			require.ErrorIs(t, err, ErrLastCredential)

			// Delete nonexistent credential
			err = as.DeleteCredential(ctx, "nonexistent-id", "user-1")
			require.ErrorIs(t, err, ErrCredentialNotFound)

			return nil, nil
		})
	})
}

func TestAuthStoreAddCredentialRequiresEpoch(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			registerReadyUser(t, ctx, as, "user-1")

			newCredential := func(credentialID string, epoch int64) AddCredentialInput {
				return AddCredentialInput{
					UserID:          "user-1",
					CredentialID:    credentialID,
					PublicKey:       `{"kty":"EC"}`,
					WrappedKeyEpoch: epoch,
				}
			}

			// The user is at epoch 1
			err := as.AddCredential(ctx, newCredential("cred-epoch-2", 2))
			require.ErrorIs(t, err, ErrWrappedKeyEpochChanged)

			_, err = as.AdvanceWrappedKeyEpoch(ctx, "user-1")
			require.NoError(t, err)

			// A credential created before the epoch advanced is refused
			err = as.AddCredential(ctx, newCredential("cred-epoch-1", 1))
			require.ErrorIs(t, err, ErrWrappedKeyEpochChanged)

			err = as.AddCredential(ctx, newCredential("cred-epoch-2", 2))
			require.NoError(t, err)
			rec, err := as.GetCredentialByCredentialID(ctx, "cred-epoch-2", "user-1")
			require.NoError(t, err)
			require.NotNil(t, rec)
			require.EqualValues(t, 2, rec.WrappedKeyEpoch)

			err = as.AddCredential(ctx, AddCredentialInput{UserID: "user-missing", CredentialID: "cred-missing", PublicKey: `{}`, WrappedKeyEpoch: 1})
			require.ErrorIs(t, err, ErrUserNotFound)

			return nil, nil
		})
	})
}

func TestAuthStoreGetUserByIDForUpdateSerializesEpochChanges(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)

		_, err = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			registerReadyUser(t, ctx, tx.AuthStore(), "user-1")
			return nil, nil
		})
		require.NoError(t, err)

		// While a passkey is being added with the user locked, a password change that advances the epoch must wait
		advanced := make(chan error, 1)
		var advancedEarly bool
		_, err = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()
			user, rErr := as.GetUserByIDForUpdate(ctx, "user-1")
			if rErr != nil {
				return nil, rErr
			}

			go func() {
				_, aErr := ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (int64, error) {
					return tx.AuthStore().AdvanceWrappedKeyEpoch(ctx, "user-1")
				})
				advanced <- aErr
			}()

			select {
			case <-advanced:
				advancedEarly = true
			case <-time.After(500 * time.Millisecond):
				// The password change is still waiting
			}

			return nil, as.AddCredential(ctx, AddCredentialInput{
				UserID:          "user-1",
				CredentialID:    "cred-new",
				PublicKey:       `{"kty":"EC"}`,
				WrappedKeyEpoch: user.WrappedKeyEpoch,
			})
		})
		require.NoError(t, err)
		require.False(t, advancedEarly, "the epoch changed while the user was locked")

		select {
		case err = <-advanced:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("the password change didn't complete after the lock was released")
		}

		// The new credential keeps the epoch it was created for, so it's reported as stale after the password change
		as := conn.AuthStore()
		user, err := as.GetUserByID(t.Context(), "user-1")
		require.NoError(t, err)
		require.EqualValues(t, 2, user.WrappedKeyEpoch)
		rec, err := as.GetCredentialByCredentialID(t.Context(), "cred-new", "user-1")
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.EqualValues(t, 1, rec.WrappedKeyEpoch)
	})
}
