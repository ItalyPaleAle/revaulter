package db

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// registerReadyUser registers a user and finalizes its signup, so it's active and ready
func registerReadyUser(t *testing.T, ctx context.Context, as *AuthStore, userID string) *User {
	t.Helper()

	_, err := as.RegisterUser(ctx, RegisterUserInput{
		UserID:         userID,
		DisplayName:    userID,
		WebAuthnUserID: "webauthn-" + userID,
		CredentialID:   "cred-" + userID,
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	user, err := as.FinalizeSignup(ctx, FinalizeSignupInput{
		UserID:                userID,
		RequestEncEcdhPubkey:  `{"kty":"EC"}`,
		RequestEncMlkemPubkey: "mlkem-pub",
		PubkeyBundleVersion:   2,
	})
	require.NoError(t, err)

	return user
}

func TestAuthStoreRequestAuthMethods(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			// New users can only use the static request key, and have no OIDC issuers
			user := registerReadyUser(t, ctx, as, "user-1")
			require.Equal(t, RequestAuthMethods{RequestKey: true}, user.RequestAuthMethods)
			require.NotNil(t, user.RequestOIDC)
			require.Empty(t, user.RequestOIDC)

			// Both methods can be enabled at once
			err := as.UpdateRequestAuthMethods(ctx, "user-1", RequestAuthMethods{RequestKey: true, OIDC: true})
			require.NoError(t, err)

			user, err = as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.Equal(t, RequestAuthMethods{RequestKey: true, OIDC: true}, user.RequestAuthMethods)

			err = as.UpdateRequestAuthMethods(ctx, "user-1", RequestAuthMethods{OIDC: true})
			require.NoError(t, err)

			// The methods are also returned when looking up by request key
			user, err = as.GetUserByRequestKey(ctx, user.RequestKey)
			require.NoError(t, err)
			require.Equal(t, RequestAuthMethods{OIDC: true}, user.RequestAuthMethods)

			err = as.UpdateRequestAuthMethods(ctx, "missing", RequestAuthMethods{RequestKey: true})
			require.ErrorIs(t, err, ErrUserNotFound)

			return nil, nil
		})
	})
}

func TestAuthStoreRequestOIDCIssuers(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			registerReadyUser(t, ctx, as, "user-1")
			registerReadyUser(t, ctx, as, "user-2")

			// Both users can trust the same issuer, audience, and subject
			in := AddRequestOIDCIssuerInput{
				DisplayName: "  Release workflow  ",
				Issuer:      "https://token.actions.githubusercontent.com",
				Audience:    "https://revaulter.example.com",
				Subject:     "repo:example/app:ref:refs/tags/*",
			}
			added, list, err := as.AddRequestOIDCIssuer(ctx, "user-1", in)
			require.NoError(t, err)
			require.NotEmpty(t, added.ID)
			require.Equal(t, "Release workflow", added.DisplayName)
			require.Equal(t, []RequestOIDCIssuer{*added}, list)

			in.JWKSURL = "https://token.actions.githubusercontent.com/.well-known/jwks"
			added2, _, err := as.AddRequestOIDCIssuer(ctx, "user-1", in)
			require.NoError(t, err)

			_, _, err = as.AddRequestOIDCIssuer(ctx, "user-2", in)
			require.NoError(t, err)

			user, err := as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.Equal(t, []RequestOIDCIssuer{*added, *added2}, user.RequestOIDC)

			// Users can't delete other users' issuers
			_, _, err = as.DeleteRequestOIDCIssuer(ctx, "user-2", added.ID)
			require.ErrorIs(t, err, ErrRequestOIDCIssuerNotFound)

			deleted, list, err := as.DeleteRequestOIDCIssuer(ctx, "user-1", added.ID)
			require.NoError(t, err)
			require.Equal(t, *added, *deleted)
			require.Equal(t, []RequestOIDCIssuer{*added2}, list)

			_, _, err = as.DeleteRequestOIDCIssuer(ctx, "user-1", added.ID)
			require.ErrorIs(t, err, ErrRequestOIDCIssuerNotFound)

			// Deleting the last entry leaves an empty list
			_, list, err = as.DeleteRequestOIDCIssuer(ctx, "user-1", added2.ID)
			require.NoError(t, err)
			require.NotNil(t, list)
			require.Empty(t, list)

			user, err = as.GetUserByID(ctx, "user-1")
			require.NoError(t, err)
			require.Empty(t, user.RequestOIDC)

			// Other users' issuers are not affected
			user, err = as.GetUserByID(ctx, "user-2")
			require.NoError(t, err)
			require.Len(t, user.RequestOIDC, 1)

			// Users that don't exist can't have issuers
			_, _, err = as.AddRequestOIDCIssuer(ctx, "missing", in)
			require.ErrorIs(t, err, ErrUserNotFound)

			return nil, nil
		})
	})
}

func TestAuthStoreRequestOIDCIssuersLimit(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			as := tx.AuthStore()

			registerReadyUser(t, ctx, as, "user-1")

			in := AddRequestOIDCIssuerInput{
				Issuer:   "https://issuer.example.com",
				Audience: "https://revaulter.example.com",
			}
			for i := range MaxRequestOIDCIssuersPerUser {
				in.Subject = "subject-" + strconv.Itoa(i)
				_, _, err := as.AddRequestOIDCIssuer(ctx, "user-1", in)
				require.NoError(t, err)
			}

			in.Subject = "one-too-many"
			_, _, err := as.AddRequestOIDCIssuer(ctx, "user-1", in)
			require.ErrorIs(t, err, ErrTooManyRequestOIDCIssuers)

			return nil, nil
		})
	})
}

func TestUserColumns(t *testing.T) {
	columns := strings.Split(userColumns, ", ")
	require.Len(t, columns, userColumnCount)
	require.Equal(t, userColumnsAliasU, "u."+strings.Join(columns, ", u."))
}

func TestRequestStoreResultTokenHash(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			registerReadyUser(t, ctx, tx.AuthStore(), "user-1")

			rs := tx.RequestStore()
			now := time.Now()
			err := rs.CreateRequest(ctx, CreateRequestInput{
				State:           "state-1",
				UserID:          "user-1",
				Operation:       "encrypt",
				RequestorIP:     "127.0.0.1",
				KeyLabel:        "key",
				Algorithm:       "A256GCM",
				CreatedAt:       now,
				ExpiresAt:       now.Add(time.Minute),
				ResultTokenHash: "abc123",
			})
			require.NoError(t, err)

			rec, err := rs.GetRequest(ctx, "state-1")
			require.NoError(t, err)
			require.Equal(t, "abc123", rec.ResultTokenHash)

			// The hash and the owner are returned together
			hash, owner, err := rs.GetResultTokenAndOwner(ctx, "state-1")
			require.NoError(t, err)
			require.Equal(t, "abc123", hash)
			require.NotNil(t, owner)
			require.Equal(t, "user-1", owner.ID)
			require.True(t, owner.RequestAuthMethods.RequestKey)
			require.NotNil(t, owner.RequestOIDC)

			hash, owner, err = rs.GetResultTokenAndOwner(ctx, "missing")
			require.NoError(t, err)
			require.Empty(t, hash)
			require.Nil(t, owner)

			rec, err = rs.CancelRequest(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.Equal(t, "abc123", rec.ResultTokenHash)

			rec, err = rs.GetAndDeleteTerminalRequest(ctx, "state-1")
			require.NoError(t, err)
			require.Equal(t, "abc123", rec.ResultTokenHash)

			return nil, nil
		})
	})
}
