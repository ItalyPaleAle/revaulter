package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV2RequestStatusIsTerminal(t *testing.T) {
	assert.False(t, V2RequestStatusPending.IsTerminal())
	assert.True(t, V2RequestStatusCompleted.IsTerminal())
	assert.True(t, V2RequestStatusCanceled.IsTerminal())
	assert.True(t, V2RequestStatusExpired.IsTerminal())
	assert.False(t, V2RequestStatus("").IsTerminal())
}

func TestRequestPayloadStore(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		err := RunMigrations(t.Context(), conn, nil)
		require.NoError(t, err)

		_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			registerReadyUser(t, ctx, tx.AuthStore(), "user-1")
			registerReadyUser(t, ctx, tx.AuthStore(), "user-2")
			return nil, nil
		})

		rs := conn.RequestPayloadStore()
		ctx := t.Context()
		now := time.Now().Truncate(time.Second)

		t.Run("insert and get", func(t *testing.T) {
			err := rs.Insert(ctx, RequestPayload{
				State:            "state-1",
				UserID:           "user-1",
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)

			got, err := rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "state-1", got.State)
			assert.Equal(t, "user-1", got.UserID)
			assert.Equal(t, now.Add(5*time.Minute).Unix(), got.ExpiresAt.Unix())
			assert.JSONEq(t, `{"ciphertext":"Y3Q"}`, got.EncryptedRequest)
			assert.Empty(t, got.EncryptedResult)
		})

		t.Run("duplicate states are rejected", func(t *testing.T) {
			err := rs.Insert(ctx, RequestPayload{
				State:            "state-1",
				UserID:           "user-1",
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{}`,
			})
			require.Error(t, err)
		})

		t.Run("rows are scoped to their owner", func(t *testing.T) {
			got, err := rs.Get(ctx, "state-1", "user-2")
			require.NoError(t, err)
			assert.Nil(t, got)

			err = rs.SetResult(ctx, "state-1", "user-2", `{"ciphertext":"cmVz"}`)
			require.ErrorIs(t, err, ErrRequestPayloadNotFound)

			err = rs.Delete(ctx, "user-2", "state-1")
			require.NoError(t, err)

			got, err = rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got, "a delete by another user must not remove the row")
		})

		t.Run("set result", func(t *testing.T) {
			err := rs.SetResult(ctx, "state-1", "user-1", `{"ciphertext":"cmVz"}`)
			require.NoError(t, err)

			got, err := rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.JSONEq(t, `{"ciphertext":"cmVz"}`, got.EncryptedResult)

			err = rs.SetResult(ctx, "missing", "user-1", `{}`)
			require.ErrorIs(t, err, ErrRequestPayloadNotFound)
		})

		t.Run("delete many", func(t *testing.T) {
			for _, state := range []string{"state-2", "state-3", "state-4"} {
				err := rs.Insert(ctx, RequestPayload{
					State:            state,
					UserID:           "user-1",
					ExpiresAt:        now.Add(5 * time.Minute),
					EncryptedRequest: `{}`,
				})
				require.NoError(t, err)
			}

			err := rs.Delete(ctx, "user-1", "state-1", "state-3", "missing")
			require.NoError(t, err)

			for state, exists := range map[string]bool{"state-1": false, "state-2": true, "state-3": false, "state-4": true} {
				got, err := rs.Get(ctx, state, "user-1")
				require.NoError(t, err)
				assert.Equal(t, exists, got != nil, state)
			}

			// Deleting nothing is a no-op
			err = rs.Delete(ctx, "user-1")
			require.NoError(t, err)
		})

		t.Run("delete expired", func(t *testing.T) {
			err := rs.Insert(ctx, RequestPayload{
				State:            "state-old",
				UserID:           "user-2",
				ExpiresAt:        now.Add(-time.Hour),
				EncryptedRequest: `{}`,
			})
			require.NoError(t, err)

			removed, err := rs.DeleteExpired(ctx, now.Add(-10*time.Minute))
			require.NoError(t, err)
			assert.Equal(t, int64(1), removed)

			got, err := rs.Get(ctx, "state-old", "user-2")
			require.NoError(t, err)
			assert.Nil(t, got)

			got, err = rs.Get(ctx, "state-2", "user-1")
			require.NoError(t, err)
			assert.NotNil(t, got, "rows that haven't expired must be kept")
		})
	})
}
