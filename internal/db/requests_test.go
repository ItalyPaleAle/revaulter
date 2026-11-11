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
			status, created, err := rs.Insert(ctx, RequestPayload{
				State:            "state-1",
				UserID:           "user-1",
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{"ciphertext":"Y3Q"}`,
			})
			require.NoError(t, err)
			assert.True(t, created)
			assert.Equal(t, V2RequestStatusPending, status)

			got, err := rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "state-1", got.State)
			assert.Equal(t, "user-1", got.UserID)
			assert.Equal(t, V2RequestStatusPending, got.Status)
			assert.Equal(t, now.Add(5*time.Minute).Unix(), got.ExpiresAt.Unix())
			assert.JSONEq(t, `{"ciphertext":"Y3Q"}`, got.EncryptedRequest)
			assert.Empty(t, got.EncryptedResult)
		})

		t.Run("inserting the same request again is a no-op", func(t *testing.T) {
			status, created, err := rs.Insert(ctx, RequestPayload{
				State:            "state-1",
				UserID:           "user-1",
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{}`,
			})
			require.NoError(t, err)
			assert.False(t, created)
			assert.Equal(t, V2RequestStatusPending, status)

			got, err := rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.JSONEq(t, `{"ciphertext":"Y3Q"}`, got.EncryptedRequest, "the stored envelope must be kept")
		})

		t.Run("a state used by another user is rejected", func(t *testing.T) {
			_, _, err := rs.Insert(ctx, RequestPayload{
				State:            "state-1",
				UserID:           "user-2",
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{}`,
			})
			require.ErrorIs(t, err, ErrRequestPayloadConflict)
		})

		t.Run("rows are scoped to their owner", func(t *testing.T) {
			got, err := rs.Get(ctx, "state-1", "user-2")
			require.NoError(t, err)
			assert.Nil(t, got)

			_, _, err = rs.Finish(ctx, "state-1", "user-2", V2RequestStatusCompleted, `{"ciphertext":"cmVz"}`)
			require.ErrorIs(t, err, ErrRequestPayloadNotFound)

			err = rs.Delete(ctx, "user-2", "state-1")
			require.NoError(t, err)

			got, err = rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got, "a delete by another user must not remove the row")
		})

		t.Run("finish", func(t *testing.T) {
			current, applied, err := rs.Finish(ctx, "state-1", "user-1", V2RequestStatusCompleted, `{"ciphertext":"cmVz"}`)
			require.NoError(t, err)
			assert.True(t, applied)
			assert.Equal(t, V2RequestStatusCompleted, current)

			got, err := rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, V2RequestStatusCompleted, got.Status)
			assert.JSONEq(t, `{"ciphertext":"cmVz"}`, got.EncryptedResult)

			// A finished request can't change again, and keeps its result
			current, applied, err = rs.Finish(ctx, "state-1", "user-1", V2RequestStatusCanceled, "")
			require.NoError(t, err)
			assert.False(t, applied)
			assert.Equal(t, V2RequestStatusCompleted, current)
			current, applied, err = rs.Finish(ctx, "state-1", "user-1", V2RequestStatusCompleted, `{"ciphertext":"b3RoZXI"}`)
			require.NoError(t, err)
			assert.False(t, applied)
			assert.Equal(t, V2RequestStatusCompleted, current)

			got, err = rs.Get(ctx, "state-1", "user-1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.JSONEq(t, `{"ciphertext":"cmVz"}`, got.EncryptedResult)

			_, _, err = rs.Finish(ctx, "missing", "user-1", V2RequestStatusCanceled, "")
			require.ErrorIs(t, err, ErrRequestPayloadNotFound)

			_, _, err = rs.Finish(ctx, "state-1", "user-1", V2RequestStatusPending, "")
			require.Error(t, err)
		})

		t.Run("inserting a finished request again returns its status", func(t *testing.T) {
			status, created, err := rs.Insert(ctx, RequestPayload{
				State:            "state-1",
				UserID:           "user-1",
				ExpiresAt:        now.Add(5 * time.Minute),
				EncryptedRequest: `{}`,
			})
			require.NoError(t, err)
			assert.False(t, created)
			assert.Equal(t, V2RequestStatusCompleted, status)
		})

		t.Run("delete many", func(t *testing.T) {
			for _, state := range []string{"state-2", "state-3", "state-4"} {
				_, _, err := rs.Insert(ctx, RequestPayload{
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

		t.Run("expire overdue and delete expired", func(t *testing.T) {
			for _, state := range []string{"state-old", "state-old-finished"} {
				_, _, err := rs.Insert(ctx, RequestPayload{
					State:            state,
					UserID:           "user-2",
					ExpiresAt:        now.Add(-time.Hour),
					EncryptedRequest: `{}`,
				})
				require.NoError(t, err)
			}
			_, _, err := rs.Finish(ctx, "state-old-finished", "user-2", V2RequestStatusCanceled, "")
			require.NoError(t, err)

			// Pending rows are kept until their expiry is recorded
			removed, err := rs.DeleteExpired(ctx, now.Add(-10*time.Minute))
			require.NoError(t, err)
			assert.Equal(t, int64(1), removed)
			got, err := rs.Get(ctx, "state-old-finished", "user-2")
			require.NoError(t, err)
			assert.Nil(t, got)
			got, err = rs.Get(ctx, "state-old", "user-2")
			require.NoError(t, err)
			require.NotNil(t, got)

			// Only pending requests past the deadline are expired
			expired, err := rs.ExpireOverdue(ctx, now.Add(-10*time.Minute))
			require.NoError(t, err)
			require.Len(t, expired, 1)
			assert.Equal(t, "state-old", expired[0].State)
			assert.Equal(t, "user-2", expired[0].UserID)

			expired, err = rs.ExpireOverdue(ctx, now.Add(-10*time.Minute))
			require.NoError(t, err)
			assert.Empty(t, expired)

			removed, err = rs.DeleteExpired(ctx, now.Add(-10*time.Minute))
			require.NoError(t, err)
			assert.Equal(t, int64(1), removed)
			got, err = rs.Get(ctx, "state-old", "user-2")
			require.NoError(t, err)
			assert.Nil(t, got)

			got, err = rs.Get(ctx, "state-2", "user-1")
			require.NoError(t, err)
			assert.NotNil(t, got, "rows that haven't expired must be kept")
		})
	})
}
