package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuditStoreInsertAndRead(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()

		actor := "user-1"
		ip := "127.0.0.1"
		ua := "test-agent/1.0"
		reqState := "abc123"

		rec, err := store.Insert(ctx, AuditEventInput{
			EventType:    AuditAuthLoginFinish,
			Outcome:      AuditOutcomeSuccess,
			AuthMethod:   AuditAuthMethodSession,
			ActorUserID:  &actor,
			TargetUserID: &actor,
			RequestState: &reqState,
			ClientIP:     &ip,
			UserAgent:    &ua,
			Metadata:     json.RawMessage(`{"flow":"webauthn"}`),
		})
		require.NoError(t, err)
		require.NotEmpty(t, rec.ID)
		require.Equal(t, AuditAuthLoginFinish, rec.EventType)
		require.Equal(t, AuditOutcomeSuccess, rec.Outcome)
		require.Equal(t, AuditAuthMethodSession, rec.AuthMethod)
		require.NotNil(t, rec.ActorUserID)
		require.Equal(t, actor, *rec.ActorUserID)
		require.NotZero(t, rec.CreatedAt.Unix())

		// Insert a second event for the same actor with different type so filtering can be exercised
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:   AuditAuthRequestKeyRegen,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &actor,
		})
		require.NoError(t, err)

		// And one for a different actor — must not surface in the first actor's list
		other := "user-2"
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:   AuditAuthLogout,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &other,
		})
		require.NoError(t, err)

		list, cursor, err := store.List(ctx, AuditFilter{UserID: actor}, 10, "")
		require.NoError(t, err)
		require.Len(t, list, 2)
		require.Empty(t, cursor)
		// Newest first
		require.Equal(t, AuditAuthRequestKeyRegen, list[0].EventType)
		require.Equal(t, AuditAuthLoginFinish, list[1].EventType)

		// Verify nullable round-trip — second event has no IP / UA / target / request state
		require.Nil(t, list[0].ClientIP)
		require.Nil(t, list[0].UserAgent)
		require.Nil(t, list[0].TargetUserID)
		require.Nil(t, list[0].RequestState)
		// Default metadata is "{}"
		require.JSONEq(t, "{}", string(list[0].Metadata))

		// First event preserves what we wrote
		require.NotNil(t, list[1].ClientIP)
		require.Equal(t, ip, *list[1].ClientIP)
		require.JSONEq(t, `{"flow":"webauthn"}`, string(list[1].Metadata))

		// Filter by event type
		filtered, _, err := store.List(ctx, AuditFilter{UserID: actor, EventType: AuditAuthLoginFinish}, 10, "")
		require.NoError(t, err)
		require.Len(t, filtered, 1)
		require.Equal(t, AuditAuthLoginFinish, filtered[0].EventType)

		return nil, nil
	})
}

func TestAuditStoreCursorPagination(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()

		actor := "user-paging"
		for range 5 {
			_, err := store.Insert(ctx, AuditEventInput{
				EventType:   AuditAuthLoginFinish,
				Outcome:     AuditOutcomeSuccess,
				AuthMethod:  AuditAuthMethodSession,
				ActorUserID: &actor,
			})
			require.NoError(t, err)
		}

		first, cursor, err := store.List(ctx, AuditFilter{UserID: actor}, 2, "")
		require.NoError(t, err)
		require.Len(t, first, 2)
		require.NotEmpty(t, cursor)

		second, cursor2, err := store.List(ctx, AuditFilter{UserID: actor}, 2, cursor)
		require.NoError(t, err)
		require.Len(t, second, 2)
		require.NotEmpty(t, cursor2)

		third, cursor3, err := store.List(ctx, AuditFilter{UserID: actor}, 2, cursor2)
		require.NoError(t, err)
		require.Len(t, third, 1)
		require.Empty(t, cursor3)

		// IDs across pages should be all distinct
		seen := map[string]struct{}{}
		for _, batch := range [][]AuditEvent{first, second, third} {
			for _, ev := range batch {
				_, dup := seen[ev.ID]
				require.False(t, dup, "duplicate id across pages: %s", ev.ID)
				seen[ev.ID] = struct{}{}
			}
		}
		require.Len(t, seen, 5)

		return nil, nil
	})
}

func TestAuditStoreTimeFilter(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()
		actor := "user-time"

		_, err := store.Insert(ctx, AuditEventInput{
			EventType:   AuditRequestCreate,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodRequestKey,
			ActorUserID: &actor,
		})
		require.NoError(t, err)

		future := time.Now().Add(1 * time.Hour).Unix()

		// Filter that starts in the future returns nothing
		empty, _, err := store.List(ctx, AuditFilter{UserID: actor, SinceUnix: future}, 10, "")
		require.NoError(t, err)
		require.Empty(t, empty)

		// Filter that ends in the past returns nothing
		past := time.Now().Add(-1 * time.Hour).Unix()
		empty, _, err = store.List(ctx, AuditFilter{UserID: actor, UntilUnix: past}, 10, "")
		require.NoError(t, err)
		require.Empty(t, empty)

		// Filter that brackets now finds the row
		all, _, err := store.List(ctx, AuditFilter{UserID: actor, SinceUnix: past, UntilUnix: future}, 10, "")
		require.NoError(t, err)
		require.Len(t, all, 1)

		return nil, nil
	})
}

func TestAuditStoreValidation(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()

		// Invalid event type
		_, err := store.Insert(ctx, AuditEventInput{
			EventType:  "bogus.event",
			Outcome:    AuditOutcomeSuccess,
			AuthMethod: AuditAuthMethodSession,
		})
		require.ErrorIs(t, err, ErrAuditInvalidEventType)

		// Invalid outcome
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:  AuditAuthLogout,
			Outcome:    "bogus",
			AuthMethod: AuditAuthMethodSession,
		})
		require.ErrorIs(t, err, ErrAuditInvalidOutcome)

		// Invalid auth_method
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:  AuditAuthLogout,
			Outcome:    AuditOutcomeSuccess,
			AuthMethod: "bogus",
		})
		require.ErrorIs(t, err, ErrAuditInvalidAuthMethod)

		// Oversize metadata
		oversize := json.RawMessage(`{"x":"` + strings.Repeat("a", 4096) + `"}`)
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:  AuditAuthLogout,
			Outcome:    AuditOutcomeSuccess,
			AuthMethod: AuditAuthMethodSession,
			Metadata:   oversize,
		})
		require.ErrorIs(t, err, ErrAuditMetadataTooLarge)

		// Invalid JSON metadata
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:  AuditAuthLogout,
			Outcome:    AuditOutcomeSuccess,
			AuthMethod: AuditAuthMethodSession,
			Metadata:   json.RawMessage(`not json`),
		})
		require.ErrorIs(t, err, ErrAuditMetadataInvalid)

		// User-agent over the cap is silently trimmed, not rejected
		ua := strings.Repeat("u", auditMaxUserAgentChars+50)
		actor := "user-trim"
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:   AuditAuthLogout,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &actor,
			UserAgent:   &ua,
		})
		require.NoError(t, err)

		got, _, err := store.List(ctx, AuditFilter{UserID: actor}, 1, "")
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.NotNil(t, got[0].UserAgent)
		require.Len(t, *got[0].UserAgent, auditMaxUserAgentChars)

		return nil, nil
	})
}

func TestAuditStorePruneOldRecords(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()
		actor := "user-prune"

		// Insert one row, then prune everything older than now+1
		_, err := store.Insert(ctx, AuditEventInput{
			EventType:   AuditAuthLogout,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &actor,
		})
		require.NoError(t, err)

		removed, err := store.PruneBefore(ctx, time.Now().Add(1*time.Minute).Unix())
		require.NoError(t, err)
		require.GreaterOrEqual(t, removed, int64(1))

		got, _, err := store.List(ctx, AuditFilter{UserID: actor}, 10, "")
		require.NoError(t, err)
		require.Empty(t, got)

		return nil, nil
	})
}

func TestAuditStoreListSystemFilter(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()

		actor := "user-sys"
		// One session-auth event for a user
		_, err := store.Insert(ctx, AuditEventInput{
			EventType:   AuditAuthLogout,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &actor,
		})
		require.NoError(t, err)
		// One system-driven background event (e.g. request expiry)
		_, err = store.Insert(ctx, AuditEventInput{
			EventType:   AuditRequestExpire,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSystem,
			ActorUserID: &actor,
		})
		require.NoError(t, err)

		// Empty filter returns both
		all, _, err := store.List(ctx, AuditFilter{}, 10, "")
		require.NoError(t, err)
		require.Len(t, all, 2)

		// System filter returns only the system row
		sysOnly, _, err := store.List(ctx, AuditFilter{System: true}, 10, "")
		require.NoError(t, err)
		require.Len(t, sysOnly, 1)
		require.Equal(t, AuditAuthMethodSystem, sysOnly[0].AuthMethod)

		// Combining UserID and System is rejected
		_, _, err = store.List(ctx, AuditFilter{UserID: actor, System: true}, 10, "")
		require.ErrorIs(t, err, ErrAuditFilterConflict)

		return nil, nil
	})
}

func TestAuditStoreInvalidCursor(t *testing.T) {
	conn := newTestDatabase(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	_, _ = ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
		store := tx.AuditStore()
		_, _, err := store.List(ctx, AuditFilter{UserID: "u"}, 10, "not-a-uuid")
		require.ErrorIs(t, err, ErrAuditInvalidCursor)
		return nil, nil
	})
}
