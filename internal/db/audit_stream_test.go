package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/italypaleale/go-kit/auditlogs/siem"
	"github.com/stretchr/testify/require"
)

// insertAuditEvent writes one committed audit event and returns its id
func insertAuditEvent(t *testing.T, conn *DB, eventType EventType) string {
	t.Helper()

	actor := "user-stream"
	rec, err := conn.AuditStore().Insert(t.Context(), AuditEventInput{
		EventType:   eventType,
		Outcome:     AuditOutcomeSuccess,
		AuthMethod:  AuditAuthMethodSession,
		ActorUserID: &actor,
	})
	require.NoError(t, err)

	return rec.ID
}

func TestAuditStreamListForShipping(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()

		first := insertAuditEvent(t, conn, AuditAuthLoginFinish)
		second := insertAuditEvent(t, conn, AuditRequestCreate)
		third := insertAuditEvent(t, conn, AuditRequestConfirm)

		var zero siem.Position

		count, err := store.CountPending(ctx, zero)
		require.NoError(t, err)
		require.Equal(t, int64(3), count)

		// The limit is honoured and the order is the shipping order
		events, err := store.ListForShipping(ctx, zero, 2)
		require.NoError(t, err)
		require.Len(t, events, 2)
		require.Equal(t, first, events[0].ID)
		require.Equal(t, second, events[1].ID)

		// Every event carries its own position, and the payload fields are mapped over
		require.Equal(t, "auth.login_finish", events[0].EventType)
		require.Equal(t, "success", events[0].Outcome)
		require.Equal(t, "session", events[0].AuthMethod)
		require.Equal(t, "user-stream", events[0].ActorUserID)
		require.Empty(t, events[0].ClientIP)
		require.JSONEq(t, `{}`, string(events[0].Metadata))
		require.NotZero(t, events[0].Position.EventCreatedAt)
		require.Equal(t, first, events[0].Position.EventID)

		// Reading past the cursor returns only what follows it
		events, err = store.ListForShipping(ctx, events[1].Position, 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, third, events[0].ID)

		count, err = store.CountPending(ctx, events[0].Position)
		require.NoError(t, err)
		require.Equal(t, int64(0), count)

		events, err = store.ListForShipping(ctx, events[0].Position, 10)
		require.NoError(t, err)
		require.Empty(t, events)
	})
}

func TestAuditStreamCursor(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()

		// Key absence, rather than a zero value, is the "not yet bootstrapped" sentinel
		_, err := store.GetPosition(ctx)
		require.ErrorIs(t, err, siem.ErrPositionNotFound)

		insertAuditEvent(t, conn, AuditAuthLoginFinish)

		head, seeded, err := store.BootstrapToHead(ctx)
		require.NoError(t, err)
		require.True(t, seeded)
		require.NotZero(t, head.EventCreatedAt)

		got, err := store.GetPosition(ctx)
		require.NoError(t, err)
		require.Equal(t, head, got)

		// Bootstrapping again is a no-op, so a restart resumes from the stored cursor rather than skipping forward
		insertAuditEvent(t, conn, AuditRequestCreate)

		again, seeded, err := store.BootstrapToHead(ctx)
		require.NoError(t, err)
		require.False(t, seeded)
		require.Equal(t, head, again)

		// The event written after the first bootstrap is still pending
		events, err := store.ListForShipping(ctx, again, 10)
		require.NoError(t, err)
		require.Len(t, events, 1)

		// Another writer moves the cursor after this store last read it, leaving this store holding a stale etag
		next := events[0].Position

		other := conn.AuditStreamStore()
		_, err = other.GetPosition(ctx)
		require.NoError(t, err)
		swapped, err := other.SetPosition(ctx, siem.Position{}, next)
		require.NoError(t, err)
		require.True(t, swapped)

		// A losing compare-and-swap reports false rather than clobbering the cursor
		swapped, err = store.SetPosition(ctx, head, next)
		require.NoError(t, err)
		require.False(t, swapped)

		// Re-reading picks up the current etag, and the write lands
		_, err = store.GetPosition(ctx)
		require.NoError(t, err)
		swapped, err = store.SetPosition(ctx, head, next)
		require.NoError(t, err)
		require.True(t, swapped)

		got, err = store.GetPosition(ctx)
		require.NoError(t, err)
		require.Equal(t, next, got)
	})
}

func TestAuditStreamBootstrapOnAnEmptyTable(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()

		// An empty audit table seeds a legitimately all-zero cursor
		head, seeded, err := store.BootstrapToHead(ctx)
		require.NoError(t, err)
		require.True(t, seeded)
		require.Equal(t, siem.Position{V: siem.PositionVersion}, head)

		// Events written afterwards must still be delivered, which is what would break if bootstrap were inferred from a zero cursor instead of from key presence
		first := insertAuditEvent(t, conn, AuditRequestCreate)

		_, seeded, err = store.BootstrapToHead(ctx)
		require.NoError(t, err)
		require.False(t, seeded)

		pos, err := store.GetPosition(ctx)
		require.NoError(t, err)

		events, err := store.ListForShipping(ctx, pos, 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, first, events[0].ID)
	})
}

func TestAuditStreamShipsEventsWrittenInATransaction(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()

		// An event committed outside a transaction, which the shipper reads and advances past
		insertAuditEvent(t, conn, AuditAuthLoginFinish)

		events, err := store.ListForShipping(ctx, siem.Position{}, 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		pos := events[0].Position

		// An event written inside a transaction, which only becomes visible at commit time
		// This is the kind the security-critical mutations use, and the kind an id-ordered cursor would drop
		actor := "user-tx"
		_, err = ExecuteInTransaction(ctx, conn, 30*time.Second, func(ctx context.Context, tx *DbTx) (any, error) {
			return tx.AuditStore().Insert(ctx, AuditEventInput{
				EventType:   AuditRequestConfirm,
				Outcome:     AuditOutcomeSuccess,
				AuthMethod:  AuditAuthMethodSession,
				ActorUserID: &actor,
			})
		})
		require.NoError(t, err)

		events, err = store.ListForShipping(ctx, pos, 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, "request.confirm", events[0].EventType)
	})
}

func TestAuditStreamPostgresExcludesUnsettledRows(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		if conn.Kind() != BackendPostgres {
			t.Skip("settled-ness is a Postgres concern; SQLite serializes writers instead")
		}

		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()
		actor := "user-settled"

		// Open a transaction and write an audit row in it, without committing yet
		// The transaction is driven directly, rather than through ExecuteInTransaction, so the test can interleave a committed write with it
		tx, err := conn.DatabaseConn.Begin(ctx)
		require.NoError(t, err)

		txStore, err := NewAuditStore(tx, conn.Kind())
		require.NoError(t, err)

		_, err = txStore.Insert(ctx, AuditEventInput{
			EventType:   AuditRequestConfirm,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &actor,
		})
		require.NoError(t, err)

		// Write and commit a later row outside that transaction
		insertAuditEvent(t, conn, AuditAuthLoginFinish)

		// Neither row is shippable while the transaction is in flight: the committed one sits above the snapshot's xmin, so advancing past it could never strand the uncommitted one behind the cursor
		events, err := store.ListForShipping(ctx, siem.Position{}, 10)
		require.NoError(t, err)
		require.Empty(t, events)

		require.NoError(t, tx.Commit(ctx))

		// Both rows become shippable once the transaction settles
		events, err = store.ListForShipping(ctx, siem.Position{}, 10)
		require.NoError(t, err)
		require.Len(t, events, 2)
	})
}

func TestAuditStreamPostgresSkipsAbortedTransactions(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		if conn.Kind() != BackendPostgres {
			t.Skip("settled-ness is a Postgres concern; SQLite serializes writers instead")
		}

		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()
		actor := "user-aborted"

		tx, err := conn.DatabaseConn.Begin(ctx)
		require.NoError(t, err)

		txStore, err := NewAuditStore(tx, conn.Kind())
		require.NoError(t, err)

		_, err = txStore.Insert(ctx, AuditEventInput{
			EventType:   AuditRequestConfirm,
			Outcome:     AuditOutcomeSuccess,
			AuthMethod:  AuditAuthMethodSession,
			ActorUserID: &actor,
		})
		require.NoError(t, err)
		require.NoError(t, tx.Rollback(ctx))

		// A rolled-back event never happened, so it must never reach the collector
		events, err := store.ListForShipping(ctx, siem.Position{}, 10)
		require.NoError(t, err)
		require.Empty(t, events)
	})
}

func TestAuditStreamSQLiteSeqDurability(t *testing.T) {
	conn := newSQLiteTestDB(t)
	require.NoError(t, RunMigrations(t.Context(), conn, nil))

	ctx := t.Context()
	store := conn.AuditStreamStore()

	for range 3 {
		insertAuditEvent(t, conn, AuditRequestCreate)
	}

	events, err := store.ListForShipping(ctx, siem.Position{}, 10)
	require.NoError(t, err)
	require.Len(t, events, 3)

	before := make([]int64, len(events))
	for i, e := range events {
		before[i] = e.Position.Seq
	}

	// VACUUM may renumber an implicit rowid, which would silently invalidate the cursor
	// An explicit INTEGER PRIMARY KEY AUTOINCREMENT survives it
	_, err = conn.Exec(ctx, "VACUUM")
	require.NoError(t, err)

	events, err = store.ListForShipping(ctx, siem.Position{}, 10)
	require.NoError(t, err)
	require.Len(t, events, 3)
	for i, e := range events {
		require.Equal(t, before[i], e.Position.Seq)
	}

	// Emptying the table must not reset the counter: a quiet instance can go a full retention period with no events, and a restart from 1 would put every new event behind the cursor forever
	_, err = conn.AuditStore().PruneBefore(ctx, time.Now().Add(time.Minute).Unix())
	require.NoError(t, err)

	insertAuditEvent(t, conn, AuditRequestConfirm)

	events, err = store.ListForShipping(ctx, siem.Position{}, 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Greater(t, events[0].Position.Seq, before[len(before)-1])
}

func TestAuditStreamSQLiteMigrationAssignsSeqInIDOrder(t *testing.T) {
	conn := newSQLiteTestDB(t)

	// Migrate only up to the level before the audit stream migration, so rows exist before seq does
	require.NoError(t, RunMigrationsUpTo(t.Context(), conn, nil, 2))

	ctx := t.Context()
	ids := make([]string, 0, 4)
	for range 4 {
		ids = append(ids, insertAuditEvent(t, conn, AuditRequestCreate))
	}

	require.NoError(t, RunMigrations(ctx, conn, nil))

	events, err := conn.AuditStreamStore().ListForShipping(ctx, siem.Position{}, 10)
	require.NoError(t, err)
	require.Len(t, events, 4)

	// The rebuild copies rows ordered by id, so seq comes out in UUIDv7 (time) order
	for i, e := range events {
		require.Equal(t, ids[i], e.ID)
		if i > 0 {
			require.Greater(t, e.Position.Seq, events[i-1].Position.Seq)
		}
	}
}

func TestAuditStreamMapsCorrelationIDsToAttributes(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		actor := "user-attrs"
		keyID := "sk-1"
		state := "abc123"

		_, err := conn.AuditStore().Insert(ctx, AuditEventInput{
			EventType:    AuditSigningKeyCreate,
			Outcome:      AuditOutcomeSuccess,
			AuthMethod:   AuditAuthMethodSession,
			ActorUserID:  &actor,
			SigningKeyID: &keyID,
			RequestState: &state,
			Metadata:     json.RawMessage(`{"algorithm":"ES384"}`),
		})
		require.NoError(t, err)

		events, err := conn.AuditStreamStore().ListForShipping(ctx, siem.Position{}, 10)
		require.NoError(t, err)
		require.Len(t, events, 1)

		// The columns the generic event has no field for travel as attributes
		require.Equal(t, keyID, events[0].Attributes["signingKeyId"])
		require.Equal(t, state, events[0].Attributes["requestState"])

		// A NULL column maps to an empty value, which the encoder drops
		require.Empty(t, events[0].Attributes["credentialId"])

		// The handler's own payload is untouched, so the feed matches the source table byte for byte
		require.JSONEq(t, `{"algorithm":"ES384"}`, string(events[0].Metadata))
	})
}

func TestAuditStreamCursorIsStoredAsText(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()

		insertAuditEvent(t, conn, AuditRequestCreate)

		head, _, err := store.BootstrapToHead(ctx)
		require.NoError(t, err)

		// What lands in the row is exactly what Encode produces, so it stays legible to an operator reading the row directly
		raw, etag, err := conn.KVStore().Get(ctx, AuditStreamCursorKey)
		require.NoError(t, err)
		require.Equal(t, head.Encode(), raw)
		require.Contains(t, raw, "v=1;")
		require.NotEmpty(t, etag)
	})
}

func TestAuditStreamCursorRequiresAReadBeforeAdvancing(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		insertAuditEvent(t, conn, AuditRequestCreate)

		seeder := conn.AuditStreamStore()
		head, seeded, err := seeder.BootstrapToHead(ctx)
		require.NoError(t, err)
		require.True(t, seeded)

		// A store that has never read the cursor holds no etag, so it cannot advance it
		// The prune reads the cursor from a throwaway store, and must not be able to move it
		fresh := conn.AuditStreamStore()
		swapped, err := fresh.SetPosition(ctx, siem.Position{}, siem.Position{V: siem.PositionVersion, Seq: 999})
		require.NoError(t, err)
		require.False(t, swapped)

		got, err := fresh.GetPosition(ctx)
		require.NoError(t, err)
		require.Equal(t, head, got)

		// Once it has read, it can
		swapped, err = fresh.SetPosition(ctx, head, siem.Position{V: siem.PositionVersion, Seq: 999})
		require.NoError(t, err)
		require.True(t, swapped)
	})
}
