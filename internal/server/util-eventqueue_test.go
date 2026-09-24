package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

func TestExecuteRequestExpiryEvent(t *testing.T) {
	// Creates a server with a user and a pending request that expires at expiresAt
	setup := func(t *testing.T, dbName string, expiresAt time.Time) (srv *Server, userID string, state string) {
		t.Helper()

		setTestConfig(t, dbName)
		srv = newTestServer(t, nil, nil, nil)
		require.NotNil(t, srv)

		_, user := seedV2SessionCookie(t, srv, "user-expiry-event", "Expiry Event User")

		state = "expiry-event-state"
		_, err := db.ExecuteInTransaction(t.Context(), srv.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
			return struct{}{}, tx.RequestStore().CreateRequest(ctx, db.CreateRequestInput{
				State:            state,
				UserID:           user.ID,
				Operation:        "encrypt",
				RequestorIP:      "127.0.0.1",
				KeyLabel:         "expiry-event-label",
				Algorithm:        "A256GCM",
				CreatedAt:        time.Now().Add(-2 * time.Minute),
				ExpiresAt:        expiresAt,
				EncryptedRequest: "{}",
			})
		})
		require.NoError(t, err)

		return srv, user.ID, state
	}

	// Subscribes to both notification channels, as a long-polling CLI and a list stream would
	subscribe := func(t *testing.T, srv *Server, state string) (watch chan struct{}, events chan *db.V2RequestListItem) {
		t.Helper()

		srv.lock.Lock()
		watch = srv.subscribeState(state)
		srv.lock.Unlock()

		events, err := srv.pubsub.Subscribe()
		require.NoError(t, err)
		t.Cleanup(func() { srv.pubsub.Unsubscribe(events) })

		return watch, events
	}

	requireNotified := func(t *testing.T, watch chan struct{}) {
		t.Helper()

		select {
		case _, ok := <-watch:
			require.True(t, ok, "subscription was closed without a notification")
		default:
			require.Fail(t, "subscriber was not notified")
		}
	}

	requireRemovedPublished := func(t *testing.T, events chan *db.V2RequestListItem, state string, userID string) {
		t.Helper()

		select {
		case msg := <-events:
			require.Equal(t, state, msg.State)
			require.Equal(t, "removed", msg.Status)
			require.Equal(t, userID, msg.UserID)
		default:
			require.Fail(t, "no list item was published")
		}
	}

	t.Run("expires a pending request", func(t *testing.T) {
		expiresAt := time.Now().Add(-1 * time.Minute)
		srv, userID, state := setup(t, "expiry-event-pending.db", expiresAt)
		watch, events := subscribe(t, srv, state)

		srv.executeRequestExpiryEvent(requestExpiryEvent{State: state, UserID: userID, TTL: expiresAt.Add(requestExpiryGrace)})

		requireNotified(t, watch)
		requireRemovedPublished(t, events, state, userID)
		require.Equal(t, 1, srv.deleteQueue.Count())
		require.Len(t, auditByType(t, srv, userID, db.AuditRequestExpire), 1)
	})

	t.Run("notifies when the request was expired lazily", func(t *testing.T) {
		expiresAt := time.Now().Add(-1 * time.Minute)
		srv, userID, state := setup(t, "expiry-event-lazy.db", expiresAt)
		watch, events := subscribe(t, srv, state)

		// Listing requests expires the request without notifying anyone
		_, err := srv.db.RequestStore().ListPending(t.Context(), userID)
		require.NoError(t, err)
		rec, err := srv.db.RequestStore().GetRequest(t.Context(), state)
		require.NoError(t, err)
		require.Equal(t, db.V2RequestStatusExpired, rec.Status)

		srv.executeRequestExpiryEvent(requestExpiryEvent{State: state, UserID: userID, TTL: expiresAt.Add(requestExpiryGrace)})

		requireNotified(t, watch)
		requireRemovedPublished(t, events, state, userID)
		require.Equal(t, 1, srv.deleteQueue.Count())

		// The expiry is audited once, by the lazy path
		require.Len(t, auditByType(t, srv, userID, db.AuditRequestExpire), 1)
	})

	t.Run("reschedules when the deadline has not passed", func(t *testing.T) {
		// The deadline is far enough in the future that the rescheduled event doesn't fire during the test
		expiresAt := time.Now().Add(time.Hour)
		srv, userID, state := setup(t, "expiry-event-early.db", expiresAt)
		watch, events := subscribe(t, srv, state)

		srv.executeRequestExpiryEvent(requestExpiryEvent{State: state, UserID: userID, TTL: time.Now()})

		require.Equal(t, 1, srv.requestExpiryQueue.Count())
		require.Equal(t, 0, srv.deleteQueue.Count())
		require.Empty(t, watch)
		require.Empty(t, events)

		rec, err := srv.db.RequestStore().GetRequest(t.Context(), state)
		require.NoError(t, err)
		require.Equal(t, db.V2RequestStatusPending, rec.Status)
	})

	t.Run("publishes removal when the request was deleted", func(t *testing.T) {
		expiresAt := time.Now().Add(-1 * time.Minute)
		srv, userID, state := setup(t, "expiry-event-deleted.db", expiresAt)

		// Fetching the result expires and deletes the request
		rec, err := srv.db.RequestStore().GetAndDeleteTerminalRequest(t.Context(), state)
		require.NoError(t, err)
		require.NotNil(t, rec)

		_, events := subscribe(t, srv, state)
		srv.executeRequestExpiryEvent(requestExpiryEvent{State: state, UserID: userID, TTL: expiresAt.Add(requestExpiryGrace)})

		requireRemovedPublished(t, events, state, userID)
		require.Equal(t, 0, srv.deleteQueue.Count())
	})

	t.Run("ignores a completed request", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Minute)
		srv, userID, state := setup(t, "expiry-event-completed.db", expiresAt)

		_, err := srv.db.RequestStore().CompleteRequest(t.Context(), state, userID, protocolv2.ResponseEnvelope{
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

		watch, events := subscribe(t, srv, state)
		srv.executeRequestExpiryEvent(requestExpiryEvent{State: state, UserID: userID, TTL: time.Now()})

		require.Empty(t, watch)
		require.Empty(t, events)
		require.Equal(t, 0, srv.requestExpiryQueue.Count())
		require.Equal(t, 0, srv.deleteQueue.Count())
		require.Empty(t, auditByType(t, srv, userID, db.AuditRequestExpire))
	})
}
