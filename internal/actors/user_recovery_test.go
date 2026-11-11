package actors

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
)

// A change is recorded in the main database before the actor saves its state
// These tests make saving the state fail after that, and check that the request ends up with the recorded status, with one audit event
func TestUserActorRecoversFromStateFailures(t *testing.T) {
	const userID = "user-actor-recovery"
	faults := injectFaults[userActorState](t, actorTypeUser)
	h := newTestHost(t, newTestDB(t, userID), ":memory:")
	user := h.User(userID)

	t.Run("a confirmation is kept, and a later cancellation is refused", func(t *testing.T) {
		const state = "confirm-then-cancel"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		faults.failSetState(1)
		_, err := user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, requestTestAudit(db.AuditRequestConfirm, userID))
		require.ErrorContains(t, err, errInjected.Error())

		payload, err := h.db.RequestPayloadStore().Get(t.Context(), state, userID)
		require.NoError(t, err)
		require.NotNil(t, payload)
		assert.Equal(t, db.V2RequestStatusCompleted, payload.Status)
		assert.Len(t, requestAuditEvents(t, h, userID, db.AuditRequestConfirm, state), 1)

		_, err = user.Cancel(t.Context(), state, requestTestAudit(db.AuditRequestCancel, userID))
		require.ErrorIs(t, err, ErrRequestNotModifiable)
		assert.Empty(t, requestAuditEvents(t, h, userID, db.AuditRequestCancel, state))

		req, err := user.Get(t.Context(), state)
		require.NoError(t, err)
		require.NotNil(t, req)
		assert.Equal(t, db.V2RequestStatusCompleted, req.Status)

		collected, err := user.Collect(t.Context(), state)
		require.NoError(t, err)
		require.True(t, collected.Found)
		assert.Equal(t, db.V2RequestStatusCompleted, collected.Status)
		assert.JSONEq(t, `{"ciphertext":"cmVz"}`, collected.EncryptedResult)
	})

	t.Run("a retried confirmation succeeds and keeps the first result", func(t *testing.T) {
		const state = "confirm-retry"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		faults.failSetState(1)
		_, err := user.Confirm(t.Context(), state, `{"ciphertext":"Zmlyc3Q"}`, requestTestAudit(db.AuditRequestConfirm, userID))
		require.ErrorContains(t, err, errInjected.Error())

		req, err := user.Confirm(t.Context(), state, `{"ciphertext":"c2Vjb25k"}`, requestTestAudit(db.AuditRequestConfirm, userID))
		require.NoError(t, err)
		assert.Equal(t, db.V2RequestStatusCompleted, req.Status)
		assert.Len(t, requestAuditEvents(t, h, userID, db.AuditRequestConfirm, state), 1)

		collected, err := user.Collect(t.Context(), state)
		require.NoError(t, err)
		require.True(t, collected.Found)
		assert.JSONEq(t, `{"ciphertext":"Zmlyc3Q"}`, collected.EncryptedResult)
	})

	t.Run("a cancellation is kept, and a later confirmation is refused", func(t *testing.T) {
		const state = "cancel-then-confirm"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		faults.failSetState(1)
		_, err := user.Cancel(t.Context(), state, requestTestAudit(db.AuditRequestCancel, userID))
		require.ErrorContains(t, err, errInjected.Error())

		_, err = user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, requestTestAudit(db.AuditRequestConfirm, userID))
		require.ErrorIs(t, err, ErrRequestNotModifiable)
		assert.Empty(t, requestAuditEvents(t, h, userID, db.AuditRequestConfirm, state))
		assert.Len(t, requestAuditEvents(t, h, userID, db.AuditRequestCancel, state), 1)

		payload, err := h.db.RequestPayloadStore().Get(t.Context(), state, userID)
		require.NoError(t, err)
		require.NotNil(t, payload)
		assert.Equal(t, db.V2RequestStatusCanceled, payload.Status)
		assert.Empty(t, payload.EncryptedResult)
	})

	t.Run("a long-poll gets a confirmation the state missed", func(t *testing.T) {
		const state = "confirm-then-subscribe"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		faults.failSetState(1)
		_, err := user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, requestTestAudit(db.AuditRequestConfirm, userID))
		require.ErrorContains(t, err, errInjected.Error())

		sub, err := user.Subscribe(t.Context(), state)
		require.NoError(t, err)
		require.True(t, sub.Found)
		assert.Equal(t, db.V2RequestStatusCompleted, sub.Status)
	})

	t.Run("expiry keeps a confirmation the state missed", func(t *testing.T) {
		const state = "confirm-then-expire"
		seedTestRequest(t, h, userID, state, time.Now().Add(time.Second))

		faults.failSetState(1)
		_, err := user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, requestTestAudit(db.AuditRequestConfirm, userID))
		require.ErrorContains(t, err, errInjected.Error())

		// The cleanup alarm runs shortly after the deadline, and finds the request completed in the database
		require.Eventually(t, func() bool {
			list, lErr := user.List(t.Context())
			require.NoError(t, lErr)
			for _, item := range list {
				if item.State == state {
					return false
				}
			}

			req, gErr := user.Get(t.Context(), state)
			require.NoError(t, gErr)
			return req != nil && req.Status == db.V2RequestStatusCompleted
		}, 15*time.Second, 100*time.Millisecond, "the cleanup alarm didn't process the request")
		assert.Empty(t, requestAuditEvents(t, h, userID, db.AuditRequestExpire, state))
	})

	t.Run("a creation can be retried", func(t *testing.T) {
		const state = "create-retry"
		in := CreateRequestInput{
			State: state,
			Request: Request{
				Operation: "encrypt",
				KeyLabel:  "test-key",
				Algorithm: "A256GCM",
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			EncryptedRequest: `{"ciphertext":"Y3Q"}`,
			Audit:            requestTestAudit(db.AuditRequestCreate, userID),
		}
		in.Audit.RequestState = new(state)

		// Create retries on its own, so make every attempt fail, then call it again
		faults.failSetState(createAttempts)
		err := user.Create(t.Context(), in)
		require.ErrorContains(t, err, errInjected.Error())

		payload, err := h.db.RequestPayloadStore().Get(t.Context(), state, userID)
		require.NoError(t, err)
		require.NotNil(t, payload)
		assert.Equal(t, db.V2RequestStatusPending, payload.Status)

		err = user.Create(t.Context(), in)
		require.NoError(t, err)
		assert.Len(t, requestAuditEvents(t, h, userID, db.AuditRequestCreate, state), 1)

		req, err := user.Get(t.Context(), state)
		require.NoError(t, err)
		require.NotNil(t, req)
		assert.Equal(t, db.V2RequestStatusPending, req.Status)
	})

	t.Run("a transient failure while creating is retried", func(t *testing.T) {
		const state = "create-transient"
		in := CreateRequestInput{
			State: state,
			Request: Request{
				Operation: "encrypt",
				KeyLabel:  "test-key",
				Algorithm: "A256GCM",
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			EncryptedRequest: `{"ciphertext":"Y3Q"}`,
			Audit:            requestTestAudit(db.AuditRequestCreate, userID),
		}
		in.Audit.RequestState = new(state)

		faults.failSetState(1)
		err := user.Create(t.Context(), in)
		require.NoError(t, err)
		assert.Len(t, requestAuditEvents(t, h, userID, db.AuditRequestCreate, state), 1)

		req, err := user.Get(t.Context(), state)
		require.NoError(t, err)
		require.NotNil(t, req)
	})
}

// requestTestAudit returns an audit event where the user is the actor
func requestTestAudit(eventType db.EventType, userID string) *db.AuditEventInput {
	return &db.AuditEventInput{
		EventType:   eventType,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: &userID,
	}
}

// requestAuditEvents returns the audit events of a type for a request, where the user is the actor
func requestAuditEvents(t *testing.T, h *Host, userID string, eventType db.EventType, state string) []db.AuditEvent {
	t.Helper()

	var res []db.AuditEvent
	for _, e := range auditEvents(t, h, userID, eventType) {
		if e.RequestState != nil && *e.RequestState == state {
			res = append(res, e)
		}
	}

	return res
}
