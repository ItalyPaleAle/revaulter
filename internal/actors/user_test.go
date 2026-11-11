package actors

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/italypaleale/francis/actor"
	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
)

func TestUserActorStateNextCleanup(t *testing.T) {
	now := time.Now()
	const sessionTimeout = 5 * time.Minute

	t.Run("empty state has no cleanup", func(t *testing.T) {
		st := userActorState{}
		assert.True(t, st.nextCleanup(sessionTimeout).IsZero())
	})

	t.Run("pending request is due shortly after its deadline", func(t *testing.T) {
		st := userActorState{
			Requests: map[string]*Request{
				"a": {Status: db.V2RequestStatusPending, ExpiresAt: now.Add(time.Minute)},
			},
			Bell: "bell",
		}
		assert.Equal(t, now.Add(time.Minute+requestExpiryGrace), st.nextCleanup(sessionTimeout))
	})

	t.Run("finished request is due after the removal grace period", func(t *testing.T) {
		st := userActorState{
			Requests: map[string]*Request{
				"a": {Status: db.V2RequestStatusCompleted, ExpiresAt: now.Add(time.Minute)},
			},
		}
		assert.Equal(t, now.Add(time.Minute+RequestRemoveGrace), st.nextCleanup(sessionTimeout))
	})

	t.Run("earliest due time wins", func(t *testing.T) {
		st := userActorState{
			Requests: map[string]*Request{
				"late":     {Status: db.V2RequestStatusPending, ExpiresAt: now.Add(time.Hour)},
				"finished": {Status: db.V2RequestStatusCanceled, ExpiresAt: now.Add(-5 * time.Minute)},
				"soon":     {Status: db.V2RequestStatusPending, ExpiresAt: now.Add(2 * time.Minute)},
			},
		}
		assert.Equal(t, now.Add(2*time.Minute+requestExpiryGrace), st.nextCleanup(sessionTimeout))
	})

	t.Run("bell alone expires one session timeout after the last change", func(t *testing.T) {
		st := userActorState{
			Bell:       "bell",
			LastChange: now,
		}
		assert.Equal(t, now.Add(sessionTimeout), st.nextCleanup(sessionTimeout))
	})
}

func TestUserActorStatePendingList(t *testing.T) {
	now := time.Now()
	st := userActorState{
		Requests: map[string]*Request{
			"newer":    {Status: db.V2RequestStatusPending, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), KeyLabel: "k2"},
			"older":    {Status: db.V2RequestStatusPending, CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(time.Minute), KeyLabel: "k1"},
			"overdue":  {Status: db.V2RequestStatusPending, CreatedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(-time.Second)},
			"finished": {Status: db.V2RequestStatusCompleted, CreatedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(time.Minute)},
		},
	}

	list := st.pendingList("user-1", now)
	require.Len(t, list, 2)
	assert.Equal(t, "older", list[0].State)
	assert.Equal(t, "k1", list[0].KeyLabel)
	assert.Equal(t, "user-1", list[0].UserID)
	assert.Equal(t, string(db.V2RequestStatusPending), list[0].Status)
	assert.Equal(t, "newer", list[1].State)

	// Overdue requests still count towards the limit until they're expired
	assert.Equal(t, 3, st.countPending())
}

func TestUserActorStateClone(t *testing.T) {
	st := userActorState{
		Requests: map[string]*Request{
			"a": {Status: db.V2RequestStatusPending, Waiter: "w1"},
		},
		Bell: "bell",
	}

	cloned := st.clone()
	cloned.Requests["a"].Waiter = "w2"
	cloned.Requests["b"] = &Request{}
	cloned.Bell = "other"

	assert.Equal(t, "w1", st.Requests["a"].Waiter)
	assert.Len(t, st.Requests, 1)
	assert.Equal(t, "bell", st.Bell)
}

func TestUserActorRequests(t *testing.T) {
	const userID = "user-actor-requests"
	h := newTestHost(t, newTestDB(t, userID), ":memory:")
	user := h.User(userID)

	t.Run("confirm and collect", func(t *testing.T) {
		const state = "confirm-collect"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		rec, err := user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, nil)
		require.NoError(t, err)
		assert.Equal(t, db.V2RequestStatusCompleted, rec.Status)
		assert.Equal(t, "encrypt", rec.Operation)

		// A second confirm is rejected
		_, err = user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, nil)
		require.ErrorIs(t, err, ErrRequestNotModifiable)

		// Collecting returns the result once, then removes the request and its payload
		collected, err := user.Collect(t.Context(), state)
		require.NoError(t, err)
		require.True(t, collected.Found)
		assert.Equal(t, db.V2RequestStatusCompleted, collected.Status)
		assert.JSONEq(t, `{"ciphertext":"cmVz"}`, collected.EncryptedResult)

		collected, err = user.Collect(t.Context(), state)
		require.NoError(t, err)
		assert.False(t, collected.Found)

		payload, err := h.db.RequestPayloadStore().Get(t.Context(), state, userID)
		require.NoError(t, err)
		assert.Nil(t, payload)
	})

	t.Run("confirm writes the audit event", func(t *testing.T) {
		const state = "confirm-audit"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		actorUserID := userID
		_, err := user.Confirm(t.Context(), state, `{}`, &db.AuditEventInput{
			EventType:   db.AuditRequestConfirm,
			Outcome:     db.AuditOutcomeSuccess,
			AuthMethod:  db.AuditAuthMethodSession,
			ActorUserID: &actorUserID,
		})
		require.NoError(t, err)

		events := auditEvents(t, h, userID, db.AuditRequestConfirm)
		require.Len(t, events, 1)
		require.NotNil(t, events[0].RequestState)
		assert.Equal(t, state, *events[0].RequestState)
		require.NotNil(t, events[0].TargetUserID)
		assert.Equal(t, userID, *events[0].TargetUserID)

		var metadata map[string]any
		err = json.Unmarshal(events[0].Metadata, &metadata)
		require.NoError(t, err)
		assert.Equal(t, "test-key", metadata["keyLabel"])
	})

	t.Run("confirm is rejected past the deadline", func(t *testing.T) {
		const state = "confirm-overdue"
		seedTestRequest(t, h, userID, state, time.Now().Add(-time.Second))

		_, err := user.Confirm(t.Context(), state, `{}`, nil)
		require.ErrorIs(t, err, ErrRequestNotModifiable)

		// The request is reported as expired even before the cleanup alarm runs
		rec, err := user.Get(t.Context(), state)
		require.NoError(t, err)
		require.NotNil(t, rec)
		assert.Equal(t, db.V2RequestStatusExpired, rec.Status)
	})

	t.Run("unknown requests can't be changed", func(t *testing.T) {
		_, err := user.Cancel(t.Context(), "missing", nil)
		require.ErrorIs(t, err, ErrRequestNotModifiable)

		sub, err := user.Subscribe(t.Context(), "missing")
		require.NoError(t, err)
		assert.False(t, sub.Found)

		rec, err := user.Get(t.Context(), "missing")
		require.NoError(t, err)
		assert.Nil(t, rec)
	})

	t.Run("requests of other users are not visible", func(t *testing.T) {
		const state = "other-user"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		rec, err := h.User("someone-else").Get(t.Context(), state)
		require.NoError(t, err)
		assert.Nil(t, rec)

		_, err = h.User("someone-else").Cancel(t.Context(), state, nil)
		require.ErrorIs(t, err, ErrRequestNotModifiable)
	})

	t.Run("create is idempotent", func(t *testing.T) {
		const state = "create-twice"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		list, err := user.List(t.Context())
		require.NoError(t, err)
		var n int
		for _, item := range list {
			if item.State == state {
				n++
			}
		}
		assert.Equal(t, 1, n)
	})
}

func TestUserActorLimitsPendingRequests(t *testing.T) {
	const userID = "user-actor-limit"
	h := newTestHost(t, newTestDB(t, userID), ":memory:")
	user := h.User(userID)

	for i := range MaxPendingRequestsPerUser {
		seedTestRequest(t, h, userID, "limit-"+strconv.Itoa(i), time.Now().Add(10*time.Minute))
	}

	create := func(state string) error {
		return user.Create(t.Context(), CreateRequestInput{
			State: state,
			Request: Request{
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			EncryptedRequest: `{}`,
		})
	}

	err := create("limit-over")
	require.ErrorIs(t, err, ErrTooManyPendingRequests)

	// Finished requests don't count
	_, err = user.Cancel(t.Context(), "limit-0", nil)
	require.NoError(t, err)

	err = create("limit-over")
	require.NoError(t, err)
}

func TestUserActorWaiters(t *testing.T) {
	const userID = "user-actor-waiters"
	h := newTestHost(t, newTestDB(t, userID), ":memory:")
	user := h.User(userID)

	const state = "waiters"
	seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

	// A newer subscription evicts the older one
	first, err := user.Subscribe(t.Context(), state)
	require.NoError(t, err)
	require.True(t, first.Found)
	require.Equal(t, db.V2RequestStatusPending, first.Status)
	require.NotEmpty(t, first.Waiter)

	second, err := user.Subscribe(t.Context(), state)
	require.NoError(t, err)
	require.NotEqual(t, first.Waiter, second.Waiter)

	evicted, err := waitForResult(t, user, state, first.Waiter)
	require.NoError(t, err)
	assert.True(t, evicted)

	// A change wakes the current waiter, which reads the final status on its next subscription
	resCh := make(chan error, 1)
	go func() {
		ev, wErr := waitForResult(t, user, state, second.Waiter)
		if wErr == nil && ev {
			wErr = errors.New("the current waiter was evicted")
		}
		resCh <- wErr
	}()

	_, err = user.Cancel(t.Context(), state, nil)
	require.NoError(t, err)
	err = <-resCh
	require.NoError(t, err)

	sub, err := user.Subscribe(t.Context(), state)
	require.NoError(t, err)
	assert.Equal(t, db.V2RequestStatusCanceled, sub.Status)
	assert.Empty(t, sub.Waiter, "no waiter is registered for a final request")

	t.Run("giving up removes the waiter", func(t *testing.T) {
		const state = "waiters-give-up"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))

		sub, err := user.Subscribe(t.Context(), state)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		_, err = user.WaitForResult(ctx, state, sub.Waiter)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		rec, err := user.Get(t.Context(), state)
		require.NoError(t, err)
		require.NotNil(t, rec)
		assert.Empty(t, rec.Waiter)
	})
}

func TestUserActorCleanup(t *testing.T) {
	t.Run("expires pending requests past their deadline", func(t *testing.T) {
		const userID = "user-cleanup-expire"
		h := newTestHost(t, newTestDB(t, userID), ":memory:")

		const state = "cleanup-expire"
		seedTestRequest(t, h, userID, state, time.Now().Add(-10*time.Second))

		require.Eventually(t, func() bool {
			return len(auditEvents(t, h, userID, db.AuditRequestExpire)) == 1
		}, 10*time.Second, 50*time.Millisecond, "the request was not expired")

		events := auditEvents(t, h, userID, db.AuditRequestExpire)
		assert.Equal(t, db.AuditAuthMethodSystem, events[0].AuthMethod)

		// The request is kept, so the caller can still learn that it expired
		var st userActorState
		err := h.host.Service().GetState(t.Context(), actorTypeUser, userID, &st)
		require.NoError(t, err)
		require.NotNil(t, st.Requests[state])
		assert.Equal(t, db.V2RequestStatusExpired, st.Requests[state].Status)

		payload, err := h.db.RequestPayloadStore().Get(t.Context(), state, userID)
		require.NoError(t, err)
		assert.NotNil(t, payload)
	})

	t.Run("removes finished requests and their payloads", func(t *testing.T) {
		const userID = "user-cleanup-remove"
		h := newTestHost(t, newTestDB(t, userID), ":memory:")

		// This request is expired and removed in the same run, as happens after downtime
		const state = "cleanup-remove"
		seedTestRequest(t, h, userID, state, time.Now().Add(-RequestRemoveGrace-time.Minute))

		require.Eventually(t, func() bool {
			rec, err := h.User(userID).Get(t.Context(), state)
			require.NoError(t, err)
			return rec == nil
		}, 10*time.Second, 50*time.Millisecond, "the request was not removed")

		assert.Len(t, auditEvents(t, h, userID, db.AuditRequestExpire), 1)

		payload, err := h.db.RequestPayloadStore().Get(t.Context(), state, userID)
		require.NoError(t, err)
		assert.Nil(t, payload)
	})

	t.Run("re-arms for the next request", func(t *testing.T) {
		const userID = "user-cleanup-rearm"
		h := newTestHost(t, newTestDB(t, userID), ":memory:")

		// The first request is due right away, while the second one is not overdue when the first run happens
		seedTestRequest(t, h, userID, "rearm-first", time.Now().Add(-10*time.Second))
		seedTestRequest(t, h, userID, "rearm-second", time.Now().Add(2*time.Second))

		require.Eventually(t, func() bool {
			return len(auditEvents(t, h, userID, db.AuditRequestExpire)) == 1
		}, 10*time.Second, 50*time.Millisecond, "the first request was not expired")

		alarm, err := h.host.GetAlarm(t.Context(), actorTypeUser, userID, userActorCleanupAlarm)
		require.NoError(t, err)
		assert.True(t, alarm.DueTime.After(time.Now()), "the alarm must be set for the second request")

		require.Eventually(t, func() bool {
			return len(auditEvents(t, h, userID, db.AuditRequestExpire)) == 2
		}, 15*time.Second, 50*time.Millisecond, "the second request was not expired")
	})

	t.Run("deletes the state once only the bell is left", func(t *testing.T) {
		const userID = "user-cleanup-bell"
		h := newTestHost(t, newTestDB(t, userID), ":memory:", map[string]any{
			"sessionTimeout": time.Second,
		})

		seedTestRequest(t, h, userID, "bell-request", time.Now().Add(-RequestRemoveGrace-time.Minute))

		require.Eventually(t, func() bool {
			var st userActorState
			err := h.host.Service().GetState(t.Context(), actorTypeUser, userID, &st)
			return errors.Is(err, actor.ErrStateNotFound)
		}, 15*time.Second, 50*time.Millisecond, "the state was not deleted")

		_, err := h.host.GetAlarm(t.Context(), actorTypeUser, userID, userActorCleanupAlarm)
		require.ErrorIs(t, err, actor.ErrAlarmNotFound)
	})
}

func TestUserActorAcrossReplicas(t *testing.T) {
	const userID = "user-actor-replicas"

	// Two replicas share the main database and a Francis SQLite file, and reach each other on their own peer addresses
	dbConn := newTestDB(t, userID)
	francisDSN := filepath.Join(t.TempDir(), "francis.db")
	hostA := newTestHost(t, dbConn, francisDSN)
	hostB := newTestHost(t, dbConn, francisDSN)
	userA := hostA.User(userID)
	userB := hostB.User(userID)

	// A list stream on replica B takes its snapshot before the request exists
	snap, err := userB.Snapshot(t.Context())
	require.NoError(t, err)
	require.Empty(t, snap.Items)

	// Create a request through replica A, which rings the bell replica B waits on
	const state = "replica-state"
	seedTestRequest(t, hostA, userID, state, time.Now().Add(10*time.Minute))

	waitCtx, waitCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer waitCancel()
	err = userB.WaitForChange(waitCtx, snap.Bell)
	require.NoError(t, err, "the list stream on replica B was not notified")

	snap, err = userB.Snapshot(t.Context())
	require.NoError(t, err)
	require.Len(t, snap.Items, 1)
	assert.Equal(t, state, snap.Items[0].State)

	// A long-poll on replica B is woken by a confirm on replica A
	sub, err := userB.Subscribe(t.Context(), state)
	require.NoError(t, err)
	require.Equal(t, db.V2RequestStatusPending, sub.Status)

	resCh := make(chan error, 1)
	go func() {
		evicted, wErr := waitForResult(t, userB, state, sub.Waiter)
		if wErr == nil && evicted {
			wErr = errors.New("the waiter was evicted")
		}
		resCh <- wErr
	}()

	_, err = userA.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, nil)
	require.NoError(t, err)

	select {
	case err = <-resCh:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the long-poll on replica B was not woken by the confirm on replica A")
	}

	collected, err := userB.Collect(t.Context(), state)
	require.NoError(t, err)
	require.True(t, collected.Found)
	assert.Equal(t, db.V2RequestStatusCompleted, collected.Status)
	assert.JSONEq(t, `{"ciphertext":"cmVz"}`, collected.EncryptedResult)
}

func TestHostRunWaitsForDrained(t *testing.T) {
	t.Cleanup(config.SetTestConfig(map[string]any{
		"databaseDSN": ":memory:",
		// #nosec G101 -- Hardcoded credentials are test ones
		"secretKey":          "dGVzdC1hY3RvcnMtc2VjcmV0LWtleQ",
		"francisPeerAddress": TestPeerAddress(t),
		"francisDatabaseDSN": ":memory:",
	}))

	h, err := NewHost(NewHostOptions{
		Log: slog.New(slog.DiscardHandler),
		DB:  newTestDB(t),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := servicerunner.NewReady()
	drained := servicerunner.NewReady()
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Run(ctx, ready, drained)
	}()

	// A service waiting on ready starts once the host accepts calls
	readyCh := make(chan struct{})
	go func() {
		_ = ready.Await(func(context.Context) error {
			close(readyCh)
			return nil
		})(t.Context())
	}()
	select {
	case <-readyCh:
	case <-time.After(10 * time.Second):
		t.Fatal("ready was not signaled")
	}

	// After ctx is canceled, the host keeps serving calls until drained is signaled
	cancel()
	select {
	case runErr := <-errCh:
		t.Fatalf("the host stopped before drained was signaled: %v", runErr)
	case <-time.After(200 * time.Millisecond):
	}

	_, err = h.User("user-drain").List(t.Context())
	require.NoError(t, err)

	drained.Signal()
	select {
	case runErr := <-errCh:
		require.NoError(t, runErr)
	case <-time.After(15 * time.Second):
		t.Fatal("the host did not stop after drained was signaled")
	}
}

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

		faults.failSetState(1)
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
}

// Once the state is saved, a change is done, even if setting the cleanup alarm fails
// These tests make setting the alarm fail, and check that changes are kept, and that the alarm is set again later
func TestUserActorRecoversFromAlarmFailures(t *testing.T) {
	const userID = "user-actor-alarm-recovery"
	faults := injectFaults[userActorState](t, actorTypeUser)
	h := newTestHost(t, newTestDB(t, userID, "user-alarm-repair", "user-alarm-quota"), ":memory:")
	user := h.User(userID)

	t.Run("collecting returns the result", func(t *testing.T) {
		// The second request has a later due time, so removing the first one moves the alarm
		seedTestRequest(t, h, userID, "collect-first", time.Now().Add(time.Minute))
		seedTestRequest(t, h, userID, "collect-second", time.Now().Add(20*time.Minute))
		_, err := user.Confirm(t.Context(), "collect-first", `{"ciphertext":"cmVz"}`, nil)
		require.NoError(t, err)

		faults.failSetAlarm(1)
		collected, err := user.Collect(t.Context(), "collect-first")
		require.NoError(t, err)
		require.True(t, collected.Found)
		assert.JSONEq(t, `{"ciphertext":"cmVz"}`, collected.EncryptedResult)
		assert.Zero(t, faults.setAlarm.Load(), "setting the alarm was not attempted")

		collected, err = user.Collect(t.Context(), "collect-first")
		require.NoError(t, err)
		assert.False(t, collected.Found)
	})

	t.Run("the next call sets the alarm again", func(t *testing.T) {
		const state = "alarm-next-call"
		faults.failSetAlarm(1)
		seedTestRequest(t, h, userID, state, time.Now().Add(time.Second))
		assert.Zero(t, faults.setAlarm.Load(), "setting the alarm was not attempted")

		_, err := user.Snapshot(t.Context())
		require.NoError(t, err)

		waitForExpiry(t, h, user, userID, state)
	})

	t.Run("the daily repair sets the alarm again", func(t *testing.T) {
		const state = "alarm-daily-repair"
		faults.failSetAlarm(1)
		seedTestRequest(t, h, "user-alarm-repair", state, time.Now().Add(time.Second))
		assert.Zero(t, faults.setAlarm.Load(), "setting the alarm was not attempted")

		repaired, err := h.repairUserActors(t.Context())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, repaired, 1)

		waitForExpiry(t, h, h.User("user-alarm-repair"), "user-alarm-repair", state)
	})

	t.Run("overdue requests don't count towards the limit", func(t *testing.T) {
		const quotaUser = "user-alarm-quota"
		quota := h.User(quotaUser)

		// Fill the quota with requests whose alarms are never set, and let them pass their deadline
		faults.failSetAlarm(10 * MaxPendingRequestsPerUser)
		for i := range MaxPendingRequestsPerUser {
			seedTestRequest(t, h, quotaUser, "quota-"+strconv.Itoa(i), time.Now().Add(time.Second))
		}
		time.Sleep(1500 * time.Millisecond)
		faults.failSetAlarm(0)

		seedTestRequest(t, h, quotaUser, "quota-new", time.Now().Add(10*time.Minute))

		list, err := quota.List(t.Context())
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "quota-new", list[0].State)
		assert.Len(t, auditEvents(t, h, quotaUser, db.AuditRequestExpire), MaxPendingRequestsPerUser)
	})
}

func TestSignupAndChallengeSetTheAlarmFirst(t *testing.T) {
	signupFaults := injectFaults[Signup](t, actorTypeSignup)
	challengeFaults := injectFaults[challengeActorState](t, actorTypeChallenge)
	h := newTestHost(t, newTestDB(t), ":memory:")

	signupFaults.failSetAlarm(1)
	err := h.Signup("signup-alarm-fails").Begin(t.Context(), Signup{
		UserID:         "user-signup-alarm",
		WebAuthnUserID: "signup-alarm-fails",
		ExpiresAt:      time.Now().Add(time.Minute),
	})
	require.ErrorContains(t, err, errInjected.Error())
	assert.Zero(t, countActorStates(t, h, actorTypeSignup), "a signup was stored without its alarm")

	challengeFaults.failSetAlarm(1)
	_, err = h.BeginChallenge(t.Context(), ChallengeKindLogin, "", time.Now().Add(time.Minute), []byte(`{}`))
	require.ErrorContains(t, err, errInjected.Error())
	assert.Zero(t, countActorStates(t, h, actorTypeChallenge), "a challenge was stored without its alarm")
}

// A long-poll that misses the signal that wakes it finds out when it checks the request
// These tests remove the waiter from the request before changing it, so no signal is sent, as if sending it failed
func TestUserActorLongPollRecoversFromMissedWakeups(t *testing.T) {
	const userID = "user-actor-missed-wakeup"
	prevInterval := longPollRecheckInterval
	longPollRecheckInterval = 200 * time.Millisecond
	t.Cleanup(func() {
		longPollRecheckInterval = prevInterval
	})

	h := newTestHost(t, newTestDB(t, userID), ":memory:")
	user := h.User(userID)

	dropWaiter := func(t *testing.T, state string, waiter string) {
		t.Helper()

		_, err := invoke[struct{}](t.Context(), h, actorTypeUser, userID, userMethodUnsubscribe, userStateReq{State: state, Waiter: waiter})
		require.NoError(t, err)
	}

	t.Run("a long-poll finds a change it wasn't woken for", func(t *testing.T) {
		const state = "missed-confirm"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		sub, err := user.Subscribe(t.Context(), state)
		require.NoError(t, err)
		require.NotEmpty(t, sub.Waiter)

		dropWaiter(t, state, sub.Waiter)
		_, err = user.Confirm(t.Context(), state, `{"ciphertext":"cmVz"}`, nil)
		require.NoError(t, err)

		evicted, err := waitForResult(t, user, state, sub.Waiter)
		require.NoError(t, err)
		assert.False(t, evicted)
	})

	t.Run("a long-poll finds out it's no longer the current one", func(t *testing.T) {
		const state = "missed-eviction"
		seedTestRequest(t, h, userID, state, time.Now().Add(10*time.Minute))
		sub, err := user.Subscribe(t.Context(), state)
		require.NoError(t, err)

		dropWaiter(t, state, sub.Waiter)

		evicted, err := waitForResult(t, user, state, sub.Waiter)
		require.NoError(t, err)
		assert.True(t, evicted)
	})
}

// newTestHost creates and starts a Francis host for tests, which uses the given database and Francis store
// Each host gets its own peer address, so several hosts can share a store and form a cluster
func newTestHost(t *testing.T, dbConn *db.DB, francisDSN string, configOverrides ...map[string]any) *Host {
	t.Helper()

	h := newUnstartedTestHost(t, dbConn, francisDSN, configOverrides...)
	RunTestHost(t, h)

	return h
}

// newUnstartedTestHost creates a Francis host for tests like newTestHost, without starting it
func newUnstartedTestHost(t *testing.T, dbConn *db.DB, francisDSN string, configOverrides ...map[string]any) *Host {
	t.Helper()

	return newUnstartedTestHostWithOptions(t, NewHostOptions{DB: dbConn}, francisDSN, configOverrides...)
}

// newUnstartedTestHostWithOptions creates a Francis host for tests with the given options, without starting it
func newUnstartedTestHostWithOptions(t *testing.T, opts NewHostOptions, francisDSN string, configOverrides ...map[string]any) *Host {
	t.Helper()

	cfg := map[string]any{
		"databaseDSN": ":memory:",
		// #nosec G101 -- Hardcoded credentials are test ones
		"secretKey":          "dGVzdC1hY3RvcnMtc2VjcmV0LWtleQ",
		"francisPeerAddress": TestPeerAddress(t),
		"francisDatabaseDSN": francisDSN,
	}
	for _, o := range configOverrides {
		maps.Copy(cfg, o)
	}
	t.Cleanup(config.SetTestConfig(cfg))

	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	h, err := NewHost(opts)
	require.NoError(t, err)

	return h
}

// newTestDB returns a migrated test database with the given users
func newTestDB(t *testing.T, userIDs ...string) *db.DB {
	t.Helper()

	conn := db.NewTestDatabaseForServerTests(t)
	err := db.RunMigrations(t.Context(), conn, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	for _, userID := range userIDs {
		_, err = db.ExecuteInTransaction(t.Context(), conn, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
			_, rErr := tx.AuthStore().RegisterUser(ctx, db.RegisterUserInput{
				UserID:         userID,
				DisplayName:    userID,
				WebAuthnUserID: "webauthn-" + userID,
				CredentialID:   "cred-" + userID,
				PublicKey:      `{}`,
				SignCount:      1,
				SessionTTL:     time.Minute,
			})
			return struct{}{}, rErr
		})
		require.NoError(t, err)
	}

	return conn
}

// seedTestRequest creates a pending request for the user, without an audit event
func seedTestRequest(t *testing.T, h *Host, userID string, state string, expiresAt time.Time) {
	t.Helper()

	err := h.User(userID).Create(t.Context(), CreateRequestInput{
		State: state,
		Request: Request{
			Operation:   "encrypt",
			KeyLabel:    "test-key",
			Algorithm:   "A256GCM",
			RequestorIP: "127.0.0.1",
			CreatedAt:   time.Now(),
			ExpiresAt:   expiresAt,
		},
		EncryptedRequest: `{"ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)
}

// waitForResult waits for a long-poll's waiter to be woken, for up to 10 seconds
func waitForResult(t *testing.T, user UserClient, state string, waiter string) (bool, error) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	return user.WaitForResult(ctx, state, waiter)
}

// auditEvents returns the audit events of a type where the user is the actor
func auditEvents(t *testing.T, h *Host, userID string, eventType db.EventType) []db.AuditEvent {
	t.Helper()

	events, _, err := h.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: userID, EventType: eventType}, 100, "")
	require.NoError(t, err)

	return events
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

// waitForExpiry waits until the cleanup alarm expires a request, and checks that its expiry is in the audit log
func waitForExpiry(t *testing.T, h *Host, user UserClient, userID string, state string) {
	t.Helper()

	require.Eventually(t, func() bool {
		return len(requestAuditEvents(t, h, userID, db.AuditRequestExpire, state)) == 1
	}, 15*time.Second, 100*time.Millisecond, "the cleanup alarm didn't expire the request")

	req, err := user.Get(t.Context(), state)
	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, db.V2RequestStatusExpired, req.Status)
}
