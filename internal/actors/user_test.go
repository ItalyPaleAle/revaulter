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

	h, err := NewHost(NewHostOptions{
		Log: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})),
		DB:  dbConn,
	})
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
