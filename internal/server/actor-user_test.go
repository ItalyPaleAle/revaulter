package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/italypaleale/francis/actor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/bufconn"
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
			Requests: map[string]*userRequest{
				"a": {Status: db.V2RequestStatusPending, ExpiresAt: now.Add(time.Minute)},
			},
			Bell: "bell",
		}
		assert.Equal(t, now.Add(time.Minute+requestExpiryGrace), st.nextCleanup(sessionTimeout))
	})

	t.Run("finished request is due after the removal grace period", func(t *testing.T) {
		st := userActorState{
			Requests: map[string]*userRequest{
				"a": {Status: db.V2RequestStatusCompleted, ExpiresAt: now.Add(time.Minute)},
			},
		}
		assert.Equal(t, now.Add(time.Minute+requestRemoveGrace), st.nextCleanup(sessionTimeout))
	})

	t.Run("earliest due time wins", func(t *testing.T) {
		st := userActorState{
			Requests: map[string]*userRequest{
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
		Requests: map[string]*userRequest{
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
		Requests: map[string]*userRequest{
			"a": {Status: db.V2RequestStatusPending, Waiter: "w1"},
		},
		Bell: "bell",
	}

	cloned := st.clone()
	cloned.Requests["a"].Waiter = "w2"
	cloned.Requests["b"] = &userRequest{}
	cloned.Bell = "other"

	assert.Equal(t, "w1", st.Requests["a"].Waiter)
	assert.Len(t, st.Requests, 1)
	assert.Equal(t, "bell", st.Bell)
}

func TestResultToken(t *testing.T) {
	t.Run("embeds the user ID", func(t *testing.T) {
		for _, userID := range []string{"0b5e5d0c-8c1f-4c6a-9b0e-5f2b6f1f4e1a", "user_with_underscores", "u"} {
			token, hash, err := newResultToken(userID)
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(token, resultTokenPrefix+userID+"_"))
			require.True(t, resultTokenMatches(token, hash))

			parsed, ok := parseResultToken(token)
			require.True(t, ok)
			assert.Equal(t, userID, parsed)
		}
	})

	t.Run("rejects malformed tokens", func(t *testing.T) {
		for _, token := range []string{
			"",
			"rvr_",
			"rvr_abc",
			"rvr__abc",
			"rvr_user_",
			"xyz_user_abc",
			"rvr_a/b_abc",
			"rvr_" + strings.Repeat("u", maxResultTokenUserIDLength+1) + "_abc",
		} {
			_, ok := parseResultToken(token)
			assert.False(t, ok, token)
		}
	})
}

func TestUserActorRequests(t *testing.T) {
	setTestConfig(t, "user-actor-requests.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	startTestServer(t, srv)

	_, user := seedV2SessionCookie(t, srv, "user-actor-requests", "Actor User")

	t.Run("confirm and collect", func(t *testing.T) {
		const state = "confirm-collect"
		seedTestRequest(t, srv, user.ID, state, time.Now().Add(10*time.Minute))

		res, err := invokeUserActor[userChangeRes](t.Context(), srv, user.ID, userMethodConfirm, userChangeReq{
			State:           state,
			EncryptedResult: `{"ciphertext":"cmVz"}`,
		})
		require.NoError(t, err)
		require.Empty(t, res.Error)
		assert.Equal(t, db.V2RequestStatusCompleted, res.Request.Status)

		// A second confirm is rejected
		res, err = invokeUserActor[userChangeRes](t.Context(), srv, user.ID, userMethodConfirm, userChangeReq{
			State:           state,
			EncryptedResult: `{"ciphertext":"cmVz"}`,
		})
		require.NoError(t, err)
		assert.Equal(t, userActorErrNotModifiable, res.Error)

		// Collecting returns the result once, then removes the request and its payload
		collected, err := invokeUserActor[userCollectRes](t.Context(), srv, user.ID, userMethodCollect, userStateReq{State: state})
		require.NoError(t, err)
		require.True(t, collected.Found)
		assert.Equal(t, db.V2RequestStatusCompleted, collected.Status)
		assert.JSONEq(t, `{"ciphertext":"cmVz"}`, collected.EncryptedResult)

		collected, err = invokeUserActor[userCollectRes](t.Context(), srv, user.ID, userMethodCollect, userStateReq{State: state})
		require.NoError(t, err)
		assert.False(t, collected.Found)

		payload, err := srv.db.RequestPayloadStore().Get(t.Context(), state, user.ID)
		require.NoError(t, err)
		assert.Nil(t, payload)
	})

	t.Run("confirm is rejected past the deadline", func(t *testing.T) {
		const state = "confirm-overdue"
		seedTestRequest(t, srv, user.ID, state, time.Now().Add(-time.Second))

		res, err := invokeUserActor[userChangeRes](t.Context(), srv, user.ID, userMethodConfirm, userChangeReq{
			State:           state,
			EncryptedResult: `{}`,
		})
		require.NoError(t, err)
		assert.Equal(t, userActorErrNotModifiable, res.Error)

		// The request is reported as expired even before the cleanup alarm runs
		rec := getTestRequest(t, srv, user.ID, state)
		require.NotNil(t, rec)
		assert.Equal(t, db.V2RequestStatusExpired, rec.Status)
	})

	t.Run("unknown requests can't be changed", func(t *testing.T) {
		res, err := invokeUserActor[userChangeRes](t.Context(), srv, user.ID, userMethodCancel, userChangeReq{State: "missing"})
		require.NoError(t, err)
		assert.Equal(t, userActorErrNotModifiable, res.Error)

		sub, err := invokeUserActor[userSubscribeRes](t.Context(), srv, user.ID, userMethodSubscribe, userStateReq{State: "missing"})
		require.NoError(t, err)
		assert.False(t, sub.Found)
	})

	t.Run("create is idempotent", func(t *testing.T) {
		const state = "create-twice"
		seedTestRequest(t, srv, user.ID, state, time.Now().Add(10*time.Minute))
		seedTestRequest(t, srv, user.ID, state, time.Now().Add(10*time.Minute))

		list, err := peekUserActor[userListRes](t.Context(), srv, user.ID, userMethodList, nil)
		require.NoError(t, err)
		var n int
		for _, item := range list.Items {
			if item.State == state {
				n++
			}
		}
		assert.Equal(t, 1, n)
	})
}

func TestUserActorLimitsPendingRequests(t *testing.T) {
	setTestConfig(t, "user-actor-limit.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)
	startTestServer(t, srv)

	_, user := seedV2SessionCookie(t, srv, "user-actor-limit", "Limit User")

	for i := range maxPendingRequestsPerUser {
		seedTestRequest(t, srv, user.ID, "limit-"+strconv.Itoa(i), time.Now().Add(10*time.Minute))
	}

	create := func(state string) userCreateRes {
		res, err := invokeUserActor[userCreateRes](t.Context(), srv, user.ID, userMethodCreate, userCreateReq{
			State: state,
			Request: userRequest{
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			EncryptedRequest: `{}`,
		})
		require.NoError(t, err)
		return res
	}

	assert.Equal(t, userActorErrTooManyPending, create("limit-over").Error)

	// Finished requests don't count
	canceled, err := invokeUserActor[userChangeRes](t.Context(), srv, user.ID, userMethodCancel, userChangeReq{State: "limit-0"})
	require.NoError(t, err)
	require.Empty(t, canceled.Error)

	assert.Empty(t, create("limit-over").Error)
}

func TestUserActorCleanup(t *testing.T) {
	t.Run("expires pending requests past their deadline", func(t *testing.T) {
		setTestConfig(t, "user-actor-cleanup-expire.db")
		srv := newTestServer(t, nil, nil, nil)
		startTestServer(t, srv)
		_, user := seedV2SessionCookie(t, srv, "user-cleanup-expire", "Cleanup User")

		const state = "cleanup-expire"
		seedTestRequest(t, srv, user.ID, state, time.Now().Add(-10*time.Second))

		require.Eventually(t, func() bool {
			return len(auditByType(t, srv, user.ID, db.AuditRequestExpire)) == 1
		}, 10*time.Second, 50*time.Millisecond, "the request was not expired")

		// The request is kept, so the caller can still learn that it expired
		var st userActorState
		err := srv.francis.Service().GetState(t.Context(), actorTypeUser, user.ID, &st)
		require.NoError(t, err)
		require.NotNil(t, st.Requests[state])
		assert.Equal(t, db.V2RequestStatusExpired, st.Requests[state].Status)

		payload, err := srv.db.RequestPayloadStore().Get(t.Context(), state, user.ID)
		require.NoError(t, err)
		assert.NotNil(t, payload)
	})

	t.Run("removes finished requests and their payloads", func(t *testing.T) {
		setTestConfig(t, "user-actor-cleanup-remove.db")
		srv := newTestServer(t, nil, nil, nil)
		startTestServer(t, srv)
		_, user := seedV2SessionCookie(t, srv, "user-cleanup-remove", "Cleanup User")

		// This request is expired and removed in the same run, as happens after downtime
		const state = "cleanup-remove"
		seedTestRequest(t, srv, user.ID, state, time.Now().Add(-requestRemoveGrace-time.Minute))

		require.Eventually(t, func() bool {
			return getTestRequest(t, srv, user.ID, state) == nil
		}, 10*time.Second, 50*time.Millisecond, "the request was not removed")

		assert.Len(t, auditByType(t, srv, user.ID, db.AuditRequestExpire), 1)

		payload, err := srv.db.RequestPayloadStore().Get(t.Context(), state, user.ID)
		require.NoError(t, err)
		assert.Nil(t, payload)
	})

	t.Run("re-arms for the next request", func(t *testing.T) {
		setTestConfig(t, "user-actor-cleanup-rearm.db")
		srv := newTestServer(t, nil, nil, nil)
		startTestServer(t, srv)
		_, user := seedV2SessionCookie(t, srv, "user-cleanup-rearm", "Cleanup User")

		// The first request is due right away, while the second one is not overdue when the first run happens
		seedTestRequest(t, srv, user.ID, "rearm-first", time.Now().Add(-10*time.Second))
		seedTestRequest(t, srv, user.ID, "rearm-second", time.Now().Add(2*time.Second))

		require.Eventually(t, func() bool {
			return len(auditByType(t, srv, user.ID, db.AuditRequestExpire)) == 1
		}, 10*time.Second, 50*time.Millisecond, "the first request was not expired")

		alarm, err := srv.francis.GetAlarm(t.Context(), actorTypeUser, user.ID, userActorCleanupAlarm)
		require.NoError(t, err)
		assert.True(t, alarm.DueTime.After(time.Now()), "the alarm must be set for the second request")

		require.Eventually(t, func() bool {
			return len(auditByType(t, srv, user.ID, db.AuditRequestExpire)) == 2
		}, 15*time.Second, 50*time.Millisecond, "the second request was not expired")
	})

	t.Run("deletes the state once only the bell is left", func(t *testing.T) {
		setTestConfig(t, "user-actor-cleanup-bell.db", map[string]any{
			"sessionTimeout": time.Second,
		})
		srv := newTestServer(t, nil, nil, nil)
		startTestServer(t, srv)
		_, user := seedV2SessionCookie(t, srv, "user-cleanup-bell", "Cleanup User")

		seedTestRequest(t, srv, user.ID, "bell-request", time.Now().Add(-requestRemoveGrace-time.Minute))

		require.Eventually(t, func() bool {
			var st userActorState
			err := srv.francis.Service().GetState(t.Context(), actorTypeUser, user.ID, &st)
			return errors.Is(err, actor.ErrStateNotFound)
		}, 15*time.Second, 50*time.Millisecond, "the state was not deleted")

		_, err := srv.francis.GetAlarm(t.Context(), actorTypeUser, user.ID, userActorCleanupAlarm)
		require.ErrorIs(t, err, actor.ErrAlarmNotFound)
	})
}

func TestUserActorAcrossReplicas(t *testing.T) {
	setTestConfig(t, "user-actor-replicas.db")

	// Two replicas share the main database and a Francis SQLite file, and reach each other on their own peer addresses
	francisDSN := filepath.Join(t.TempDir(), "francis.db")
	srvA := newTestReplica(t, db.NewTestDatabaseForServerTests(t), francisDSN)
	err := db.RunMigrations(t.Context(), srvA.db, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	srvB := newTestReplica(t, srvA.db, francisDSN)

	startTestServer(t, srvA)
	startTestServer(t, srvB)
	clientB := clientForListener(srvB.appListener)

	_, user := seedV2SessionCookie(t, srvA, "user-replicas", "Replica User")

	// Create a request through replica A
	const state = "replica-state"
	seedTestRequest(t, srvA, user.ID, state, time.Now().Add(10*time.Minute))

	// Replica B sees the request, wherever the actor is placed
	rec := getTestRequest(t, srvB, user.ID, state)
	require.NotNil(t, rec)
	assert.Equal(t, db.V2RequestStatusPending, rec.Status)

	// Long-poll for the result on replica B
	type pollResult struct {
		status int
		body   map[string]any
		err    error
	}
	resCh := make(chan pollResult, 1)
	go func() {
		url := fmt.Sprintf("https://localhost:%d/v2/request/result/%s", testServerPort, state)
		req, rErr := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if rErr != nil {
			resCh <- pollResult{err: rErr}
			return
		}
		req.Header.Set("Authorization", "Bearer "+user.RequestKey)

		res, dErr := clientB.Do(req)
		if dErr != nil {
			resCh <- pollResult{err: dErr}
			return
		}
		defer func() {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}()

		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		resCh <- pollResult{status: res.StatusCode, body: body}
	}()

	require.Eventually(t, func() bool {
		r := getTestRequest(t, srvA, user.ID, state)
		return r != nil && r.Waiter != ""
	}, 5*time.Second, 10*time.Millisecond, "waiter was not registered")

	// Confirm through replica A, which must wake the long-poll on replica B
	envJSON, err := json.Marshal(newV2ResponseEnvelope(protocolv2.ECP256PublicJWK{Kty: "EC", Crv: "P-256", X: "x", Y: "y"}))
	require.NoError(t, err)
	res, err := invokeUserActor[userChangeRes](t.Context(), srvA, user.ID, userMethodConfirm, userChangeReq{
		State:           state,
		EncryptedResult: string(envJSON),
	})
	require.NoError(t, err)
	require.Empty(t, res.Error)

	select {
	case r := <-resCh:
		require.NoError(t, r.err)
		require.Equal(t, http.StatusOK, r.status, r.body)
		assert.Equal(t, true, r.body["done"])
		assert.NotNil(t, r.body["responseEnvelope"])
	case <-time.After(10 * time.Second):
		t.Fatal("the long-poll on replica B was not woken by the confirm on replica A")
	}
}

// newTestReplica creates a server that uses the given database and Francis store, with its own peer address
func newTestReplica(t *testing.T, dbConn *db.DB, francisDSN string) *Server {
	t.Helper()

	cert, key, err := getSelfSignedTLSCredentials()
	require.NoError(t, err, "cannot get TLS credentials")

	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"tLSCertPEM":         cert,
			"tLSKeyPEM":          key,
			"francisPeerAddress": freeUDPAddress(t),
			"francisDatabaseDSN": francisDSN,
		}),
	)

	log := slog.New(slog.NewTextHandler(os.Stdout, nil)).With(slog.String("app", "test"))
	srv, err := NewServer(NewServerOpts{
		Log: log,
		DB:  dbConn,
	})
	require.NoError(t, err)

	srv.appListener = bufconn.Listen(bufconnBufSize)

	return srv
}
