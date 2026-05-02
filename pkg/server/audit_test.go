package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func auditByType(t *testing.T, srv *Server, userID string, eventType db.EventType) []db.AuditEvent {
	t.Helper()
	out, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{UserID: userID, EventType: eventType}, 50, "")
	require.NoError(t, err)
	return out
}

func doAuditEventsRequest(t *testing.T, client *http.Client, sessionCookie *http.Cookie, path string) (*http.Response, v2AuditEventsResponse) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://localhost:%d%s", testServerPort, path), nil)
	require.NoError(t, err)
	req.AddCookie(sessionCookie)

	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	var out v2AuditEventsResponse
	if res.StatusCode == http.StatusOK {
		err = json.NewDecoder(res.Body).Decode(&out)
		require.NoError(t, err)
	} else {
		_, err = io.Copy(io.Discard, res.Body)
		require.NoError(t, err)
	}

	return res, out
}

func TestAuditEventsRouteFiltersEventType(t *testing.T) {
	setTestConfig(t, "audit-route-filter.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, alice := seedV2SessionCookie(t, srv, "user-audit-route-alice", "Route Alice")
	_, bob := seedV2SessionCookie(t, srv, "user-audit-route-bob", "Route Bob")

	store := srv.db.AuditStore()
	_, err := store.Insert(t.Context(), db.AuditEventInput{
		EventType:   db.AuditAuthLoginFinish,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: &alice.ID,
	})
	require.NoError(t, err)
	_, err = store.Insert(t.Context(), db.AuditEventInput{
		EventType:   db.AuditAuthLogout,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: &alice.ID,
	})
	require.NoError(t, err)
	_, err = store.Insert(t.Context(), db.AuditEventInput{
		EventType:   db.AuditAuthLoginFinish,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: &bob.ID,
	})
	require.NoError(t, err)

	//nolint:bodyclose
	res, out := doAuditEventsRequest(t, client, sessionCookie, "/v2/api/audit-events?eventType=auth.login_finish")
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Len(t, out.Events, 1)
	require.Equal(t, db.AuditAuthLoginFinish, out.Events[0].EventType)
	require.NotNil(t, out.Events[0].ActorUserID)
	require.Equal(t, alice.ID, *out.Events[0].ActorUserID)

	//nolint:bodyclose
	res, out = doAuditEventsRequest(t, client, sessionCookie, "/v2/api/audit-events")
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Len(t, out.Events, 2)
}

func TestAuditEventsRouteRejectsInvalidFilters(t *testing.T) {
	setTestConfig(t, "audit-route-invalid.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, _ := seedV2SessionCookie(t, srv, "user-audit-route-invalid", "Invalid Alice")

	//nolint:bodyclose
	res, _ := doAuditEventsRequest(t, client, sessionCookie, "/v2/api/audit-events?eventType=nope")
	require.Equal(t, http.StatusBadRequest, res.StatusCode)

	//nolint:bodyclose
	res, _ = doAuditEventsRequest(t, client, sessionCookie, "/v2/api/audit-events?cursor=not-a-uuid")
	require.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestAuditRequestConfirmAndCancel(t *testing.T) {
	setTestConfig(t, "audit-confirm.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, alice := seedV2SessionCookie(t, srv, "user-audit-alice", "Audit Alice")

	clientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientJWK, err := protocolv2.ECP256PublicJWKFromECDH(clientPriv.PublicKey())
	require.NoError(t, err)

	// Create a request — audit row should land
	//nolint:bodyclose
	createRes, createOut := doRequestKeyJSON(t, client, http.MethodPost, "encrypt", alice.RequestKey, newV2CreateRequestBody("audit-label", "A256GCM", clientJWK))
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	state, _ := createOut["state"].(string)
	require.NotEmpty(t, state)

	creates := auditByType(t, srv, alice.ID, db.AuditRequestCreate)
	require.Len(t, creates, 1)
	require.Equal(t, db.AuditOutcomeSuccess, creates[0].Outcome)
	require.Equal(t, db.AuditAuthMethodRequestKey, creates[0].AuthMethod)
	require.NotNil(t, creates[0].RequestState)
	require.Equal(t, state, *creates[0].RequestState)

	// Confirm the request
	browserPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	browserJWK, err := protocolv2.ECP256PublicJWKFromECDH(browserPriv.PublicKey())
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"state":            state,
		"confirm":          true,
		"responseEnvelope": newV2ResponseEnvelope(browserJWK),
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("https://localhost:%d/v2/api/confirm", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)
	res, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	confirms := auditByType(t, srv, alice.ID, db.AuditRequestConfirm)
	require.Len(t, confirms, 1)
	require.Equal(t, db.AuditAuthMethodSession, confirms[0].AuthMethod)
	require.NotNil(t, confirms[0].RequestState)
	require.Equal(t, state, *confirms[0].RequestState)
	cancels := auditByType(t, srv, alice.ID, db.AuditRequestCancel)
	require.Empty(t, cancels)

	// Now create a second request, then cancel it
	//nolint:bodyclose
	res2, out2 := doRequestKeyJSON(t, client, http.MethodPost, "encrypt", alice.RequestKey, newV2CreateRequestBody("audit-label-2", "A256GCM", clientJWK))
	require.Equal(t, http.StatusAccepted, res2.StatusCode)
	state2, _ := out2["state"].(string)
	require.NotEmpty(t, state2)

	cancelBody, err := json.Marshal(map[string]any{"state": state2, "cancel": true})
	require.NoError(t, err)
	cancelReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("https://localhost:%d/v2/api/confirm", testServerPort), bytes.NewReader(cancelBody))
	require.NoError(t, err)
	cancelReq.Header.Set("Content-Type", "application/json")
	cancelReq.AddCookie(sessionCookie)
	cancelRes, err := client.Do(cancelReq)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, cancelRes.Body)
	cancelRes.Body.Close()
	require.Equal(t, http.StatusOK, cancelRes.StatusCode)

	cancels = auditByType(t, srv, alice.ID, db.AuditRequestCancel)
	require.Len(t, cancels, 1)
	require.NotNil(t, cancels[0].RequestState)
	require.Equal(t, state2, *cancels[0].RequestState)
}

func TestAuditRequestKeyRegenerate(t *testing.T) {
	setTestConfig(t, "audit-rk.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, alice := seedV2SessionCookie(t, srv, "user-audit-rk", "RK Alice")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("https://localhost:%d/v2/auth/regenerate-request-key", testServerPort), nil)
	require.NoError(t, err)
	req.AddCookie(sessionCookie)
	res, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	rows := auditByType(t, srv, alice.ID, db.AuditAuthRequestKeyRegen)
	require.Len(t, rows, 1)
	require.Equal(t, db.AuditOutcomeSuccess, rows[0].Outcome)
	require.NotNil(t, rows[0].ActorUserID)
	require.Equal(t, alice.ID, *rows[0].ActorUserID)
}

func TestAuditDisplayNameChange(t *testing.T) {
	setTestConfig(t, "audit-dn.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	sessionCookie, alice := seedV2SessionCookie(t, srv, "user-audit-dn", "Old Name")

	body, err := json.Marshal(map[string]any{"displayName": "New Name"})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("https://localhost:%d/v2/auth/update-display-name", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)
	res, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	rows := auditByType(t, srv, alice.ID, db.AuditAuthDisplayNameChange)
	require.Len(t, rows, 1)
}

func TestAuditRequestExpireFromBackground(t *testing.T) {
	setTestConfig(t, "audit-expire.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	// We don't start the HTTP server; just exercise the goroutine handler directly
	// First, seed a user and a pending request via the request store
	_, alice := seedV2SessionCookie(t, srv, "user-audit-expire", "Expire Alice")

	state := "expire-state-1"
	expiresAt := time.Now().Add(-1 * time.Second)
	_, err := db.ExecuteInTransaction(t.Context(), srv.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.RequestStore().CreateRequest(ctx, db.CreateRequestInput{
			State:            state,
			UserID:           alice.ID,
			Operation:        "encrypt",
			RequestorIP:      "127.0.0.1",
			KeyLabel:         "expire-label",
			Algorithm:        "A256GCM",
			CreatedAt:        time.Now().Add(-1 * time.Minute),
			ExpiresAt:        expiresAt,
			EncryptedRequest: "{}",
		})
		return struct{}{}, rErr
	})
	require.NoError(t, err)

	// Run the expiry handler synchronously
	srv.executeRequestExpiryEvent(requestExpiryEvent{
		State:  state,
		UserID: alice.ID,
		TTL:    expiresAt,
	})

	rows := auditByType(t, srv, alice.ID, db.AuditRequestExpire)
	require.Len(t, rows, 1)
	require.Equal(t, db.AuditAuthMethodSystem, rows[0].AuthMethod)
	require.NotNil(t, rows[0].RequestState)
	require.Equal(t, state, *rows[0].RequestState)
}

func TestAuditLoginFinishFailureWritesRow(t *testing.T) {
	setTestConfig(t, "audit-login-fail.db")

	srv := newTestServer(t, nil, nil, nil)
	require.NotNil(t, srv)

	startTestServer(t, srv)
	client := clientForListener(srv.appListener)

	// Bogus payload that the handler will reject
	body, err := json.Marshal(map[string]any{
		"challengeId": "non-existent-challenge",
		"credential":  json.RawMessage(`{"id":"x","rawId":"x","type":"public-key","response":{}}`),
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("https://localhost:%d/v2/auth/login/finish", testServerPort), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	require.NotEqual(t, http.StatusOK, res.StatusCode)

	// Failure rows have no actor, so query by event_type only and filter for the failure outcome
	all, _, err := srv.db.AuditStore().List(t.Context(), db.AuditFilter{EventType: db.AuditAuthLoginFinish}, 10, "")
	require.NoError(t, err)
	require.NotEmpty(t, all)
	var sawFailure bool
	for _, ev := range all {
		if ev.Outcome == db.AuditOutcomeFailure {
			sawFailure = true
			break
		}
	}
	require.True(t, sawFailure, "expected at least one auth.login_finish row with outcome=failure")
}
