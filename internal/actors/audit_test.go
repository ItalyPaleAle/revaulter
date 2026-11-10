package actors

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
)

func TestStreamPruneCutoff(t *testing.T) {
	now := time.Date(2026, 9, 15, 20, 0, 0, 0, time.UTC)
	horizon := now.Add(-AuditRetention).Unix()
	floor := now.Add(-auditStreamRetentionGrace).Unix()

	t.Run("prunes at the regular horizon when the cursor is ahead of it", func(t *testing.T) {
		cursor := now.Add(-time.Hour).Unix()

		assert.Equal(t, horizon, streamPruneCutoff(horizon, cursor, floor))
	})

	t.Run("holds rows back when the cursor is behind the horizon", func(t *testing.T) {
		cursor := now.Add(-45 * 24 * time.Hour).Unix()

		assert.Equal(t, cursor, streamPruneCutoff(horizon, cursor, floor))
	})

	t.Run("releases rows at the retention grace floor", func(t *testing.T) {
		// A collector that has been down for longer than the grace period stops holding the table back
		cursor := now.Add(-200 * 24 * time.Hour).Unix()

		assert.Equal(t, floor, streamPruneCutoff(horizon, cursor, floor))
	})

	t.Run("prunes at the regular horizon when the cursor has never advanced", func(t *testing.T) {
		// Without this check, a cursor that never advanced would move the cutoff to 0, and pruning would stop forever
		assert.Equal(t, horizon, streamPruneCutoff(horizon, 0, floor))
	})
}

func TestPruneAuditLog(t *testing.T) {
	const userID = "user-audit-prune"
	h := newTestHost(t, newTestDB(t, userID), ":memory:")

	auditID := insertTestAuditEvent(t, h, userID)
	err := h.db.RequestPayloadStore().Insert(t.Context(), db.RequestPayload{
		State:            "prune-state",
		UserID:           userID,
		ExpiresAt:        time.Now(),
		EncryptedRequest: `{}`,
	})
	require.NoError(t, err)

	// Nothing is old enough yet
	h.pruneAuditLog(t.Context(), time.Now())
	assert.Len(t, auditEvents(t, h, userID, db.AuditAuthLogout), 1)
	payload, err := h.db.RequestPayloadStore().Get(t.Context(), "prune-state", userID)
	require.NoError(t, err)
	assert.NotNil(t, payload)

	// Past the retention period, both the event and the envelope are removed
	h.pruneAuditLog(t.Context(), time.Now().Add(AuditRetention+time.Hour))
	events := auditEvents(t, h, userID, db.AuditAuthLogout)
	for _, e := range events {
		assert.NotEqual(t, auditID, e.ID)
	}
	payload, err = h.db.RequestPayloadStore().Get(t.Context(), "prune-state", userID)
	require.NoError(t, err)
	assert.Nil(t, payload)
}

func TestAuditStream(t *testing.T) {
	const userID = "user-audit-stream"

	t.Run("one replica", func(t *testing.T) {
		collector := newTestAuditCollector(t)
		h := newTestHost(t, newTestDB(t, userID), ":memory:", collector.config())

		// The long flush interval means the event is shipped quickly only if the nudge wakes the stream
		waitForAuditStream(t, h)
		eventID := insertTestAuditEvent(t, h, userID)
		h.NudgeAuditStream()

		require.Eventually(t, func() bool {
			return collector.has(eventID)
		}, 10*time.Second, 50*time.Millisecond, "the event was not shipped")
	})

	t.Run("two replicas", func(t *testing.T) {
		collector := newTestAuditCollector(t)
		dbConn := newTestDB(t, userID)
		francisDSN := filepath.Join(t.TempDir(), "francis.db")
		hostA := newTestHost(t, dbConn, francisDSN, collector.config())
		hostB := newTestHost(t, dbConn, francisDSN, collector.config())

		// Only one replica runs the stream, and the other one forwards its nudges
		require.Eventually(t, func() bool {
			return hostA.auditStream.nudge() || hostB.auditStream.nudge()
		}, 10*time.Second, 50*time.Millisecond, "the audit log stream did not start")
		assert.False(t, hostA.auditStream.nudge() && hostB.auditStream.nudge(), "the audit log stream runs on both replicas")
		waitForAuditCursor(t, hostA)

		for _, h := range []*Host{hostA, hostB} {
			eventID := insertTestAuditEvent(t, h, userID)
			h.NudgeAuditStream()

			require.Eventually(t, func() bool {
				return collector.has(eventID)
			}, 10*time.Second, 50*time.Millisecond, "the event was not shipped")
		}
	})
}

// waitForAuditStream waits until the audit log stream runs on the host
func waitForAuditStream(t *testing.T, h *Host) {
	t.Helper()

	require.NotNil(t, h.auditStream)
	require.Eventually(t, h.auditStream.nudge, 10*time.Second, 50*time.Millisecond, "the audit log stream did not start")
	waitForAuditCursor(t, h)
}

// waitForAuditCursor waits until the audit log stream has seeded its cursor
// The stream never ships events written before that
func waitForAuditCursor(t *testing.T, h *Host) {
	t.Helper()

	require.Eventually(t, func() bool {
		_, err := h.db.AuditStreamStore().GetPosition(t.Context())
		return err == nil
	}, 10*time.Second, 50*time.Millisecond, "the audit log stream cursor was not seeded")
}

// insertTestAuditEvent writes an audit event where the user is the actor, and returns its ID
func insertTestAuditEvent(t *testing.T, h *Host, userID string) string {
	t.Helper()

	rec, err := h.db.AuditStore().Insert(t.Context(), db.AuditEventInput{
		EventType:   db.AuditAuthLogout,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: &userID,
	})
	require.NoError(t, err)

	return rec.ID
}

// testAuditCollector records the bodies the audit log stream delivers to it
type testAuditCollector struct {
	*httptest.Server

	lock   sync.Mutex
	bodies []string
}

func newTestAuditCollector(t *testing.T) *testAuditCollector {
	t.Helper()

	c := &testAuditCollector{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		c.lock.Lock()
		c.bodies = append(c.bodies, string(body))
		c.lock.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.Close)

	return c
}

// config returns the configuration that enables the audit log stream, with a flush interval long enough that only nudges ship events within a test
func (c *testAuditCollector) config() map[string]any {
	return map[string]any{
		"auditStreamUrl":           c.URL,
		"auditStreamFormat":        "ndjson",
		"auditStreamBatchSize":     10,
		"auditStreamFlushInterval": "5m",
	}
}

// has returns true if the collector received the event
func (c *testAuditCollector) has(eventID string) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	for _, body := range c.bodies {
		if strings.Contains(body, `"id":"`+eventID+`"`) {
			return true
		}
	}

	return false
}
