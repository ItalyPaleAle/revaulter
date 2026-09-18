package db

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/italypaleale/go-kit/auditlogs/siem"
	"github.com/stretchr/testify/require"
)

// shipperTestCollector records everything a shipper delivers to it
type shipperTestCollector struct {
	*httptest.Server

	mu     sync.Mutex
	bodies []string
}

func newShipperTestCollector(t *testing.T) *shipperTestCollector {
	t.Helper()

	c := &shipperTestCollector{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		c.mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(c.Close)

	return c
}

// delivered returns every event id the collector has seen, in delivery order
func (c *shipperTestCollector) delivered() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ids []string
	for _, body := range c.bodies {
		for line := range strings.SplitSeq(strings.TrimSuffix(body, "\n"), "\n") {
			if line == "" {
				continue
			}

			// The id is enough for the assertions here, and pulling it out by substring keeps the test independent of the payload's field order
			_, rest, found := strings.Cut(line, `"id":"`)
			if !found {
				continue
			}

			id, _, found := strings.Cut(rest, `"`)
			if !found {
				continue
			}

			ids = append(ids, id)
		}
	}

	return ids
}

// runTestShipper starts a shipper against the given store and returns a function that stops it
func runTestShipper(t *testing.T, store siem.Store, url string) func() {
	t.Helper()

	shipper, err := siem.NewShipper(siem.ShipperOptions{
		Store:           store,
		URL:             url,
		Source:          "revaulter",
		InstanceID:      "test",
		AllowPrivateIPs: true,
		BatchSize:       10,
		FlushInterval:   time.Second,
		Logger:          slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = shipper.Run(ctx)
	}()

	return func() {
		cancel()
		<-done
	}
}

func TestAuditStreamEndToEnd(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		store := conn.AuditStreamStore()
		collector := newShipperTestCollector(t)

		// Two events already in the table when the feature is turned on
		preexisting := []string{
			insertAuditEvent(t, conn, AuditAuthLoginFinish),
			insertAuditEvent(t, conn, AuditAuthLogout),
		}

		_, seeded, err := store.BootstrapToHead(ctx)
		require.NoError(t, err)
		require.True(t, seeded)

		stop := runTestShipper(t, store, collector.URL)

		fresh := []string{
			insertAuditEvent(t, conn, AuditRequestCreate),
			insertAuditEvent(t, conn, AuditRequestConfirm),
		}

		require.Eventually(t, func() bool {
			return len(collector.delivered()) >= len(fresh)
		}, 20*time.Second, 20*time.Millisecond, "timed out waiting for the events to be delivered")

		stop()

		// Only events created after the feature was enabled are ever POSTed
		delivered := collector.delivered()
		require.Equal(t, fresh, delivered)
		for _, id := range preexisting {
			require.NotContains(t, delivered, id)
		}

		// The cursor is durable, so a restart resumes from it rather than re-seeding to head or re-sending what already went out
		duringDowntime := insertAuditEvent(t, conn, AuditSigningKeyCreate)

		stop = runTestShipper(t, store, collector.URL)
		t.Cleanup(stop)

		require.Eventually(t, func() bool {
			return len(collector.delivered()) >= len(fresh)+1
		}, 20*time.Second, 20*time.Millisecond, "timed out waiting for the event written while the shipper was down")

		require.Equal(t, append(append([]string{}, fresh...), duringDowntime), collector.delivered())
	})
}
