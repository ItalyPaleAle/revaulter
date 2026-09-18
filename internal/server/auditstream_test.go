package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClampAuditPruneCutoff(t *testing.T) {
	now := time.Date(2026, 9, 15, 20, 0, 0, 0, time.UTC)
	horizon := now.Add(-auditRetention).Unix()
	floor := now.Add(-auditStreamRetentionGrace).Unix()

	t.Run("prunes at the regular horizon when the cursor is ahead of it", func(t *testing.T) {
		cursor := now.Add(-time.Hour).Unix()

		assert.Equal(t, horizon, clampAuditPruneCutoff(horizon, cursor, floor))
	})

	t.Run("holds rows back when the cursor is behind the horizon", func(t *testing.T) {
		cursor := now.Add(-45 * 24 * time.Hour).Unix()

		assert.Equal(t, cursor, clampAuditPruneCutoff(horizon, cursor, floor))
	})

	t.Run("releases rows at the retention grace floor", func(t *testing.T) {
		// A collector that has been down for longer than the grace period stops holding the table back
		cursor := now.Add(-200 * 24 * time.Hour).Unix()

		assert.Equal(t, floor, clampAuditPruneCutoff(horizon, cursor, floor))
	})

	t.Run("prunes at the regular horizon when the cursor has never advanced", func(t *testing.T) {
		// Without this guard a never-advanced cursor would clamp the cutoff to 0 and pruning would stop forever
		assert.Equal(t, horizon, clampAuditPruneCutoff(horizon, 0, floor))
	})
}
