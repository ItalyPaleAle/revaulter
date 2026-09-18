package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/italypaleale/go-kit/auditlogs/siem"

	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

const (
	// auditStreamRetentionGrace caps how long the audit stream can hold rows back from the retention prune
	auditStreamRetentionGrace = 90 * 24 * time.Hour
	// auditStreamHeaderPrefix is the prefix for the informational headers sent with every batch
	auditStreamHeaderPrefix = "X-Revaulter"
)

// initAuditStream creates the audit log stream shipper, when the feature is enabled
// It returns nil, with no error, when `auditStreamUrl` is empty
func (s *Server) initAuditStream(log *slog.Logger) (*siem.Shipper, error) {
	cfg := config.Get()
	if cfg.AuditStreamUrl == "" {
		return nil, nil
	}

	if s.db == nil {
		return nil, errors.New("the audit log stream requires a database connection")
	}

	shipper, err := siem.NewShipper(siem.ShipperOptions{
		Store:      s.db.AuditStreamStore(),
		URL:        cfg.AuditStreamUrl,
		Source:     buildinfo.AppName,
		InstanceID: cfg.GetInstanceID(),
		Format:     siem.Format(cfg.AuditStreamFormat),

		Key:                 cfg.AuditStreamKey,
		AuthorizationHeader: cfg.AuditStreamAuthHeader,
		HeaderPrefix:        auditStreamHeaderPrefix,
		UserAgent:           buildinfo.AppName + "/" + buildinfo.AppVersion,

		BatchSize:     cfg.AuditStreamBatchSize,
		FlushInterval: cfg.AuditStreamFlushInterval,

		EventTypes:      cfg.AuditStreamEventTypes,
		KnownEventTypes: db.AllEventTypes(),

		// A collector is almost always an internal host, and there is no path from user input to the destination: the URL comes from the operator's own configuration and redirects are never followed
		AllowPrivateIPs: true,

		Metrics: s.metrics.AuditStream(),
		Logger:  log.With(slog.String("component", "auditstream")),
	})
	if err != nil {
		return nil, err
	}

	return shipper, nil
}

// startAuditStream seeds the cursor and runs the shipper until ctx is canceled
func (s *Server) startAuditStream(ctx context.Context) error {
	log := logging.LogFromContext(ctx)

	// Seed the cursor to the current high-water mark, so pre-existing history is never shipped
	// This is a no-op once the key exists, which is what makes a disable/re-enable cycle resume from the stored cursor rather than skipping everything written while the feature was off
	pos, seeded, err := s.db.AuditStreamStore().BootstrapToHead(ctx)
	if err != nil {
		return fmt.Errorf("failed to bootstrap the audit log stream cursor: %w", err)
	}

	if seeded {
		log.InfoContext(ctx, "Audit log stream cursor seeded at the current high-water mark; existing events will not be streamed",
			slog.Int64("seq", pos.Seq),
			slog.String("xactId", pos.XactID),
		)
	}

	s.wg.Go(func() {
		_ = s.auditStream.Run(ctx)
	})

	return nil
}

// nudgeAuditStream wakes the shipper so a freshly-written event does not have to wait out the flush interval
func (s *Server) nudgeAuditStream() {
	if s.auditStream == nil {
		return
	}

	s.auditStream.Nudge()
}

// auditPruneCutoff returns the created_at threshold for the recurring audit prune
func (s *Server) auditPruneCutoff(ctx context.Context, now time.Time) int64 {
	horizon := now.Add(-auditRetention).Unix()
	if s.auditStream == nil {
		return horizon
	}

	pos, err := s.db.AuditStreamStore().GetPosition(ctx)
	if err != nil {
		// Without a readable cursor there is nothing to clamp against
		// Pruning at the usual horizon is the safer failure: a cursor that reads as zero would stop pruning forever
		logging.LogFromContext(ctx).WarnContext(ctx, "Failed to read the audit log stream cursor while pruning; using the regular retention horizon",
			slog.Any("error", err),
		)
		return horizon
	}

	cutoff := clampAuditPruneCutoff(horizon, pos.EventCreatedAt, now.Add(-auditStreamRetentionGrace).Unix())
	if cutoff < horizon {
		logging.LogFromContext(ctx).WarnContext(ctx, "The audit log stream is behind the retention horizon; holding rows back from the prune",
			slog.Int64("cutoffUnix", cutoff),
			slog.Int64("horizonUnix", horizon),
		)
	}

	return cutoff
}

// clampAuditPruneCutoff holds the prune back to what the stream has shipped, without letting a dead collector grow the table without bound
func clampAuditPruneCutoff(horizon int64, cursorCreatedAt int64, floor int64) int64 {
	// A cursor that has never advanced past an event carries no usable timestamp
	if cursorCreatedAt <= 0 {
		return horizon
	}

	// Never delete past what has been shipped …
	cutoff := min(horizon, cursorCreatedAt)

	// … but do not let a dead collector grow the table without bound
	return max(cutoff, floor)
}
