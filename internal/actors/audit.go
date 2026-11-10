package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/italypaleale/francis/actor"
	"github.com/italypaleale/go-kit/auditlogs/siem"

	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/metrics"
)

const (
	// actorTypeAudit is the singleton actor that prunes the audit log and runs the audit log stream
	actorTypeAudit = "revaulter.audit"
	// auditActorPruneAlarm is the name of the recurring alarm that prunes the audit log and the envelopes of expired requests
	auditActorPruneAlarm = "prune"
	// auditActorPruneInterval is how often the prune runs, as an ISO8601 duration
	auditActorPruneInterval = "PT24H"
	// auditActorKeepaliveAlarm is the name of the recurring alarm that keeps the actor active while the audit log stream is enabled
	// If the host running the actor goes away, the next tick activates it on another host, which resumes the stream
	auditActorKeepaliveAlarm = "keepalive"
	// auditActorKeepaliveInterval is how often the keepalive alarm fires, as an ISO8601 duration
	auditActorKeepaliveInterval = "PT1M"
	// auditMethodNudge is the method that wakes the audit log stream
	auditMethodNudge = "nudge"

	// AuditRetention is how long audit events are kept before the recurring prune deletes them
	AuditRetention = 30 * 24 * time.Hour
	// auditStreamRetentionGrace caps how long the audit log stream can hold rows back from the retention prune
	auditStreamRetentionGrace = 90 * 24 * time.Hour
	// auditStreamHeaderPrefix is the prefix for the informational headers sent with every batch
	auditStreamHeaderPrefix = "X-Revaulter"
)

// auditActor is the revaulter.audit singleton actor
// While it's active on a host, that host runs the audit log stream, so only one replica ships events at a time
// It has no state: the stream's cursor is in the main database
type auditActor struct {
	host   *Host
	log    *slog.Logger
	client actor.Client[struct{}]
}

// newAuditActor is the factory for the revaulter.audit actor
func (h *Host) newAuditActor(actorID string, service *actor.Service) actor.Actor {
	return &auditActor{
		host:   h,
		log:    h.log.With(slog.String("actorType", actorTypeAudit)),
		client: actor.NewActorClient[struct{}](actorTypeAudit, actorID, service),
	}
}

// Bootstrap implements actor.ActorBootstrapper
// Every host runs it once it starts, so it must be idempotent
func (a *auditActor) Bootstrap(ctx context.Context, _ actor.Envelope) error {
	// Prune when a host starts, and then once a day
	err := a.client.SetAlarm(ctx, auditActorPruneAlarm, actor.AlarmProperties{
		DueTime:  time.Now(),
		Interval: auditActorPruneInterval,
	})
	if err != nil {
		return fmt.Errorf("failed to set prune alarm: %w", err)
	}

	if a.host.auditStream == nil {
		// The audit log stream is disabled, so the actor doesn't need to stay active
		err = a.client.DeleteAlarm(ctx, auditActorKeepaliveAlarm)
		if err != nil && !errors.Is(err, actor.ErrAlarmNotFound) {
			return fmt.Errorf("failed to delete keepalive alarm: %w", err)
		}
		return nil
	}

	err = a.client.SetAlarm(ctx, auditActorKeepaliveAlarm, actor.AlarmProperties{
		DueTime:  time.Now().Add(time.Minute),
		Interval: auditActorKeepaliveInterval,
	})
	if err != nil {
		return fmt.Errorf("failed to set keepalive alarm: %w", err)
	}

	a.host.auditStream.start()

	return nil
}

// Peek implements actor.ActorPeek
// Nudging doesn't change the actor's state, so it can run alongside other calls
func (a *auditActor) Peek(_ context.Context, method string, _ actor.Envelope) (any, error) {
	if method != auditMethodNudge {
		return nil, fmt.Errorf("unsupported method '%s'", method)
	}

	if a.host.auditStream != nil {
		a.host.auditStream.start()
		a.host.auditStream.nudge()
	}

	return nil, nil
}

// Alarm implements actor.ActorAlarm
func (a *auditActor) Alarm(ctx context.Context, name string, _ actor.Envelope) error {
	switch name {
	case auditActorKeepaliveAlarm:
		if a.host.auditStream == nil {
			// The audit log stream was disabled after the alarm was set
			err := a.client.DeleteAlarm(ctx, auditActorKeepaliveAlarm)
			if err != nil && !errors.Is(err, actor.ErrAlarmNotFound) {
				a.log.WarnContext(ctx, "Failed to delete keepalive alarm", slog.Any("error", err))
			}
			return nil
		}

		a.host.auditStream.start()

	case auditActorPruneAlarm:
		if a.host.auditStream != nil {
			a.host.auditStream.start()
		}

		// Errors are logged only, so the recurring alarm is never dropped, and the next prune tries again
		a.host.pruneAuditLog(ctx, time.Now())

	default:
		a.log.WarnContext(ctx, "Ignoring unknown alarm", slog.String("alarm", name))
	}

	return nil
}

// Deactivate implements actor.ActorDeactivate
// It runs when the host stops, so the stream can resume on the host that activates the actor next
func (a *auditActor) Deactivate(_ context.Context) error {
	if a.host.auditStream != nil {
		a.host.auditStream.stop()
	}

	return nil
}

// pruneAuditLog deletes the audit events past the retention period, and the envelopes of requests that the revaulter.user actors missed
func (h *Host) pruneAuditLog(ctx context.Context, now time.Time) {
	// The cutoff is the retention horizon, held back so the prune never deletes events that the audit log stream hasn't shipped yet
	threshold := h.auditPruneCutoff(ctx, now)
	removed, err := h.db.AuditStore().PruneBefore(ctx, threshold)
	if err != nil {
		h.log.WarnContext(ctx, "Audit log prune failed", slog.Any("error", err))
	} else if removed > 0 {
		h.log.InfoContext(ctx, "Audit log pruned",
			slog.Int64("removed", removed),
			slog.Int64("thresholdUnix", threshold),
		)
	}

	// Remove the envelopes of requests that the revaulter.user actors missed, for example after their state was lost
	removed, err = h.db.RequestPayloadStore().DeleteExpired(ctx, now.Add(-RequestRemoveGrace))
	if err != nil {
		h.log.WarnContext(ctx, "Request payload prune failed", slog.Any("error", err))
	} else if removed > 0 {
		h.log.InfoContext(ctx, "Expired request payloads pruned", slog.Int64("removed", removed))
	}
}

// auditPruneCutoff returns the created_at threshold for the recurring audit prune
func (h *Host) auditPruneCutoff(ctx context.Context, now time.Time) int64 {
	horizon := now.Add(-AuditRetention).Unix()
	if h.auditStream == nil {
		return horizon
	}

	pos, err := h.db.AuditStreamStore().GetPosition(ctx)
	if err != nil {
		// Without a readable cursor, there's nothing to compare the horizon with
		// Pruning at the usual horizon is the safer failure: a cursor that reads as zero would stop pruning forever
		h.log.WarnContext(ctx, "Failed to read the audit log stream cursor while pruning; using the regular retention horizon",
			slog.Any("error", err),
		)
		return horizon
	}

	cutoff := streamPruneCutoff(horizon, pos.EventCreatedAt, now.Add(-auditStreamRetentionGrace).Unix())
	if cutoff < horizon {
		h.log.WarnContext(ctx, "The audit log stream is behind the retention horizon; holding rows back from the prune",
			slog.Int64("cutoffUnix", cutoff),
			slog.Int64("horizonUnix", horizon),
		)
	}

	return cutoff
}

// streamPruneCutoff returns the prune cutoff that keeps the events the stream hasn't shipped yet, but it never goes back further than floor
// This way, a collector that stays down can't make the table grow forever
func streamPruneCutoff(horizon int64, cursorCreatedAt int64, floor int64) int64 {
	// A cursor that has never advanced past an event carries no usable timestamp
	if cursorCreatedAt <= 0 {
		return horizon
	}

	// Never delete past what has been shipped …
	cutoff := min(horizon, cursorCreatedAt)

	// … but do not let a dead collector grow the table without bound
	return max(cutoff, floor)
}

// NudgeAuditStream wakes the audit log stream, so freshly written audit events don't have to wait out the flush interval
// It never blocks: when the stream runs on another host, the nudge is sent in background, and nudges that arrive in the meantime are coalesced
func (h *Host) NudgeAuditStream() {
	if h.auditStream == nil {
		return
	}

	// When the stream runs on this host, wake it directly
	if h.auditStream.nudge() {
		return
	}

	select {
	case h.auditNudges <- struct{}{}:
	default:
		// A nudge is already pending
	}
}

// runAuditNudger sends the nudges for an audit log stream that runs on another host, until ctx is canceled
// It sends at most one nudge per auditNudgeMinInterval, so a burst of audit events results in a single call
func (h *Host) runAuditNudger(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.auditNudges:
		}

		// The stream may have moved to this host since the nudge was queued
		if !h.auditStream.nudge() {
			nudgeCtx, nudgeCancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := peek[struct{}](nudgeCtx, h, actorTypeAudit, actor.SingletonActorID, auditMethodNudge, nil)
			nudgeCancel()
			if err != nil && ctx.Err() == nil {
				// The stream still ships the event at the next flush
				h.log.DebugContext(ctx, "Failed to nudge the audit log stream", slog.Any("error", err))
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// auditStream runs the audit log stream on the host where the revaulter.audit actor is active
type auditStream struct {
	shipper *siem.Shipper
	db      *db.DB
	log     *slog.Logger

	lock    sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// newAuditStream creates the audit log stream, when the feature is enabled
// It returns nil, with no error, when `auditStreamUrl` is empty
func newAuditStream(database *db.DB, m *metrics.RevaulterMetrics, log *slog.Logger) (*auditStream, error) {
	cfg := config.Get()
	if cfg.AuditStreamUrl == "" {
		return nil, nil
	}

	log = log.With(slog.String("component", "auditstream"))
	shipper, err := siem.NewShipper(siem.ShipperOptions{
		Store:      database.AuditStreamStore(),
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

		Metrics: m.AuditStream(),
		Logger:  log,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize the audit log stream: %w", err)
	}

	return &auditStream{
		shipper: shipper,
		db:      database,
		log:     log,
	}, nil
}

// start runs the stream in background, if it's not running already
func (s *auditStream) start() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.running {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.running = true
	s.cancel = cancel
	s.done = done

	go func() {
		defer close(done)

		err := s.bootstrapCursor(ctx)
		if err != nil {
			// The context was canceled
			return
		}

		// Run returns only when ctx is canceled
		// A shipper can be run again once the previous run has returned
		_ = s.shipper.Run(ctx)
	}()
}

// stop stops the stream, and waits for it to return
func (s *auditStream) stop() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if !s.running {
		return
	}

	s.cancel()
	<-s.done
	s.running = false
	s.cancel = nil
	s.done = nil
}

// nudge wakes the stream, if it runs on this host, and returns whether it does
func (s *auditStream) nudge() bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	if !s.running {
		return false
	}

	s.shipper.Nudge()
	return true
}

// bootstrapCursor seeds the cursor to the current high-water mark the first time the stream runs, so pre-existing history is never shipped
// Once the cursor exists, this does nothing, so turning the stream off and on again resumes from the stored cursor, and the events written in between are still shipped
// It retries until it succeeds, or until ctx is canceled
func (s *auditStream) bootstrapCursor(ctx context.Context) error {
	delay := time.Second
	for {
		bootstrapCtx, bootstrapCancel := context.WithTimeout(ctx, 15*time.Second)
		pos, seeded, err := s.db.AuditStreamStore().BootstrapToHead(bootstrapCtx)
		bootstrapCancel()
		if err == nil {
			if seeded {
				s.log.InfoContext(ctx, "Audit log stream cursor seeded at the current high-water mark; existing events will not be streamed",
					slog.Int64("seq", pos.Seq),
					slog.String("xactId", pos.XactID),
				)
			}
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		s.log.WarnContext(ctx, "Failed to bootstrap the audit log stream cursor; will retry",
			slog.Any("error", err),
			slog.Duration("retryIn", delay),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}
