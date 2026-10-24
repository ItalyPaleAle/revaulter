package server

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// deleteEvent implements eventqueue.Queueable
type deleteEvent struct {
	KeyName string
	Kind    string
	ID      string
	TTL     time.Time
}

func (e deleteEvent) Key() string {
	return e.KeyName
}

func (e deleteEvent) DueTime() time.Time {
	return e.TTL
}

func (s *Server) executeDeleteEvent(ev deleteEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log := logging.LogFromContext(ctx)

	switch ev.Kind {
	case "challenge":
		err := s.db.AuthStore().DeleteExpiredAuthChallenge(ctx, ev.ID, ev.TTL)
		if err != nil {
			log.WarnContext(ctx, "auth challenge cleanup failed", slog.Any("error", err), slog.String("challenge_id", ev.ID))
		}
	case "nonready-user":
		err := s.db.AuthStore().DeleteNonreadyUser(ctx, ev.ID, ev.TTL)
		if err != nil {
			log.WarnContext(ctx, "non-ready user cleanup failed", slog.Any("error", err), slog.String("user_id", ev.ID))
		}
	case "audit-prune":
		// The cutoff is the retention horizon, clamped so the prune never deletes events the audit log stream has not shipped yet
		threshold := s.auditPruneCutoff(ctx, time.Now())
		removed, err := s.db.AuditStore().PruneBefore(ctx, threshold)
		if err != nil {
			log.WarnContext(ctx, "audit prune failed", slog.Any("error", err))
		} else if removed > 0 {
			log.InfoContext(ctx, "audit log pruned",
				slog.Int64("removed", removed),
				slog.Int64("threshold_unix", threshold),
			)
		}

		// Remove the envelopes of requests that the revaulter.user actors missed, for example after their state was lost
		removed, err = s.db.RequestPayloadStore().DeleteExpired(ctx, time.Now().Add(-requestRemoveGrace))
		if err != nil {
			log.WarnContext(ctx, "request payload prune failed", slog.Any("error", err))
		} else if removed > 0 {
			log.InfoContext(ctx, "expired request payloads pruned", slog.Int64("removed", removed))
		}

		// Re-enqueue the next prune
		err = s.enqueueAuditPrune(time.Now().Add(auditPruneInterval))
		if err != nil {
			log.WarnContext(ctx, "failed to re-enqueue audit prune", slog.Any("error", err))
		}
	default:
		log.WarnContext(ctx, "executing unsupported cleanup event kind", slog.String("kind", ev.Kind))
	}
}

// enqueueAuditPrune schedules an audit-prune deleteEvent to fire at the given time
func (s *Server) enqueueAuditPrune(at time.Time) error {
	// Each call uses a fresh KeyName so the eventqueue treats it as a new entry rather than deduping against a previous prune
	return s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "audit-prune:" + strconv.FormatInt(at.UnixNano(), 10),
		Kind:    "audit-prune",
		TTL:     at,
	})
}
