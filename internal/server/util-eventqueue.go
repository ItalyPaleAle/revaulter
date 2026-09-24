package server

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// requestExpiryGrace is added to a request's deadline when scheduling its expiry event, so the deadline has passed when the event fires
const requestExpiryGrace = 5 * time.Second

// requestExpiryEvent implements eventqueue.Queueable
type requestExpiryEvent struct {
	State  string
	UserID string
	TTL    time.Time
}

func (e requestExpiryEvent) Key() string {
	return "request-expiry:" + e.State
}

func (e requestExpiryEvent) DueTime() time.Time {
	return e.TTL
}

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

func (s *Server) executeRequestExpiryEvent(ev requestExpiryEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log := logging.LogFromContext(ctx)

	// MarkExpired also writes the audit event for the expiry
	rs := s.db.RequestStore()
	rec, err := rs.MarkExpired(ctx, ev.State)
	if err != nil {
		log.WarnContext(ctx, "error expiring request", slog.Any("error", err), slog.String("state", ev.State))
		return
	}

	if rec != nil {
		s.nudgeAuditStream()
	} else {
		// The request was not expired by this call
		// It may have been expired lazily by a read (which doesn't notify anyone), resolved by the user, deleted, or not be past its deadline yet
		rec, err = rs.GetRequest(ctx, ev.State)
		if err != nil {
			log.WarnContext(ctx, "error reading request to expire", slog.Any("error", err), slog.String("state", ev.State))
			return
		}

		switch {
		case rec == nil:
			// The request was already deleted, but list streams may still be showing it
			s.publishListItem(&db.V2RequestListItem{
				State:  ev.State,
				Status: "removed",
				UserID: ev.UserID,
			})
			return
		case rec.Status == db.V2RequestStatusPending:
			// The deadline hasn't passed yet, for example because the event fired within the same second as the deadline: try again later
			err = s.requestExpiryQueue.Enqueue(requestExpiryEvent{
				State:  ev.State,
				UserID: rec.UserID,
				TTL:    rec.ExpiresAt.Add(requestExpiryGrace),
			})
			if err != nil {
				log.WarnContext(ctx, "failed to re-enqueue request expiry", slog.Any("error", err), slog.String("state", ev.State))
			}
			return
		case rec.Status != db.V2RequestStatusExpired:
			// Completed or canceled requests are handled by the route that resolved them
			return
		}

		// The request was expired lazily: notify subscribers and schedule the cleanup below
	}

	s.lock.Lock()
	s.notifySubscriber(ev.State)
	s.lock.Unlock()

	s.publishListItem(&db.V2RequestListItem{
		State:  ev.State,
		Status: "removed",
		UserID: rec.UserID,
	})
	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "request-delete:" + ev.State,
		Kind:    "request",
		ID:      ev.State,
		TTL:     ev.TTL.Add(10 * time.Minute),
	})
	if err != nil {
		log.WarnContext(ctx, "failed to enqueue request delete", slog.Any("error", err), slog.String("state", ev.State))
	}
}

func (s *Server) executeDeleteEvent(ev deleteEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log := logging.LogFromContext(ctx)

	switch ev.Kind {
	case "request":
		err := s.db.RequestStore().DeleteTerminalRequest(ctx, ev.ID, &ev.TTL)
		if err != nil {
			log.WarnContext(ctx, "request cleanup failed", slog.Any("error", err), slog.String("state", ev.ID))
		}
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
