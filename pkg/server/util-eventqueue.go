package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

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

	rec, err := s.requestStore.MarkExpired(ctx, ev.State)
	if err != nil {
		log.WarnContext(ctx, "error expiring request", slog.Any("error", err), slog.String("state", ev.State))
		return
	}
	if rec == nil {
		return
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
		err := s.requestStore.DeleteTerminalRequest(ctx, ev.ID, &ev.TTL)
		if err != nil {
			log.WarnContext(ctx, "request cleanup failed", slog.Any("error", err), slog.String("state", ev.ID))
		}
	case "challenge":
		err := s.authStore.DeleteExpiredAuthChallenge(ctx, ev.ID, ev.TTL)
		if err != nil {
			log.WarnContext(ctx, "auth challenge cleanup failed", slog.Any("error", err), slog.String("challenge_id", ev.ID))
		}
	case "nonready-user":
		err := s.authStore.DeleteNonreadyUser(ctx, ev.ID, ev.TTL)
		if err != nil {
			log.WarnContext(ctx, "non-ready user cleanup failed", slog.Any("error", err), slog.String("user_id", ev.ID))
		}
	}
}
