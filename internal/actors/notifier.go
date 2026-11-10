package actors

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/italypaleale/francis/actor"

	"github.com/italypaleale/revaulter/internal/db"
)

const (
	// actorTypeNotifier is the actor type that sends the notifications for a user's requests, keyed by user ID
	actorTypeNotifier = "revaulter.notifier"
	// notifierJobRequestCreated is the job that sends the notification for a new request
	notifierJobRequestCreated = "request-created"

	// notifierMaxAttempts is how many times a notification is sent, including the first time, before it's given up
	notifierMaxAttempts = 3
	// notifierDeadLetteredRetention is how long the record of a notification that was given up is kept
	notifierDeadLetteredRetention = 24 * time.Hour
)

// notifierInitialRetryDelay is how long to wait before sending a notification again after the first failure
// It's a variable so tests can shorten it
var notifierInitialRetryDelay = 20 * time.Second

// RequestNotification describes a new request, for the notification sent to its user
type RequestNotification struct {
	// Base URL of Revaulter, which the notification links to
	BaseURL string
	// Display name of the user, or the user ID when the user has no display name
	UserDisplayName string
	Operation       string
	KeyLabel        string
	Algorithm       string
	RequestorIP     string
	Note            string
}

// Notifier sends the notification for a new request
// It must make a single attempt, as the revaulter.notifier actor retries notifications that fail
type Notifier func(ctx context.Context, n RequestNotification) error

// notifyRequestJob is the input of the job that sends the notification for a new request
type notifyRequestJob struct {
	State   string
	BaseURL string
}

// notifierActor is the revaulter.notifier actor, which sends the notifications for a user's requests as jobs, so they survive a restart and are retried when they fail
// It has no state
type notifierActor struct {
	host   *Host
	userID string
	log    *slog.Logger
}

// newNotifierActor is the factory for revaulter.notifier actors
func (h *Host) newNotifierActor(actorID string, _ *actor.Service) actor.Actor {
	return &notifierActor{
		host:   h,
		userID: actorID,
		log:    h.log.With(slog.String("actorType", actorTypeNotifier), slog.String("userId", actorID)),
	}
}

// Job implements actor.ActorJob
func (a *notifierActor) Job(ctx context.Context, method string, data actor.Envelope) error {
	if method != notifierJobRequestCreated {
		a.log.WarnContext(ctx, "Ignoring unknown job", slog.String("method", method))
		return actor.ErrJobPermanentFailure
	}

	var in notifyRequestJob
	err := decodeActorEnvelope(data, &in)
	if err != nil {
		// Retrying can't fix a job whose input can't be read
		a.log.WarnContext(ctx, "Invalid notification job", slog.Any("error", err))
		return actor.ErrJobPermanentFailure
	}

	return a.notifyRequestCreated(ctx, in)
}

// JobFailed implements actor.ActorJobFailed
func (a *notifierActor) JobFailed(ctx context.Context, jobID string, method string, data actor.Envelope, jobErr error) error {
	var in notifyRequestJob
	if data != nil {
		_ = data.Decode(&in)
	}

	a.log.ErrorContext(ctx, "Failed to send the notification for a request, giving up",
		slog.String("jobId", jobID),
		slog.String("method", method),
		slog.String("state", in.State),
		slog.Any("error", jobErr),
	)

	return nil
}

// notifyRequestCreated sends the notification for a new request, unless the request isn't pending anymore
func (a *notifierActor) notifyRequestCreated(ctx context.Context, in notifyRequestJob) error {
	log := a.log.With(slog.String("state", in.State))

	// When a retry happens after the user acted on the request, or after it expired, there is nothing to notify anymore
	req, err := a.host.User(a.userID).Get(ctx, in.State)
	if err != nil {
		return fmt.Errorf("failed to load request: %w", err)
	}
	if req == nil || req.Status != db.V2RequestStatusPending {
		log.DebugContext(ctx, "Request is not pending anymore, skipping its notification")
		return nil
	}

	user, err := a.host.db.AuthStore().GetUserByID(ctx, a.userID)
	if err != nil {
		return fmt.Errorf("failed to load user: %w", err)
	}
	if user == nil {
		log.DebugContext(ctx, "User does not exist anymore, skipping the notification")
		return nil
	}
	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.ID
	}

	err = a.host.notifier(ctx, RequestNotification{
		BaseURL:         in.BaseURL,
		UserDisplayName: displayName,
		Operation:       req.Operation,
		KeyLabel:        req.KeyLabel,
		Algorithm:       req.Algorithm,
		RequestorIP:     req.RequestorIP,
		Note:            req.Note,
	})
	if err != nil {
		// Francis retries the job, until it runs out of attempts
		log.WarnContext(ctx, "Error sending the notification for a request", slog.Any("error", err))
		return err
	}

	log.InfoContext(ctx, "Sent the notification for a request")
	return nil
}

// NotifyRequestCreated schedules the notification for a new request, which is sent in background
// It's a no-op when notifications aren't enabled
// Scheduling the notification for the same request more than once has no effect
func (h *Host) NotifyRequestCreated(ctx context.Context, userID string, state string, baseURL string) error {
	if h.notifier == nil {
		return nil
	}

	err := h.checkRunning()
	if err != nil {
		return err
	}

	_, _, err = h.host.Service().Dispatch(ctx, actorTypeNotifier, userID, notifierJobRequestCreated,
		notifyRequestJob{
			State:   state,
			BaseURL: baseURL,
		},
		actor.WithIdempotencyKey(state),
	)
	if err != nil {
		return fmt.Errorf("failed to schedule the notification: %w", err)
	}

	return nil
}
