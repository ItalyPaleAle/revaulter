package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

var (
	// ErrRequestNotModifiable is returned when a request doesn't exist, isn't pending, or can't be changed anymore
	// Requests of other users live in other actors, so they are reported the same way, and callers can't probe for another user's requests
	ErrRequestNotModifiable = errors.New("request cannot be modified")
	// ErrTooManyPendingRequests is returned when a user already has MaxPendingRequestsPerUser pending requests
	ErrTooManyPendingRequests = errors.New("too many pending requests")
)

// UserClient calls the revaulter.user actor of a user, which holds all of that user's requests
type UserClient struct {
	host   *Host
	userID string
}

// User returns a client for the revaulter.user actor of a user
func (h *Host) User(userID string) UserClient {
	return UserClient{
		host:   h,
		userID: userID,
	}
}

// Create stores a new pending request, with its envelope and audit event, and notifies the user's list streams
// It returns ErrTooManyPendingRequests if the user has too many pending requests
// Creating a request that already exists is a no-op, so a call can be retried safely
func (c UserClient) Create(ctx context.Context, in CreateRequestInput) error {
	res, err := invoke[userCreateRes](ctx, c.host, actorTypeUser, c.userID, userMethodCreate, in)
	if err != nil {
		return err
	}

	if res.Error == userActorErrTooManyPending {
		return ErrTooManyPendingRequests
	}

	return nil
}

// Confirm completes a pending request with the response envelope, writes the audit event, and wakes the request's long-poll and the user's list streams
// The actor fills the fields of the audit event that describe the request, and it's optional
// It returns the request, or ErrRequestNotModifiable if the request can't be completed
func (c UserClient) Confirm(ctx context.Context, state string, encryptedResult string, audit *db.AuditEventInput) (Request, error) {
	return c.change(ctx, userMethodConfirm, userChangeReq{
		State:           state,
		EncryptedResult: encryptedResult,
		Audit:           audit,
	})
}

// Cancel cancels a pending request, writes the audit event, and wakes the request's long-poll and the user's list streams
// The actor fills the fields of the audit event that describe the request, and it's optional
// It returns the request, or ErrRequestNotModifiable if the request can't be canceled
func (c UserClient) Cancel(ctx context.Context, state string, audit *db.AuditEventInput) (Request, error) {
	return c.change(ctx, userMethodCancel, userChangeReq{
		State: state,
		Audit: audit,
	})
}

func (c UserClient) change(ctx context.Context, method string, in userChangeReq) (Request, error) {
	res, err := invoke[userChangeRes](ctx, c.host, actorTypeUser, c.userID, method, in)
	if err != nil {
		return Request{}, err
	}

	if res.Error == userActorErrNotModifiable {
		return Request{}, ErrRequestNotModifiable
	}

	return res.Request, nil
}

// Subscribe registers a new long-poll for the result of a request, evicting the previous one, and returns the request's status
// When the request is pending, the caller must then call WaitForResult with the returned waiter
func (c UserClient) Subscribe(ctx context.Context, state string) (Subscription, error) {
	return invoke[Subscription](ctx, c.host, actorTypeUser, c.userID, userMethodSubscribe, userStateReq{State: state})
}

// WaitForResult waits until the request of a long-poll registered with Subscribe changes, or a newer long-poll evicts this one
// It returns true if the long-poll was evicted
// If it returns an error, for example because ctx was canceled, the waiter has been removed
func (c UserClient) WaitForResult(ctx context.Context, state string, waiter string) (evicted bool, err error) {
	env, err := c.host.waiters.Wait(ctx, waiterSignalID(state, waiter))
	if err != nil {
		// Remove the waiter, using a separate context because ctx may be canceled
		unsubCtx, unsubCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer unsubCancel()
		_, unsubErr := invoke[struct{}](unsubCtx, c.host, actorTypeUser, c.userID, userMethodUnsubscribe, userStateReq{
			State:  state,
			Waiter: waiter,
		})
		if unsubErr != nil {
			logging.LogFromContext(ctx).WarnContext(ctx, "Failed to remove long-poll waiter",
				slog.String("state", state),
				slog.Any("error", unsubErr),
			)
		}

		return false, err
	}

	// The actor removes the waiter before waking it
	var wake waiterWake
	if env != nil {
		err = env.Decode(&wake)
		if err != nil {
			return false, fmt.Errorf("failed to decode wake-up reason: %w", err)
		}
	}

	return wake.Reason == waiterReasonEvicted, nil
}

// Collect returns the result of a finished request and removes it
// It runs in a single turn of the actor, so only one caller can collect a result
func (c UserClient) Collect(ctx context.Context, state string) (CollectedResult, error) {
	return invoke[CollectedResult](ctx, c.host, actorTypeUser, c.userID, userMethodCollect, userStateReq{State: state})
}

// Snapshot returns the user's pending requests, and the bell that rings at the next change, read together so no change can slip in between
func (c UserClient) Snapshot(ctx context.Context) (Snapshot, error) {
	return invoke[Snapshot](ctx, c.host, actorTypeUser, c.userID, userMethodSnapshot, nil)
}

// WaitForChange waits until a bell returned by Snapshot rings, which means the user's pending requests changed
func (c UserClient) WaitForChange(ctx context.Context, bell string) error {
	_, err := c.host.inbox.Wait(ctx, bell)
	return err
}

// List returns the user's pending requests, oldest first
func (c UserClient) List(ctx context.Context) ([]db.V2RequestListItem, error) {
	res, err := peek[userListRes](ctx, c.host, actorTypeUser, c.userID, userMethodList, nil)
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

// Get returns a request of the user, or nil if it doesn't exist
// A pending request past its deadline is reported as expired, even before the cleanup alarm expires it
func (c UserClient) Get(ctx context.Context, state string) (*Request, error) {
	res, err := peek[userGetRes](ctx, c.host, actorTypeUser, c.userID, userMethodGet, userStateReq{State: state})
	if err != nil {
		return nil, err
	}

	if !res.Found {
		return nil, nil
	}

	return &res.Request, nil
}
