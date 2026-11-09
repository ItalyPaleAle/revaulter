//go:build e2e

// This file includes methods for the e2e tests, and it's only built with the "e2e" tag

package actors

import (
	"context"
	"fmt"
	"time"

	"github.com/italypaleale/francis/actor"

	"github.com/italypaleale/revaulter/internal/db"
)

// Methods of the revaulter.user actor used by the e2e tests only
const (
	userMethodTestReset  = "test-reset"
	userMethodTestExpire = "test-expire"
)

func init() {
	testMethods = invokeTestMethod
}

// invokeTestMethod handles the methods of the revaulter.user actor used by the e2e tests
func invokeTestMethod(ctx context.Context, a *userActor, method string, data actor.Envelope) (any, bool, error) {
	switch method {
	case userMethodTestReset:
		return nil, true, a.testReset(ctx)
	case userMethodTestExpire:
		var in userStateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, true, err
		}
		return nil, true, a.testExpire(ctx, in)
	default:
		return nil, false, nil
	}
}

// TestResetAllUsers removes the requests of every user
// Each actor deletes its own state, so active actors don't keep serving a stale copy
func (h *Host) TestResetAllUsers(ctx context.Context) error {
	svc := h.host.Service()
	var after string
	for {
		list, err := svc.ListStates(ctx, actorTypeUser, &actor.ListStatesOpts{After: after})
		if err != nil {
			return fmt.Errorf("failed to list user actors: %w", err)
		}

		for _, st := range list.States {
			_, err = invoke[struct{}](ctx, h, actorTypeUser, st.ActorID, userMethodTestReset, nil)
			if err != nil {
				return err
			}
		}

		after = list.AfterID()
		if after == "" {
			return nil
		}
	}
}

// TestExpire moves a pending request past its deadline, and expires it
func (c UserClient) TestExpire(ctx context.Context, state string) error {
	_, err := invoke[struct{}](ctx, c.host, actorTypeUser, c.userID, userMethodTestExpire, userStateReq{State: state})
	return err
}

// testReset removes all requests of the user
func (a *userActor) testReset(ctx context.Context) error {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	err = a.deleteState(ctx)
	if err != nil {
		return err
	}

	for state, r := range st.Requests {
		a.wakeWaiter(ctx, state, r.Waiter, waiterReasonDone)
	}
	a.ringBell(ctx, st.Bell)

	return nil
}

// testExpire moves a pending request past its deadline, and expires it
func (a *userActor) testExpire(ctx context.Context, in userStateReq) error {
	st, err := a.loadState(ctx)
	if err != nil {
		return err
	}

	r := st.Requests[in.State]
	if r == nil || r.Status != db.V2RequestStatusPending {
		return nil
	}

	now := time.Now()
	r.ExpiresAt = now.Add(-time.Second)
	return a.expireOne(ctx, &st, in.State, now)
}
