//go:build e2e

// This file includes the methods that reset the actors in the e2e tests, and it's only built with the "e2e" tag

package actors

import (
	"context"
	"errors"
	"fmt"

	"github.com/italypaleale/francis/actor"
)

// methodTestReset is the method that removes the state of an actor in the e2e tests
const methodTestReset = "test-reset"

func init() {
	testChallengeMethods = func(ctx context.Context, a *challengeActor, method string, _ actor.Envelope) (any, bool, error) {
		if method != methodTestReset {
			return nil, false, nil
		}
		return nil, true, testDeleteStateAndAlarm(ctx, a.client, challengeActorCleanupAlarm)
	}

	testSignupMethods = func(ctx context.Context, a *signupActor, method string, _ actor.Envelope) (any, bool, error) {
		if method != methodTestReset {
			return nil, false, nil
		}
		return nil, true, testDeleteStateAndAlarm(ctx, a.client, signupActorCleanupAlarm)
	}
}

// TestResetAll removes the requests of every user, and all challenges and signups
// Each actor deletes its own state, so active actors don't keep serving a stale copy
func (h *Host) TestResetAll(ctx context.Context) error {
	for _, actorType := range []string{actorTypeUser, actorTypeChallenge, actorTypeSignup} {
		err := h.testResetActors(ctx, actorType)
		if err != nil {
			return err
		}
	}

	return nil
}

// testResetActors invokes the test-reset method of every actor of a type that has state
func (h *Host) testResetActors(ctx context.Context, actorType string) error {
	svc := h.host.Service()
	var after string
	for {
		list, err := svc.ListStates(ctx, actorType, &actor.ListStatesOpts{After: after})
		if err != nil {
			return fmt.Errorf("failed to list actors of type '%s': %w", actorType, err)
		}

		for _, st := range list.States {
			_, err = invoke[struct{}](ctx, h, actorType, st.ActorID, methodTestReset, nil)
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

// testDeleteStateAndAlarm removes the state of an actor and its alarm
func testDeleteStateAndAlarm[T any](ctx context.Context, client actor.Client[T], alarm string) error {
	err := client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		return fmt.Errorf("failed to delete state: %w", err)
	}

	err = client.DeleteAlarm(ctx, alarm)
	if err != nil && !errors.Is(err, actor.ErrAlarmNotFound) {
		return fmt.Errorf("failed to delete alarm: %w", err)
	}

	return nil
}
