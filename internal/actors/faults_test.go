package actors

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/italypaleale/francis/actor"
)

// errInjected is the error returned by a call that a test made fail
var errInjected = errors.New("injected failure")

// clientFaults counts how many upcoming calls of each kind fail
type clientFaults struct {
	setState atomic.Int32
	setAlarm atomic.Int32
}

// failSetState makes the next n SetState calls fail
func (f *clientFaults) failSetState(n int) {
	f.setState.Store(int32(n)) //nolint:gosec
}

// take consumes one failure from the counter, and returns true if the call must fail
func take(counter *atomic.Int32) bool {
	for {
		n := counter.Load()
		if n <= 0 {
			return false
		}
		if counter.CompareAndSwap(n, n-1) {
			return true
		}
	}
}

// faultyClient is an actor client that fails the calls its faults ask for
type faultyClient[T any] struct {
	actor.Client[T]

	faults *clientFaults
}

func (c *faultyClient[T]) SetState(ctx context.Context, state T, opts *actor.SetStateOpts) error {
	if take(&c.faults.setState) {
		return errInjected
	}
	return c.Client.SetState(ctx, state, opts)
}

func (c *faultyClient[T]) SetAlarm(ctx context.Context, alarmName string, properties actor.AlarmProperties) error {
	if take(&c.faults.setAlarm) {
		return errInjected
	}
	return c.Client.SetAlarm(ctx, alarmName, properties)
}

// injectFaults wraps the clients of the actors of a type until the test ends, and returns the faults to arm
// T is the actor's state type
func injectFaults[T any](t *testing.T, actorType string) *clientFaults {
	t.Helper()

	faults := &clientFaults{}
	prev := testClientWrapper
	testClientWrapper = func(typ string, actorID string, client any) any {
		inner, ok := client.(actor.Client[T])
		if typ != actorType || !ok {
			if prev != nil {
				return prev(typ, actorID, client)
			}
			return client
		}
		return &faultyClient[T]{Client: inner, faults: faults}
	}
	t.Cleanup(func() {
		testClientWrapper = prev
	})

	return faults
}
