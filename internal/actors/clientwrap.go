//go:build !unit

package actors

import (
	"github.com/italypaleale/francis/actor"
)

// wrapActorClient returns the client an actor uses for its state and alarms
// Unit tests build a version that can wrap the client to inject failures
func wrapActorClient[T any](_ string, _ string, client actor.Client[T]) actor.Client[T] {
	return client
}
