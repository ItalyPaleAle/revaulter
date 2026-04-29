package server

import (
	"github.com/italypaleale/revaulter/pkg/db"
)

func (s *Server) publishListItem(item *db.V2RequestListItem) {
	if s.pubsub == nil || item == nil {
		return
	}

	s.pubsub.Publish(item)
}

// Adds a subscription to a state by key
// If another subscription to the same key exists, evicts that first
// Callers must hold lock with s.lock
func (s *Server) subscribeState(state string) chan struct{} {
	ch := s.subs[state]
	if ch != nil {
		// Close the previous subscription
		close(ch)
	}

	// Create a new subscription
	ch = make(chan struct{}, 1)
	s.subs[state] = ch
	return ch
}

// Callers must hold lock with s.lock
func (s *Server) unsubscribeState(state string, watch chan struct{}) {
	ch := s.subs[state]
	if ch != nil && ch == watch {
		close(ch)
		delete(s.subs, state)
	}
}

// Callers must hold lock with s.lock
func (s *Server) notifySubscriber(state string) {
	// Fans out a single notification to every current subscriber of state
	ch := s.subs[state]
	if ch == nil {
		return
	}

	// Send the notification
	// Non-blocking send: the channel buffer is 1 so a second notify before the receiver wakes up is a harmless drop
	select {
	case ch <- struct{}{}:
	default:
	}

	// Close the channel and remove it from the subscribers
	close(ch)
	delete(s.subs, state)
}
