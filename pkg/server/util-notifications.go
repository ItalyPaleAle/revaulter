package server

import (
	"github.com/italypaleale/revaulter/pkg/db"
)

func (s *Server) publishListItem(item *db.V2RequestListItem) {
	if s.pubsub == nil || item == nil {
		return
	}

	go s.pubsub.Publish(item)
}

// Callers must hold lock with s.lock
func (s *Server) subscribeState(state string) chan struct{} {
	// Multiple pollers can subscribe to the same state concurrently; each receives its own channel and is notified independently in notifySubscriber
	ch := make(chan struct{}, 1)
	s.subs[state] = append(s.subs[state], ch)
	return ch
}

// Callers must hold lock with s.lock
func (s *Server) unsubscribeState(state string, watch chan struct{}) {
	list := s.subs[state]
	for i, ch := range list {
		if ch != watch {
			continue
		}

		// Remove element i while preserving order is not necessary; swap-with-last keeps this O(1)
		list[i] = list[len(list)-1]
		list = list[:len(list)-1]
		break
	}

	if len(list) == 0 {
		delete(s.subs, state)
	} else {
		s.subs[state] = list
	}
}

// Callers must hold lock with s.lock
func (s *Server) notifySubscriber(state string) {
	// Fans out a single notification to every current subscriber of state
	list := s.subs[state]
	if len(list) == 0 {
		return
	}

	for _, ch := range list {
		// Non-blocking send: the channel buffer is 1 so a second notify before the receiver wakes up is a harmless drop
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	// Clear the slot
	delete(s.subs, state)
}
