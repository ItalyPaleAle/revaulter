package server

import (
	"github.com/italypaleale/revaulter/pkg/v2db"
)

func (s *Server) publishV2ListItem(item *v2db.V2RequestListItem) {
	if s.v2Pubsub == nil || item == nil {
		return
	}
	go s.v2Pubsub.Publish(item)
}

// Callers must hold lock with s.lock
func (s *Server) subscribeToV2State(state string) chan struct{} {
	ch := s.v2Subs[state]
	if ch != nil {
		close(ch)
	}
	ch = make(chan struct{}, 1)
	s.v2Subs[state] = ch
	return ch
}

// Callers must hold lock with s.lock
func (s *Server) unsubscribeToV2State(state string, watch chan struct{}) {
	ch := s.v2Subs[state]
	if ch != nil && ch == watch {
		close(ch)
		delete(s.v2Subs, state)
	}
}

// Callers must hold lock with s.lock
func (s *Server) notifyV2Subscriber(state string) {
	ch := s.v2Subs[state]
	if ch == nil {
		return
	}
	ch <- struct{}{}
	close(ch)
	delete(s.v2Subs, state)
}
