package server

import (
	"github.com/italypaleale/revaulter/pkg/v2db"
)

func (s *Server) publishListItem(item *v2db.V2RequestListItem) {
	if s.v2Pubsub == nil || item == nil {
		return
	}

	go s.v2Pubsub.Publish(item)
}

// Callers must hold lock with s.lock
func (s *Server) subscribeState(state string) chan struct{} {
	ch := s.subs[state]
	if ch != nil {
		close(ch)
	}

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
	ch := s.subs[state]
	if ch == nil {
		return
	}

	ch <- struct{}{}
	close(ch)

	delete(s.subs, state)
}
