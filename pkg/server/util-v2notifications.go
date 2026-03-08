package server

// Important: methods below must be called with s.lock held.

func (s *Server) subscribeToV2State(state string) chan struct{} {
	ch := s.v2Subs[state]
	if ch != nil {
		close(ch)
	}
	ch = make(chan struct{}, 1)
	s.v2Subs[state] = ch
	return ch
}

func (s *Server) unsubscribeToV2State(state string, watch chan struct{}) {
	ch := s.v2Subs[state]
	if ch != nil && ch == watch {
		close(ch)
		delete(s.v2Subs, state)
	}
}

func (s *Server) notifyV2Subscriber(state string) {
	ch := s.v2Subs[state]
	if ch == nil {
		return
	}
	ch <- struct{}{}
	close(ch)
	delete(s.v2Subs, state)
}
