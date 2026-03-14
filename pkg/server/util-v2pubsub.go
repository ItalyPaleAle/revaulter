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
