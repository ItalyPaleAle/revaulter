package server

import (
	"net/http"
)

// RouteHealthzHandler is the handler for the GET /healthz request as a http.Handler.
// It can be used to ping the server and ensure everything is working.
func (s *Server) RouteHealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
