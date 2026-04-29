package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	serverintegrity "github.com/italypaleale/revaulter/pkg/server/integrity"
)

// RouteHealthzHandler is the handler for the GET /healthz request as a http.Handler.
// It can be used to ping the server and ensure everything is working.
func (s *Server) RouteHealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

type v2InfoResponse struct {
	Product      string `json:"product"`
	APIVersion   int    `json:"apiVersion"`
	Version      string `json:"version,omitempty"`
	Commit       string `json:"commit,omitempty"`
	BuildDate    string `json:"buildDate,omitempty"`
	HasIntegrity bool   `json:"hasIntegrity"`
}

// RouteInfoHandler is the handler for the GET /info request
func (s *Server) RouteInfoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, v2InfoResponse{
		Product:      "revaulter",
		APIVersion:   2,
		Version:      buildinfo.AppVersion,
		Commit:       buildinfo.CommitHash,
		BuildDate:    buildinfo.BuildDate,
		HasIntegrity: serverintegrity.HasManifest(),
	})
}
