package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	serverintegrity "github.com/italypaleale/revaulter/pkg/server/integrity"
)

type v2IntegrityResponse struct {
	// Raw manifest text (see pkg/integrity for the format)
	// Signature verification runs against the exact UTF-8 bytes of this string, including the trailing LF
	Manifest string `json:"manifest"`
	// Cosign signing bundle, inlined as nested JSON (it is already JSON on disk)
	Bundle json.RawMessage `json:"bundle"`
}

// RouteInfoIntegrityHandler is the handler for GET /info/integrity
// It returns the embedded manifest + cosign bundle so CLI clients can verify the server's web assets
// For dev / unsigned builds no manifest is embedded and the handler returns 404
func (s *Server) RouteInfoIntegrityHandler(c *gin.Context) {
	if !serverintegrity.HasManifest() {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Integrity manifest is not available for this build"))
		return
	}

	// Manifest is immutable per release, cache for a few minutes
	// This overrides the Cache-Control set by the middleware
	c.Header("Cache-Control", "public, max-age=300")

	c.JSON(http.StatusOK, v2IntegrityResponse{
		Manifest: string(serverintegrity.ManifestBytes),
		Bundle:   json.RawMessage(serverintegrity.BundleBytes),
	})
}
