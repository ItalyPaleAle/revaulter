package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/utils"
)

// RouteRequestResult is the handler for the GET /request/result/:state request
// This can be invoked by the app to periodically poll for the result
func (s *Server) RouteRequestResult(c *gin.Context) {
	// Get the state parameter
	stateId := c.Param("state")
	if stateId == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing parameter state"))
		return
	}

	// Check if the user wants a raw response
	rawResult := utils.IsTruthy(c.Query("raw"))

	// Get the state and ensure the it's valid
	// We need to use a full lock (Lock rather than RLock) because we may need to subscribe later
	s.lock.Lock()
	state, ok := s.states[stateId]
	if !ok || state == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		s.lock.Unlock()
		return
	}
	// Check if the operation is already complete
	if state.Status != StatusPending {
		// Send the response
		s.sendResponse(c, stateId, state, rawResult)
		s.lock.Unlock()
		return
	}

	// Subscribe to the state and wait till the request is complete, or if the context is done
	watch := s.subscribeToState(stateId)
	s.lock.Unlock()

	pendingReq := &requestState{Status: StatusPending}

	select {
	case <-c.Request.Context().Done():
		// Client has probably disconnected at this point, but just respond with the pending message
		// We need a lock because we're modifying s.states inside the method
		s.lock.Lock()
		s.sendResponse(c, stateId, pendingReq, rawResult)
		s.unsubscribeToState(stateId, watch)
		s.lock.Unlock()
	case state = <-watch:
		// If res is nil, the channel was closed (perhaps because another request evicted this), so respond with the pending message
		if state == nil {
			state = pendingReq
		}
		// Send the response
		// We need a lock because we're modifying s.states inside the method
		s.lock.Lock()
		s.sendResponse(c, stateId, state, rawResult)
		s.unsubscribeToState(stateId, watch)
		s.lock.Unlock()
	}
}

func (s *Server) sendResponse(c *gin.Context, stateId string, state *requestState, rawResult bool) {
	// Check if the operation is done (complete or canceled)
	switch state.Status {
	case StatusPending:
		c.JSON(http.StatusAccepted, &operationResponse{
			State:   stateId,
			Pending: true,
		})
	case StatusComplete:
		// Respond with the result
		if keyID := state.Result.KeyID(); keyID != "" {
			c.Header("x-key-id", keyID)
		}
		if rawResult {
			c.Data(http.StatusOK, "application/octet-stream", state.Result.Raw())
		} else {
			c.JSON(http.StatusOK, &operationResponse{
				KeyVaultResponse: state.Result,
				State:            stateId,
				Done:             true,
			})
		}
		// Remove from the states map
		delete(s.states, stateId)
	case StatusCanceled:
		// It's been canceled, so tell the client
		c.JSON(http.StatusConflict, &operationResponse{
			State:  stateId,
			Failed: true,
		})
		// Remove from the states map
		delete(s.states, stateId)
	}
}
