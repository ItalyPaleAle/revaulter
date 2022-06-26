package server

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/unlocker/utils"
)

// RouteResult is the handler for the GET /result/:state request
// This can be invoked by the app to periodically poll for the result
func (s *Server) RouteResult(c *gin.Context) {
	// Get the state parameter
	stateId := c.Param("state")
	if stateId == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "Missing parameter state"})
		return
	}

	// Check if the user wants a raw response
	rawResult := utils.IsTruthy(c.Query("raw"))

	// Get the state and ensure the it's valid
	s.lock.Lock()
	state, ok := s.states[stateId]
	if !ok || state == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "State not found or expired"})
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
	for {
		select {
		case <-c.Request.Context().Done():
			// Client has probably disconnected at this point, but just respond with the pending message
			s.sendResponse(c, stateId, pendingReq, rawResult)
			return
		case state := <-watch:
			// If res is nil, the channel was closed (perhaps because another request evicted this), so respond with the pending message
			if state == nil {
				state = pendingReq
			}
			// Send the response
			s.sendResponse(c, stateId, state, rawResult)
			return
		}
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
		if rawResult {
			c.Data(http.StatusOK, "application/octet-stream", state.Output)
		} else {
			c.JSON(http.StatusOK, &operationResponse{
				State: stateId,
				Done:  true,
				Value: base64.StdEncoding.EncodeToString(state.Output),
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
