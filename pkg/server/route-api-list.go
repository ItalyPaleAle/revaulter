package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type apiListResponse []requestStatePublic

// RouteApiListGet is the handler for the GET /api/list request
// This returns the list of all pending requests
// If the Accept header is `application/x-ndjson`, then this sends a stream of records, updated as soon as they come in, using the NDJSON format (https://github.com/ndjson/ndjson-spec)
func (s *Server) RouteApiListGet(c *gin.Context) {
	accept := c.GetHeader("accept")
	if strings.ToLower(accept) == ndJSONContentType {
		s.routeApiListGetStream(c)
	} else {
		s.routeApiListGetSingle(c)
	}
}

// Returns the response as a single JSON fragment
func (s *Server) routeApiListGetSingle(c *gin.Context) {
	// Get the list of pending requests
	s.lock.RLock()
	res := make(apiListResponse, len(s.states))
	i := 0
	for stateId, state := range s.states {
		if state.Status != StatusPending || state.Processing || state.Expired() {
			continue
		}
		res[i] = state.Public(stateId)
		i++
	}
	res = res[:i]
	s.lock.RUnlock()

	c.JSON(http.StatusOK, res)
}

// Returns the response as a stream of NDJSON until the client disconnects or the session expires
func (s *Server) routeApiListGetStream(c *gin.Context) {
	// Timeout for the user's session
	var timeout *time.Timer
	expirationAny, ok := c.Get(contextKeySessionExpiration)
	if ok {
		expiration, ok := expirationAny.(time.Time)
		if ok {
			timeout = time.NewTimer(time.Until(expiration))
		}
	}
	if timeout == nil {
		AbortWithErrorJSON(c, errors.New("request did not contain a valid session expiration in the context"))
		return
	}
	defer timeout.Stop()

	// Send the content-type header and the status code, so we can start sending data over the stream
	c.Header("content-type", ndJSONContentType)
	c.Status(http.StatusOK)

	// JSON stream encoder
	enc := json.NewEncoder(c.Writer)
	enc.SetEscapeHTML(false)
	sent := false

	// Start by sending all the requests currently pending
	s.lock.Lock()
	for stateId, state := range s.states {
		if state.Status != StatusPending || state.Processing || state.Expired() {
			continue
		}
		sent = true
		_ = enc.Encode(state.Public(stateId))
	}

	// Subscribe to receive new events
	events, err := s.pubsub.Subscribe()
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("error subscribing to events: %w", err))
		s.lock.Unlock()
		return
	}

	// Release the lock now
	s.lock.Unlock()

	// If we haven't sent any record yet, send an empty line so the client receives a byte
	if !sent {
		_, _ = c.Writer.Write([]byte{0x0A})
	}

	// Send any data to the client
	c.Writer.Flush()

	// Process all events
	// Stop when the request's context is canceled or if the user's session times out
	// Every 200ms, we flush the data to the client
	ticker := time.NewTicker(100 * time.Millisecond)
	hasData := false
	defer func() {
		// Unsubscribe and stop the ticker once the method returns
		s.pubsub.Unsubscribe(events)
		ticker.Stop()
		// Flush anything that may be in the buffer
		if hasData {
			c.Writer.Flush()
		}
	}()

	for {
		select {
		case msg, more := <-events:
			// Encode the event and add it to the buffer
			if msg != nil {
				_ = enc.Encode(msg)
				hasData = true
			}
			// If the channel is closed, return
			if !more {
				return
			}
		case <-ticker.C:
			// Flush the buffer
			if hasData {
				c.Writer.Flush()
				hasData = false
			}
		case <-c.Request.Context().Done():
			return
		case <-timeout.C:
			return
		}
	}
}
