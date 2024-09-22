package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/keyvault"
)

// RouteApiConfirmPost is the handler for the POST /api/confirm request
// This receives the results of the confirm/reject action
func (s *Server) RouteApiConfirmPost(c *gin.Context) {
	// Get the fields from the body
	req := &confirmRequest{}
	err := c.Bind(req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.StateId == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing state in request body"))
		return
	}

	// Get the request
	s.lock.Lock()
	state, ok := s.states[req.StateId]
	switch {
	case !ok || state == nil:
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		s.lock.Unlock()
		return
	case state.Expired():
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		s.lock.Unlock()
		return
	case state.Status != StatusPending:
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Request already completed"))
		s.lock.Unlock()
		return
	case state.Processing:
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request is already being processed"))
		s.lock.Unlock()
		return
	case (req.Confirm && req.Cancel) || (!req.Confirm && !req.Cancel):
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "One and only one of confirm and cancel must be set to true in the body"))
		s.lock.Unlock()
		return
	}

	// Set processing flag
	// It's safe then to release the lock as no other goroutine can alter this request then
	state.Processing = true
	s.lock.Unlock()

	// Because the request is not pending anymore, send a notification that it has been removed
	go s.pubsub.Publish(&requestStatePublic{
		State:  req.StateId,
		Status: StatusRemoved.String(),
	})

	if req.Cancel {
		s.handleCancel(c, req.StateId, state)
	} else if req.Confirm {
		s.handleConfirm(c, req.StateId, state)
	}
}

// Handle confirmation of operations
func (s *Server) handleConfirm(c *gin.Context, stateId string, state *requestState) {
	ctx := c.Request.Context()
	defer func() {
		// Record the result in a deferred function to automatically catch failures
		if len(c.Errors) > 0 {
			s.metrics.RecordResult("error")
		} else {
			s.metrics.RecordResult("confirmed")
		}
	}()

	// Errors here should never happen
	var (
		at         string
		expiration time.Time
	)
	atAny, ok := c.Get(contextKeySessionAccessToken)
	if ok {
		at, ok = atAny.(string)
		if !ok {
			at = ""
		}
	}
	expirationAny, ok := c.Get(contextKeySessionExpiration)
	if ok {
		expiration, ok = expirationAny.(time.Time)
		if !ok {
			expiration = time.Time{}
		}
	}

	start := time.Now()

	// Init the Key Vault client
	akv := s.kvClientFactory(at, expiration)

	// Make the request
	var (
		output keyvault.KeyVaultResponse
		err    error
	)
	switch state.Operation {
	case OperationEncrypt:
		output, err = akv.Encrypt(ctx, state.Vault, state.KeyId, state.KeyVersion, state.AzkeysKeyOperationsParams())
	case OperationDecrypt:
		output, err = akv.Decrypt(ctx, state.Vault, state.KeyId, state.KeyVersion, state.AzkeysKeyOperationsParams())
	case OperationSign:
		output, err = akv.Sign(ctx, state.Vault, state.KeyId, state.KeyVersion, state.AzkeysSignParams())
	case OperationVerify:
		output, err = akv.Verify(ctx, state.Vault, state.KeyId, state.KeyVersion, state.AzkeysVerifyParams())
	case OperationWrapKey:
		output, err = akv.WrapKey(ctx, state.Vault, state.KeyId, state.KeyVersion, state.AzkeysKeyOperationsParams())
	case OperationUnwrapKey:
		output, err = akv.UnwrapKey(ctx, state.Vault, state.KeyId, state.KeyVersion, state.AzkeysKeyOperationsParams())
	default:
		err = fmt.Errorf("invalid operation %s", state.Operation)
	}
	if err != nil {
		var azErr *azcore.ResponseError
		if errors.As(err, &azErr) {
			// If the error comes from Key Vault, we need to cancel the request
			s.cancelRequest(stateId, state)
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusConflict, "Azure Key Vault returned an error: %s (%s)", azErr.ErrorCode, azErr.RawResponse.Status))
			return
		}
		AbortWithErrorJSON(c, err)
		return
	}

	// Record the latency
	s.metrics.RecordLatency(state.Vault, time.Since(start))

	// Re-acquire a lock before modifying the state object and sending a notification
	s.lock.Lock()
	defer s.lock.Unlock()

	// Ensure the request hasn't expired in the meanwhile
	if state.Expired() || state.Status != StatusPending {
		_ = c.Error(errors.New("state object is expired after receiving response from Key Vault"))
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}

	// Store the result and mark as complete
	state.Result = output
	state.Value = nil
	state.Status = StatusComplete

	// Response
	c.Set("log-message", "Operation confirmed: "+stateId)
	c.JSON(http.StatusOK, struct {
		Confirmed bool `json:"confirmed"`
	}{
		Confirmed: true,
	})

	// Send a notification to the subscriber if any
	s.notifySubscriber(stateId, state)
}

// Handle cancellation of operations
func (s *Server) handleCancel(c *gin.Context, stateId string, state *requestState) {
	s.cancelRequest(stateId, state)

	// Response
	c.Set("log-message", "Operation canceled: "+stateId)
	c.JSON(http.StatusOK, struct {
		Canceled bool `json:"canceled"`
	}{
		Canceled: true,
	})
}

// Marks a request as canceled and sends a notification to the subscribers
func (s *Server) cancelRequest(stateId string, state *requestState) {
	// Re-acquire a lock before modifying the state object and sending a notification
	s.lock.Lock()
	defer s.lock.Unlock()

	// Mark the request as canceled and remove the input
	state.Value = nil
	state.Status = StatusCanceled

	// Send a notification to the subscriber if any
	s.notifySubscriber(stateId, state)

	// Record the result
	s.metrics.RecordResult("canceled")
}

type confirmRequest struct {
	StateId string `json:"state" form:"state"`
	Confirm bool   `json:"confirm" form:"confirm"`
	Cancel  bool   `json:"cancel" form:"cancel"`
}
