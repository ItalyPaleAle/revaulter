package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/cast"
	"github.com/spf13/viper"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/keyvault"
	"github.com/italypaleale/unlocker/pkg/utils"
)

// RouteRequestOperations is the handler for the routes that perform operations:
// - POST /request/encrypt
// - POST /request/decrypt
// - POST /request/sign
// - POST /request/verify
// - POST /request/wrap
// - POST /request/unwrap
func (s *Server) RouteRequestOperations(op requestOperation) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the fields from the body
		req := &subtleRequest{}
		err := c.Bind(req)
		if err != nil {
			_ = c.Error(err)
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request body"))
			return
		}
		err = req.Parse(op)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Invalid request: "+err.Error()))
			return
		}

		// Start the request process
		// First, store the request in the states map
		stateUuid, err := uuid.NewRandom()
		if err != nil {
			_ = c.Error(fmt.Errorf("failed to generate UUID: %w", err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		stateId := stateUuid.String()
		state := req.GetRequestState(op, c.ClientIP())

		// Use the lock to ensure we are not modifying s.states concurrently
		s.lock.Lock()
		s.states[stateId] = state
		s.lock.Unlock()

		s.metrics.RecordRequest(op.String(), req.Vault+"/"+req.KeyId)

		// Invoke the webhook and send a message with the URL to unlock, in background
		go func() {
			// Use a background context so it's not tied to the incoming request
			webhookErr := s.webhook.SendWebhook(context.Background(), &utils.WebhookRequest{
				OperationName: op.String(),
				KeyId:         state.KeyId,
				Vault:         state.Vault,
				StateId:       stateId,
				Requestor:     state.Requestor,
				Note:          state.Note,
			})
			if webhookErr != nil {
				s.log.Raw().Error().
					Err(webhookErr).
					Msg("Error sending webhook")
			}
		}()

		// Make the request expire in background
		go s.expireRequest(stateId, req.timeoutDuration)

		// Respond with the state ID
		c.JSON(http.StatusAccepted, operationResponse{
			State:   stateId,
			Pending: true,
		})

		// Send a notification to all subscribers, in background
		pub := state.Public(stateId)
		go s.pubsub.Publish(&pub)
	}
}

type subtleRequest struct {
	Vault      string `json:"vault" form:"vault"`
	KeyId      string `json:"keyId" form:"keyId"`
	KeyVersion string `json:"keyVersion" form:"keyVersion"`

	Algorithm      string `json:"algorithm" form:"algorithm"`
	Value          string `json:"value" form:"value"`
	Digest         string `json:"digest" form:"digest"`
	Signature      string `json:"signature" form:"digest"`
	AdditionalData string `json:"additionalData" form:"additionalData"`
	Nonce          string `json:"nonce" form:"nonce"`
	Tag            string `json:"tag" form:"tag"`

	Timeout any    `json:"timeout" form:"timeout"`
	Note    string `json:"note" form:"note"`

	timeoutDuration     time.Duration
	valueBytes          []byte
	digestBytes         []byte
	signatureBytes      []byte
	additionalDataBytes []byte
	nonceBytes          []byte
	tagBytes            []byte
}

var (
	durationNumber = regexp.MustCompile(`^[0-9]+$`)
	noteValidate   = regexp.MustCompile(`[^A-Za-z0-9 .\/_-]`)
)

// Parse and validate the request object
func (req *subtleRequest) Parse(op requestOperation) (err error) {
	if req.Vault == "" {
		return errors.New("missing parameter 'vault'")
	}
	if req.KeyId == "" {
		return errors.New("missing parameter 'keyId'")
	}
	if req.Note != "" && noteValidate.MatchString(req.Note) {
		return errors.New("parameter 'note' contains invalid characters (only `A-Za-z0-9 ._\\/-` are allowed)")
	}
	if len(req.Note) > 40 {
		return errors.New("parameter 'note' cannot be longer than 40 characters")
	}
	if req.Algorithm == "" {
		return errors.New("missing parameter 'algorithm'")
	}
	req.Algorithm = strings.ToUpper(req.Algorithm)
	if !keyvault.IsAlgorithmSupported(req.Algorithm) {
		return errors.New("invalid parameter 'algorithm'")
	}

	// Parse other values specific to the operation
	switch op {
	case OperationEncrypt, OperationDecrypt, OperationWrapKey, OperationUnwrapKey:
		if req.Value == "" {
			return errors.New("missing parameter 'value'")
		}

		// Decode the binary values
		req.valueBytes, err = utils.DecodeBase64String(req.Value)
		if err != nil {
			return errors.New("invalid 'value' format")
		}
		req.additionalDataBytes, err = utils.DecodeBase64String(req.AdditionalData)
		if err != nil {
			return errors.New("invalid 'additionalData' format")
		}
		req.nonceBytes, err = utils.DecodeBase64String(req.Nonce)
		if err != nil {
			return errors.New("invalid 'nonce' format")
		}
		req.tagBytes, err = utils.DecodeBase64String(req.Tag)
		if err != nil {
			return errors.New("invalid 'tag' format")
		}

	case OperationSign:
		if req.Digest == "" {
			return errors.New("missing parameter 'digest'")
		}

		// Decode the binary values
		req.digestBytes, err = utils.DecodeBase64String(req.Digest)
		if err != nil {
			return errors.New("invalid 'digest' format")
		}

	case OperationVerify:
		if req.Digest == "" {
			return errors.New("missing parameter 'digest'")
		}
		if req.Signature == "" {
			return errors.New("missing parameter 'signature'")
		}

		// Decode the binary values
		req.digestBytes, err = utils.DecodeBase64String(req.Digest)
		if err != nil {
			return errors.New("invalid 'digest' format")
		}
		req.signatureBytes, err = utils.DecodeBase64String(req.Signature)
		if err != nil {
			return errors.New("invalid 'signature' format")
		}
	}

	// Parse timeout
	// If it's just a number, interpret it as seconds
	// Otherwise, parse it as a Go duration
	timeoutStr := cast.ToString(req.Timeout)
	if timeoutStr == "" {
		req.timeoutDuration = viper.GetDuration(config.KeyRequestTimeout)
	} else if durationNumber.MatchString(timeoutStr) {
		timeout, _ := strconv.Atoi(timeoutStr)
		if timeout > 0 {
			req.timeoutDuration = time.Duration(timeout) * time.Second
		}
	} else {
		var timeout time.Duration
		timeout, err = time.ParseDuration(timeoutStr)
		if err != nil {
			return errors.New("invalid parameter 'timeout'")
		}
		if timeout >= time.Second {
			req.timeoutDuration = timeout
		}
	}

	// If we don't have the key version, or if it's "latest", we'll leave this empty and later we'll retrieve the latest version
	if strings.ToLower(req.KeyVersion) == "latest" {
		req.KeyVersion = ""
	}

	return nil
}

// GetRequestState returns the requestState object from this request
func (req *subtleRequest) GetRequestState(op requestOperation, requestor string) *requestState {
	now := time.Now()
	return &requestState{
		Operation: op,

		Vault:      req.Vault,
		KeyId:      req.KeyId,
		KeyVersion: req.KeyVersion,

		Algorithm:      req.Algorithm,
		Value:          req.valueBytes,
		Digest:         req.digestBytes,
		Signature:      req.signatureBytes,
		AdditionalData: req.additionalDataBytes,
		Nonce:          req.nonceBytes,
		Tag:            req.tagBytes,

		Requestor: requestor,
		Date:      now,
		Expiry:    now.Add(req.timeoutDuration),
		Note:      req.Note,
	}
}
