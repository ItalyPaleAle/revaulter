//go:build e2e

// This file includes routes for the e2e tests, and it's only built with the "e2e" tag

package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

const e2eHeaderToken = "x-revaulter-e2e-token"

type e2eOKResponse struct {
	OK bool `json:"ok"`
}

type e2eSeedUserResponse struct {
	OK          bool   `json:"ok"`
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	RequestKey  string `json:"requestKey"`
	Ready       bool   `json:"ready"`
}

type e2eSeedSessionResponse struct {
	OK          bool   `json:"ok"`
	SessionID   string `json:"sessionId"`
	CookieName  string `json:"cookieName"`
	CookiePath  string `json:"cookiePath"`
	CookieValue string `json:"cookieValue"`
}

type e2eSeedRequestResponse struct {
	OK     bool   `json:"ok"`
	State  string `json:"state"`
	Status string `json:"status"`
}

type e2eGetRequestResponse struct {
	State     string `json:"state"`
	Status    string `json:"status"`
	Operation string `json:"operation"`
	UserID    string `json:"userId"`
	KeyLabel  string `json:"keyLabel"`
	Algorithm string `json:"algorithm"`
	Requestor string `json:"requestor"`
	Note      string `json:"note"`
}

type e2eGetRequestResultResponse struct {
	State            string          `json:"state"`
	Status           string          `json:"status"`
	Operation        string          `json:"operation"`
	UserID           string          `json:"userId"`
	KeyLabel         string          `json:"keyLabel"`
	Algorithm        string          `json:"algorithm"`
	Requestor        string          `json:"requestor"`
	Note             string          `json:"note"`
	EncryptedRequest json.RawMessage `json:"encryptedRequest"`
	ResponseEnvelope any             `json:"responseEnvelope"`
}

type e2eSeedCredentialResponse struct {
	OK           bool   `json:"ok"`
	CredentialID string `json:"credentialId"`
}

type e2eSeedUserRequest struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Password    string `json:"password,omitempty"`
}

type e2eSeedSessionRequest struct {
	UserID string `json:"userId"`
}

type e2eSeedRequestRequest struct {
	UserID     string `json:"userId"`
	Operation  string `json:"operation"`
	KeyLabel   string `json:"keyLabel"`
	Algorithm  string `json:"algorithm"`
	Requestor  string `json:"requestor"`
	Note       string `json:"note,omitempty"`
	TimeoutSec int    `json:"timeoutSec,omitempty"`
	State      string `json:"state,omitempty"`
	Status     string `json:"status,omitempty"`
}

func AddE2ETestRoutes(token string) func(s *Server, r gin.IRouter) {
	return func(s *Server, r gin.IRouter) {
		group := r.Group("/__e2e__")

		group.Use(func(c *gin.Context) {
			if token == "" || c.GetHeader(e2eHeaderToken) != token {
				AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "invalid e2e token"))
				return
			}
		})

		group.POST("/reset", s.RouteE2EReset)
		group.POST("/seed-user", s.RouteE2ESeedUser)
		group.POST("/seed-session", s.RouteE2ESeedSession)
		group.POST("/seed-request", s.RouteE2ESeedRequest)
		group.POST("/seed-credential", s.RouteE2ESeedCredential)
		group.GET("/request/:state", s.RouteE2EGetRequest)
		group.GET("/request/:state/result", s.RouteE2EGetRequestResult)
	}
}

func init() {
	authRateLimitRPM = 10_000

	token := strings.TrimSpace(os.Getenv("REVAULTER_E2E_TOKEN"))
	if token == "" {
		return
	}

	testRoutes = append(testRoutes, AddE2ETestRoutes(token))
}

// RouteE2EReset is the handler for POST /__e2e__/reset
func (s *Server) RouteE2EReset(c *gin.Context) {
	// Reset the database
	err := s.db.ResetAllForTests(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	s.lock.Lock()
	s.subs = map[string][]chan struct{}{}
	s.lock.Unlock()

	c.JSON(http.StatusOK, e2eOKResponse{OK: true})
}

// RouteE2ESeedUser is the handler for POST /__e2e__/seed-user
func (s *Server) RouteE2ESeedUser(c *gin.Context) {
	// Parse the request body and validate
	var req e2eSeedUserRequest
	bindErr := c.ShouldBindJSON(&req)
	if bindErr != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.UserID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "userId is required"))
		return
	}
	if req.State == "" {
		req.State = "ready-no-password"
	}

	// Execute the rest in a transaction
	user, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Minute, func(ctx context.Context, tx *db.DbTx) (*db.User, error) {
		as := tx.AuthStore()

		_, err := as.RegisterUser(c.Request.Context(), db.RegisterUserInput{
			UserID:         req.UserID,
			DisplayName:    req.DisplayName,
			WebAuthnUserID: base64.RawURLEncoding.EncodeToString([]byte("e2e-webauthn-" + req.UserID)),
			CredentialID:   "e2e-cred-" + req.UserID,
			PublicKey:      `{}`,
			SignCount:      1,
			SessionTTL:     config.Get().SessionTimeout,
		})
		if err != nil && !errors.Is(err, db.ErrUserAlreadyExists) {
			return nil, err
		}

		switch req.State {
		case "registered-nonready":
			// Keep the user unfinalized
		case "ready-no-password", "ready-with-password":
			user, getUserErr := as.GetUserByID(c.Request.Context(), req.UserID)
			if getUserErr != nil {
				return nil, getUserErr
			}
			if user == nil {
				return nil, NewResponseError(http.StatusNotFound, "User not found")
			}

			if !user.Ready {
				requestEncPriv, err := ecdh.P256().GenerateKey(rand.Reader)
				if err != nil {
					return nil, err
				}
				requestEncJWK, err := protocolv2.ECP256PublicJWKFromECDH(requestEncPriv.PublicKey())
				if err != nil {
					return nil, err
				}
				requestEncJWKJSON, err := json.Marshal(requestEncJWK)
				if err != nil {
					return nil, err
				}

				wrappedKey := ""
				if req.State == "ready-with-password" {
					if req.Password == "" {
						return nil, NewResponseError(http.StatusBadRequest, "password is required for ready-with-password state")
					}
					// Store a placeholder wrapped key so the login flow returns it
					wrappedKey = "e2e-wrapped-key-" + req.UserID
				}

				_, err = as.FinalizeSignup(
					c.Request.Context(),
					db.FinalizeSignupInput{
						UserID:                req.UserID,
						WrappedPrimaryKey:     wrappedKey,
						RequestEncEcdhPubkey:  string(requestEncJWKJSON),
						RequestEncMlkemPubkey: base64.RawURLEncoding.EncodeToString([]byte("test-mlkem-pubkey-" + req.UserID)),
					},
				)
				if err != nil && !errors.Is(err, db.ErrAlreadyFinalized) {
					return nil, err
				}
			}
		default:
			return nil, NewResponseError(http.StatusBadRequest, "unsupported seed user state")
		}

		user, err := as.GetUserByID(c.Request.Context(), req.UserID)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, NewResponseError(http.StatusNotFound, "User not found")
		}
		return user, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, e2eSeedUserResponse{
		OK:          true,
		UserID:      user.ID,
		DisplayName: user.DisplayName,
		RequestKey:  user.RequestKey,
		Ready:       user.Ready,
	})
}

// RouteE2ESeedSession is the handler for /__e2e__/seed-session
func (s *Server) RouteE2ESeedSession(c *gin.Context) {
	// Parse the request body
	var req e2eSeedSessionRequest
	bindErr := c.ShouldBindJSON(&req)
	if bindErr != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.UserID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "userId is required"))
		return
	}

	user, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Minute, func(ctx context.Context, tx *db.DbTx) (*db.User, error) {
		as := tx.AuthStore()

		user, err := as.GetUserByID(c.Request.Context(), req.UserID)
		if err != nil {
			return nil, err
		}

		err = as.Login(c.Request.Context(), db.LoginInput{
			UserID:       req.UserID,
			CredentialID: "e2e-cred-" + req.UserID,
			SignCount:    2,
			SessionTTL:   config.Get().SessionTimeout,
		})
		if err != nil {
			return nil, err
		}

		return user, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Create a new session token
	sess, err := newAuthSessionToken(user, config.Get().SessionTimeout)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Sign the session token
	token, err := signAuthSessionToken(sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	cookieName := sessionCookieNameInsecure
	cookiePath := "/"
	if config.Get().ForceSecureCookies {
		cookieName = sessionCookieNameSecure
		cookiePath = "/"
	}

	// Send response
	c.JSON(http.StatusOK, e2eSeedSessionResponse{
		OK:          true,
		SessionID:   token,
		CookieName:  cookieName,
		CookiePath:  cookiePath,
		CookieValue: token,
	})
}

// RouteE2ESeedRequest is the handler for /__e2e__/seed-request
func (s *Server) RouteE2ESeedRequest(c *gin.Context) {
	// Read the request body and populate default values if unset
	var req e2eSeedRequestRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.UserID == "" || req.Operation == "" || req.KeyLabel == "" || req.Algorithm == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "userId, operation, keyLabel, and algorithm are required"))
		return
	}
	if req.Requestor == "" {
		req.Requestor = "198.51.100.20"
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = 300
	}
	if req.State == "" {
		req.State = uuid.NewString()
	}
	if req.Status == "" {
		req.Status = string(db.V2RequestStatusPending)
	}

	rs := s.db.RequestStore()

	// Note: we are not using a transaction here as this is just test code
	// Create the request in the database
	now := time.Now().UTC()
	encryptedRequest := `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"mlkemCiphertext":"dGVzdC1tbGtlbS1jaXBoZXJ0ZXh0","nonce":"MTIzNDU2Nzg5MDEy","ciphertext":"dGVzdC1yZXF1ZXN0LWNpcGhlcnRleHQifQ}`
	err = rs.CreateRequest(c.Request.Context(), db.CreateRequestInput{
		State:            req.State,
		UserID:           req.UserID,
		Operation:        req.Operation,
		RequestorIP:      req.Requestor,
		KeyLabel:         req.KeyLabel,
		Algorithm:        req.Algorithm,
		Note:             req.Note,
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Duration(req.TimeoutSec) * time.Second),
		EncryptedRequest: encryptedRequest,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Update the request if needed
	switch req.Status {
	case string(db.V2RequestStatusPending):
		// Publish the pending item
		s.publishListItem(&db.V2RequestListItem{
			State:     req.State,
			Status:    req.Status,
			Operation: req.Operation,
			UserID:    req.UserID,
			KeyLabel:  req.KeyLabel,
			Algorithm: req.Algorithm,
			Requestor: req.Requestor,
			Date:      now.Unix(),
			Expiry:    now.Add(time.Duration(req.TimeoutSec) * time.Second).Unix(),
			Note:      req.Note,
		})
	case string(db.V2RequestStatusCanceled):
		_, err = rs.CancelRequest(c.Request.Context(), req.State, req.UserID)
	case string(db.V2RequestStatusCompleted):
		_, err = rs.CompleteRequest(c.Request.Context(), req.State, req.UserID, protocolv2.ResponseEnvelope{
			TransportAlg: protocolv2.TransportAlg,
			BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
				Kty: "EC",
				Crv: "P-256",
				X:   "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Y:   "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			MlkemCiphertext: "dGVzdC1yZXNwb25zZS1tbGtlbS1jaXBoZXJ0ZXh0",
			Nonce:           "MTIzNDU2Nzg5MDEy",
			Ciphertext:      "dGVzdC1yZXNwb25zZS1jaXBoZXJ0ZXh0",
			ResultType:      "bytes",
		})
	case string(db.V2RequestStatusExpired):
		execErr := rs.ForceExpireRequestForTests(c.Request.Context(), req.State, now.Add(-time.Second))
		if execErr == nil {
			_, err = rs.MarkExpired(c.Request.Context(), req.State)
		} else {
			err = execErr
		}
	default:
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "unsupported request status"))
		return
	}
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send the response
	c.JSON(http.StatusOK, e2eSeedRequestResponse{
		OK:     true,
		State:  req.State,
		Status: req.Status,
	})
}

// RouteE2EGetRequest is the handler for /__e2e__/request/:state
func (s *Server) RouteE2EGetRequest(c *gin.Context) {
	state := c.Param("state")

	// Retrieve the request form the database
	rec, err := s.db.RequestStore().GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request not found"))
		return
	}

	// Send response
	c.JSON(http.StatusOK, e2eGetRequestResponse{
		State:     rec.State,
		Status:    string(rec.Status),
		Operation: rec.Operation,
		UserID:    rec.UserID,
		KeyLabel:  rec.KeyLabel,
		Algorithm: rec.Algorithm,
		Requestor: rec.RequestorIP,
		Note:      rec.Note,
	})
}

// RouteE2EGetRequestResult is the handler for /__e2e__/request/:state/result
func (s *Server) RouteE2EGetRequestResult(c *gin.Context) {
	state := c.Param("state")

	// Retrieve the request form the database
	rec, err := s.db.RequestStore().GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request not found"))
		return
	}

	// Send response
	c.JSON(http.StatusOK, e2eGetRequestResultResponse{
		State:            rec.State,
		Status:           string(rec.Status),
		Operation:        rec.Operation,
		UserID:           rec.UserID,
		KeyLabel:         rec.KeyLabel,
		Algorithm:        rec.Algorithm,
		Requestor:        rec.RequestorIP,
		Note:             rec.Note,
		EncryptedRequest: json.RawMessage(rec.EncryptedRequest),
		ResponseEnvelope: rec.ResponseEnvelope,
	})
}

type e2eSeedCredentialRequest struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
}

// RouteE2ESeedCredential is the handler for /__e2e__/seed-credential
func (s *Server) RouteE2ESeedCredential(c *gin.Context) {
	// Parse and validate the request body
	var req e2eSeedCredentialRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.UserID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "userId is required"))
		return
	}

	// Store the credential in the database
	credID := "e2e-cred-extra-" + uuid.NewString()[:8]
	err = s.db.AuthStore().AddCredential(c.Request.Context(), db.AddCredentialInput{
		UserID:       req.UserID,
		CredentialID: credID,
		DisplayName:  req.DisplayName,
		PublicKey:    `{}`,
		SignCount:    0,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, e2eSeedCredentialResponse{
		OK:           true,
		CredentialID: credID,
	})
}
