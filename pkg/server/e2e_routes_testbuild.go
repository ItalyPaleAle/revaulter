//go:build e2e

// This file includes routes for the e2e tests, and it's only built with the "e2e" tag

package server

import (
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
			c.Next()
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

func (s *Server) RouteE2EReset(c *gin.Context) {
	if s.db == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "database is not configured"))
		return
	}

	err := s.db.ResetAllForTests(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	s.lock.Lock()
	s.subs = map[string]chan struct{}{}
	s.lock.Unlock()

	c.JSON(http.StatusOK, e2eOKResponse{OK: true})
}

func (s *Server) RouteE2ESeedUser(c *gin.Context) {
	var req e2eSeedUserRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
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

	_, err = s.authStore.RegisterUser(c.Request.Context(), db.RegisterUserInput{
		UserID:         req.UserID,
		DisplayName:    req.DisplayName,
		WebAuthnUserID: base64.RawURLEncoding.EncodeToString([]byte("e2e-webauthn-" + req.UserID)),
		CredentialID:   "e2e-cred-" + req.UserID,
		PublicKey:      `{}`,
		SignCount:      1,
		SessionTTL:     config.Get().SessionTimeout,
	})
	if err != nil && !errors.Is(err, db.ErrUserAlreadyExists) {
		AbortWithErrorJSON(c, err)
		return
	}

	switch req.State {
	case "registered-nonready":
		// Keep the user unfinalized
	case "ready-no-password", "ready-with-password":
		user, getUserErr := s.authStore.GetUserByID(c.Request.Context(), req.UserID)
		if getUserErr != nil {
			AbortWithErrorJSON(c, getUserErr)
			return
		}
		if user == nil {
			AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "User not found"))
			return
		}

		if !user.Ready {
			requestEncPriv, keyErr := ecdh.P256().GenerateKey(rand.Reader)
			if keyErr != nil {
				AbortWithErrorJSON(c, keyErr)
				return
			}
			requestEncJWK, keyErr := protocolv2.ECP256PublicJWKFromECDH(requestEncPriv.PublicKey())
			if keyErr != nil {
				AbortWithErrorJSON(c, keyErr)
				return
			}
			requestEncJWKJSON, keyErr := json.Marshal(requestEncJWK)
			if keyErr != nil {
				AbortWithErrorJSON(c, keyErr)
				return
			}

			wrappedKey := ""
			if req.State == "ready-with-password" {
				if req.Password == "" {
					AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "password is required for ready-with-password state"))
					return
				}
				// Store a placeholder wrapped key so the login flow returns it
				wrappedKey = "e2e-wrapped-key-" + req.UserID
			}

			keyErr = s.authStore.FinalizeSignup(
				c.Request.Context(),
				req.UserID,
				wrappedKey,
				string(requestEncJWKJSON),
				base64.RawURLEncoding.EncodeToString([]byte("test-mlkem-pubkey-"+req.UserID)),
			)
			if keyErr != nil && !errors.Is(keyErr, db.ErrAlreadyFinalized) {
				AbortWithErrorJSON(c, keyErr)
				return
			}
		}
	default:
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "unsupported seed user state"))
		return
	}

	user, err := s.authStore.GetUserByID(c.Request.Context(), req.UserID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if user == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "User not found"))
		return
	}

	c.JSON(http.StatusOK, e2eSeedUserResponse{
		OK:          true,
		UserID:      user.ID,
		DisplayName: user.DisplayName,
		RequestKey:  user.RequestKey,
		Ready:       user.Ready,
	})
}

func (s *Server) RouteE2ESeedSession(c *gin.Context) {
	var req e2eSeedSessionRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.UserID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "userId is required"))
		return
	}

	sess, err := s.authStore.Login(c.Request.Context(), db.LoginInput{
		UserID:       req.UserID,
		CredentialID: "e2e-cred-" + req.UserID,
		SignCount:    2,
		SessionTTL:   config.Get().SessionTimeout,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	cookieName := sessionCookieNameInsecure
	cookiePath := "/v2"
	if config.Get().ForceSecureCookies {
		cookieName = sessionCookieNameSecure
		cookiePath = "/"
	}

	c.JSON(http.StatusOK, e2eSeedSessionResponse{
		OK:          true,
		SessionID:   sess.ID,
		CookieName:  cookieName,
		CookiePath:  cookiePath,
		CookieValue: sess.ID,
	})
}

func (s *Server) RouteE2ESeedRequest(c *gin.Context) {
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

	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = string(db.V2RequestStatusPending)
	}

	now := time.Now().UTC()
	encryptedRequest := `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"mlkemCiphertext":"dGVzdC1tbGtlbS1jaXBoZXJ0ZXh0","nonce":"MTIzNDU2Nzg5MDEy","ciphertext":"dGVzdC1yZXF1ZXN0LWNpcGhlcnRleHQifQ}`
	err = s.requestStore.CreateRequest(c.Request.Context(), db.CreateRequestInput{
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

	switch status {
	case string(db.V2RequestStatusPending):
		// nothing else to do
	case string(db.V2RequestStatusCanceled):
		_, err = s.requestStore.CancelRequest(c.Request.Context(), req.State, req.UserID)
	case string(db.V2RequestStatusCompleted):
		_, err = s.requestStore.CompleteRequest(c.Request.Context(), req.State, req.UserID, protocolv2.ResponseEnvelope{
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
		execErr := s.requestStore.ForceExpireRequestForTests(c.Request.Context(), req.State, now.Add(-time.Second))
		if execErr == nil {
			_, err = s.requestStore.MarkExpired(c.Request.Context(), req.State)
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

	if status == string(db.V2RequestStatusPending) {
		s.publishListItem(&db.V2RequestListItem{
			State:     req.State,
			Status:    status,
			Operation: req.Operation,
			UserID:    req.UserID,
			KeyLabel:  req.KeyLabel,
			Algorithm: req.Algorithm,
			Requestor: req.Requestor,
			Date:      now.Unix(),
			Expiry:    now.Add(time.Duration(req.TimeoutSec) * time.Second).Unix(),
			Note:      req.Note,
		})
	}

	c.JSON(http.StatusOK, e2eSeedRequestResponse{
		OK:     true,
		State:  req.State,
		Status: status,
	})
}

func (s *Server) RouteE2EGetRequest(c *gin.Context) {
	state := c.Param("state")
	rec, err := s.requestStore.GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request not found"))
		return
	}

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

func (s *Server) RouteE2EGetRequestResult(c *gin.Context) {
	state := c.Param("state")
	rec, err := s.requestStore.GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request not found"))
		return
	}

	var responseEnvelope any
	if rec.ResponseEnvelope != nil {
		responseEnvelope = rec.ResponseEnvelope
	}

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
		ResponseEnvelope: responseEnvelope,
	})
}

type e2eSeedCredentialRequest struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
}

func (s *Server) RouteE2ESeedCredential(c *gin.Context) {
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

	credID := "e2e-cred-extra-" + uuid.NewString()[:8]
	err = s.authStore.AddCredential(c.Request.Context(), db.AddCredentialInput{
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

	c.JSON(http.StatusOK, e2eSeedCredentialResponse{
		OK:           true,
		CredentialID: credID,
	})
}
