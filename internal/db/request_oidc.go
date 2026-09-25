package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"
)

// MaxRequestOIDCIssuersPerUser limits how many trusted OIDC issuers each user can configure
const MaxRequestOIDCIssuersPerUser = 25

var (
	ErrRequestOIDCIssuerNotFound = errors.New("OIDC issuer not found")
	ErrTooManyRequestOIDCIssuers = errors.New("too many OIDC issuers")
)

// RequestAuthMethods are the credentials the CLI can use to authenticate requests for a user
type RequestAuthMethods struct {
	// The static request key
	RequestKey bool
	// Short-lived JWTs signed by one of the user's trusted OIDC issuers
	OIDC bool
}

// RequestOIDCIssuer is a trusted OIDC issuer configured by a user
// A list of these is stored as JSON in the user's request_oidc column
type RequestOIDCIssuer struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
	Issuer      string `json:"issuer"`
	Audience    string `json:"audience"`
	Subject     string `json:"subject"`
	JWKSURL     string `json:"jwksUrl,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
}

// AddRequestOIDCIssuerInput contains the fields for a new trusted OIDC issuer
// Values must already be validated and normalized by the caller
type AddRequestOIDCIssuerInput struct {
	DisplayName string
	Issuer      string
	Audience    string
	Subject     string
	JWKSURL     string
}

// UpdateRequestAuthMethods sets which credentials the CLI can use to authenticate requests for the user
func (s *AuthStore) UpdateRequestAuthMethods(ctx context.Context, userID string, methods RequestAuthMethods) error {
	// Only allow mutations for users that are active and have completed setup
	affected, err := s.db.Exec(ctx,
		`UPDATE v2_users SET request_key_enabled = $1, request_oidc_enabled = $2, updated_at = $3 WHERE id = $4 AND status = 'active' AND ready = true`,
		methods.RequestKey, methods.OIDC, time.Now().Unix(), userID,
	)
	if err != nil {
		return err
	}

	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// AddRequestOIDCIssuer adds a trusted OIDC issuer to the user, and returns the new entry together with the updated list
// Returns ErrTooManyRequestOIDCIssuers when the user already has the maximum number of issuers
// It must be invoked in a transaction
func (s *AuthStore) AddRequestOIDCIssuer(ctx context.Context, userID string, in AddRequestOIDCIssuerInput) (*RequestOIDCIssuer, []RequestOIDCIssuer, error) {
	added := RequestOIDCIssuer{
		ID:          uuid.NewV4().String(),
		DisplayName: strings.TrimSpace(in.DisplayName),
		Issuer:      in.Issuer,
		Audience:    in.Audience,
		Subject:     in.Subject,
		JWKSURL:     in.JWKSURL,
		CreatedAt:   time.Now().Unix(),
	}

	list, err := s.updateRequestOIDC(ctx, userID, func(list []RequestOIDCIssuer) ([]RequestOIDCIssuer, error) {
		if len(list) >= MaxRequestOIDCIssuersPerUser {
			return nil, ErrTooManyRequestOIDCIssuers
		}

		return append(list, added), nil
	})
	if err != nil {
		return nil, nil, err
	}

	return &added, list, nil
}

// DeleteRequestOIDCIssuer removes a trusted OIDC issuer from the user, and returns the deleted entry together with the updated list
// It must be invoked in a transaction
func (s *AuthStore) DeleteRequestOIDCIssuer(ctx context.Context, userID string, id string) (*RequestOIDCIssuer, []RequestOIDCIssuer, error) {
	var deleted RequestOIDCIssuer
	list, err := s.updateRequestOIDC(ctx, userID, func(list []RequestOIDCIssuer) ([]RequestOIDCIssuer, error) {
		// Filter the issuer out of the list
		var j int
		for i, e := range list {
			if e.ID == id {
				deleted = e
			} else {
				list[j] = list[i]
				j++
			}
		}
		if deleted.ID == "" {
			return nil, ErrRequestOIDCIssuerNotFound
		}

		return list[:j], nil
	})
	if err != nil {
		return nil, nil, err
	}

	return &deleted, list, nil
}

// updateRequestOIDC applies fn to the user's trusted OIDC issuers and stores the result
// It must be invoked in a transaction, which holds a lock on the user's row until it ends, so concurrent changes are serialized instead of lost
func (s *AuthStore) updateRequestOIDC(ctx context.Context, userID string, fn func(list []RequestOIDCIssuer) ([]RequestOIDCIssuer, error)) ([]RequestOIDCIssuer, error) {
	// Must be invoked as a transaction
	if !s.db.IsTransaction() {
		// Indicates a development-time error
		panic("updateRequestOIDC must be invoked in a transaction")
	}

	// On Postgres, lock the row with FOR UPDATE
	// SQLite transactions take the write lock when they begin (txlock=immediate), so they're already serialized
	query := `SELECT request_oidc FROM v2_users WHERE id = $1 AND status = 'active' AND ready = true`
	jsonParam := "$1"
	if s.kind == BackendPostgres {
		query += ` FOR UPDATE`
		jsonParam = "$1::jsonb"
	}

	// Only allow mutations for users that are active and have completed setup
	var raw []byte
	err := s.db.QueryRow(ctx, query, userID).Scan(&raw)
	if s.db.IsNoRowsError(err) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	list, err := parseRequestOIDC(raw)
	if err != nil {
		return nil, err
	}

	list, err = fn(list)
	if err != nil {
		return nil, err
	}

	updated, err := json.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("failed to encode OIDC issuers: %w", err)
	}

	_, err = s.db.Exec(ctx,
		`UPDATE v2_users SET request_oidc = `+jsonParam+`, updated_at = $2 WHERE id = $3`,
		string(updated), time.Now().Unix(), userID,
	)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// parseRequestOIDC decodes the JSON stored in the request_oidc column
// It always returns a non-nil slice
func parseRequestOIDC(raw []byte) ([]RequestOIDCIssuer, error) {
	list := []RequestOIDCIssuer{}
	if len(raw) == 0 {
		return list, nil
	}

	err := json.Unmarshal(raw, &list)
	if err != nil {
		return nil, fmt.Errorf("failed to decode OIDC issuers: %w", err)
	}

	if list == nil {
		list = []RequestOIDCIssuer{}
	}

	return list, nil
}
