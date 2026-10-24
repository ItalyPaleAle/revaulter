package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// PairingSession is a pairing session between an unlocked client and a new device
type PairingSession struct {
	ID     string
	UserID string
	Status string
	// Server is the base URL the existing client put in the pairing payload
	Server string
	// Hello is the device's protocolv2.PairingHello as JSON, set once the device sends it
	Hello string
	// Nonce and NonceMAC are set by the existing client after it accepts the hello
	Nonce     string
	NonceMAC  string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

var (
	ErrPairingSessionNotFound = errors.New("pairing session not found")
	// ErrPairingSessionState is returned when a session exists but is expired, finished, or not at the step the change needs
	ErrPairingSessionState = errors.New("pairing session is expired or not in the expected state")
)

// pairingOpenStatuses lists the statuses of a session that is still in progress, as a SQL list
const pairingOpenStatuses = `('` + protocolv2.PairingStatusCreated + `', '` + protocolv2.PairingStatusHello + `', '` + protocolv2.PairingStatusNonce + `')`

const pairingSessionColumns = `id, user_id, status, server, hello, nonce, nonce_mac, created_at, updated_at, expires_at`

func scanPairingSession(scanner interface{ Scan(dest ...any) error }) (*PairingSession, error) {
	var (
		p                              PairingSession
		createdAt, updatedAt, expireAt int64
	)
	err := scanner.Scan(&p.ID, &p.UserID, &p.Status, &p.Server, &p.Hello, &p.Nonce, &p.NonceMAC, &createdAt, &updatedAt, &expireAt)
	if err != nil {
		return nil, err
	}

	p.CreatedAt = time.Unix(createdAt, 0)
	p.UpdatedAt = time.Unix(updatedAt, 0)
	p.ExpiresAt = time.Unix(expireAt, 0)

	return &p, nil
}

// IsOpen reports whether the session is still in progress at the given time
func (p *PairingSession) IsOpen(now time.Time) bool {
	switch p.Status {
	case protocolv2.PairingStatusCreated, protocolv2.PairingStatusHello, protocolv2.PairingStatusNonce:
		return !now.After(p.ExpiresAt)
	default:
		return false
	}
}

// CreatePairingSession opens a pairing session for the user
// Any session the user still has open is canceled first, so only the newest payload can be used
func (s *AuthStore) CreatePairingSession(ctx context.Context, userID string, server string, ttl time.Duration) (*PairingSession, error) {
	// Must be invoked as a transaction
	if !s.db.IsTransaction() {
		// Indicates a development-time error
		panic("CreatePairingSession must be invoked in a transaction")
	}

	idBytes := make([]byte, protocolv2.PairingSessionIDSize)
	_, err := rand.Read(idBytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	p := &PairingSession{
		ID:        base64.RawURLEncoding.EncodeToString(idBytes),
		UserID:    userID,
		Status:    protocolv2.PairingStatusCreated,
		Server:    server,
		CreatedAt: time.Unix(now.Unix(), 0),
		UpdatedAt: time.Unix(now.Unix(), 0),
		ExpiresAt: time.Unix(now.Add(ttl).Unix(), 0),
	}

	_, err = s.db.Exec(ctx,
		`UPDATE v2_pairing_sessions SET status = $1, updated_at = $2 WHERE user_id = $3 AND status IN `+pairingOpenStatuses,
		protocolv2.PairingStatusCanceled, now.Unix(), userID,
	)
	if err != nil {
		return nil, err
	}

	// Gate the insert on the user being active and ready, like the other credential changes
	affected, err := s.db.Exec(ctx,
		`INSERT INTO v2_pairing_sessions (id, user_id, status, server, created_at, updated_at, expires_at)
			SELECT $1, $2, $3, $4, $5, $5, $6
			WHERE EXISTS (SELECT 1 FROM v2_users WHERE id = $2 AND status = 'active' AND ready = true)`,
		p.ID, p.UserID, p.Status, p.Server, now.Unix(), p.ExpiresAt.Unix(),
	)
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, ErrUserNotFound
	}

	return p, nil
}

// GetPairingSession returns a pairing session by ID, whatever its status
func (s *AuthStore) GetPairingSession(ctx context.Context, id string) (*PairingSession, error) {
	p, err := scanPairingSession(s.db.QueryRow(ctx,
		`SELECT `+pairingSessionColumns+` FROM v2_pairing_sessions WHERE id = $1`,
		id,
	))
	if s.db.IsNoRowsError(err) {
		return nil, ErrPairingSessionNotFound
	} else if err != nil {
		return nil, err
	}

	return p, nil
}

// SetPairingHello stores the device's hello, moving the session from created to hello
// It succeeds only once per session, and only before the session expires
func (s *AuthStore) SetPairingHello(ctx context.Context, id string, helloJSON string, now time.Time) error {
	return s.advancePairingSession(ctx,
		`UPDATE v2_pairing_sessions SET status = $1, hello = $2, updated_at = $3
			WHERE id = $4 AND status = $5 AND expires_at >= $3`,
		protocolv2.PairingStatusHello, helloJSON, now.Unix(), id, protocolv2.PairingStatusCreated,
	)
}

// SetPairingNonce stores the existing client's nonce and its MAC, moving the session from hello to nonce
// The session must belong to userID
func (s *AuthStore) SetPairingNonce(ctx context.Context, id string, userID string, nonce string, nonceMAC string, now time.Time) error {
	return s.advancePairingSession(ctx,
		`UPDATE v2_pairing_sessions SET status = $1, nonce = $2, nonce_mac = $3, updated_at = $4
			WHERE id = $5 AND user_id = $6 AND status = $7 AND expires_at >= $4`,
		protocolv2.PairingStatusNonce, nonce, nonceMAC, now.Unix(), id, userID, protocolv2.PairingStatusHello,
	)
}

// CompletePairing adds the device credential and closes the session in one transaction
// The session must belong to the credential's user, be at the nonce step, and not be expired
func (s *AuthStore) CompletePairing(ctx context.Context, id string, credential AddCredentialInput, now time.Time) error {
	// Must be invoked as a transaction
	if !s.db.IsTransaction() {
		// Indicates a development-time error
		panic("CompletePairing must be invoked in a transaction")
	}

	if credential.CredentialType != protocolv2.CredentialTypeDevice {
		return fmt.Errorf("pairing can only add device credentials, got %q", credential.CredentialType)
	}

	err := s.advancePairingSession(ctx,
		`UPDATE v2_pairing_sessions SET status = $1, updated_at = $2
			WHERE id = $3 AND user_id = $4 AND status = $5 AND expires_at >= $2`,
		protocolv2.PairingStatusCompleted, now.Unix(), id, credential.UserID, protocolv2.PairingStatusNonce,
	)
	if err != nil {
		return err
	}

	return s.AddCredential(ctx, credential)
}

// CancelPairingSession cancels a session that is still in progress
// The session must belong to userID
func (s *AuthStore) CancelPairingSession(ctx context.Context, id string, userID string, now time.Time) error {
	return s.advancePairingSession(ctx,
		`UPDATE v2_pairing_sessions SET status = $1, updated_at = $2
			WHERE id = $3 AND user_id = $4 AND status IN `+pairingOpenStatuses,
		protocolv2.PairingStatusCanceled, now.Unix(), id, userID,
	)
}

// HasOpenPairingSession reports whether the user has a pairing session in progress
func (s *AuthStore) HasOpenPairingSession(ctx context.Context, userID string, now time.Time) (bool, error) {
	var exists bool
	err := s.db.
		QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM v2_pairing_sessions WHERE user_id = $1 AND status IN `+pairingOpenStatuses+` AND expires_at >= $2)`,
			userID, now.Unix(),
		).
		Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

// DeleteExpiredPairingSession deletes a session once it expired more than 10 minutes before now
func (s *AuthStore) DeleteExpiredPairingSession(ctx context.Context, id string, now time.Time) error {
	cutoff := now.Add(-10 * time.Minute).Unix()
	_, err := s.db.Exec(ctx,
		`DELETE FROM v2_pairing_sessions WHERE id = $1 AND expires_at < $2`,
		id, cutoff,
	)
	if err != nil {
		return fmt.Errorf("error deleting pairing session: %w", err)
	}

	return nil
}

// advancePairingSession runs a conditional status change and returns ErrPairingSessionState when no row matched
// Callers that need to tell a missing session apart load it with GetPairingSession first
func (s *AuthStore) advancePairingSession(ctx context.Context, query string, args ...any) error {
	affected, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	return ErrPairingSessionState
}
