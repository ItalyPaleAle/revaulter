package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func TestRequestStoreLifecycle(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-1",
		DisplayName:    "Alice",
		WebAuthnUserID: "webauthn-user-1",
		CredentialID:   "cred-1",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-1",
		UserID:           "user-1",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "boot-disk",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	list, err := store.ListPending(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "state-1", list[0].State)

	rec, err := store.GetRequest(ctx, "state-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusPending, rec.Status)
	require.Equal(t, "user-1", rec.UserID)
	require.Contains(t, rec.EncryptedRequest, "cliEphemeralPublicKey")
	require.Nil(t, rec.ResponseEnvelope)

	completed, err := store.CompleteRequest(ctx, "state-1", "user-1", protocolv2.ResponseEnvelope{
		TransportAlg: protocolv2.TransportAlg,
		BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		Nonce:      "bm9uY2U",
		Ciphertext: "Y2lwaGVy",
	})
	require.NoError(t, err)
	require.NotNil(t, completed)
	require.Equal(t, V2RequestStatusCompleted, completed.Status)
	require.NotNil(t, completed.ResponseEnvelope)

	rec, err = store.GetRequest(ctx, "state-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusCompleted, rec.Status)
	require.NotNil(t, rec.ResponseEnvelope)
	require.Equal(t, protocolv2.TransportAlg, rec.ResponseEnvelope.TransportAlg)
}

func TestRequestStoreCancel(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-2",
		DisplayName:    "Bob",
		WebAuthnUserID: "webauthn-user-2",
		CredentialID:   "cred-2",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-2",
		UserID:           "user-2",
		Operation:        "decrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "x",
		Algorithm:        "A256GCM",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"t","y":"t"},"nonce":"n","ciphertext":"c"}`,
	})
	require.NoError(t, err)

	canceled, err := store.CancelRequest(ctx, "state-2", "user-2")
	require.NoError(t, err)
	require.NotNil(t, canceled)
	require.Equal(t, V2RequestStatusCanceled, canceled.Status)

	rec, err := store.GetRequest(ctx, "state-2")
	require.NoError(t, err)
	require.Equal(t, V2RequestStatusCanceled, rec.Status)
}

func TestRequestStoreGetAndDeleteTerminalRequest(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-get-delete",
		DisplayName:    "Get Delete User",
		WebAuthnUserID: "webauthn-user-get-delete",
		CredentialID:   "cred-get-delete",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-terminal",
		UserID:           "user-get-delete",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "terminal-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	_, err = store.CompleteRequest(ctx, "state-terminal", "user-get-delete", protocolv2.ResponseEnvelope{
		TransportAlg: protocolv2.TransportAlg,
		BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		Nonce:      "bm9uY2U",
		Ciphertext: "Y2lwaGVy",
	})
	require.NoError(t, err)

	rec, err := store.GetAndDeleteTerminalRequest(ctx, "state-terminal")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusCompleted, rec.Status)

	rec, err = store.GetRequest(ctx, "state-terminal")
	require.NoError(t, err)
	require.Nil(t, rec)
}

func TestRequestStoreGetAndDeleteTerminalRequestExpiresPending(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	// #nosec G101 - Hardcoded credentials are test ones
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-get-delete-expired",
		DisplayName:    "Get Delete Expired User",
		WebAuthnUserID: "webauthn-user-get-delete-expired",
		CredentialID:   "cred-get-delete-expired",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-expired-terminal",
		UserID:           "user-get-delete-expired",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "expired-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now.Add(-2 * time.Minute),
		ExpiresAt:        now.Add(-1 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	rec, err := store.GetAndDeleteTerminalRequest(ctx, "state-expired-terminal")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusExpired, rec.Status)

	rec, err = store.GetRequest(ctx, "state-expired-terminal")
	require.NoError(t, err)
	require.Nil(t, rec)
}

func TestRequestStoreMarkExpired(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-expire",
		DisplayName:    "Expire User",
		WebAuthnUserID: "webauthn-user-expire",
		CredentialID:   "cred-expire",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-expired",
		UserID:           "user-expire",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "expired-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now.Add(-2 * time.Minute),
		ExpiresAt:        now.Add(-1 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-fresh",
		UserID:           "user-expire",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "fresh-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-completed",
		UserID:           "user-expire",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "completed-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	completed, err := store.CompleteRequest(ctx, "state-completed", "user-expire", protocolv2.ResponseEnvelope{
		TransportAlg: protocolv2.TransportAlg,
		BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		Nonce:      "bm9uY2U",
		Ciphertext: "Y2lwaGVy",
	})
	require.NoError(t, err)
	require.NotNil(t, completed)

	expired, err := store.MarkExpired(ctx, "state-expired")
	require.NoError(t, err)
	require.NotNil(t, expired)
	require.Equal(t, "state-expired", expired.State)
	require.Equal(t, "user-expire", expired.UserID)
	require.Equal(t, V2RequestStatusExpired, expired.Status)

	rec, err := store.GetRequest(ctx, "state-expired")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusExpired, rec.Status)

	expired, err = store.MarkExpired(ctx, "state-fresh")
	require.NoError(t, err)
	require.Nil(t, expired)

	expired, err = store.MarkExpired(ctx, "state-completed")
	require.NoError(t, err)
	require.Nil(t, expired)
}

func TestRequestStoreDeleteTerminalRequestWithCutoff(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-delete",
		DisplayName:    "Delete User",
		WebAuthnUserID: "webauthn-user-delete",
		CredentialID:   "cred-delete",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-old-terminal",
		UserID:           "user-delete",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "old-terminal",
		Algorithm:        "A256GCM",
		CreatedAt:        now.Add(-25 * time.Minute),
		ExpiresAt:        now.Add(-20 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	canceled, err := store.CancelRequest(ctx, "state-old-terminal", "user-delete")
	require.NoError(t, err)
	require.NotNil(t, canceled)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-pending",
		UserID:           "user-delete",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "pending",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(30 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-recent-terminal",
		UserID:           "user-delete",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "recent-terminal",
		Algorithm:        "A256GCM",
		CreatedAt:        now.Add(-5 * time.Minute),
		ExpiresAt:        now.Add(-2 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	canceled, err = store.CancelRequest(ctx, "state-recent-terminal", "user-delete")
	require.NoError(t, err)
	require.NotNil(t, canceled)

	err = store.DeleteTerminalRequest(ctx, "state-old-terminal", &now)
	require.NoError(t, err)
	err = store.DeleteTerminalRequest(ctx, "state-pending", &now)
	require.NoError(t, err)
	err = store.DeleteTerminalRequest(ctx, "state-recent-terminal", &now)
	require.NoError(t, err)

	rec, err := store.GetRequest(ctx, "state-old-terminal")
	require.NoError(t, err)
	require.Nil(t, rec)

	rec, err = store.GetRequest(ctx, "state-pending")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusPending, rec.Status)

	rec, err = store.GetRequest(ctx, "state-recent-terminal")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusCanceled, rec.Status)
}

func TestRequestStoreDeleteTerminalRequest(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, conn.kind)
	require.NoError(t, err)
	_, err = authStore.RegisterUser(ctx, RegisterUserInput{
		UserID:         "user-delete-now",
		DisplayName:    "Delete Now User",
		WebAuthnUserID: "webauthn-user-delete-now",
		CredentialID:   "cred-delete-now",
		PublicKey:      `{"kty":"EC"}`,
		SignCount:      1,
		SessionTTL:     time.Minute,
	})
	require.NoError(t, err)

	store, err := NewRequestStore(conn)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-terminal-delete",
		UserID:           "user-delete-now",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "terminal-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-pending-keep",
		UserID:           "user-delete-now",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "pending-key",
		Algorithm:        "A256GCM",
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"test","y":"test"},"nonce":"bm9uY2U","ciphertext":"Y3Q"}`,
	})
	require.NoError(t, err)

	_, err = store.CompleteRequest(ctx, "state-terminal-delete", "user-delete-now", protocolv2.ResponseEnvelope{
		TransportAlg: protocolv2.TransportAlg,
		BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		Nonce:      "bm9uY2U",
		Ciphertext: "Y2lwaGVy",
	})
	require.NoError(t, err)

	err = store.DeleteTerminalRequest(ctx, "state-terminal-delete", nil)
	require.NoError(t, err)

	rec, err := store.GetRequest(ctx, "state-terminal-delete")
	require.NoError(t, err)
	require.Nil(t, rec)

	err = store.DeleteTerminalRequest(ctx, "state-pending-keep", nil)
	require.NoError(t, err)

	rec, err = store.GetRequest(ctx, "state-pending-keep")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusPending, rec.Status)
}
