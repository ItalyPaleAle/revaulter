package v2db

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

	authStore, err := NewAuthStore(conn, nil)
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

	store, err := NewRequestStore(conn, nil)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-1",
		UserID:           "user-1",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "boot-disk",
		Algorithm:        "aes-gcm-256",
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

	ok, err := store.CompleteRequest(ctx, "state-1", protocolv2.ResponseEnvelope{
		TransportAlg: "ecdh-p256+mlkem768+a256gcm",
		BrowserEphemeralPublicKey: protocolv2.ECP256PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Y: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		Nonce:      "bm9uY2U",
		Ciphertext: "Y2lwaGVy",
	})
	require.NoError(t, err)
	require.True(t, ok)

	rec, err = store.GetRequest(ctx, "state-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusCompleted, rec.Status)
	require.NotNil(t, rec.ResponseEnvelope)
	require.Equal(t, "ecdh-p256+mlkem768+a256gcm", rec.ResponseEnvelope.TransportAlg)
}

func TestRequestStoreCancel(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
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

	store, err := NewRequestStore(conn, nil)
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:            "state-2",
		UserID:           "user-2",
		Operation:        "decrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "x",
		Algorithm:        "aes-gcm-256",
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(time.Minute),
		EncryptedRequest: `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"t","y":"t"},"nonce":"n","ciphertext":"c"}`,
	})
	require.NoError(t, err)

	ok, err := store.CancelRequest(ctx, "state-2")
	require.NoError(t, err)
	require.True(t, ok)

	rec, err := store.GetRequest(ctx, "state-2")
	require.NoError(t, err)
	require.Equal(t, V2RequestStatusCanceled, rec.Status)
}

func TestRequestStoreExpirePendingAndReturnStates(t *testing.T) {
	ctx := t.Context()
	conn := newTestDatabase(t)

	require.NoError(t, RunMigrations(ctx, conn, nil))

	authStore, err := NewAuthStore(conn, nil)
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

	store, err := NewRequestStore(conn, nil)
	require.NoError(t, err)

	now := time.Now().UTC()
	encReq := `{"cliEphemeralPublicKey":{"kty":"EC","crv":"P-256","x":"t","y":"t"},"nonce":"n","ciphertext":"c"}`
	require.NoError(t, store.CreateRequest(ctx, CreateRequestInput{
		State:            "expired-1",
		UserID:           "user-1",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "k",
		Algorithm:        "aes-gcm-256",
		CreatedAt:        now.Add(-2 * time.Second),
		ExpiresAt:        now.Add(-1 * time.Second),
		EncryptedRequest: encReq,
	}))
	require.NoError(t, store.CreateRequest(ctx, CreateRequestInput{
		State:            "pending-1",
		UserID:           "user-1",
		Operation:        "encrypt",
		RequestorIP:      "127.0.0.1",
		KeyLabel:         "k",
		Algorithm:        "aes-gcm-256",
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Minute),
		EncryptedRequest: encReq,
	}))

	expired, err := store.ExpirePendingAndReturnStates(ctx, now)
	require.NoError(t, err)
	require.Equal(t, []ExpiredRequestRef{{State: "expired-1", UserID: "user-1"}}, expired)

	rec, err := store.GetRequest(ctx, "expired-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusExpired, rec.Status)

	rec, err = store.GetRequest(ctx, "pending-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusPending, rec.Status)
}
