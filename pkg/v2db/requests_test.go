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

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
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

	store, err := NewRequestStore(conn, key, nil)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	body := protocolv2.RequestCreateBody{
		KeyLabel:  "boot-disk",
		Algorithm: "aes-gcm-256",
		Value:     "aGVsbG8",
		ClientTransportKey: protocolv2.ECP256PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Y: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:       "state-1",
		UserID:      "user-1",
		Operation:   "encrypt",
		RequestorIP: "127.0.0.1",
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
		Body:        body,
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
	require.Equal(t, "aGVsbG8", rec.RequestBody.Value)
	require.Nil(t, rec.ResponseEnvelope)

	ok, err := store.CompleteRequest(ctx, "state-1", protocolv2.ResponseEnvelope{
		TransportAlg: "ecdh-p256+a256gcm",
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
	require.Equal(t, "ecdh-p256+a256gcm", rec.ResponseEnvelope.TransportAlg)
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

	store, err := NewRequestStore(conn, bytes32(7), nil)
	require.NoError(t, err)

	err = store.CreateRequest(ctx, CreateRequestInput{
		State:       "state-2",
		UserID:      "user-2",
		Operation:   "decrypt",
		RequestorIP: "127.0.0.1",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(time.Minute),
		Body: protocolv2.RequestCreateBody{
			KeyLabel:  "x",
			Algorithm: "aes-gcm-256",
			Value:     "aGVsbG8",
			ClientTransportKey: protocolv2.ECP256PublicJWK{
				Kty: "EC", Crv: "P-256",
				X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Y: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		},
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

	store, err := NewRequestStore(conn, bytes32(9), nil)
	require.NoError(t, err)

	now := time.Now().UTC()
	mkBody := func() protocolv2.RequestCreateBody {
		return protocolv2.RequestCreateBody{
			KeyLabel:  "k",
			Algorithm: "aes-gcm-256",
			Value:     "aGVsbG8",
			ClientTransportKey: protocolv2.ECP256PublicJWK{
				Kty: "EC", Crv: "P-256",
				X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				Y: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		}
	}
	require.NoError(t, store.CreateRequest(ctx, CreateRequestInput{
		State:       "expired-1",
		UserID:      "user-1",
		Operation:   "encrypt",
		RequestorIP: "127.0.0.1",
		CreatedAt:   now.Add(-2 * time.Second),
		ExpiresAt:   now.Add(-1 * time.Second),
		Body:        mkBody(),
	}))
	require.NoError(t, store.CreateRequest(ctx, CreateRequestInput{
		State:       "pending-1",
		UserID:      "user-1",
		Operation:   "encrypt",
		RequestorIP: "127.0.0.1",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Minute),
		Body:        mkBody(),
	}))

	expired, err := store.ExpirePendingAndReturnStates(ctx, now)
	require.NoError(t, err)
	require.Equal(t, []string{"expired-1"}, expired)

	rec, err := store.GetRequest(ctx, "expired-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusExpired, rec.Status)

	rec, err = store.GetRequest(ctx, "pending-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.Equal(t, V2RequestStatusPending, rec.Status)
}

func bytes32(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}
