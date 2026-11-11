package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

func addTestDeviceCredential(t *testing.T, srv *Server, in db.AddCredentialInput) {
	t.Helper()

	in.CredentialType = protocolv2.CredentialTypeDevice
	if in.WrappedKeyEpoch == 0 {
		in.WrappedKeyEpoch = 1
	}
	_, err := db.ExecuteInTransaction(t.Context(), srv.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		return struct{}{}, tx.AuthStore().AddCredential(ctx, in)
	})
	require.NoError(t, err)
}

func TestLoadWebAuthnUserSkipsDeviceCredentials(t *testing.T) {
	setTestConfig(t, "v2-load-webauthn-user.db")
	srv := newTestServer(t, nil, nil, nil)

	_, user := seedV2SessionCookie(t, srv, "user-alice", "Alice")
	addTestDeviceCredential(t, srv, db.AddCredentialInput{
		UserID:       "user-alice",
		CredentialID: "device-1",
		DisplayName:  "iPhone",
		PublicKey:    `{"signP256":"a","kaP256":"b","signMldsa65":"c","kemMlkem768":"d"}`,
	})

	// Two credentials are stored, but only the passkey is a WebAuthn credential
	records, err := srv.db.AuthStore().ListCredentials(t.Context(), "user-alice")
	require.NoError(t, err)
	require.Len(t, records, 2)

	userRecord, err := loadWebAuthnUser(t.Context(), srv.db.AuthStore(), user)
	require.NoError(t, err)
	require.NotNil(t, userRecord)
	require.Len(t, userRecord.WebAuthnCredentials(), 1)
}
