//go:build unit && unix

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

func TestShellQuoteEscapesSingleQuotes(t *testing.T) {
	got := shellQuote("/tmp/revaulter agent/alice's key.sock")
	require.Equal(t, "'/tmp/revaulter agent/alice'\\''s key.sock'", got)
}

func TestSSHAgentSignNote(t *testing.T) {
	require.Equal(t, "SSH auth", sshAgentSignNote(""))
	require.Equal(t, "SSH auth prod.example.com", sshAgentSignNote("prod.example.com"))
}

func TestSSHAgentOperationContextCancelsOnShutdown(t *testing.T) {
	shutdown := make(chan struct{})
	a := &revaulterSSHAgent{shutdown: shutdown}

	ctx, cancel := a.operationContext(time.Hour)
	defer cancel()

	close(shutdown)

	select {
	case <-ctx.Done():
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("operation context was not cancelled by shutdown")
	}
}

// newSSHAgentFlagsWithRequired builds an ssh-agent flag set with the required base flags pre-filled so Validate can focus on agent-specific behavior
func newSSHAgentFlagsWithRequired(t *testing.T) *sshAgentFlags {
	t.Helper()
	f := &sshAgentFlags{}
	f.Server = "https://example.invalid"
	f.RequestKey = "rk-test"
	f.KeyLabel = "label-test"
	return f
}

// TestSSHAgentValidateNoteLength pins the client-side note check
// The agent prefixes every note, so the usable budget is MaxNoteLength minus the prefix
func TestSSHAgentValidateNoteLength(t *testing.T) {
	// The require.Len assertion below is the independent check on this budget: it fails if the constant and the note the agent actually builds disagree
	maxUserNote := sshAgentMaxUserNoteLength

	t.Run("accepts a note that exactly fills the budget", func(t *testing.T) {
		f := newSSHAgentFlagsWithRequired(t)
		f.Note = strings.Repeat("n", maxUserNote)
		err := f.Validate()
		require.NoError(t, err)
		require.Len(t, sshAgentSignNote(f.Note), protocolv2.MaxNoteLength)
	})

	t.Run("rejects a note over the budget", func(t *testing.T) {
		f := newSSHAgentFlagsWithRequired(t)
		f.Note = strings.Repeat("n", maxUserNote+1)

		err := f.Validate()
		require.ErrorContains(t, err, "note cannot be longer than")
		require.Greater(t, len(sshAgentSignNote(f.Note)), protocolv2.MaxNoteLength, "the rejected note must actually exceed the server limit")
	})

	t.Run("accepts an empty note", func(t *testing.T) {
		f := newSSHAgentFlagsWithRequired(t)
		err := f.Validate()
		require.NoError(t, err)
	})
}

// shortTempDir returns a temporary directory with a short path
// t.TempDir() embeds the test name, which easily pushes a socket path past the ~104 byte sun_path limit on macOS
//
//nolint:usetesting // t.TempDir() is exactly what produces the over-long path this helper exists to avoid
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rv")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// TestListenAgentSocketPermissions asserts the socket is never world-accessible, even when it lives in a world-traversable directory
// The umask inside listenAgentSocket is what closes the window between net.Listen and the follow-up Chmod
func TestListenAgentSocketPermissions(t *testing.T) {
	// A 0777 parent directory is the case a custom --socket path can produce
	dir := shortTempDir(t)
	err := os.Chmod(dir, 0o777)
	require.NoError(t, err)

	socketPath := filepath.Join(dir, "agent.sock")
	l, err := listenAgentSocket(socketPath)
	require.NoError(t, err)
	defer l.Close()

	st, err := os.Stat(socketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "agent socket must be owner-only")
}

// TestListenAgentSocketRestoresUmask makes sure the temporary umask narrowing does not leak into the rest of the process
func TestListenAgentSocketRestoresUmask(t *testing.T) {
	before := syscall.Umask(0o022)
	syscall.Umask(before)

	socketPath := filepath.Join(shortTempDir(t), "agent.sock")
	l, err := listenAgentSocket(socketPath)
	require.NoError(t, err)
	defer l.Close()

	after := syscall.Umask(0o022)
	syscall.Umask(after)
	require.Equal(t, before, after, "listenAgentSocket must restore the previous umask")
}

// signingKeyProofFixture is a signed publication proof plus the anchor that produced it
type signingKeyProofFixture struct {
	anchor  *pinnedAnchor
	payload protocolv2.SigningKeyPublicationPayload
	resp    *v2RequestSigningPubkeyClientResponse
}

// newSigningKeyProofFixture mints a fresh hybrid anchor and signs a publication proof binding the given key id
func newSigningKeyProofFixture(t *testing.T, userID, algorithm, keyLabel, keyID string) *signingKeyProofFixture {
	t.Helper()

	esPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	mlPub, mlPriv, err := mldsa87.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mlPubBytes, err := mlPub.MarshalBinary()
	require.NoError(t, err)

	payload := protocolv2.SigningKeyPublicationPayload{
		UserID:          userID,
		Algorithm:       algorithm,
		KeyLabel:        keyLabel,
		KeyID:           keyID,
		WrappedKeyEpoch: 1,
		CreatedAt:       time.Now().Unix(),
		V:               protocolv2.SigningKeyPublicationVersion,
	}
	msg := protocolv2.CanonicalSigningKeyPublicationMessage(&payload)

	return &signingKeyProofFixture{
		anchor: &pinnedAnchor{
			UserID:          userID,
			Es384Pub:        &esPriv.PublicKey,
			Mldsa87PubBytes: mlPubBytes,
		},
		payload: payload,
		resp: &v2RequestSigningPubkeyClientResponse{
			Algorithm:                   algorithm,
			KeyLabel:                    keyLabel,
			PublicationPayload:          payload.CanonicalBody(),
			PublicationSignatureEs384:   base64.RawURLEncoding.EncodeToString(testSignES384Raw(t, esPriv, msg)),
			PublicationSignatureMldsa87: base64.RawURLEncoding.EncodeToString(testSignMLDSA87(t, mlPriv, msg)),
		},
	}
}

func testSignES384Raw(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	const coordinateSize = 48
	digest := sha512.Sum384(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	require.NoError(t, err)
	sig := make([]byte, protocolv2.ES384SignatureSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[coordinateSize-len(rBytes):coordinateSize], rBytes)
	copy(sig[protocolv2.ES384SignatureSize-len(sBytes):], sBytes)
	return sig
}

func testSignMLDSA87(t *testing.T, sk *mldsa87.PrivateKey, msg []byte) []byte {
	t.Helper()
	sig := make([]byte, protocolv2.MLDSA87SignatureSize)
	err := mldsa87.SignTo(sk, msg, nil, false, sig)
	require.NoError(t, err)
	return sig
}

// newTestSSHAgent builds an agent wired to the given label/algorithm, with logging discarded
func newTestSSHAgent(keyLabel, algorithm string) *revaulterSSHAgent {
	f := &sshAgentFlags{}
	f.Server = "https://example.invalid"
	f.KeyLabel = keyLabel
	f.Algorithm = algorithm

	return &revaulterSSHAgent{
		flags: f,
		log:   slog.New(slog.DiscardHandler),
	}
}

// TestVerifySigningKeyPublication covers the binding between the advertised signing key and the pinned anchor
// This is what stops a compromised server from advertising a key of its own choosing, which a user would then copy into an authorized_keys file
func TestVerifySigningKeyPublication(t *testing.T) {
	const (
		userID    = "user-abc"
		keyLabel  = "ssh-main"
		algorithm = protocolv2.SigningAlgES256
		keyID     = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	)

	t.Run("accepts a proof signed by the pinned anchor", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)
		a := newTestSSHAgent(keyLabel, algorithm)

		require.NoError(t, a.verifySigningKeyPublication(fx.anchor, fx.resp, keyID))
	})

	t.Run("rejects an auto-stored key that carries no proof", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)
		a := newTestSSHAgent(keyLabel, algorithm)

		for _, field := range []string{"payload", "es384", "mldsa87"} {
			t.Run("missing-"+field, func(t *testing.T) {
				resp := *fx.resp
				switch field {
				case "payload":
					resp.PublicationPayload = ""
				case "es384":
					resp.PublicationSignatureEs384 = ""
				case "mldsa87":
					resp.PublicationSignatureMldsa87 = ""
				}

				err := a.verifySigningKeyPublication(fx.anchor, &resp, keyID)
				require.ErrorContains(t, err, "no publication proof")
			})
		}
	})

	t.Run("rejects a proof signed by a different anchor", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)
		// A malicious server can mint its own anchor and sign a well-formed proof with it
		attacker := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, keyID)
		a := newTestSSHAgent(keyLabel, algorithm)

		err := a.verifySigningKeyPublication(fx.anchor, attacker.resp, keyID)
		require.ErrorContains(t, err, "not valid")
	})

	t.Run("rejects a proof bound to a different key id", func(t *testing.T) {
		// The proof is internally consistent, but covers a key other than the one the server just served
		fx := newSigningKeyProofFixture(t, userID, algorithm, keyLabel, "some-other-key-id")
		a := newTestSSHAgent(keyLabel, algorithm)

		err := a.verifySigningKeyPublication(fx.anchor, fx.resp, keyID)
		require.ErrorContains(t, err, "keyId")
	})

	t.Run("rejects a proof bound to a different key label", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, algorithm, "a-different-label", keyID)
		a := newTestSSHAgent(keyLabel, algorithm)

		err := a.verifySigningKeyPublication(fx.anchor, fx.resp, keyID)
		require.ErrorContains(t, err, "keyLabel")
	})

	t.Run("rejects a proof bound to a different algorithm", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, userID, protocolv2.SigningAlgEd25519, keyLabel, keyID)
		a := newTestSSHAgent(keyLabel, algorithm)

		err := a.verifySigningKeyPublication(fx.anchor, fx.resp, keyID)
		require.ErrorContains(t, err, "algorithm")
	})

	t.Run("rejects a proof issued for a different user", func(t *testing.T) {
		fx := newSigningKeyProofFixture(t, "someone-else", algorithm, keyLabel, keyID)
		// The anchor is pinned per (server, userId), so the pinned userId is the one the agent expects
		fx.anchor.UserID = userID
		a := newTestSSHAgent(keyLabel, algorithm)

		err := a.verifySigningKeyPublication(fx.anchor, fx.resp, keyID)
		require.ErrorContains(t, err, "userId")
	})

	t.Run("skips verification when anchor pinning is disabled", func(t *testing.T) {
		// --no-trust-store leaves no trusted anchor to verify against, so there is nothing to check
		a := newTestSSHAgent(keyLabel, algorithm)
		require.NoError(t, a.verifySigningKeyPublication(nil, &v2RequestSigningPubkeyClientResponse{}, keyID))
	})
}
