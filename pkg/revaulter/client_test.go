package revaulter

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/clienttest"
)

// newTestClient starts a simulated Revaulter server and returns a client for it
func newTestClient(t *testing.T) (*clienttest.Server, *Client) {
	t.Helper()

	srv := clienttest.NewServer(t)
	client, err := New(Options{
		Server:       srv.URL,
		RequestKey:   clienttest.RequestKey,
		HTTPClient:   srv.HTTPClient(),
		NoTrustStore: true,
	})
	require.NoError(t, err)

	return srv, client
}

func TestNewValidatesOptions(t *testing.T) {
	t.Run("requires a server", func(t *testing.T) {
		_, err := New(Options{RequestKey: "key"})
		require.ErrorContains(t, err, "Server")
	})

	t.Run("requires a request key", func(t *testing.T) {
		_, err := New(Options{Server: "https://revaulter.example.com"})
		require.ErrorContains(t, err, "RequestKey")
	})

	t.Run("rejects an oversize note", func(t *testing.T) {
		_, err := New(Options{
			Server:     "https://revaulter.example.com",
			RequestKey: "key",
			Note:       strings.Repeat("a", MaxNoteLength+1),
		})
		require.ErrorContains(t, err, "note cannot be longer")
	})

	t.Run("trims the trailing slash from the server", func(t *testing.T) {
		client, err := New(Options{
			Server:     "https://revaulter.example.com/",
			RequestKey: "key",
		})
		require.NoError(t, err)
		require.Equal(t, "https://revaulter.example.com", client.Server())
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	srv, client := newTestClient(t)
	ctx := t.Context()

	plaintext := []byte("hello revaulter")
	aad := []byte("bound metadata")

	enc, err := client.Encrypt(ctx, EncryptRequest{
		KeyLabel:       "My-Key",
		Algorithm:      AlgorithmA256GCM,
		Plaintext:      plaintext,
		AdditionalData: aad,
		Note:           "test note",
	})
	require.NoError(t, err)
	require.Equal(t, "my-key", enc.KeyLabel, "key labels are normalized to lowercase")
	require.Equal(t, AlgorithmA256GCM, enc.Algorithm)
	require.NotEmpty(t, enc.Ciphertext)
	require.Len(t, enc.Nonce, 12)
	require.Len(t, enc.Tag, 16)
	require.Equal(t, aad, enc.AdditionalData)
	require.NotEmpty(t, enc.State)
	require.NotEqual(t, plaintext, enc.Ciphertext)

	require.Equal(t, "test note", srv.LastNote())
	require.True(t, strings.HasPrefix(srv.LastUserAgent(), "RevaulterGo/"), "unexpected user agent: %s", srv.LastUserAgent())

	dec, err := client.Decrypt(ctx, DecryptRequest{
		KeyLabel:       "my-key",
		Algorithm:      AlgorithmA256GCM,
		Ciphertext:     enc.Ciphertext,
		Nonce:          enc.Nonce,
		Tag:            enc.Tag,
		AdditionalData: enc.AdditionalData,
	})
	require.NoError(t, err)
	require.Equal(t, plaintext, dec.Plaintext)
	require.Equal(t, "my-key", dec.KeyLabel)
}

func TestDecryptFailsWithWrongAdditionalData(t *testing.T) {
	_, client := newTestClient(t)
	ctx := t.Context()

	enc, err := client.Encrypt(ctx, EncryptRequest{
		KeyLabel:       "my-key",
		Algorithm:      AlgorithmA256GCM,
		Plaintext:      []byte("hello"),
		AdditionalData: []byte("aad-1"),
	})
	require.NoError(t, err)

	_, err = client.Decrypt(ctx, DecryptRequest{
		KeyLabel:       "my-key",
		Algorithm:      AlgorithmA256GCM,
		Ciphertext:     enc.Ciphertext,
		Nonce:          enc.Nonce,
		Tag:            enc.Tag,
		AdditionalData: []byte("aad-2"),
	})
	require.Error(t, err)
}

func TestEncryptValidatesRequest(t *testing.T) {
	_, client := newTestClient(t)
	ctx := t.Context()

	t.Run("rejects an invalid key label", func(t *testing.T) {
		_, err := client.Encrypt(ctx, EncryptRequest{KeyLabel: "not a valid label!", Algorithm: AlgorithmA256GCM, Plaintext: []byte("x")})
		require.ErrorContains(t, err, "invalid key label")
	})

	t.Run("rejects an unsupported algorithm", func(t *testing.T) {
		_, err := client.Encrypt(ctx, EncryptRequest{KeyLabel: "my-key", Algorithm: "RSA-OAEP", Plaintext: []byte("x")})
		require.ErrorContains(t, err, "unsupported encryption algorithm")
	})

	t.Run("rejects an empty plaintext", func(t *testing.T) {
		_, err := client.Encrypt(ctx, EncryptRequest{KeyLabel: "my-key", Algorithm: AlgorithmA256GCM})
		require.ErrorContains(t, err, "plaintext is required")
	})

	t.Run("rejects an oversize plaintext", func(t *testing.T) {
		_, err := client.Encrypt(ctx, EncryptRequest{
			KeyLabel:  "my-key",
			Algorithm: AlgorithmA256GCM,
			Plaintext: make([]byte, MaxPayloadSize+1),
		})
		require.ErrorContains(t, err, "exceeds the maximum allowed size")
	})

	t.Run("rejects an oversize note", func(t *testing.T) {
		_, err := client.Encrypt(ctx, EncryptRequest{
			KeyLabel:  "my-key",
			Algorithm: AlgorithmA256GCM,
			Plaintext: []byte("x"),
			Note:      strings.Repeat("a", MaxNoteLength+1),
		})
		require.ErrorContains(t, err, "note cannot be longer")
	})
}

func TestSignAndVerifyES256(t *testing.T) {
	srv, client := newTestClient(t)
	ctx := t.Context()

	message := []byte("message to sign")
	res, err := client.Sign(ctx, SignRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmES256,
		Message:   message,
	})
	require.NoError(t, err)
	require.Len(t, res.Signature, 64)
	require.NotEmpty(t, res.SigningKeyID)

	// The signature covers the SHA-256 digest of the message
	digest := sha256.Sum256(message)
	require.True(t, ecdsa.Verify(srv.ES256PublicKey(), digest[:], bigFromBytes(res.Signature[:32]), bigFromBytes(res.Signature[32:])))

	// Verify via the server-published public key
	err = client.Verify(ctx, VerifyRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmES256,
		Message:   message,
		Signature: res.Signature,
	})
	require.NoError(t, err)

	// The same works when passing a pre-computed digest
	err = client.Verify(ctx, VerifyRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmES256,
		Digest:    digest[:],
		Signature: res.Signature,
	})
	require.NoError(t, err)

	t.Run("rejects a tampered message", func(t *testing.T) {
		err := client.Verify(ctx, VerifyRequest{
			KeyLabel:  "my-key",
			Algorithm: AlgorithmES256,
			Message:   []byte("another message"),
			Signature: res.Signature,
		})
		require.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("rejects a tampered signature", func(t *testing.T) {
		tampered := make([]byte, len(res.Signature))
		copy(tampered, res.Signature)
		tampered[0] ^= 0xFF

		err := client.Verify(ctx, VerifyRequest{
			KeyLabel:  "my-key",
			Algorithm: AlgorithmES256,
			Message:   message,
			Signature: tampered,
		})
		require.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("rejects a signature of the wrong length", func(t *testing.T) {
		err := client.Verify(ctx, VerifyRequest{
			KeyLabel:  "my-key",
			Algorithm: AlgorithmES256,
			Message:   message,
			Signature: res.Signature[:32],
		})
		require.ErrorIs(t, err, ErrInvalidSignature)
	})
}

func TestSignAndVerifyEd25519(t *testing.T) {
	srv, client := newTestClient(t)
	ctx := t.Context()

	message := []byte("message to sign with ed25519")
	res, err := client.Sign(ctx, SignRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmEd25519,
		Message:   message,
	})
	require.NoError(t, err)
	require.Len(t, res.Signature, 64)
	require.True(t, ed25519.Verify(srv.Ed25519PublicKey(), message, res.Signature))

	err = client.Verify(ctx, VerifyRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmEd25519,
		Message:   message,
		Signature: res.Signature,
	})
	require.NoError(t, err)

	t.Run("does not accept a digest", func(t *testing.T) {
		digest := sha512.Sum512(message)
		_, err := client.Sign(ctx, SignRequest{
			KeyLabel:  "my-key",
			Algorithm: AlgorithmEd25519,
			Digest:    digest[:],
		})
		require.ErrorContains(t, err, "digest is not supported for Ed25519")
	})
}

func TestSignAndVerifyEd25519ph(t *testing.T) {
	_, client := newTestClient(t)
	ctx := t.Context()

	message := []byte("message to sign with ed25519ph")
	res, err := client.Sign(ctx, SignRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmEd25519ph,
		Message:   message,
	})
	require.NoError(t, err)

	err = client.Verify(ctx, VerifyRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmEd25519ph,
		Message:   message,
		Signature: res.Signature,
	})
	require.NoError(t, err)

	// Signing from the pre-computed digest produces a signature over the same bytes
	digest := sha512.Sum512(message)
	fromDigest, err := client.Sign(ctx, SignRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmEd25519ph,
		Digest:    digest[:],
	})
	require.NoError(t, err)
	require.Equal(t, res.Signature, fromDigest.Signature, "Ed25519 signatures are deterministic")
}

func TestSignValidatesRequest(t *testing.T) {
	_, client := newTestClient(t)
	ctx := t.Context()

	t.Run("rejects an unsupported algorithm", func(t *testing.T) {
		_, err := client.Sign(ctx, SignRequest{KeyLabel: "my-key", Algorithm: "RS256", Message: []byte("x")})
		require.ErrorContains(t, err, "unsupported signing algorithm")
	})

	t.Run("requires a message or a digest", func(t *testing.T) {
		_, err := client.Sign(ctx, SignRequest{KeyLabel: "my-key", Algorithm: AlgorithmES256})
		require.ErrorContains(t, err, "one of message or digest is required")
	})

	t.Run("rejects both a message and a digest", func(t *testing.T) {
		digest := sha256.Sum256([]byte("x"))
		_, err := client.Sign(ctx, SignRequest{KeyLabel: "my-key", Algorithm: AlgorithmES256, Message: []byte("x"), Digest: digest[:]})
		require.ErrorContains(t, err, "mutually exclusive")
	})

	t.Run("rejects a digest of the wrong size", func(t *testing.T) {
		_, err := client.Sign(ctx, SignRequest{KeyLabel: "my-key", Algorithm: AlgorithmES256, Digest: make([]byte, 16)})
		require.ErrorContains(t, err, "invalid digest length")
	})

	t.Run("accepts a lowercase algorithm", func(t *testing.T) {
		res, err := client.Sign(ctx, SignRequest{KeyLabel: "my-key", Algorithm: "es256", Message: []byte("x")})
		require.NoError(t, err)
		require.Equal(t, AlgorithmES256, res.Algorithm)
	})
}

func TestSigningPublicKey(t *testing.T) {
	srv, client := newTestClient(t)
	ctx := t.Context()

	key, err := client.SigningPublicKey(ctx, "my-key", AlgorithmES256)
	require.NoError(t, err)
	require.Equal(t, "my-key", key.KeyLabel)
	require.Equal(t, AlgorithmES256, key.Algorithm)
	require.NotEmpty(t, key.KeyID)

	pub, ok := key.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, pub.Equal(srv.ES256PublicKey()))

	// A key fetched once can verify signatures without contacting the server again
	message := []byte("offline verification")
	res, err := client.Sign(ctx, SignRequest{KeyLabel: "my-key", Algorithm: AlgorithmES256, Message: message})
	require.NoError(t, err)
	require.Equal(t, key.KeyID, res.SigningKeyID)

	err = key.Verify(VerifyRequest{Message: message, Signature: res.Signature})
	require.NoError(t, err)

	t.Run("refuses a key for a different algorithm", func(t *testing.T) {
		err := key.Verify(VerifyRequest{Algorithm: AlgorithmEd25519, Message: message, Signature: res.Signature})
		require.ErrorContains(t, err, "key is for algorithm")
	})

	t.Run("refuses a key for a different label", func(t *testing.T) {
		err := key.Verify(VerifyRequest{KeyLabel: "other-key", Message: message, Signature: res.Signature})
		require.ErrorContains(t, err, "key is for label")
	})
}

func TestOperationRespectsContext(t *testing.T) {
	_, client := newTestClient(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.Encrypt(ctx, EncryptRequest{
		KeyLabel:  "my-key",
		Algorithm: AlgorithmA256GCM,
		Plaintext: []byte("hello"),
		Timeout:   time.Minute,
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled), "expected a context error, got: %v", err)
}

// bigFromBytes converts a big-endian byte slice into a big.Int, for checking raw r||s signatures
func bigFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
