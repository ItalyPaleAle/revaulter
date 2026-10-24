package protocolv2

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testDevice holds the four private keys of a device credential, as the Secure Enclave would
type testDevice struct {
	signP256    *ecdsa.PrivateKey
	kaP256      *ecdh.PrivateKey
	signMldsa65 *mldsa.PrivateKey
	kem         *mlkem.DecapsulationKey768
	public      DevicePublicKeys
}

func newTestDevice(t *testing.T) *testDevice {
	t.Helper()

	signP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kaP256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	signMldsa65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	kem, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	signP256Bytes, err := signP256.PublicKey.Bytes()
	require.NoError(t, err)

	return &testDevice{
		signP256:    signP256,
		kaP256:      kaP256,
		signMldsa65: signMldsa65,
		kem:         kem,
		public: DevicePublicKeys{
			SignP256:    base64.RawURLEncoding.EncodeToString(signP256Bytes),
			KaP256:      base64.RawURLEncoding.EncodeToString(kaP256.PublicKey().Bytes()),
			SignMldsa65: base64.RawURLEncoding.EncodeToString(signMldsa65.PublicKey().Bytes()),
			KemMlkem768: base64.RawURLEncoding.EncodeToString(kem.EncapsulationKey().Bytes()),
		},
	}
}

// sign returns the raw r||s P-256 signature and the ML-DSA-65 signature of msg, in the formats CryptoKit produces
func (d *testDevice) sign(t *testing.T, msg []byte) (sigP256 []byte, sigMldsa65 []byte) {
	t.Helper()

	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, d.signP256, digest[:])
	require.NoError(t, err)
	sigP256 = make([]byte, P256SignatureSize)
	r.FillBytes(sigP256[:P256SignatureSize/2])
	s.FillBytes(sigP256[P256SignatureSize/2:])

	sigMldsa65, err = d.signMldsa65.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)

	return sigP256, sigMldsa65
}

func (d *testDevice) parsed(t *testing.T) *ParsedDevicePublicKeys {
	t.Helper()

	keys, err := d.public.Parse()
	require.NoError(t, err)

	return keys
}

func testDeviceLoginPayload() *DeviceLoginPayload {
	return &DeviceLoginPayload{
		Challenge:    base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		CredentialID: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		UserID:       "user-123",
		V:            DeviceLoginVersion,
	}
}

func TestDevicePublicKeysParse(t *testing.T) {
	d := newTestDevice(t)

	t.Run("accepts valid keys", func(t *testing.T) {
		keys, err := d.public.Parse()
		require.NoError(t, err)
		require.True(t, keys.SignP256.Equal(&d.signP256.PublicKey))
		require.True(t, keys.KaP256.Equal(d.kaP256.PublicKey()))
		require.True(t, keys.SignMldsa65.Equal(d.signMldsa65.PublicKey()))
		require.Equal(t, d.kem.EncapsulationKey().Bytes(), keys.KemMlkem768.Bytes())
	})

	notOnCurve := make([]byte, P256PublicKeySize)
	notOnCurve[0] = 0x04
	notOnCurve[1] = 0x01

	compressed := make([]byte, P256PublicKeySize)
	compressed[0] = 0x02

	tests := []struct {
		name   string
		mutate func(k *DevicePublicKeys)
		errMsg string
	}{
		{"empty signP256", func(k *DevicePublicKeys) { k.SignP256 = "" }, "signP256 is empty"},
		{"signP256 not base64url", func(k *DevicePublicKeys) { k.SignP256 = "not base64!" }, "signP256 is not valid base64url"},
		{"signP256 wrong size", func(k *DevicePublicKeys) { k.SignP256 = base64.RawURLEncoding.EncodeToString(make([]byte, 33)) }, "signP256 must be 65 bytes"},
		{"signP256 not on the curve", func(k *DevicePublicKeys) { k.SignP256 = base64.RawURLEncoding.EncodeToString(notOnCurve) }, "signP256 is not a valid P-256 public key"},
		{"kaP256 not uncompressed", func(k *DevicePublicKeys) { k.KaP256 = base64.RawURLEncoding.EncodeToString(compressed) }, "kaP256 is not a valid P-256 public key"},
		{"same key for signing and key agreement", func(k *DevicePublicKeys) { k.KaP256 = k.SignP256 }, "must be different keys"},
		{"signMldsa65 wrong size", func(k *DevicePublicKeys) {
			k.SignMldsa65 = base64.RawURLEncoding.EncodeToString(make([]byte, MLDSA87PublicKeySize))
		}, "signMldsa65 must be 1952 bytes"},
		{"kemMlkem768 wrong size", func(k *DevicePublicKeys) { k.KemMlkem768 = base64.RawURLEncoding.EncodeToString(make([]byte, 1568)) }, "kemMlkem768 must be 1184 bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := d.public
			tc.mutate(&k)
			_, err := k.Parse()
			require.Error(t, err)
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestDevicePublicKeysHash(t *testing.T) {
	d := newTestDevice(t)
	base := d.public.Hash()

	// The hash is stable for the same keys
	require.Equal(t, base, d.public.Hash())

	// Changing any one key changes the hash
	other := newTestDevice(t)
	mutations := map[string]func(k *DevicePublicKeys){
		"signP256":    func(k *DevicePublicKeys) { k.SignP256 = other.public.SignP256 },
		"kaP256":      func(k *DevicePublicKeys) { k.KaP256 = other.public.KaP256 },
		"signMldsa65": func(k *DevicePublicKeys) { k.SignMldsa65 = other.public.SignMldsa65 },
		"kemMlkem768": func(k *DevicePublicKeys) { k.KemMlkem768 = other.public.KemMlkem768 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			k := d.public
			mutate(&k)
			require.NotEqual(t, base, k.Hash())
		})
	}

	// Swapping the two P-256 keys must not produce the same hash
	swapped := d.public
	swapped.SignP256, swapped.KaP256 = swapped.KaP256, swapped.SignP256
	require.NotEqual(t, base, swapped.Hash())
}

func TestVerifyDeviceLogin(t *testing.T) {
	d := newTestDevice(t)
	keys := d.parsed(t)
	payload := testDeviceLoginPayload()
	sigP256, sigMldsa65 := d.sign(t, CanonicalDeviceLoginMessage(payload))

	t.Run("accepts both signatures", func(t *testing.T) {
		err := VerifyDeviceLogin(keys, payload, sigP256, sigMldsa65)
		require.NoError(t, err)
	})

	t.Run("rejects a wrong P-256 signature", func(t *testing.T) {
		bad := append([]byte(nil), sigP256...)
		bad[10] ^= 0x01
		err := VerifyDeviceLogin(keys, payload, bad, sigMldsa65)
		require.Error(t, err)
		require.ErrorContains(t, err, "P-256")
		require.NotContains(t, err.Error(), "ML-DSA-65")
	})

	t.Run("rejects a wrong ML-DSA-65 signature", func(t *testing.T) {
		bad := append([]byte(nil), sigMldsa65...)
		bad[10] ^= 0x01
		err := VerifyDeviceLogin(keys, payload, sigP256, bad)
		require.Error(t, err)
		require.ErrorContains(t, err, "ML-DSA-65")
		require.NotContains(t, err.Error(), "P-256")
	})

	t.Run("rejects a DER-encoded P-256 signature", func(t *testing.T) {
		digest := sha256.Sum256(CanonicalDeviceLoginMessage(payload))
		der, err := ecdsa.SignASN1(rand.Reader, d.signP256, digest[:])
		require.NoError(t, err)

		err = VerifyDeviceLogin(keys, payload, der, sigMldsa65)
		require.Error(t, err)
		require.ErrorContains(t, err, "wrong length")
	})

	t.Run("rejects signatures over a different challenge", func(t *testing.T) {
		other := *payload
		other.Challenge = base64.RawURLEncoding.EncodeToString([]byte("another challenge of 32 bytes!!!"))
		err := VerifyDeviceLogin(keys, &other, sigP256, sigMldsa65)
		require.Error(t, err)
		require.ErrorContains(t, err, "P-256")
		require.ErrorContains(t, err, "ML-DSA-65")
	})

	t.Run("rejects another device's keys", func(t *testing.T) {
		err := VerifyDeviceLogin(newTestDevice(t).parsed(t), payload, sigP256, sigMldsa65)
		require.Error(t, err)
	})

	t.Run("rejects an unknown version", func(t *testing.T) {
		other := *payload
		other.V = 2
		err := VerifyDeviceLogin(keys, &other, sigP256, sigMldsa65)
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported device login version")
	})

	t.Run("rejects nil keys", func(t *testing.T) {
		err := VerifyDeviceLogin(nil, payload, sigP256, sigMldsa65)
		require.Error(t, err)
	})
}

func TestCanonicalDeviceLoginMessage(t *testing.T) {
	msg := string(CanonicalDeviceLoginMessage(testDeviceLoginPayload()))
	require.True(t, strings.HasPrefix(msg, DeviceLoginPrefix))
	require.True(t, strings.HasSuffix(msg, "\nuserId=user-123\nv=1"))
}

func TestDeviceUnlockInfo(t *testing.T) {
	ephPub := []byte("ephemeral public key")
	kemCt := []byte("ml-kem ciphertext")
	base := DeviceUnlockInfo("user-123", "cred-1", ephPub, kemCt)
	require.True(t, strings.HasPrefix(base, DeviceUnlockInfoPrefix))

	// Every input is bound into the info string
	require.NotEqual(t, base, DeviceUnlockInfo("user-456", "cred-1", ephPub, kemCt))
	require.NotEqual(t, base, DeviceUnlockInfo("user-123", "cred-2", ephPub, kemCt))
	require.NotEqual(t, base, DeviceUnlockInfo("user-123", "cred-1", []byte("other ephemeral key"), kemCt))
	require.NotEqual(t, base, DeviceUnlockInfo("user-123", "cred-1", ephPub, []byte("other ciphertext")))
}

func TestDecodeBase64FieldIsStrict(t *testing.T) {
	canonical := base64.RawURLEncoding.EncodeToString(make([]byte, DeviceCredentialIDSize))
	require.Equal(t, "AAAAAAAAAAAAAAAAAAAAAA", canonical)

	_, err := decodeBase64Field("credentialId", canonical, DeviceCredentialIDSize)
	require.NoError(t, err)

	// The last character carries 4 unused bits; setting one decodes to the same bytes with the default decoder, so it must be refused
	_, err = decodeBase64Field("credentialId", "AAAAAAAAAAAAAAAAAAAAAB", DeviceCredentialIDSize)
	require.Error(t, err)

	// Padding is not allowed either
	_, err = decodeBase64Field("credentialId", canonical+"==", DeviceCredentialIDSize)
	require.Error(t, err)
}

func TestIsValidCredentialType(t *testing.T) {
	require.True(t, IsValidCredentialType(CredentialTypePasskey))
	require.True(t, IsValidCredentialType(CredentialTypeDevice))
	require.False(t, IsValidCredentialType(""))
	require.False(t, IsValidCredentialType("Passkey"))
}
