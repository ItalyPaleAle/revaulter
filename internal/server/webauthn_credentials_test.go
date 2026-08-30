package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

const (
	testWebAuthnRPID   = "revaulter.example.com"
	testWebAuthnOrigin = "https://revaulter.example.com"
)

// authData flag bits
// Specification: §6.1. Authenticator Data (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
const (
	testFlagUserPresent        = 0x01
	testFlagUserVerified       = 0x04
	testFlagBackupEligible     = 0x08
	testFlagBackupState        = 0x10
	testFlagAttestedCredential = 0x40
)

// testPasskey is a software authenticator holding one credential, which lets the tests run a full WebAuthn ceremony for any credential algorithm
type testPasskey struct {
	coseAlgorithm webauthncose.COSEAlgorithmIdentifier
	credentialID  []byte
	coseKey       []byte
	sign          func(data []byte) ([]byte, error)
	signCount     uint32
}

func newTestPasskey(t *testing.T, alg webauthncose.COSEAlgorithmIdentifier) *testPasskey {
	t.Helper()

	credentialID := make([]byte, 32)
	_, err := rand.Read(credentialID)
	require.NoError(t, err)

	pk := &testPasskey{
		coseAlgorithm: alg,
		credentialID:  credentialID,
	}

	switch alg {
	case webauthncose.AlgES256:
		pk.coseKey, pk.sign = newTestECDSAKey(t, alg, elliptic.P256(), 1, crypto.SHA256)
	case webauthncose.AlgES384:
		pk.coseKey, pk.sign = newTestECDSAKey(t, alg, elliptic.P384(), 2, crypto.SHA384)
	case webauthncose.AlgEdDSA:
		pk.coseKey, pk.sign = newTestEd25519Key(t)
	case webauthncose.AlgRS256:
		pk.coseKey, pk.sign = newTestRSAKey(t, alg, crypto.SHA256, false)
	case webauthncose.AlgPS256:
		pk.coseKey, pk.sign = newTestRSAKey(t, alg, crypto.SHA256, true)
	case webauthncose.AlgMLDSA44:
		pk.coseKey, pk.sign = newTestMLDSAKey(t, alg, mldsa.MLDSA44())
	case webauthncose.AlgMLDSA65:
		pk.coseKey, pk.sign = newTestMLDSAKey(t, alg, mldsa.MLDSA65())
	case webauthncose.AlgMLDSA87:
		pk.coseKey, pk.sign = newTestMLDSAKey(t, alg, mldsa.MLDSA87())
	default:
		t.Fatalf("unsupported test credential algorithm %d", alg)
	}

	return pk
}

func newTestECDSAKey(t *testing.T, alg webauthncose.COSEAlgorithmIdentifier, curve elliptic.Curve, coseCurve int64, hash crypto.Hash) ([]byte, func([]byte) ([]byte, error)) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	byteLen := (curve.Params().BitSize + 7) / 8
	cose := marshalTestCOSEKey(t, webauthncose.EC2PublicKeyData{
		PublicKeyData: testPublicKeyData(webauthncose.EllipticKey, alg),
		Curve:         coseCurve,
		XCoord:        key.X.FillBytes(make([]byte, byteLen)),
		YCoord:        key.Y.FillBytes(make([]byte, byteLen)),
	})

	// WebAuthn ECDSA signatures are ASN.1 DER encoded
	return cose, func(data []byte) ([]byte, error) {
		digest := hash.New()
		digest.Write(data)
		return ecdsa.SignASN1(rand.Reader, key, digest.Sum(nil))
	}
}

func newTestEd25519Key(t *testing.T) ([]byte, func([]byte) ([]byte, error)) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cose := marshalTestCOSEKey(t, webauthncose.OKPPublicKeyData{
		PublicKeyData: testPublicKeyData(webauthncose.OctetKey, webauthncose.AlgEdDSA),
		Curve:         int64(webauthncose.Ed25519),
		XCoord:        pub,
	})

	// Ed25519 signs the message itself rather than a digest
	return cose, func(data []byte) ([]byte, error) {
		return ed25519.Sign(priv, data), nil
	}
}

func newTestRSAKey(t *testing.T, alg webauthncose.COSEAlgorithmIdentifier, hash crypto.Hash, pss bool) ([]byte, func([]byte) ([]byte, error)) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(exponent, uint32(key.E)) //nolint:gosec
	cose := marshalTestCOSEKey(t, webauthncose.RSAPublicKeyData{
		PublicKeyData: testPublicKeyData(webauthncose.RSAKey, alg),
		Modulus:       key.N.Bytes(),
		// The exponent is an unsigned big-endian integer, which authenticators write without leading zero bytes
		Exponent: bytes.TrimLeft(exponent, "\x00"),
	})

	return cose, func(data []byte) ([]byte, error) {
		digest := hash.New()
		digest.Write(data)
		if pss {
			return rsa.SignPSS(rand.Reader, key, hash, digest.Sum(nil), nil)
		}
		return rsa.SignPKCS1v15(rand.Reader, key, hash, digest.Sum(nil))
	}
}

func newTestMLDSAKey(t *testing.T, alg webauthncose.COSEAlgorithmIdentifier, params mldsa.Parameters) ([]byte, func([]byte) ([]byte, error)) {
	t.Helper()

	key, err := mldsa.GenerateKey(params)
	require.NoError(t, err)

	cose := marshalTestCOSEKey(t, webauthncose.AKPPublicKeyData{
		PublicKeyData: testPublicKeyData(webauthncose.AKP, alg),
		PublicKey:     key.PublicKey().Bytes(),
	})

	// ML-DSA credentials sign with pure ML-DSA and an empty context
	return cose, func(data []byte) ([]byte, error) {
		return key.Sign(rand.Reader, data, &mldsa.Options{})
	}
}

func testPublicKeyData(keyType webauthncose.COSEKeyType, alg webauthncose.COSEAlgorithmIdentifier) webauthncose.PublicKeyData {
	return webauthncose.PublicKeyData{
		KeyType:   int64(keyType),
		Algorithm: int64(alg),
	}
}

func marshalTestCOSEKey(t *testing.T, key any) []byte {
	t.Helper()

	cose, err := webauthncbor.Marshal(key)
	require.NoError(t, err)
	return cose
}

// authenticatorData builds the authData an authenticator writes for one ceremony
func (pk *testPasskey) authenticatorData(attested bool) []byte {
	rpIDHash := sha256.Sum256([]byte(testWebAuthnRPID))

	flags := byte(testFlagUserPresent | testFlagUserVerified | testFlagBackupEligible | testFlagBackupState)
	out := make([]byte, 37, 37+len(pk.coseKey)+64)
	copy(out, rpIDHash[:])
	binary.BigEndian.PutUint32(out[33:37], pk.signCount)

	if attested {
		flags |= testFlagAttestedCredential

		// Layout: aaguid(16) | credentialIdLength(2) | credentialId | credentialPublicKey
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(pk.credentialID))) //nolint:gosec
		out = append(out, pk.credentialID...)
		out = append(out, pk.coseKey...)
	}

	out[32] = flags
	return out
}

func (pk *testPasskey) clientDataJSON(t *testing.T, ceremony string, challenge string) []byte {
	t.Helper()

	out, err := json.Marshal(map[string]any{
		"type":        ceremony,
		"challenge":   challenge,
		"origin":      testWebAuthnOrigin,
		"crossOrigin": false,
	})
	require.NoError(t, err)
	return out
}

// attestationResponse builds the registration credential a browser posts to the server
func (pk *testPasskey) attestationResponse(t *testing.T, challenge string) json.RawMessage {
	t.Helper()

	authData := pk.authenticatorData(true)
	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	require.NoError(t, err)

	return marshalTestJSON(t, map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(pk.credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(pk.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(pk.clientDataJSON(t, "webauthn.create", challenge)),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{"prf": map[string]any{"enabled": true}},
	})
}

// assertionResponse builds the login credential a browser posts to the server
func (pk *testPasskey) assertionResponse(t *testing.T, challenge string, userHandle []byte) json.RawMessage {
	t.Helper()

	pk.signCount++
	authData := pk.authenticatorData(false)
	clientDataJSON := pk.clientDataJSON(t, "webauthn.get", challenge)
	clientDataHash := sha256.Sum256(clientDataJSON)

	signature, err := pk.sign(append(authData, clientDataHash[:]...))
	require.NoError(t, err)

	return marshalTestJSON(t, map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(pk.credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(pk.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userHandle),
		},
		"clientExtensionResults": map[string]any{
			"prf": map[string]any{
				"enabled": true,
				"results": map[string]any{"first": base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
			},
		},
	})
}

func marshalTestJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()

	out, err := json.Marshal(value)
	require.NoError(t, err)
	return out
}

func newTestWebAuthn(t *testing.T) *webauthnlib.WebAuthn {
	t.Helper()

	t.Cleanup(
		config.SetTestConfig(map[string]any{
			"baseUrl":        testWebAuthnOrigin,
			"webauthnRpId":   testWebAuthnRPID,
			"webauthnRpName": "Revaulter",
		}),
	)

	wa, err := (&Server{}).initWebAuthn()
	require.NoError(t, err)
	return wa
}

func newTestJSONRequest(t *testing.T, body json.RawMessage) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// The credential algorithms the server offers and is expected to complete a full ceremony with
var testCredentialAlgorithms = map[string]webauthncose.COSEAlgorithmIdentifier{
	"ES256":     webauthncose.AlgES256,
	"ES384":     webauthncose.AlgES384,
	"EdDSA":     webauthncose.AlgEdDSA,
	"RS256":     webauthncose.AlgRS256,
	"PS256":     webauthncose.AlgPS256,
	"ML-DSA-44": webauthncose.AlgMLDSA44,
	"ML-DSA-65": webauthncose.AlgMLDSA65,
	"ML-DSA-87": webauthncose.AlgMLDSA87,
}

func TestCredentialParametersOffersPostQuantumAndClassicalAlgorithms(t *testing.T) {
	params := credentialParameters()

	// The post-quantum parameter sets come first so an authenticator that implements one picks it
	require.GreaterOrEqual(t, len(params), 3)
	assert.Equal(t, webauthncose.AlgMLDSA44, params[0].Algorithm)
	assert.Equal(t, webauthncose.AlgMLDSA65, params[1].Algorithm)
	assert.Equal(t, webauthncose.AlgMLDSA87, params[2].Algorithm)

	// Every classical algorithm the library offers by default is still offered, in its original order
	offered := make([]webauthncose.COSEAlgorithmIdentifier, 0, len(params))
	for _, param := range params {
		assert.Equal(t, protocol.PublicKeyCredentialType, param.Type)
		offered = append(offered, param.Algorithm)
	}

	classical := make([]webauthncose.COSEAlgorithmIdentifier, 0, len(params))
	for _, param := range webauthnlib.CredentialParametersDefault() {
		classical = append(classical, param.Algorithm)
	}
	assert.Equal(t, classical, offered[3:])

	// Every algorithm the tests run a full ceremony with must actually be on the list
	for name, alg := range testCredentialAlgorithms {
		assert.Contains(t, offered, alg, "algorithm %s is not offered during registration", name)
	}
}

func TestRegistrationBeginOffersPostQuantumCredentialParameters(t *testing.T) {
	wa := newTestWebAuthn(t)
	user, err := newV2WebAuthnUserForRegistration("user-1", "Test User")
	require.NoError(t, err)

	s := &Server{webAuthn: wa}
	creation, session, err := s.beginWebAuthnSession(user)
	require.NoError(t, err)
	require.NotNil(t, session)

	offered := make([]webauthncose.COSEAlgorithmIdentifier, 0, len(creation.Response.Parameters))
	for _, param := range creation.Response.Parameters {
		offered = append(offered, param.Algorithm)
	}
	assert.Equal(t, credentialParametersAlgorithms(), offered)
}

func credentialParametersAlgorithms() []webauthncose.COSEAlgorithmIdentifier {
	params := credentialParameters()
	out := make([]webauthncose.COSEAlgorithmIdentifier, len(params))
	for i, param := range params {
		out[i] = param.Algorithm
	}
	return out
}

// Registration and login must work for every credential algorithm the server offers, not only for the ECDSA keys every authenticator in general use produces today
func TestWebAuthnCeremoniesAcrossCredentialAlgorithms(t *testing.T) {
	for name, alg := range testCredentialAlgorithms {
		t.Run(name, func(t *testing.T) {
			wa := newTestWebAuthn(t)
			user, err := newV2WebAuthnUserForRegistration("user-"+name, "Test User")
			require.NoError(t, err)

			s := &Server{webAuthn: wa}
			creation, registrationSession, err := s.beginWebAuthnSession(user)
			require.NoError(t, err)

			pk := newTestPasskey(t, alg)
			jr := newTestJSONRequest(t, pk.attestationResponse(t, creation.Response.Challenge.String()))
			credential, err := wa.FinishRegistration(user, *registrationSession, jr)
			require.NoError(t, err, "registration must succeed for %s", name)
			assert.Equal(t, pk.credentialID, credential.ID)

			// The stored credential public key is the exact COSE the authenticator wrote, which is what makes the credential hash algorithm-agnostic
			assert.Equal(t, pk.coseKey, credential.PublicKey)

			user.credentials = append(user.credentials, *credential)

			_, loginSession, err := wa.BeginDiscoverableLogin(
				webauthnlib.WithAssertionExtensions(webauthnlib.WithExtensionPRFSupport()),
			)
			require.NoError(t, err)

			handler := func(rawID []byte, userHandle []byte) (webauthnlib.User, error) {
				assert.Equal(t, pk.credentialID, rawID)
				assert.Equal(t, user.WebAuthnID(), userHandle)
				return user, nil
			}

			jr = newTestJSONRequest(t, pk.assertionResponse(t, loginSession.Challenge, user.WebAuthnID()))
			loginCredential, err := wa.FinishDiscoverableLogin(handler, *loginSession, jr)
			require.NoError(t, err, "login must succeed for %s", name)
			assert.Equal(t, pk.credentialID, loginCredential.ID)
			assert.Equal(t, uint32(1), loginCredential.Authenticator.SignCount)
		})
	}
}

// The credential hash both sides compare is taken over the raw COSE bytes, so it must agree for every key type without any per-algorithm handling
func TestCredentialPublicKeyHashMatchesStoredCredentialAcrossAlgorithms(t *testing.T) {
	seen := make(map[string]string, len(testCredentialAlgorithms))

	for name, alg := range testCredentialAlgorithms {
		t.Run(name, func(t *testing.T) {
			wa := newTestWebAuthn(t)
			user, err := newV2WebAuthnUserForRegistration("user-"+name, "Test User")
			require.NoError(t, err)

			s := &Server{webAuthn: wa}
			creation, session, err := s.beginWebAuthnSession(user)
			require.NoError(t, err)

			pk := newTestPasskey(t, alg)
			jr := newTestJSONRequest(t, pk.attestationResponse(t, creation.Response.Challenge.String()))
			credential, err := wa.FinishRegistration(user, *session, jr)
			require.NoError(t, err)

			// What the browser hashes: the COSE bytes it sliced out of the attestation object
			fromAuthenticator, err := protocolv2.CredentialPublicKeyHash(pk.coseKey)
			require.NoError(t, err)

			// What the server re-derives: the COSE bytes it stored for the credential
			credJSON, err := json.Marshal(credential)
			require.NoError(t, err)
			fromStored, err := protocolv2.CredentialPublicKeyHashFromStoredCredJSON(string(credJSON))
			require.NoError(t, err)

			assert.Equal(t, fromAuthenticator, fromStored)

			previous, dup := seen[fromAuthenticator]
			assert.False(t, dup, "hash collision between %s and %s", name, previous)
			seen[fromAuthenticator] = name
		})
	}
}

func TestRegistrationRejectsAnAlgorithmTheServerDoesNotOffer(t *testing.T) {
	wa := newTestWebAuthn(t)
	user, err := newV2WebAuthnUserForRegistration("user-unoffered", "Test User")
	require.NoError(t, err)

	s := &Server{webAuthn: wa}
	creation, session, err := s.beginWebAuthnSession(user)
	require.NoError(t, err)

	// ES256K is registered with COSE but is not on the list the server offers
	require.NotContains(t, credentialParametersAlgorithms(), webauthncose.AlgES256K)

	pk := newTestPasskey(t, webauthncose.AlgES256)
	// Claim an algorithm the server never offered while keeping the rest of the credential well-formed
	pk.coseKey = marshalTestCOSEKey(t, webauthncose.EC2PublicKeyData{
		PublicKeyData: testPublicKeyData(webauthncose.EllipticKey, webauthncose.AlgES256K),
		Curve:         int64(webauthncose.Secp256k1),
		XCoord:        make([]byte, 32),
		YCoord:        make([]byte, 32),
	})

	jr := newTestJSONRequest(t, pk.attestationResponse(t, creation.Response.Challenge.String()))
	_, err = wa.FinishRegistration(user, *session, jr)
	require.Error(t, err)

	// The reason is carried on the structured error rather than in the message the caller sees
	var protocolErr *protocol.Error
	require.ErrorAs(t, err, &protocolErr)
	assert.Equal(t, "Credential public key algorithm not supported", protocolErr.DevInfo)
}

func TestLoginRejectsAnAssertionSignedByADifferentCredential(t *testing.T) {
	for name, alg := range testCredentialAlgorithms {
		t.Run(name, func(t *testing.T) {
			wa := newTestWebAuthn(t)
			user, err := newV2WebAuthnUserForRegistration("user-"+name, "Test User")
			require.NoError(t, err)

			s := &Server{webAuthn: wa}
			creation, session, err := s.beginWebAuthnSession(user)
			require.NoError(t, err)

			pk := newTestPasskey(t, alg)
			jr := newTestJSONRequest(t, pk.attestationResponse(t, creation.Response.Challenge.String()))
			credential, err := wa.FinishRegistration(user, *session, jr)
			require.NoError(t, err)
			user.credentials = append(user.credentials, *credential)

			_, loginSession, err := wa.BeginDiscoverableLogin()
			require.NoError(t, err)

			// A second passkey of the same algorithm signs while claiming the registered credential's ID
			impostor := newTestPasskey(t, alg)
			impostor.credentialID = pk.credentialID

			handler := func(_ []byte, _ []byte) (webauthnlib.User, error) {
				return user, nil
			}

			jr = newTestJSONRequest(t, impostor.assertionResponse(t, loginSession.Challenge, user.WebAuthnID()))
			_, err = wa.FinishDiscoverableLogin(handler, *loginSession, jr)
			require.Error(t, err, "an assertion signed by another key must not verify for %s", name)
		})
	}
}
