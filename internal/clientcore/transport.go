package clientcore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils"
)

// TransportKeyPair is the ephemeral hybrid key pair the client generates for each operation
// The browser encrypts its response to these keys, so the server never sees the plaintext result
type TransportKeyPair struct {
	EcdhPrivate  *ecdh.PrivateKey
	EcdhPublic   protocolv2.ECP256PublicJWK
	MlkemPrivate *mlkem.DecapsulationKey768
	MlkemPublic  string // base64url-encoded raw encapsulation key
}

// NewTransportKeyPair generates a new ephemeral hybrid (ECDH P-256 + ML-KEM-768) transport key pair
func NewTransportKeyPair() (*TransportKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 transport key: %w", err)
	}
	pub, err := protocolv2.ECP256PublicJWKFromECDH(priv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to convert transport public key to JWK: %w", err)
	}

	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-768 transport key: %w", err)
	}

	return &TransportKeyPair{
		EcdhPrivate:  priv,
		EcdhPublic:   pub,
		MlkemPrivate: mlkemDK,
		MlkemPublic:  base64.RawURLEncoding.EncodeToString(mlkemDK.EncapsulationKey().Bytes()),
	}, nil
}

// BuildTransportAAD constructs the AAD that the browser binds into the AES-GCM tag during encryption
func BuildTransportAAD(state, operation, algorithm string) []byte {
	// Keep the transport AAD serialization deterministic and independent from JSON key ordering so browser and CLI always bind the same AES-GCM tag bytes
	return fmt.Appendf(nil, "algorithm=%s\noperation=%s\nstate=%s\nv=1", algorithm, operation, state)
}

// BuildRequestEncAAD constructs the AAD used when encrypting/decrypting request payloads
// It binds the plaintext metadata to the E2EE ciphertext
func BuildRequestEncAAD(algorithm, keyLabel, operation string) []byte {
	return fmt.Appendf(nil, "algorithm=%s\nkeyLabel=%s\noperation=%s\nv=1", algorithm, keyLabel, operation)
}

// DecryptResponseEnvelope decrypts the response envelope produced by the browser, using the ephemeral transport key pair
func DecryptResponseEnvelope(state string, kp *TransportKeyPair, env *protocolv2.ResponseEnvelope, aad []byte) ([]byte, error) {
	if kp == nil || kp.EcdhPrivate == nil || kp.MlkemPrivate == nil {
		return nil, errors.New("missing client transport key pair")
	}
	if env == nil {
		return nil, errors.New("missing responseEnvelope")
	}

	err := validateResponseEnvelope(env)
	if err != nil {
		return nil, err
	}

	// ECDH shared secret
	peerPub, err := env.BrowserEphemeralPublicKey.ToECDHPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid browserEphemeralPublicKey: %w", err)
	}
	ecdhShared, err := kp.EcdhPrivate.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("failed ECDH: %w", err)
	}

	// ML-KEM decapsulation
	mlkemCT, err := utils.DecodeBase64String(env.MlkemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid mlkemCiphertext: %w", err)
	}
	mlkemShared, err := kp.MlkemPrivate.Decapsulate(mlkemCT)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	// Combine shared secrets: ECDH || ML-KEM
	combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
	combined = append(combined, ecdhShared...)
	combined = append(combined, mlkemShared...)

	// Derive the transport key
	key, err := DeriveTransportKey(combined, state)
	if err != nil {
		return nil, err
	}

	// Create the AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decode the nonce
	nonce, err := utils.DecodeBase64String(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce: bad size")
	}

	// Decode the ciphertext
	ciphertext, err := utils.DecodeBase64String(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	// Decrypt
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}

	return plain, nil
}

// DeriveTransportKey derives the AES-256-GCM key protecting the browser's response, from the hybrid shared secret
func DeriveTransportKey(sharedSecret []byte, state string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, "revaulter/v2/transport/"+state, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive transport key: %w", err)
	}
	return key, nil
}

// validateResponseEnvelope performs the client-side checks on the response envelope before attempting decryption
func validateResponseEnvelope(env *protocolv2.ResponseEnvelope) error {
	if env.TransportAlg != protocolv2.TransportAlg {
		return fmt.Errorf("unsupported transportAlg: %s", env.TransportAlg)
	}

	err := env.BrowserEphemeralPublicKey.ValidatePublic()
	if err != nil {
		return err
	}

	if env.MlkemCiphertext == "" {
		return errors.New("missing mlkemCiphertext in response envelope")
	}

	return nil
}

// EncryptRequestPayload encrypts the inner request payload using hybrid ECDH + ML-KEM
// The client generates an ephemeral ECDH key pair, performs ECDH with the browser user's static ECDH public key, encapsulates to the user's ML-KEM public key, combines both shared secrets, and derives an AES-256-GCM key via HKDF.
func EncryptRequestPayload(
	peerStaticEcdhPub *ecdh.PublicKey,
	peerStaticMlkemPub *mlkem.EncapsulationKey768,
	payload protocolv2.RequestPayloadInner,
	aad []byte,
) (cliEphPub protocolv2.ECP256PublicJWK, mlkemCiphertextB64 string, nonceB64 string, ciphertextB64 string, err error) {
	// Generate ephemeral ECDH key pair
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return cliEphPub, "", "", "", fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	cliEphPub, err = protocolv2.ECP256PublicJWKFromECDH(ephPriv.PublicKey())
	if err != nil {
		return cliEphPub, "", "", "", fmt.Errorf("failed to export ephemeral public key: %w", err)
	}

	// ECDH shared secret
	ecdhShared, err := ephPriv.ECDH(peerStaticEcdhPub)
	if err != nil {
		return cliEphPub, "", "", "", fmt.Errorf("failed ECDH: %w", err)
	}

	// ML-KEM encapsulation
	mlkemShared, mlkemCT := peerStaticMlkemPub.Encapsulate()
	mlkemCiphertextB64 = base64.RawURLEncoding.EncodeToString(mlkemCT)

	// Combine shared secrets: ECDH || ML-KEM
	combined := make([]byte, 0, len(ecdhShared)+len(mlkemShared))
	combined = append(combined, ecdhShared...)
	combined = append(combined, mlkemShared...)

	// HKDF to derive AES-256-GCM key
	aesKey, err := hkdf.Key(sha256.New, combined, nil, "revaulter/v2/request-enc", 32)
	if err != nil {
		return cliEphPub, "", "", "", fmt.Errorf("failed to derive request encryption key: %w", err)
	}

	// Create the AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return cliEphPub, "", "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return cliEphPub, "", "", "", err
	}

	// Get a random nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return cliEphPub, "", "", "", err
	}

	// Serialize payload to JSON
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return cliEphPub, "", "", "", fmt.Errorf("failed to serialize payload: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	nonceB64 = base64.RawURLEncoding.EncodeToString(nonce)
	ciphertextB64 = base64.RawURLEncoding.EncodeToString(ciphertext)

	return cliEphPub, mlkemCiphertextB64, nonceB64, ciphertextB64, nil
}
