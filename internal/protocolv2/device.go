package protocolv2

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/italypaleale/revaulter/internal/utils"
)

// Domain-separation prefixes for device credentials
// DevicePublicKeysPrefix separates the hash of a device's public keys from every other hashed value
// DeviceLoginPrefix tags the challenge a device signs to log in
// DeviceUnlockInfoPrefix starts the HKDF info for the secret that unwraps a device's copy of the primary key
const (
	DevicePublicKeysPrefix = "revaulter/v2/device-public-keys\n"
	DeviceLoginPrefix      = "revaulter/v2/device-login\n"
	DeviceUnlockInfoPrefix = "revaulter/v2/deviceUnlock\n"
)

// Format versions bound into the device canonical bodies
const (
	DevicePublicKeysVersion int64 = 1
	DeviceLoginVersion      int64 = 1
	DeviceUnlockVersion     int64 = 1
)

// DevicePublicKeys holds the four public keys of a device credential, each base64url-encoded (raw, no padding)
// The JSON form is what the pairing hello carries and what the server stores for the credential
// P-256 keys are uncompressed points; the ML-DSA-65 and ML-KEM-768 keys are their raw encodings
type DevicePublicKeys struct {
	// P-256 ECDSA key that signs the login challenge
	SignP256 string `json:"signP256"`
	// P-256 ECDH key that the wrapper's ephemeral key agrees with
	KaP256 string `json:"kaP256"`
	// ML-DSA-65 key that signs the login challenge
	SignMldsa65 string `json:"signMldsa65"`
	// ML-KEM-768 encapsulation key the wrapper encapsulates to
	KemMlkem768 string `json:"kemMlkem768"`
}

// devicePublicKeysCanonical is the canonical body of DevicePublicKeys
// The order is load-bearing: the credential public-key hash covers these exact bytes
type devicePublicKeysCanonical struct {
	SignP256    string `key:"signP256"`
	KaP256      string `key:"kaP256"`
	SignMldsa65 string `key:"signMldsa65"`
	KemMlkem768 string `key:"kemMlkem768"`
	V           int64  `key:"v"`
}

// CanonicalBody encodes the public keys as ordered key=value lines separated by '\n', with no trailing newline
func (k DevicePublicKeys) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(devicePublicKeysCanonical{
		SignP256:    k.SignP256,
		KaP256:      k.KaP256,
		SignMldsa65: k.SignMldsa65,
		KemMlkem768: k.KemMlkem768,
		V:           DevicePublicKeysVersion,
	})
}

// Hash returns base64url(SHA-256(DevicePublicKeysPrefix || canonical body))
// For device credentials this is the credentialPublicKeyHash that the anchor attestation binds
func (k DevicePublicKeys) Hash() string {
	return utils.SHA256Base64URL([]byte(DevicePublicKeysPrefix), []byte(k.CanonicalBody()))
}

// ParsedDevicePublicKeys holds the decoded and validated public keys of a device credential
type ParsedDevicePublicKeys struct {
	SignP256    *ecdsa.PublicKey
	KaP256      *ecdh.PublicKey
	SignMldsa65 *mldsa.PublicKey
	KemMlkem768 *mlkem.EncapsulationKey768
}

// Parse decodes and validates the four public keys
// It refuses points that are not on the curve, keys of the wrong size, and a signing key that is also used for key agreement
func (k DevicePublicKeys) Parse() (*ParsedDevicePublicKeys, error) {
	signP256Bytes, err := decodeBase64Field("signP256", k.SignP256, P256PublicKeySize)
	if err != nil {
		return nil, err
	}
	signP256, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), signP256Bytes)
	if err != nil {
		return nil, fmt.Errorf("signP256 is not a valid P-256 public key: %w", err)
	}

	kaP256Bytes, err := decodeBase64Field("kaP256", k.KaP256, P256PublicKeySize)
	if err != nil {
		return nil, err
	}
	kaP256, err := ecdh.P256().NewPublicKey(kaP256Bytes)
	if err != nil {
		return nil, fmt.Errorf("kaP256 is not a valid P-256 public key: %w", err)
	}

	// Each key has a single purpose, so the same point must not appear twice
	if subtle.ConstantTimeCompare(signP256Bytes, kaP256Bytes) == 1 {
		return nil, errors.New("signP256 and kaP256 must be different keys")
	}

	mldsaBytes, err := decodeBase64Field("signMldsa65", k.SignMldsa65, MLDSA65PublicKeySize)
	if err != nil {
		return nil, err
	}
	signMldsa65, err := mldsa.NewPublicKey(mldsa.MLDSA65(), mldsaBytes)
	if err != nil {
		return nil, fmt.Errorf("signMldsa65 is not a valid ML-DSA-65 public key: %w", err)
	}

	mlkemBytes, err := decodeBase64Field("kemMlkem768", k.KemMlkem768, MLKEM768EncapsulationKeySize)
	if err != nil {
		return nil, err
	}
	kemMlkem768, err := mlkem.NewEncapsulationKey768(mlkemBytes)
	if err != nil {
		return nil, fmt.Errorf("kemMlkem768 is not a valid ML-KEM-768 encapsulation key: %w", err)
	}

	return &ParsedDevicePublicKeys{
		SignP256:    signP256,
		KaP256:      kaP256,
		SignMldsa65: signMldsa65,
		KemMlkem768: kemMlkem768,
	}, nil
}

// DeviceLoginPayload is the canonicalized payload a device signs with both signing keys to log in
// The order is load-bearing: client and server must produce identical bytes
type DeviceLoginPayload struct {
	Challenge    string `key:"challenge"`
	CredentialID string `key:"credentialId"`
	UserID       string `key:"userId"`
	V            int64  `key:"v"`
}

// CanonicalBody encodes the login payload as ordered key=value lines separated by '\n', with no trailing newline
func (p DeviceLoginPayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

// CanonicalDeviceLoginMessage returns the domain-separated message that both device signing keys sign to log in
func CanonicalDeviceLoginMessage(payload *DeviceLoginPayload) []byte {
	return prefixedMessage(DeviceLoginPrefix, payload.CanonicalBody())
}

// VerifyDeviceLogin verifies both signatures a device produced over the login message
// Both must validate; if either fails the call returns an error describing which ones were rejected
//
// SECURITY: callers must build the payload from server-side state (the challenge they issued, the stored credential ID and user ID) and load the keys from the stored credential, never from the request
func VerifyDeviceLogin(keys *ParsedDevicePublicKeys, payload *DeviceLoginPayload, sigP256 []byte, sigMldsa65 []byte) error {
	if payload.V != DeviceLoginVersion {
		return fmt.Errorf("unsupported device login version %d", payload.V)
	}

	return verifyDeviceSignatures(keys, CanonicalDeviceLoginMessage(payload), sigP256, sigMldsa65)
}

// verifyDeviceSignatures checks the P-256 and ML-DSA-65 signatures of a device over the same message
func verifyDeviceSignatures(keys *ParsedDevicePublicKeys, msg []byte, sigP256 []byte, sigMldsa65 []byte) error {
	if keys == nil {
		return errors.New("device public keys are nil")
	}

	p256Err := verifyP256(keys.SignP256, msg, sigP256)
	mldsaErr := verifyMLDSA65(keys.SignMldsa65, msg, sigMldsa65)
	if p256Err == nil && mldsaErr == nil {
		return nil
	}

	var errs []error
	if p256Err != nil {
		errs = append(errs, fmt.Errorf("P-256: %w", p256Err))
	}
	if mldsaErr != nil {
		errs = append(errs, fmt.Errorf("ML-DSA-65: %w", mldsaErr))
	}
	return errors.Join(errs...)
}

// verifyP256 accepts a raw r||s signature over SHA-256(msg), the format CryptoKit's P256.Signing produces
func verifyP256(pub *ecdsa.PublicKey, msg []byte, sig []byte) error {
	if pub == nil {
		return errors.New("public key is nil")
	}
	if len(sig) != P256SignatureSize {
		return fmt.Errorf("signature has wrong length %d, expected %d", len(sig), P256SignatureSize)
	}

	r := new(big.Int).SetBytes(sig[:P256SignatureSize/2])
	s := new(big.Int).SetBytes(sig[P256SignatureSize/2:])
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errSignatureVerification
	}

	return nil
}

// verifyMLDSA65 verifies a pure ML-DSA-65 signature with an empty context string
func verifyMLDSA65(pub *mldsa.PublicKey, msg []byte, sig []byte) error {
	if pub == nil {
		return errors.New("public key is nil")
	}
	if len(sig) != MLDSA65SignatureSize {
		return fmt.Errorf("signature has wrong length %d, expected %d", len(sig), MLDSA65SignatureSize)
	}

	err := mldsa.Verify(pub, msg, sig, nil)
	if err != nil {
		return errSignatureVerification
	}

	return nil
}

// DeviceUnlockPayload is the canonical body of the HKDF info that derives a device wrapper's secret
// It binds the secret to the credential, the wrapper's ephemeral P-256 key and its ML-KEM ciphertext, so a wrapper can't be moved to another credential
// The ciphertext is bound through its SHA-256 hash to keep the info string short
type DeviceUnlockPayload struct {
	CredentialID string `key:"credentialId"`
	EphPub       string `key:"ephPub"`
	KemCtHash    string `key:"kemCtHash"`
	UserID       string `key:"userId"`
	V            int64  `key:"v"`
}

// CanonicalBody encodes the unlock payload as ordered key=value lines separated by '\n', with no trailing newline
func (p DeviceUnlockPayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

// DeviceUnlockInfo returns the HKDF info for the secret that unwraps a device's copy of the primary key
// ephPub is the wrapper's ephemeral P-256 public key (uncompressed) and kemCt its ML-KEM-768 ciphertext
func DeviceUnlockInfo(userID string, credentialID string, ephPub []byte, kemCt []byte) string {
	p := DeviceUnlockPayload{
		CredentialID: credentialID,
		EphPub:       base64.RawURLEncoding.EncodeToString(ephPub),
		KemCtHash:    utils.SHA256Base64URL(kemCt),
		UserID:       userID,
		V:            DeviceUnlockVersion,
	}
	return DeviceUnlockInfoPrefix + p.CanonicalBody()
}
