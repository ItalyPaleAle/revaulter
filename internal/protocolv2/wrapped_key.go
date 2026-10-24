package protocolv2

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// WrappedPrimaryKeyAADFmt is the AES-GCM additional data of every wrapped primary key, for passkeys and devices alike
const WrappedPrimaryKeyAADFmt = "revaulter/v2/wrapped-primary-key\nuserId=%s\nv=1"

// WrappedPrimaryKeyVersion is the only envelope version in use
const WrappedPrimaryKeyVersion = 1

// WrappedKeyKindDevice marks an envelope that a device unwraps with its Secure Enclave keys
// Envelopes made from a passkey's PRF output have no kind
const WrappedKeyKindDevice = "device"

// Limits applied when parsing an envelope
// The Argon2id caps stop a malicious server from making a client spend unbounded memory or time; the web client's production cost is m=131072 (128 MiB), t=4, p=1
const (
	MaxArgon2idMemoryKiB   = 1 << 20 // 1 GiB
	MaxArgon2idIterations  = 64
	MaxArgon2idParallelism = 16

	argon2idSaltSize = 16

	// MaxWrappedPrimaryKeyLength bounds the encoded envelope, which with a device's ML-KEM ciphertext is about 2 KB
	MaxWrappedPrimaryKeyLength = 8 << 10

	wrappedPrimaryKeyNonceSize = 12
	// wrappedPrimaryKeyCiphertextSize is a 32-byte primary key followed by a 16-byte AES-GCM tag
	wrappedPrimaryKeyCiphertextSize = 32 + 16
)

// Argon2idParams are the password-stretching parameters stored in an envelope
// M is in KiB, as in the Argon2 specification
type Argon2idParams struct {
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"`
}

// WrappedPrimaryKeyEnvelope is the decoded form of a credential's wrapped primary key
// On the wire and in storage it is base64url(JSON)
// Device envelopes add the wrapper's ephemeral P-256 public key and ML-KEM-768 ciphertext, which the device needs to derive its unwrapping secret
type WrappedPrimaryKeyEnvelope struct {
	V                int             `json:"v"`
	Kind             string          `json:"kind,omitempty"`
	PasswordRequired bool            `json:"passwordRequired"`
	Argon2id         *Argon2idParams `json:"argon2id,omitempty"`
	EphPub           string          `json:"ephPub,omitempty"`
	KemCt            string          `json:"kemCt,omitempty"`
	Nonce            string          `json:"nonce"`
	Ciphertext       string          `json:"ciphertext"`
}

// ParseWrappedPrimaryKeyEnvelope decodes and validates a wrapped primary key envelope
// It checks structure only: decrypting it still needs the credential's secret
func ParseWrappedPrimaryKeyEnvelope(wrapped string) (*WrappedPrimaryKeyEnvelope, error) {
	if wrapped == "" {
		return nil, errors.New("wrapped primary key is empty")
	}
	if len(wrapped) > MaxWrappedPrimaryKeyLength {
		return nil, fmt.Errorf("wrapped primary key must be at most %d characters", MaxWrappedPrimaryKeyLength)
	}

	raw, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("wrapped primary key is not valid base64url: %w", err)
	}

	var env WrappedPrimaryKeyEnvelope
	err = json.Unmarshal(raw, &env)
	if err != nil {
		return nil, fmt.Errorf("wrapped primary key is not a valid envelope: %w", err)
	}

	err = env.Validate()
	if err != nil {
		return nil, err
	}

	return &env, nil
}

// Encode returns the base64url(JSON) form of the envelope after validating it
func (e *WrappedPrimaryKeyEnvelope) Encode() (string, error) {
	err := e.Validate()
	if err != nil {
		return "", err
	}

	raw, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to encode envelope: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// IsDevice reports whether the envelope belongs to a device credential
func (e *WrappedPrimaryKeyEnvelope) IsDevice() bool {
	return e.Kind == WrappedKeyKindDevice
}

// Validate checks the envelope's version, kind, Argon2id parameters and field sizes
func (e *WrappedPrimaryKeyEnvelope) Validate() error {
	if e.V != WrappedPrimaryKeyVersion {
		return fmt.Errorf("unsupported wrapped primary key version %d", e.V)
	}

	switch e.Kind {
	case "":
		if e.EphPub != "" || e.KemCt != "" {
			return errors.New("ephPub and kemCt are only allowed in device envelopes")
		}
	case WrappedKeyKindDevice:
		ephPub, err := decodeBase64Field("ephPub", e.EphPub, P256PublicKeySize)
		if err != nil {
			return err
		}
		_, err = ecdh.P256().NewPublicKey(ephPub)
		if err != nil {
			return fmt.Errorf("ephPub is not a valid P-256 public key: %w", err)
		}

		_, err = decodeBase64Field("kemCt", e.KemCt, MLKEM768CiphertextSize)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported wrapped primary key kind %q", e.Kind)
	}

	if e.PasswordRequired != (e.Argon2id != nil) {
		return errors.New("argon2id parameters must be present exactly when a password is required")
	}
	if e.Argon2id != nil {
		err := e.Argon2id.Validate()
		if err != nil {
			return err
		}
	}

	_, err := decodeBase64Field("nonce", e.Nonce, wrappedPrimaryKeyNonceSize)
	if err != nil {
		return err
	}

	_, err = decodeBase64Field("ciphertext", e.Ciphertext, wrappedPrimaryKeyCiphertextSize)
	if err != nil {
		return err
	}

	return nil
}

// Validate checks the Argon2id parameters against the specification's minimums and this package's caps
func (p *Argon2idParams) Validate() error {
	if p.P < 1 || p.P > MaxArgon2idParallelism {
		return fmt.Errorf("argon2id parallelism must be between 1 and %d, got %d", MaxArgon2idParallelism, p.P)
	}
	if p.T < 1 || p.T > MaxArgon2idIterations {
		return fmt.Errorf("argon2id iterations must be between 1 and %d, got %d", MaxArgon2idIterations, p.T)
	}

	// The Argon2 specification requires at least 8 KiB per lane
	if p.M < 8*uint32(p.P) || p.M > MaxArgon2idMemoryKiB {
		return fmt.Errorf("argon2id memory must be between %d and %d KiB, got %d", 8*uint32(p.P), MaxArgon2idMemoryKiB, p.M)
	}

	_, err := decodeBase64Field("argon2id salt", p.Salt, argon2idSaltSize)
	if err != nil {
		return err
	}

	return nil
}
