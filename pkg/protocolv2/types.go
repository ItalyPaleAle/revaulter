package protocolv2

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/italypaleale/revaulter/pkg/utils"
)

const TransportAlg = "ecdh-p256+mlkem768+a256gcm"

// Operation identifiers used in RequestCreateBody
const (
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"
	OperationSign    = "sign"
)

// SigningAlgES256 is the JWA identifier for ECDSA using P-256 with SHA-256
const SigningAlgES256 = "ES256"

// IsSupportedSigningAlgorithm reports whether alg is a signing algorithm supported by the server for the "sign" operation
func IsSupportedSigningAlgorithm(alg string) bool {
	return alg == SigningAlgES256
}

// IsSupportedEncryptionAlgorithm reports whether alg is an encryption algorithm accepted by the server for the "encrypt" / "decrypt" operations
// The check is case-insensitive on the dashes and uppercase forms; comparison happens after lowercasing the input
func IsSupportedEncryptionAlgorithm(alg string) bool {
	switch strings.ToLower(alg) {
	case "a256gcm", "aes-256-gcm", "aes256gcm",
		"c20p", "chacha20-poly1305", "chacha20poly1305":
		return true
	default:
		return false
	}
}

type RequestCreateBody struct {
	KeyLabel  string `json:"keyLabel,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	Timeout string `json:"timeout,omitempty"`
	Note    string `json:"note,omitempty"`

	// E2EE envelope (opaque to server)
	RequestEncAlg         string          `json:"requestEncAlg"`
	CliEphemeralPublicKey ECP256PublicJWK `json:"cliEphemeralPublicKey"`
	MlkemCiphertext       string          `json:"mlkemCiphertext"`
	EncryptedPayloadNonce string          `json:"encryptedPayloadNonce"`
	EncryptedPayload      string          `json:"encryptedPayload"`
}

// ValidateNote validates the Note property
func (r *RequestCreateBody) ValidateNote() bool {
	for i := range len(r.Note) {
		ch := r.Note[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			continue
		}
		switch ch {
		case ' ', '.', '/', '_', '-':
			continue
		default:
			return false
		}
	}

	return true
}

// MaxKeyLabelLength is the maximum length of a v2 key label
// 24 chars is enough for human-readable labels and short enough that the value can be used in tight UI rows or log lines without truncation
const MaxKeyLabelLength = 24

// NormalizeAndValidateKeyLabel checks that a key label is well-formed and returns its canonical form
// Allowed: `[A-Za-z0-9_-.+]{1,MaxKeyLabelLength}“
// The result is lowercased
func NormalizeAndValidateKeyLabel(label string) (string, bool) {
	if label == "" || len(label) > MaxKeyLabelLength {
		return "", false
	}

	out := make([]byte, len(label))
	for i := range len(label) {
		ch := label[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			out[i] = ch
		case ch >= 'A' && ch <= 'Z':
			// Fold to lowercase so 'A' and 'a' canonicalize to the same byte
			out[i] = ch + ('a' - 'A')
		case ch >= '0' && ch <= '9':
			out[i] = ch
		case ch == '_' || ch == '-' || ch == '.' || ch == '+':
			out[i] = ch
		default:
			return "", false
		}
	}

	return string(out), true
}

// GetTimeout returns the request timeout as a time.Duration
func (r *RequestCreateBody) GetTimeout() time.Duration {
	if r.Timeout == "" {
		return 0
	}

	timeoutInt, err := strconv.Atoi(r.Timeout)
	if err == nil && timeoutInt > 0 {
		return time.Duration(timeoutInt) * time.Second
	}

	d, err := time.ParseDuration(r.Timeout)
	if err == nil && d >= time.Second {
		return d
	}

	return 0
}

// RequestPayloadInner is the plaintext payload encrypted inside the E2EE envelope
// It is serialized to JSON by the CLI before encryption and deserialized by the browser after decryption
type RequestPayloadInner struct {
	Value                   string          `json:"value,omitempty"`
	Nonce                   string          `json:"nonce,omitempty"`
	Tag                     string          `json:"tag,omitempty"`
	AdditionalData          string          `json:"additionalData,omitempty"`
	ClientTransportEcdhKey  ECP256PublicJWK `json:"clientTransportEcdhKey"`
	ClientTransportMlkemKey string          `json:"clientTransportMlkemKey"`
}

// RequestEncEnvelope is the E2EE envelope stored by the server and forwarded to the browser
// The server cannot decrypt it
type RequestEncEnvelope struct {
	CliEphemeralPublicKey ECP256PublicJWK `json:"cliEphemeralPublicKey"`
	MlkemCiphertext       string          `json:"mlkemCiphertext"`
	Nonce                 string          `json:"nonce"`
	Ciphertext            string          `json:"ciphertext"`
}

type ResponseEnvelope struct {
	TransportAlg              string          `json:"transportAlg"`
	BrowserEphemeralPublicKey ECP256PublicJWK `json:"browserEphemeralPublicKey"`
	MlkemCiphertext           string          `json:"mlkemCiphertext"`
	Nonce                     string          `json:"nonce"`
	Ciphertext                string          `json:"ciphertext"`
	ResultType                string          `json:"resultType,omitempty"`
}

// Validate the request object
func (env *ResponseEnvelope) Validate() error {
	if env.TransportAlg != TransportAlg {
		return errors.New("unsupported transportAlg")
	}

	// Validate the browser's ephemeral ECDH public key
	err := env.BrowserEphemeralPublicKey.ValidatePublic()
	if err != nil {
		return err
	}

	// Validate ML-KEM ciphertext
	if env.MlkemCiphertext == "" {
		return errors.New("missing mlkemCiphertext")
	}
	_, err = utils.DecodeBase64String(env.MlkemCiphertext)
	if err != nil {
		return errors.New("invalid mlkemCiphertext format")
	}

	// Validate required fields
	if env.Nonce == "" || env.Ciphertext == "" {
		return errors.New("nonce and ciphertext are required")
	}

	// Validate base64-encoded fields
	_, err = utils.DecodeBase64String(env.Nonce)
	if err != nil {
		return errors.New("invalid nonce format")
	}
	_, err = utils.DecodeBase64String(env.Ciphertext)
	if err != nil {
		return errors.New("invalid ciphertext format")
	}
	return nil
}

type RequestResultResponse struct {
	State            string            `json:"state"`
	Pending          bool              `json:"pending,omitempty"`
	Done             bool              `json:"done,omitempty"`
	Failed           bool              `json:"failed,omitempty"`
	ResponseEnvelope *ResponseEnvelope `json:"responseEnvelope,omitempty"`
	Error            string            `json:"error,omitempty"`
}
