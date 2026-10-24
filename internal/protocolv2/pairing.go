package protocolv2

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Pairing adds a device credential from a client that is already unlocked
// The existing client shows a payload (as a QR code, a link or text) whose secret never reaches the server
// Every message the server relays between the two clients is authenticated with a key derived from that secret, and both screens show a 6-digit code that the user compares

// Prefixes of the pairing payload's text and link forms
const (
	PairingPayloadPrefix = "revaulter-pair:"
	PairingLinkPrefix    = "revaulter://pair/"
)

// Domain-separation prefixes and HKDF info of the pairing messages
const (
	PairingHelloPrefix   = "revaulter/v2/pair/hello\n"
	PairingNoncePrefix   = "revaulter/v2/pair/nonce\n"
	PairingCodePrefix    = "revaulter/v2/pair/code\n"
	PairingMACKeyInfoFmt = "revaulter/v2/pair/mac\nsessionId=%s\nv=1"
)

// PairingVersion is the `v` value of every pairing canonical body
const PairingVersion int64 = 1

// Pairing sizes and limits
const (
	PairingSecretSize    = 32
	PairingSessionIDSize = 16
	PairingNonceSize     = 32
	PairingMACSize       = sha256.Size

	// PairingTTL is how long a pairing session stays open
	PairingTTL = 5 * time.Minute

	// MaxDeviceNameLength matches the limit on credential display names
	MaxDeviceNameLength = 100

	maxPairingServerLength  = 512
	maxPairingUserIDLength  = 128
	maxPairingPayloadLength = 2048
)

// PairingPayload is what the existing client hands to the new device out of band
// The canonical body is base64url-encoded behind PairingPayloadPrefix (text and QR code) or PairingLinkPrefix (link)
// The order is load-bearing: both sides must produce identical bytes
type PairingPayload struct {
	// Server is the base URL of the Revaulter server
	Server string `key:"server"`
	// UserID is the ID of the account being paired
	UserID string `key:"userId"`
	// SessionID is the pairing session's ID, base64url of PairingSessionIDSize random bytes
	SessionID string `key:"sessionId"`
	// Secret is base64url of PairingSecretSize random bytes, and is never sent to the server
	Secret string `key:"secret"`
	// AnchorFingerprint is the user's anchor fingerprint (AnchorFingerprint), which the new device pins
	AnchorFingerprint string `key:"anchorFingerprint"`
	V                 int64  `key:"v"`
}

// CanonicalBody encodes the payload as ordered key=value lines separated by '\n', with no trailing newline
func (p PairingPayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

// String returns the text form of the payload, which is also what the QR code encodes
func (p PairingPayload) String() string {
	return PairingPayloadPrefix + base64.RawURLEncoding.EncodeToString([]byte(p.CanonicalBody()))
}

// Link returns the payload as a link that opens the native app
func (p PairingPayload) Link() string {
	return PairingLinkPrefix + base64.RawURLEncoding.EncodeToString([]byte(p.CanonicalBody()))
}

// Validate checks every field of the payload
func (p PairingPayload) Validate() error {
	if p.V != PairingVersion {
		return fmt.Errorf("unsupported pairing version %d", p.V)
	}

	err := ValidatePairingServer(p.Server)
	if err != nil {
		return err
	}

	err = validateCanonicalText("userId", p.UserID, maxPairingUserIDLength)
	if err != nil {
		return err
	}

	_, err = decodeBase64Field("sessionId", p.SessionID, PairingSessionIDSize)
	if err != nil {
		return err
	}

	_, err = decodeBase64Field("secret", p.Secret, PairingSecretSize)
	if err != nil {
		return err
	}

	err = validateAnchorFingerprint(p.AnchorFingerprint)
	if err != nil {
		return err
	}

	return nil
}

// MACKey derives the key that authenticates the pairing messages
func (p PairingPayload) MACKey() ([]byte, error) {
	secret, err := decodeBase64Field("secret", p.Secret, PairingSecretSize)
	if err != nil {
		return nil, err
	}

	return PairingMACKey(secret, p.SessionID)
}

// ParsePairingPayload parses the text or link form of a pairing payload and validates it
// Surrounding whitespace is ignored, so a pasted string with a trailing newline still parses
func ParsePairingPayload(s string) (PairingPayload, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxPairingPayloadLength {
		return PairingPayload{}, fmt.Errorf("pairing payload must be at most %d characters", maxPairingPayloadLength)
	}

	var encoded string
	switch {
	case strings.HasPrefix(s, PairingPayloadPrefix):
		encoded = s[len(PairingPayloadPrefix):]
	case strings.HasPrefix(s, PairingLinkPrefix):
		encoded = s[len(PairingLinkPrefix):]
	default:
		return PairingPayload{}, errors.New("not a Revaulter pairing payload")
	}

	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return PairingPayload{}, fmt.Errorf("pairing payload is not valid base64url: %w", err)
	}

	var p PairingPayload
	err = parseTaggedFields(string(body), &p)
	if err != nil {
		return PairingPayload{}, fmt.Errorf("invalid pairing payload: %w", err)
	}

	err = p.Validate()
	if err != nil {
		return PairingPayload{}, err
	}

	return p, nil
}

// ValidatePairingServer checks a server base URL carried in a pairing payload
// It must be https, or http on a loopback address for local development, with no credentials, query or fragment
func ValidatePairingServer(server string) error {
	err := validateCanonicalText("server", server, maxPairingServerLength)
	if err != nil {
		return err
	}

	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("server is not a valid URL: %w", err)
	}
	if u.Opaque != "" || u.Host == "" {
		return errors.New("server must be an absolute URL with a host")
	}
	if u.User != nil {
		return errors.New("server must not contain credentials")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("server must not contain a query or fragment")
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.New("server must use https unless it runs on a loopback address")
	default:
		return fmt.Errorf("unsupported server scheme %q", u.Scheme)
	}
}

// validateAnchorFingerprint checks the lowercase hex SHA-256 format that AnchorFingerprint produces
func validateAnchorFingerprint(fp string) error {
	if len(fp) != 2*sha256.Size || strings.ToLower(fp) != fp {
		return errors.New("anchorFingerprint must be 64 lowercase hex characters")
	}

	_, err := hex.DecodeString(fp)
	if err != nil {
		return errors.New("anchorFingerprint must be 64 lowercase hex characters")
	}

	return nil
}

// PairingMACKey derives the pairing MAC key from the payload secret, bound to the session ID
func PairingMACKey(secret []byte, sessionID string) ([]byte, error) {
	if len(secret) != PairingSecretSize {
		return nil, fmt.Errorf("pairing secret must be %d bytes, got %d", PairingSecretSize, len(secret))
	}

	return hkdf.Key(sha256.New, secret, nil, fmt.Sprintf(PairingMACKeyInfoFmt, sessionID), sha256.Size)
}

// PairingHello is what the new device sends after scanning the payload
// The two signatures prove it holds the private halves of its signing keys, and the MAC proves it saw the payload secret
// All three cover the canonical message of the PairingTranscript built from this hello
type PairingHello struct {
	DeviceName       string           `json:"deviceName"`
	CredentialID     string           `json:"credentialId"`
	PublicKeys       DevicePublicKeys `json:"publicKeys"`
	SignatureP256    string           `json:"signatureP256"`
	SignatureMldsa65 string           `json:"signatureMldsa65"`
	MAC              string           `json:"mac"`
}

// Validate checks the hello's structure and returns its parsed public keys
// It does not verify the signatures or the MAC, which need the transcript
func (h *PairingHello) Validate() (*ParsedDevicePublicKeys, error) {
	err := validateCanonicalText("deviceName", h.DeviceName, MaxDeviceNameLength)
	if err != nil {
		return nil, err
	}

	_, err = decodeBase64Field("credentialId", h.CredentialID, DeviceCredentialIDSize)
	if err != nil {
		return nil, err
	}

	keys, err := h.PublicKeys.Parse()
	if err != nil {
		return nil, err
	}

	_, err = decodeBase64Field("signatureP256", h.SignatureP256, P256SignatureSize)
	if err != nil {
		return nil, err
	}

	_, err = decodeBase64Field("signatureMldsa65", h.SignatureMldsa65, MLDSA65SignatureSize)
	if err != nil {
		return nil, err
	}

	_, err = decodeBase64Field("mac", h.MAC, PairingMACSize)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// PairingTranscript binds a hello to the session it answers: the server, user, session and anchor from the payload, then the device's name, credential ID and public keys
// The order is load-bearing: both clients and the server must produce identical bytes
type PairingTranscript struct {
	Server            string `key:"server"`
	UserID            string `key:"userId"`
	SessionID         string `key:"sessionId"`
	AnchorFingerprint string `key:"anchorFingerprint"`
	CredentialID      string `key:"credentialId"`
	DeviceName        string `key:"deviceName"`
	SignP256          string `key:"signP256"`
	KaP256            string `key:"kaP256"`
	SignMldsa65       string `key:"signMldsa65"`
	KemMlkem768       string `key:"kemMlkem768"`
	V                 int64  `key:"v"`
}

// NewPairingTranscript builds the transcript of a hello
// server, userID, sessionID and anchorFingerprint come from the payload (the server takes them from its own state)
func NewPairingTranscript(server string, userID string, sessionID string, anchorFingerprint string, hello *PairingHello) PairingTranscript {
	return PairingTranscript{
		Server:            server,
		UserID:            userID,
		SessionID:         sessionID,
		AnchorFingerprint: anchorFingerprint,
		CredentialID:      hello.CredentialID,
		DeviceName:        hello.DeviceName,
		SignP256:          hello.PublicKeys.SignP256,
		KaP256:            hello.PublicKeys.KaP256,
		SignMldsa65:       hello.PublicKeys.SignMldsa65,
		KemMlkem768:       hello.PublicKeys.KemMlkem768,
		V:                 PairingVersion,
	}
}

// CanonicalBody encodes the transcript as ordered key=value lines separated by '\n', with no trailing newline
func (t PairingTranscript) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(t)
}

// CanonicalPairingHelloMessage returns the message that the hello's signatures and MAC cover
func CanonicalPairingHelloMessage(t *PairingTranscript) []byte {
	return prefixedMessage(PairingHelloPrefix, t.CanonicalBody())
}

// PairingHelloMAC returns the MAC the new device attaches to its hello
func PairingHelloMAC(macKey []byte, t *PairingTranscript) []byte {
	return hmacSHA256(macKey, CanonicalPairingHelloMessage(t))
}

// VerifyPairingHelloMAC checks a hello's MAC in constant time
// Only the two clients can do this: the server never has the MAC key
func VerifyPairingHelloMAC(macKey []byte, t *PairingTranscript, mac []byte) error {
	if t.V != PairingVersion {
		return fmt.Errorf("unsupported pairing version %d", t.V)
	}

	return verifyPairingMAC(macKey, PairingHelloMAC(macKey, t), mac)
}

// VerifyPairingHelloSignatures checks that both of the device's signing keys signed the transcript
// The server and the existing client both run this check
func VerifyPairingHelloSignatures(keys *ParsedDevicePublicKeys, t *PairingTranscript, sigP256 []byte, sigMldsa65 []byte) error {
	if t.V != PairingVersion {
		return fmt.Errorf("unsupported pairing version %d", t.V)
	}

	return verifyDeviceSignatures(keys, CanonicalPairingHelloMessage(t), sigP256, sigMldsa65)
}

// PairingNoncePayload is what the existing client authenticates after it accepted a hello
// HelloMAC identifies the hello, and Nonce is fresh randomness that both sides mix into the comparison code
// The nonce is chosen only after the hello is fixed, so nobody can pick device keys that produce a given code
type PairingNoncePayload struct {
	HelloMAC string `key:"helloMac"`
	Nonce    string `key:"nonce"`
	V        int64  `key:"v"`
}

// CanonicalBody encodes the nonce payload as ordered key=value lines separated by '\n', with no trailing newline
func (p PairingNoncePayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

// Validate checks the sizes of the hello MAC and the nonce
func (p PairingNoncePayload) Validate() error {
	if p.V != PairingVersion {
		return fmt.Errorf("unsupported pairing version %d", p.V)
	}

	_, err := decodeBase64Field("helloMac", p.HelloMAC, PairingMACSize)
	if err != nil {
		return err
	}

	_, err = decodeBase64Field("nonce", p.Nonce, PairingNonceSize)
	if err != nil {
		return err
	}

	return nil
}

// CanonicalPairingNonceMessage returns the message that the nonce MAC covers
func CanonicalPairingNonceMessage(p *PairingNoncePayload) []byte {
	return prefixedMessage(PairingNoncePrefix, p.CanonicalBody())
}

// PairingNonceMAC returns the MAC the existing client attaches to the nonce
func PairingNonceMAC(macKey []byte, p *PairingNoncePayload) []byte {
	return hmacSHA256(macKey, CanonicalPairingNonceMessage(p))
}

// VerifyPairingNonceMAC checks the nonce's MAC in constant time
func VerifyPairingNonceMAC(macKey []byte, p *PairingNoncePayload, mac []byte) error {
	err := p.Validate()
	if err != nil {
		return err
	}

	return verifyPairingMAC(macKey, PairingNonceMAC(macKey, p), mac)
}

// PairingCode returns the 6-digit code both screens show, zero-padded
// It is the first 4 bytes of an HMAC over the hello MAC and the nonce, read as a big-endian integer, modulo 10^6
func PairingCode(macKey []byte, p *PairingNoncePayload) string {
	sum := hmacSHA256(macKey, prefixedMessage(PairingCodePrefix, p.CanonicalBody()))
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[:4])%1_000_000)
}

func verifyPairingMAC(macKey []byte, expected []byte, mac []byte) error {
	if len(macKey) != sha256.Size {
		return fmt.Errorf("pairing MAC key must be %d bytes, got %d", sha256.Size, len(macKey))
	}
	if len(mac) != PairingMACSize {
		return fmt.Errorf("pairing MAC must be %d bytes, got %d", PairingMACSize, len(mac))
	}
	if !hmac.Equal(expected, mac) {
		return errors.New("pairing MAC verification failed")
	}

	return nil
}

func hmacSHA256(key []byte, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
