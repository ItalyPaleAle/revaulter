package protocolv2

// Request and response bodies of the device login and pairing endpoints
// The server and the native client library both use these types, so the two sides can't drift
// Binary values are base64url (raw, no padding) and timestamps are Unix seconds

// DeviceLoginBeginRequest is the body of POST /v2/auth/device/login/begin
type DeviceLoginBeginRequest struct {
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
}

// DeviceLoginBeginResponse carries the challenge the device signs
type DeviceLoginBeginResponse struct {
	ChallengeID string `json:"challengeId"`
	Challenge   string `json:"challenge"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// DeviceLoginFinishRequest is the body of POST /v2/auth/device/login/finish
// Both signatures cover CanonicalDeviceLoginMessage
type DeviceLoginFinishRequest struct {
	ChallengeID      string `json:"challengeId"`
	CredentialID     string `json:"credentialId"`
	SignatureP256    string `json:"signatureP256"`
	SignatureMldsa65 string `json:"signatureMldsa65"`
}

// DeviceLoginFinishResponse returns the session token, which the app sends as a bearer token, and the device's wrapped keys
// The rest of the session details come from GET /v2/auth/session
type DeviceLoginFinishResponse struct {
	Authenticated             bool   `json:"authenticated"`
	SessionToken              string `json:"sessionToken"`
	SessionExpiresAt          int64  `json:"sessionExpiresAt"`
	UserID                    string `json:"userId"`
	WrappedPrimaryKey         string `json:"wrappedPrimaryKey"`
	WrappedAnchorKey          string `json:"wrappedAnchorKey"`
	CredentialWrappedKeyEpoch int64  `json:"credentialWrappedKeyEpoch"`
	WrappedKeyStale           bool   `json:"wrappedKeyStale"`
}

// Pairing session statuses
// A session moves forward only: created, then hello, then nonce, then completed; it can be canceled at any point before completion
// PairingStatusExpired is never stored: the server reports it for a session that reached its expiry before completing
const (
	PairingStatusCreated   = "created"
	PairingStatusHello     = "hello"
	PairingStatusNonce     = "nonce"
	PairingStatusCompleted = "completed"
	PairingStatusCanceled  = "canceled"
	PairingStatusExpired   = "expired"
)

// PairingCreateRequest is the body of POST /v2/auth/pairing/create, sent by the existing client
// Server is the base URL the client puts in the payload; the server stores it to rebuild the transcript when it checks the hello's signatures
type PairingCreateRequest struct {
	Server string `json:"server"`
}

// PairingCreateResponse returns the new session's ID and expiry
type PairingCreateResponse struct {
	SessionID string `json:"sessionId"`
	ExpiresAt int64  `json:"expiresAt"`
}

// PairingHelloRequest is the body of POST /v2/auth/pairing/hello, sent by the new device
type PairingHelloRequest struct {
	SessionID string       `json:"sessionId"`
	Hello     PairingHello `json:"hello"`
}

// PairingSessionResponse is returned by GET /v2/auth/pairing/:id to the existing client
type PairingSessionResponse struct {
	SessionID string        `json:"sessionId"`
	Status    string        `json:"status"`
	ExpiresAt int64         `json:"expiresAt"`
	Hello     *PairingHello `json:"hello,omitempty"`
}

// PairingNonceRequest is the body of POST /v2/auth/pairing/nonce, sent by the existing client
// NonceMAC is PairingNonceMAC over a PairingNoncePayload that binds the nonce to the accepted hello
type PairingNonceRequest struct {
	SessionID string `json:"sessionId"`
	Nonce     string `json:"nonce"`
	NonceMAC  string `json:"nonceMac"`
}

// PairingDeviceStatusResponse is returned by GET /v2/auth/pairing/:id/device to the new device
// Nonce and NonceMAC are set once the existing client has sent them
type PairingDeviceStatusResponse struct {
	Status    string `json:"status"`
	ExpiresAt int64  `json:"expiresAt"`
	Nonce     string `json:"nonce,omitempty"`
	NonceMAC  string `json:"nonceMac,omitempty"`
}

// PairingCompleteRequest is the body of POST /v2/auth/pairing/complete, sent by the existing client
// The attestation is an AttestationPayloadV2 for a device credential, signed by the user's anchor
type PairingCompleteRequest struct {
	SessionID                   string `json:"sessionId"`
	DisplayName                 string `json:"displayName"`
	WrappedPrimaryKey           string `json:"wrappedPrimaryKey"`
	WrappedAnchorKey            string `json:"wrappedAnchorKey"`
	AttestationPayload          string `json:"attestationPayload"`
	AttestationSignatureEs384   string `json:"attestationSignatureEs384"`
	AttestationSignatureMldsa87 string `json:"attestationSignatureMldsa87"`
}

// PairingCompleteResponse identifies the credential that was added
// ID is the server's record ID, which the credential management endpoints take; CredentialID is the device's own ID from the hello
type PairingCompleteResponse struct {
	ID           string `json:"id"`
	CredentialID string `json:"credentialId"`
}

// PairingCancelRequest is the body of POST /v2/auth/pairing/cancel, sent by the existing client
type PairingCancelRequest struct {
	SessionID string `json:"sessionId"`
}
