package protocolv2

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

type RequestResultResponse struct {
	State            string            `json:"state"`
	Pending          bool              `json:"pending,omitempty"`
	Done             bool              `json:"done,omitempty"`
	Failed           bool              `json:"failed,omitempty"`
	ResponseEnvelope *ResponseEnvelope `json:"responseEnvelope,omitempty"`
	Error            string            `json:"error,omitempty"`
}
