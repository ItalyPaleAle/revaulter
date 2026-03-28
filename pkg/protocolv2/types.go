package protocolv2

type RequestCreateBody struct {
	TargetUser string `json:"targetUser,omitempty"`
	KeyLabel   string `json:"keyLabel,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`

	Value          string `json:"value,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	Tag            string `json:"tag,omitempty"`
	AdditionalData string `json:"additionalData,omitempty"`

	Timeout string `json:"timeout,omitempty"`
	Note    string `json:"note,omitempty"`

	ClientTransportKey ECP256PublicJWK `json:"clientTransportKey"`
}

type ResponseEnvelope struct {
	TransportAlg              string          `json:"transportAlg"`
	BrowserEphemeralPublicKey ECP256PublicJWK `json:"browserEphemeralPublicKey"`
	Nonce                     string          `json:"nonce"`
	Ciphertext                string          `json:"ciphertext"`
	AAD                       string          `json:"aad,omitempty"`
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
