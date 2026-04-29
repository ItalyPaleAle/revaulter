package cmd

import (
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type v2OperationRequest struct {
	KeyLabel  string `json:"keyLabel,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	Timeout string `json:"timeout,omitempty"`
	Note    string `json:"note,omitempty"`

	// E2EE envelope
	RequestEncAlg         string                     `json:"requestEncAlg"`
	CliEphemeralPublicKey protocolv2.ECP256PublicJWK `json:"cliEphemeralPublicKey"`
	MlkemCiphertext       string                     `json:"mlkemCiphertext"`
	EncryptedPayloadNonce string                     `json:"encryptedPayloadNonce"`
	EncryptedPayload      string                     `json:"encryptedPayload"`
}
