package cmd

import "github.com/italypaleale/revaulter/pkg/protocolv2"

type v2OperationRequest struct {
	KeyLabel  string `json:"keyLabel,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	Value          string `json:"value,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	Tag            string `json:"tag,omitempty"`
	AdditionalData string `json:"additionalData,omitempty"`

	Timeout string `json:"timeout,omitempty"`
	Note    string `json:"note,omitempty"`

	ClientTransportKey protocolv2.ECP256PublicJWK `json:"clientTransportKey"`
}
