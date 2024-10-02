package cmd

import "encoding/json"

// Type for operation requests
type operationRequest struct {
	Vault      string `json:"vault,omitempty"`
	KeyId      string `json:"keyId,omitempty"`
	KeyVersion string `json:"keyVersion,omitempty"`

	Algorithm      string `json:"algorithm,omitempty"`
	Value          string `json:"value,omitempty"`
	Digest         string `json:"digest,omitempty"`
	Signature      string `json:"signature,omitempty"`
	AdditionalData string `json:"additionalData,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	Tag            string `json:"tag,omitempty"`

	Timeout string `json:"timeout,omitempty"`
	Note    string `json:"note,omitempty"`
}

type operationResponse struct {
	State    string          `json:"state"`
	Error    string          `json:"error"`
	Pending  bool            `json:"pending"`
	Done     bool            `json:"done"`
	Failed   bool            `json:"failed"`
	Response json.RawMessage `json:"response"`
}
