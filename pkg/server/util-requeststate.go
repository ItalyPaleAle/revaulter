package server

import (
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/italypaleale/revaulter/pkg/keyvault"
)

type requestOperation uint8

const (
	OperationEncrypt requestOperation = iota
	OperationDecrypt
	OperationSign
	OperationVerify
	OperationWrapKey
	OperationUnwrapKey
)

// String representation
func (r requestOperation) String() string {
	switch r {
	case OperationEncrypt:
		return "encrypt"
	case OperationDecrypt:
		return "decrypt"
	case OperationSign:
		return "sign"
	case OperationVerify:
		return "verify"
	case OperationWrapKey:
		return "wrap"
	case OperationUnwrapKey:
		return "unwrap"
	default:
		return ""
	}
}

type requestStatus uint8

const (
	// Request is pending
	StatusPending requestStatus = iota
	// Request is completed and was successful
	StatusComplete
	// Request is completed and was canceled
	StatusCanceled
	// Request has been removed
	// This is only used in the public response
	StatusRemoved
)

// String representation
func (r requestStatus) String() string {
	switch r {
	case StatusPending:
		return "pending"
	case StatusComplete:
		return "complete"
	case StatusCanceled:
		return "canceled"
	case StatusRemoved:
		return "removed"
	default:
		return ""
	}
}

// requestState contains a state request
// All fields have tag `json:"-"` to prevent accidental exposure
type requestState struct {
	Operation  requestOperation `json:"-"`
	Status     requestStatus    `json:"-"`
	Processing bool             `json:"-"`

	Vault      string `json:"-"`
	KeyId      string `json:"-"`
	KeyVersion string `json:"-"`

	Algorithm      string `json:"-"`
	Value          []byte `json:"-"`
	Digest         []byte `json:"-"`
	Signature      []byte `json:"-"`
	AdditionalData []byte `json:"-"`
	Nonce          []byte `json:"-"`
	Tag            []byte `json:"-"`

	Result keyvault.KeyVaultResponse `json:"-"`

	Requestor string    `json:"-"`
	Date      time.Time `json:"-"`
	Expiry    time.Time `json:"-"`
	Note      string    `json:"-"`
}

// Expired returns true if the request has expired
func (rs requestState) Expired() bool {
	return rs.Expiry.Before(time.Now())
}

// Public returns the public version of the object
func (rs requestState) Public(stateId string) requestStatePublic {
	return requestStatePublic{
		State:     stateId,
		Status:    rs.Status.String(),
		Operation: rs.Operation.String(),
		KeyId:     rs.KeyId,
		VaultName: rs.Vault,
		Requestor: rs.Requestor,
		Date:      rs.Date.Unix(),
		Expiry:    rs.Expiry.Unix(),
		Note:      rs.Note,
	}
}

// AzkeysKeyOperationsParams returns the azkeys.KeyOperationParameters object for this request, that can be used with the Azure SDK.
func (rs requestState) AzkeysKeyOperationsParams() azkeys.KeyOperationParameters {
	return azkeys.KeyOperationParameters{
		Algorithm:                   to.Ptr(azkeys.EncryptionAlgorithm(rs.Algorithm)),
		Value:                       rs.Value,
		AdditionalAuthenticatedData: rs.AdditionalData,
		IV:                          rs.Nonce,
		AuthenticationTag:           rs.Tag,
	}
}

// AzkeysSignParams returns the azkeys.SignParameters object for this request, that can be used with the Azure SDK.
func (rs requestState) AzkeysSignParams() azkeys.SignParameters {
	return azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithm(rs.Algorithm)),
		Value:     rs.Digest,
	}
}

// AzkeysVerifyParams returns the azkeys.VerifyParameters object for this request, that can be used with the Azure SDK.
func (rs requestState) AzkeysVerifyParams() azkeys.VerifyParameters {
	return azkeys.VerifyParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithm(rs.Algorithm)),
		Digest:    rs.Digest,
		Signature: rs.Signature,
	}
}

// requestStatePublic is a version of requestState that can be sent to clients
type requestStatePublic struct {
	State     string `json:"state"`
	Status    string `json:"status"`
	Operation string `json:"operation,omitempty"`
	KeyId     string `json:"keyId,omitempty"`
	VaultName string `json:"vaultName,omitempty"`
	Requestor string `json:"requestor,omitempty"`
	Date      int64  `json:"date,omitempty"`
	Expiry    int64  `json:"expiry,omitempty"`
	Note      string `json:"note,omitempty"`
}
