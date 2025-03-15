package keyvault

// KeyVaultResponse is the interface implemented by all response objects returned by the methods in this package
type KeyVaultResponse interface {
	// Raw returns the raw response
	Raw() []byte
	// KeyID returns the key ID
	KeyID() string
}

// Base for all responses, which includes the KeyID method
type keyVaultResponseBase struct {
	keyID string
}

// SetKeyID sets the key ID
func (b *keyVaultResponseBase) SetKeyID(kid string) {
	b.keyID = kid
}

// KeyID returns the key ID
func (b *keyVaultResponseBase) KeyID() string {
	return b.keyID
}

// KeyVaultEncryptResponse is the response from the Encrypt and WrapKey methods
type KeyVaultEncryptResponse struct {
	keyVaultResponseBase

	Data  []byte `json:"data,omitempty"`
	Nonce []byte `json:"nonce,omitempty"`
	Tag   []byte `json:"tag,omitempty"`
}

// Raw returns the raw response
func (e KeyVaultEncryptResponse) Raw() []byte {
	dataLen := len(e.Data)
	nonceLen := len(e.Nonce)
	tagLen := len(e.Tag)

	res := make([]byte, dataLen+nonceLen+tagLen)
	if nonceLen > 0 {
		copy(res[0:nonceLen], e.Nonce)
	}
	if len(e.Data) > 0 {
		copy(res[nonceLen:(dataLen+nonceLen)], e.Data)
	}
	if len(e.Tag) > 0 {
		copy(res[(dataLen+nonceLen):], e.Tag)
	}

	return res
}

// KeyVaultDecryptResponse is the response from the Decrypt and UnwrapKey methods
type KeyVaultDecryptResponse struct {
	keyVaultResponseBase

	Data []byte `json:"data,omitempty"`
}

// Raw returns the raw response
func (d KeyVaultDecryptResponse) Raw() []byte {
	return d.Data
}

// KeyVaultSignResponse is the response from the Sign method
type KeyVaultSignResponse struct {
	keyVaultResponseBase

	Data []byte `json:"data,omitempty"`
}

// Raw returns the raw response
func (s KeyVaultSignResponse) Raw() []byte {
	return s.Data
}

// KeyVaultVerifyResponse is the response from the Verify method
type KeyVaultVerifyResponse struct {
	keyVaultResponseBase

	Valid bool `json:"valid,omitempty"`
}

// Raw returns the raw response
func (v KeyVaultVerifyResponse) Raw() []byte {
	if v.Valid {
		return []byte("true")
	} else {
		return []byte("false")
	}
}
