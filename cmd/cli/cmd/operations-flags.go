package cmd

import (
	"encoding/json"
	"strings"

	"github.com/spf13/cobra"
)

type operationFlags interface {
	BindToCommand(cmd *cobra.Command)
	Validate() error
	RequestBody() ([]byte, error)
	GetServer() (string, bool)
}

// Flags for the operations commands
type operationFlagsBase struct {
	// TODO: Add option to enable HTTP/1 support

	Server   string
	Insecure bool

	Vault      string
	KeyId      string
	KeyVersion string

	Algorithm string

	Timeout durationValue
	Note    string
}

func (f *operationFlagsBase) BindToCommand(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server")
	cmd.MarkFlagRequired("server")
	cmd.Flags().BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")

	cmd.Flags().StringVarP(&f.Vault, "vault", "v", "", "Name or URL of the Azure Key Vault")
	cmd.MarkFlagRequired("vault")
	cmd.Flags().StringVarP(&f.KeyId, "key-id", "k", "", "ID of the key stored in the Key Vault")
	cmd.MarkFlagRequired("key-id")
	cmd.Flags().StringVar(&f.KeyVersion, "key-version", "", "Version of the key stored in the Key Vault")

	cmd.Flags().StringVarP(&f.Algorithm, "algorithm", "a", "", "Algorithm identifier")
	cmd.MarkFlagRequired("algorithm")

	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Timeout for the operation, as a number of seconds or Go duration")
	cmd.Flags().StringVarP(&f.Note, "note", "n", "", "Optional message displayed alongside the request (up to 40 characters)")
}

func (f *operationFlagsBase) Validate() error {
	// Remove the trailing slash from the server URL if set
	f.Server = strings.TrimSuffix(f.Server, "/")
	return nil
}

func (f operationFlagsBase) GetServer() (string, bool) {
	return f.Server, f.Insecure
}

func (f operationFlagsBase) AddBaseRequestBodyFields(data *operationRequest) {
	data.Vault = f.Vault
	data.KeyId = f.KeyId
	data.KeyVersion = f.KeyVersion
	data.Algorithm = f.Algorithm
	data.Timeout = f.Timeout.String()
	data.Note = f.Note
}

type operationFlagsEncrypt struct {
	operationFlagsBase

	Value          stringValue
	Nonce          stringValue
	AdditionalData stringValue
}

func (f *operationFlagsEncrypt) BindToCommand(cmd *cobra.Command) {
	f.operationFlagsBase.BindToCommand(cmd)

	cmd.Flags().Var(&f.Value, "value", "The message to encrypt (base64-encoded)")
	cmd.MarkFlagRequired("value")

	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce (or Initialization Vector) for the encryption operation, if required by the algorithm (base64-encoded)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional Authenticated Data, which may not be supported by all algorithms (base64-encoded)")
}

func (f operationFlagsEncrypt) RequestBody() ([]byte, error) {
	data := operationRequest{
		Value:          f.Value.String(),
		Nonce:          f.Nonce.String(),
		AdditionalData: f.AdditionalData.String(),
	}
	f.operationFlagsBase.AddBaseRequestBodyFields(&data)

	return json.Marshal(data)
}

type operationFlagsDecrypt struct {
	operationFlagsBase

	Value          stringValue
	Tag            stringValue
	Nonce          stringValue
	AdditionalData stringValue
}

func (f *operationFlagsDecrypt) BindToCommand(cmd *cobra.Command) {
	f.operationFlagsBase.BindToCommand(cmd)

	cmd.Flags().Var(&f.Value, "value", "The message to decrypt (base64-encoded)")
	cmd.MarkFlagRequired("value")

	cmd.Flags().Var(&f.Tag, "tag", "Authentication tag for the decryption operation, if required by the algorithm (base64-encoded)")
	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce (or Initialization Vector) for the decryption operation, if required by the algorithm (base64-encoded)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional Authenticated Data, which may not be supported by all algorithms (base64-encoded)")
}

func (f operationFlagsDecrypt) RequestBody() ([]byte, error) {
	data := operationRequest{
		Value:          f.Value.String(),
		Tag:            f.Tag.String(),
		Nonce:          f.Nonce.String(),
		AdditionalData: f.AdditionalData.String(),
	}
	f.operationFlagsBase.AddBaseRequestBodyFields(&data)

	return json.Marshal(data)
}

type operationFlagsSign struct {
	operationFlagsBase

	Digest stringValue
}

func (f *operationFlagsSign) BindToCommand(cmd *cobra.Command) {
	f.operationFlagsBase.BindToCommand(cmd)

	cmd.Flags().Var(&f.Digest, "digest", "The digest (hash) of the message to sign (base64-encoded)")
	cmd.MarkFlagRequired("digest")
}

func (f operationFlagsSign) RequestBody() ([]byte, error) {
	data := operationRequest{
		Digest: f.Digest.String(),
	}
	f.operationFlagsBase.AddBaseRequestBodyFields(&data)

	return json.Marshal(data)
}

type operationFlagsVerify struct {
	operationFlagsBase

	Digest    stringValue
	Signature stringValue
}

func (f *operationFlagsVerify) BindToCommand(cmd *cobra.Command) {
	f.operationFlagsBase.BindToCommand(cmd)

	cmd.Flags().Var(&f.Digest, "digest", "The digest (hash) of the message that was signed (base64-encoded)")
	cmd.MarkFlagRequired("digest")
	cmd.Flags().Var(&f.Signature, "signature", "The signature to verify (base64-encoded)")
	cmd.MarkFlagRequired("signature")
}

func (f operationFlagsVerify) RequestBody() ([]byte, error) {
	data := operationRequest{
		Digest:    f.Digest.String(),
		Signature: f.Signature.String(),
	}
	f.operationFlagsBase.AddBaseRequestBodyFields(&data)

	return json.Marshal(data)
}

type operationFlagsWrapKey struct {
	operationFlagsBase

	Value          stringValue
	Nonce          stringValue
	AdditionalData stringValue
}

func (f *operationFlagsWrapKey) BindToCommand(cmd *cobra.Command) {
	f.operationFlagsBase.BindToCommand(cmd)

	cmd.Flags().Var(&f.Value, "value", "The key to wrap (base64-encoded)")
	cmd.MarkFlagRequired("value")

	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce (or Initialization Vector) for the wrapping operation, if required by the algorithm (base64-encoded)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional Authenticated Data, which may not be supported by all algorithms (base64-encoded)")
}

func (f operationFlagsWrapKey) RequestBody() ([]byte, error) {
	data := operationRequest{
		Value:          f.Value.String(),
		Nonce:          f.Nonce.String(),
		AdditionalData: f.AdditionalData.String(),
	}
	f.operationFlagsBase.AddBaseRequestBodyFields(&data)

	return json.Marshal(data)
}

type operationFlagsUnwrapKey struct {
	operationFlagsBase

	Value          stringValue
	Tag            stringValue
	Nonce          stringValue
	AdditionalData stringValue
}

func (f *operationFlagsUnwrapKey) BindToCommand(cmd *cobra.Command) {
	f.operationFlagsBase.BindToCommand(cmd)

	cmd.Flags().Var(&f.Value, "value", "The key to unwrap (base64-encoded)")
	cmd.MarkFlagRequired("value")

	cmd.Flags().Var(&f.Tag, "tag", "Authentication tag for the unwrapping operation, if required by the algorithm (base64-encoded)")
	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce (or Initialization Vector) for the unwrapping operation, if required by the algorithm (base64-encoded)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional Authenticated Data, which may not be supported by all algorithms (base64-encoded)")
}

func (f operationFlagsUnwrapKey) RequestBody() ([]byte, error) {
	data := operationRequest{
		Value:          f.Value.String(),
		Tag:            f.Tag.String(),
		Nonce:          f.Nonce.String(),
		AdditionalData: f.AdditionalData.String(),
	}
	f.operationFlagsBase.AddBaseRequestBodyFields(&data)

	return json.Marshal(data)
}
