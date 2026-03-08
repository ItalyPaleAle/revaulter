package cmd

import (
	"encoding/json"
	"strings"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type v2OperationFlagsBase struct {
	Server   string
	Insecure bool
	NoH2C    bool

	TargetUser string
	KeyLabel   string
	Algorithm  string

	SecretKey string
	Timeout   durationValue
	Note      string
}

func (f *v2OperationFlagsBase) BindBase(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&f.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")

	cmd.Flags().StringVar(&f.TargetUser, "target-user", "", "Target admin user for the request")
	_ = cmd.MarkFlagRequired("target-user")
	cmd.Flags().StringVar(&f.KeyLabel, "key-label", "", "Logical key label used for v2 key derivation")
	_ = cmd.MarkFlagRequired("key-label")
	cmd.Flags().StringVarP(&f.Algorithm, "algorithm", "a", "", "v2 algorithm identifier")
	_ = cmd.MarkFlagRequired("algorithm")

	cmd.Flags().StringVarP(&f.SecretKey, "secret-key", "K", "", "Secret key if required by the server to access the /request endpoints")
	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Timeout for the operation, as a number of seconds or Go duration")
	cmd.Flags().StringVarP(&f.Note, "note", "n", "", "Optional message displayed alongside the request (up to 40 characters)")
}

func (f *v2OperationFlagsBase) Validate() error {
	f.Server = strings.TrimSuffix(f.Server, "/")
	return nil
}

func (f *v2OperationFlagsBase) GetServer() string                  { return f.Server }
func (f *v2OperationFlagsBase) GetRequestKey() string              { return f.SecretKey }
func (f *v2OperationFlagsBase) GetConnectionOptions() (bool, bool) { return f.Insecure, f.NoH2C }

func (f *v2OperationFlagsBase) AddBaseRequestFields(data *v2OperationRequest, keyJWK protocolv2.ECP256PublicJWK) {
	data.TargetUser = f.TargetUser
	data.KeyLabel = f.KeyLabel
	data.Algorithm = f.Algorithm
	data.Timeout = f.Timeout.String()
	data.Note = f.Note
	data.ClientTransportKey = keyJWK
}

type v2OperationFlags interface {
	BindToCommand(cmd *cobra.Command)
	Validate() error
	RequestBody(clientTransportKey protocolv2.ECP256PublicJWK) ([]byte, error)
	GetServer() string
	GetRequestKey() string
	GetConnectionOptions() (insecure bool, noh2c bool)
}

type v2OperationFlagsEncrypt struct {
	v2OperationFlagsBase
	Value          stringValue
	Nonce          stringValue
	AdditionalData stringValue
}

func (f *v2OperationFlagsEncrypt) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)
	cmd.Flags().Var(&f.Value, "value", "The message to encrypt (base64-encoded)")
	_ = cmd.MarkFlagRequired("value")
	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce/IV for the operation (base64-encoded)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional authenticated data (base64-encoded)")
}

func (f *v2OperationFlagsEncrypt) RequestBody(clientTransportKey protocolv2.ECP256PublicJWK) ([]byte, error) {
	data := v2OperationRequest{
		Value:          f.Value.String(),
		Nonce:          f.Nonce.String(),
		AdditionalData: f.AdditionalData.String(),
	}
	f.AddBaseRequestFields(&data, clientTransportKey)
	return json.Marshal(data)
}

type v2OperationFlagsDecrypt struct {
	v2OperationFlagsBase
	Value          stringValue
	Tag            stringValue
	Nonce          stringValue
	AdditionalData stringValue
}

func (f *v2OperationFlagsDecrypt) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)
	cmd.Flags().Var(&f.Value, "value", "The message to decrypt (base64-encoded)")
	_ = cmd.MarkFlagRequired("value")
	cmd.Flags().Var(&f.Tag, "tag", "Authentication tag (base64-encoded)")
	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce/IV (base64-encoded)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional authenticated data (base64-encoded)")
}

func (f *v2OperationFlagsDecrypt) RequestBody(clientTransportKey protocolv2.ECP256PublicJWK) ([]byte, error) {
	data := v2OperationRequest{
		Value:          f.Value.String(),
		Tag:            f.Tag.String(),
		Nonce:          f.Nonce.String(),
		AdditionalData: f.AdditionalData.String(),
	}
	f.AddBaseRequestFields(&data, clientTransportKey)
	return json.Marshal(data)
}

type v2OperationFlagsWrapKey = v2OperationFlagsEncrypt
type v2OperationFlagsUnwrapKey = v2OperationFlagsDecrypt
