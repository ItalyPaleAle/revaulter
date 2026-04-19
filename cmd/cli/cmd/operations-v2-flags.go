package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type v2OperationFlagsBase struct {
	Server   string
	Insecure bool
	NoH2C    bool

	RequestKey string
	KeyLabel   string
	Algorithm  string

	Timeout durationValue
	Note    string

	Output string
	Raw    bool

	// Trust store: the CLI pins the server's hybrid anchor (ES384 + ML-DSA-87)
	// on first contact and refuses to proceed on mismatch. --trust-store picks
	// the file; --no-trust-store disables both pinning and verification.
	TrustStorePath string
	NoTrustStore   bool
}

func (f *v2OperationFlagsBase) BindBase(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&f.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")

	cmd.Flags().StringVar(&f.RequestKey, "request-key", "", "Per-user request key used to route the request")
	_ = cmd.MarkFlagRequired("request-key")
	cmd.Flags().StringVar(&f.KeyLabel, "key-label", "", "Logical key label used for v2 key derivation")
	_ = cmd.MarkFlagRequired("key-label")
	cmd.Flags().StringVarP(&f.Algorithm, "algorithm", "a", "", "v2 algorithm identifier")
	_ = cmd.MarkFlagRequired("algorithm")

	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Timeout for the operation, as a number of seconds or Go duration")
	cmd.Flags().StringVarP(&f.Note, "note", "n", "", "Optional message displayed alongside the request (up to 40 characters)")

	cmd.Flags().StringVarP(&f.Output, "output", "o", "", "Write the result to this file path instead of stdout (mode 0600, refuses symlinks)")
	cmd.Flags().BoolVar(&f.Raw, "raw", false, "Write the decrypted plaintext as raw bytes instead of the default JSON envelope")

	cmd.Flags().StringVar(&f.TrustStorePath, "trust-store", "", "Path to the anchor trust store (defaults to $XDG_CONFIG_HOME/revaulter-cli/trust.json)")
	cmd.Flags().BoolVar(&f.NoTrustStore, "no-trust-store", false, "Skip anchor pinning and hybrid bundle verification (equivalent to SSH StrictHostKeyChecking=no)")
}

func (f *v2OperationFlagsBase) Validate() error {
	f.Server = strings.TrimSuffix(f.Server, "/")
	return nil
}

func (f *v2OperationFlagsBase) GetServer() string                  { return f.Server }
func (f *v2OperationFlagsBase) GetRequestKey() string              { return f.RequestKey }
func (f *v2OperationFlagsBase) GetKeyLabel() string                { return f.KeyLabel }
func (f *v2OperationFlagsBase) GetAlgorithm() string               { return f.Algorithm }
func (f *v2OperationFlagsBase) GetTimeout() string                 { return f.Timeout.String() }
func (f *v2OperationFlagsBase) GetNote() string                    { return f.Note }
func (f *v2OperationFlagsBase) GetConnectionOptions() (bool, bool) { return f.Insecure, f.NoH2C }
func (f *v2OperationFlagsBase) GetOutput() string                  { return f.Output }
func (f *v2OperationFlagsBase) GetRaw() bool                       { return f.Raw }
func (f *v2OperationFlagsBase) GetTrustStorePath() string          { return f.TrustStorePath }
func (f *v2OperationFlagsBase) GetNoTrustStore() bool              { return f.NoTrustStore }

type v2OperationFlags interface {
	BindToCommand(cmd *cobra.Command)
	Validate() error
	InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner
	GetServer() string
	GetRequestKey() string
	GetKeyLabel() string
	GetAlgorithm() string
	GetTimeout() string
	GetNote() string
	GetConnectionOptions() (insecure bool, noh2c bool)
	GetOutput() string
	GetRaw() bool
	GetTrustStorePath() string
	GetNoTrustStore() bool
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

func (f *v2OperationFlagsEncrypt) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.Value.String(),
		Nonce:                   f.Nonce.String(),
		AdditionalData:          f.AdditionalData.String(),
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
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

func (f *v2OperationFlagsDecrypt) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.Value.String(),
		Tag:                     f.Tag.String(),
		Nonce:                   f.Nonce.String(),
		AdditionalData:          f.AdditionalData.String(),
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}
