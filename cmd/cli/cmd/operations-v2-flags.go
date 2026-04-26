package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"time"

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

	// Trust store: the CLI pins the server's hybrid anchor (ES384 + ML-DSA-87) on first contact and refuses to proceed on mismatch
	// --trust-store picks the file; --no-trust-store disables both pinning and verification.
	TrustStorePath string
	NoTrustStore   bool
}

func (f *v2OperationFlagsBase) BindBase(cmd *cobra.Command) {
	defaultPath, _ := defaultTrustStorePath()
	var trustStoreDefault string
	if defaultPath != "" {
		trustStoreDefault = " (defaults to " + defaultPath + ")"
	}

	cmd.Flags().StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&f.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")

	cmd.Flags().StringVar(&f.RequestKey, "request-key", "", "Per-user request key used to route the request")
	_ = cmd.MarkFlagRequired("request-key")
	cmd.Flags().StringVar(&f.KeyLabel, "key-label", "", "Logical key label used for v2 key derivation")
	_ = cmd.MarkFlagRequired("key-label")
	cmd.Flags().StringVarP(&f.Algorithm, "algorithm", "a", "", "algorithm identifier")
	_ = cmd.MarkFlagRequired("algorithm")

	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Timeout for the operation, as a number of seconds or Go duration")
	cmd.Flags().StringVarP(&f.Note, "note", "n", "", "Optional message displayed alongside the request (up to 40 characters)")

	cmd.Flags().StringVarP(&f.Output, "output", "o", "", "Write the result to this file path instead of stdout (mode 0600, refuses symlinks)")
	cmd.Flags().BoolVar(&f.Raw, "raw", false, "Write the decrypted plaintext as raw bytes instead of the default JSON envelope")

	cmd.Flags().StringVar(&f.TrustStorePath, "trust-store", "", "Path to the anchor trust store"+trustStoreDefault)
	cmd.Flags().BoolVar(&f.NoTrustStore, "no-trust-store", false, "Skip anchor pinning and hybrid bundle verification (equivalent to SSH StrictHostKeyChecking=no)")
}

func (f *v2OperationFlagsBase) Validate() error {
	f.Server = strings.TrimSuffix(f.Server, "/")

	// Normalize the key label up-front so subsequent reads (and the request body) use the canonical form
	// The server applies the same rule and would reject anything else with a BadRequest
	canonicalKeyLabel, ok := protocolv2.NormalizeAndValidateKeyLabel(f.KeyLabel)
	if !ok {
		return fmt.Errorf("key-label must be 1-%d bytes and contain only [A-Za-z0-9_.+-]", protocolv2.MaxKeyLabelLength)
	}
	f.KeyLabel = canonicalKeyLabel

	return nil
}

func (f *v2OperationFlagsBase) GetServer() string                  { return f.Server }
func (f *v2OperationFlagsBase) GetRequestKey() string              { return f.RequestKey }
func (f *v2OperationFlagsBase) GetKeyLabel() string                { return f.KeyLabel }
func (f *v2OperationFlagsBase) GetAlgorithm() string               { return f.Algorithm }
func (f *v2OperationFlagsBase) GetTimeout() string                 { return f.Timeout.String() }
func (f *v2OperationFlagsBase) GetTimeoutDuration() time.Duration  { return time.Duration(f.Timeout) }
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
	GetTimeoutDuration() time.Duration
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

// v2OperationFlagsSign carries flags specific to the `sign` operation
// The resolved digest/header/payload fields are populated during Validate so Run can compose the inner request payload and the final emitted output
type v2OperationFlagsSign struct {
	v2OperationFlagsBase

	Input     string
	File      string
	Digest    string
	Format    string
	JwsHeader string

	// Resolved state after Validate()
	digestB64         string // base64url-encoded 32-byte SHA-256 digest of the signing input
	jwsOutput         bool   // emit compact JWS
	jwsHeaderSegment  string // base64url header segment
	jwsPayloadSegment string // base64url payload segment
}

func (f *v2OperationFlagsSign) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)
	cmd.Flags().StringVar(&f.Input, "input", "", "Path to the message file to sign; use '-' for stdin. Aliased by --file")
	cmd.Flags().StringVar(&f.File, "file", "", "Alias for --input")
	cmd.Flags().StringVar(&f.Digest, "digest", "", "Pre-computed SHA-256 digest (hex or base64url, 32 bytes)")
	cmd.Flags().StringVar(&f.Format, "format", "raw", "Output format: 'raw' (JSON envelope with base64url r||s signature) or 'jws' (compact JWS string)")
	cmd.Flags().StringVar(&f.JwsHeader, "jws-header", "", "Optional JSON fragment merged into the default protected header when building a JWS from --input")
	cmd.MarkFlagsMutuallyExclusive("input", "file")
}

func (f *v2OperationFlagsSign) Validate() error {
	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}

	if f.Algorithm != protocolv2.SigningAlgES256 {
		return fmt.Errorf("unsupported signing algorithm %q (only %q is supported in v1)", f.Algorithm, protocolv2.SigningAlgES256)
	}

	// --file is an alias for --input; cobra enforces mutual exclusion, so only one is non-empty here
	if f.File != "" {
		f.Input = f.File
	}

	// Exactly one of --input, --digest must be set
	inputCount := 0
	if f.Input != "" {
		inputCount++
	}
	if f.Digest != "" {
		inputCount++
	}
	if inputCount == 0 {
		return errors.New("one of --input or --digest is required")
	}
	if inputCount > 1 {
		return errors.New("--input and --digest are mutually exclusive")
	}

	switch f.Format {
	case "raw":
		f.jwsOutput = false
	case "jws":
		f.jwsOutput = true
	default:
		return fmt.Errorf("invalid --format %q: expected 'raw' or 'jws'", f.Format)
	}

	if f.jwsOutput && f.Digest != "" {
		return errors.New("--format jws requires --input (digest alone is not enough to reconstruct the JWS signing input)")
	}
	if f.jwsOutput && f.Raw {
		return errors.New("--raw cannot be combined with --format jws")
	}

	switch {
	case f.Input != "":
		return f.resolveFromInput()
	case f.Digest != "":
		return f.resolveFromDigest()
	}
	return nil
}

// resolveFromInput reads the message file (or stdin) and computes its SHA-256
// When the output format is JWS, a protected header is constructed so the signing input is "<header>.<payload>" in JWS compact form
func (f *v2OperationFlagsSign) resolveFromInput() error {
	var data []byte
	var err error
	if f.Input == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		// #nosec G304 - user-supplied input path is intentional
		data, err = os.ReadFile(f.Input)
	}
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if !f.jwsOutput {
		sum := sha256.Sum256(data)
		f.digestB64 = base64.RawURLEncoding.EncodeToString(sum[:])
		return nil
	}

	// Build the JWS protected header, starting from the default and merging any user-supplied header JSON
	// The `alg` field is always forced to ES256
	header := map[string]any{"alg": protocolv2.SigningAlgES256}
	if f.JwsHeader != "" {
		var user map[string]any
		err = json.Unmarshal([]byte(f.JwsHeader), &user)
		if err != nil {
			return fmt.Errorf("invalid --jws-header JSON: %w", err)
		}
		maps.Copy(header, user)
		header["alg"] = protocolv2.SigningAlgES256
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to serialize JWS header: %w", err)
	}

	f.jwsHeaderSegment = base64.RawURLEncoding.EncodeToString(headerJSON)
	f.jwsPayloadSegment = base64.RawURLEncoding.EncodeToString(data)

	sum := sha256.Sum256([]byte(f.jwsHeaderSegment + "." + f.jwsPayloadSegment))
	f.digestB64 = base64.RawURLEncoding.EncodeToString(sum[:])

	return nil
}

// resolveFromDigest decodes a pre-computed 32-byte SHA-256 digest from hex or base64url
func (f *v2OperationFlagsSign) resolveFromDigest() error {
	raw, err := hex.DecodeString(f.Digest)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(f.Digest, "="))
		if err != nil {
			return errors.New("invalid --digest: not valid hex or base64url")
		}
	}

	if len(raw) != sha256.Size {
		return fmt.Errorf("invalid --digest length: expected %d bytes, got %d", sha256.Size, len(raw))
	}

	f.digestB64 = base64.RawURLEncoding.EncodeToString(raw)
	return nil
}

func (f *v2OperationFlagsSign) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.digestB64,
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

// v2SignResponsePayload is the JSON shape produced by the browser after signing
// `signature` carries the base64url-encoded raw r||s bytes
type v2SignResponsePayload struct {
	State     string `json:"state"`
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	KeyLabel  string `json:"keyLabel"`
	Signature string `json:"signature"`
}

// FormatResult shapes the decrypted plaintext depending on the selected output format
// - `--format jws` emits `<header>.<payload>.<sig>`
// - `--raw` emits the 64 raw `r||s` bytes
// - the default emits the JSON envelope indented for stdout
func (f *v2OperationFlagsSign) FormatResult(state string, plain []byte, raw bool) ([]byte, error) {
	// Parse the JSON response
	var resp v2SignResponsePayload
	err := json.Unmarshal(plain, &resp)
	if err != nil {
		return nil, fmt.Errorf("invalid sign response JSON: %w", err)
	}

	// Validate the response
	if resp.State != state {
		return nil, errors.New("sign response state mismatch")
	}
	if resp.Operation != protocolv2.OperationSign {
		return nil, fmt.Errorf("unexpected operation in sign response: %q", resp.Operation)
	}
	if resp.Algorithm != protocolv2.SigningAlgES256 {
		return nil, fmt.Errorf("unexpected algorithm in sign response: %q", resp.Algorithm)
	}
	if resp.KeyLabel != f.KeyLabel {
		return nil, fmt.Errorf("sign response keyLabel %q does not match requested %q", resp.KeyLabel, f.KeyLabel)
	}
	if resp.Signature == "" {
		return nil, errors.New("sign response missing signature")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature base64url: %w", err)
	}

	// ECDSA P-256 raw r||s is exactly 64 bytes
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("unexpected signature length: got %d bytes, want 64", len(sigBytes))
	}

	switch {
	case f.jwsOutput:
		if f.jwsHeaderSegment == "" || f.jwsPayloadSegment == "" {
			return nil, errors.New("missing JWS header/payload segments")
		}
		sigSeg := base64.RawURLEncoding.EncodeToString(sigBytes)
		out := f.jwsHeaderSegment + "." + f.jwsPayloadSegment + "." + sigSeg + "\n"
		return []byte(out), nil

	case raw:
		return sigBytes, nil

	default:
		// Pretty-print the JSON envelope for stdout friendliness, preserving field order produced by the browser
		var buf bytes.Buffer
		err = json.Indent(&buf, plain, "", " ")
		if err != nil {
			return nil, fmt.Errorf("failed to indent response: %w", err)
		}
		buf.WriteByte('\n')
		return buf.Bytes(), nil
	}
}
