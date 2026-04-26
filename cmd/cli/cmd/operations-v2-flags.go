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

	// Format selects how the result is written out
	// Each operation accepts a different subset of values, validated in its own Validate()
	// - encrypt: only "json" (default)
	// - decrypt: "json" (default) or "raw" (write decrypted plaintext as raw bytes)
	// - sign:    "json" (default: JSON envelope), "jws" (compact JWS string), or "raw" (64-byte r||s signature)
	Format string

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

	// Each operation overrides the Usage string after BindBase to spell out its allowed values
	cmd.Flags().StringVar(&f.Format, "format", "json", "Output format")

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
func (f *v2OperationFlagsBase) GetFormat() string                  { return f.Format }
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
	GetFormat() string
	GetTrustStorePath() string
	GetNoTrustStore() bool
}

type v2OperationFlagsEncrypt struct {
	v2OperationFlagsBase

	// Plaintext sources: exactly one of Message, Input, or JSON must be set
	Message string
	Input   string
	JSON    string

	AdditionalData stringValue

	// Resolved state populated by Validate() and consumed by InnerPayload()
	// Both are base64url-encoded so they can travel verbatim through the inner payload to the browser
	resolvedValueB64 string
	resolvedAADB64   string
}

func (f *v2OperationFlagsEncrypt) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)
	cmd.Flag("format").Usage = "Output format: 'json' (only)"
	cmd.Flags().StringVar(&f.Message, "message", "", "The message to encrypt as a raw string (UTF-8). Mutually exclusive with --input and --json")
	cmd.Flags().StringVar(&f.Input, "input", "", "Path to the message file to encrypt; use '-' to read from stdin. Mutually exclusive with --message and --json")
	cmd.Flags().StringVar(&f.JSON, "json", "", `Path to a JSON file (use '-' to read from stdin) of shape {"value":"<base64url>","additionalData":"<base64url>"}. Mutually exclusive with --message, --input, and --aad`)
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional authenticated data, base64-encoded (when not using --json)")
	cmd.MarkFlagsMutuallyExclusive("message", "input", "json")
	cmd.MarkFlagsMutuallyExclusive("aad", "json")
}

func (f *v2OperationFlagsEncrypt) Validate() error {
	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}
	if f.Format != "json" {
		return fmt.Errorf("invalid --format %q: encrypt only supports 'json'", f.Format)
	}

	// Exactly one of --message, --input, --json must be supplied
	sourceCount := 0
	if f.Message != "" {
		sourceCount++
	}
	if f.Input != "" {
		sourceCount++
	}
	if f.JSON != "" {
		sourceCount++
	}
	if sourceCount == 0 {
		return errors.New("one of --message, --input, or --json is required")
	}

	switch {
	case f.JSON != "":
		// Inner payload comes pre-encoded from the JSON file
		raw, rErr := readMaybeStdin(f.JSON)
		if rErr != nil {
			return fmt.Errorf("failed to read --json: %w", rErr)
		}

		// Parse the JSON message
		var parsed encryptJSONInput
		uErr := json.Unmarshal(raw, &parsed)
		if uErr != nil {
			return fmt.Errorf("invalid --json: %w", uErr)
		}
		if parsed.Value == "" {
			return errors.New("--json: 'value' field is required")
		}

		f.resolvedValueB64 = parsed.Value
		f.resolvedAADB64 = parsed.AdditionalData

	case f.Input != "":
		raw, rErr := readMaybeStdin(f.Input)
		if rErr != nil {
			return fmt.Errorf("failed to read --input: %w", rErr)
		}

		f.resolvedValueB64 = base64.RawURLEncoding.EncodeToString(raw)
		f.resolvedAADB64 = f.AdditionalData.String()

	case f.Message != "":
		// --message takes a raw UTF-8 string; the browser decodes the inner Value field as base64url, so we encode here
		f.resolvedValueB64 = base64.RawURLEncoding.EncodeToString([]byte(f.Message))
		f.resolvedAADB64 = f.AdditionalData.String()
	}

	return nil
}

func (f *v2OperationFlagsEncrypt) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.resolvedValueB64,
		AdditionalData:          f.resolvedAADB64,
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

// encryptJSONInput is the shape accepted by `encrypt --json`
// Both fields are base64url-encoded
type encryptJSONInput struct {
	Value          string `json:"value"`
	AdditionalData string `json:"additionalData"`
}

type v2OperationFlagsDecrypt struct {
	v2OperationFlagsBase

	Value          stringValue
	Tag            stringValue
	Nonce          stringValue
	AdditionalData stringValue

	// JSON points to a file (or stdin via "-") whose contents match the JSON envelope produced by `encrypt`
	// When set, the individual --value/--tag/--nonce/--aad flags must be empty
	JSON string

	// Resolved fields populated by Validate() so InnerPayload doesn't need to re-parse
	resolvedValueB64 string
	resolvedTagB64   string
	resolvedNonceB64 string
	resolvedAADB64   string
}

func (f *v2OperationFlagsDecrypt) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)
	cmd.Flag("format").Usage = "Output format: 'json' (default: JSON envelope) or 'raw' (write the decrypted plaintext as raw bytes)"
	cmd.Flags().Var(&f.Value, "value", "The message to decrypt, base64-encoded (when not using --json)")
	cmd.Flags().Var(&f.Tag, "tag", "Authentication tag, base64-encoded (when not using --json)")
	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce/IV, base64-encoded (when not using --json)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional authenticated data, base64-encoded (when not using --json)")
	cmd.Flags().StringVar(&f.JSON, "json", "", `Path to a JSON file (use '-' to read from stdin) in the shape produced by "encrypt": {"value":"<base64url>","nonce":"<base64url>","tag":"<base64url>","additionalData":"<base64url>"}. Mutually exclusive with --value, --tag, --nonce, and --aad`)
	cmd.MarkFlagsMutuallyExclusive("json", "value")
	cmd.MarkFlagsMutuallyExclusive("json", "tag")
	cmd.MarkFlagsMutuallyExclusive("json", "nonce")
	cmd.MarkFlagsMutuallyExclusive("json", "aad")
}

func (f *v2OperationFlagsDecrypt) Validate() error {
	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}
	if f.Format != "json" && f.Format != "raw" {
		return fmt.Errorf("invalid --format %q: decrypt supports 'json' or 'raw'", f.Format)
	}

	if f.JSON != "" {
		raw, rErr := readMaybeStdin(f.JSON)
		if rErr != nil {
			return fmt.Errorf("failed to read --json: %w", rErr)
		}

		var parsed decryptJSONInput
		uErr := json.Unmarshal(raw, &parsed)
		if uErr != nil {
			return fmt.Errorf("invalid --json: %w", uErr)
		}
		if parsed.Value == "" {
			return errors.New("--json: 'value' field is required")
		}

		f.resolvedValueB64 = parsed.Value
		f.resolvedTagB64 = parsed.Tag
		f.resolvedNonceB64 = parsed.Nonce
		f.resolvedAADB64 = parsed.AdditionalData
		return nil
	}

	if f.Value.String() == "" {
		return errors.New("either --value or --json is required")
	}

	f.resolvedValueB64 = f.Value.String()
	f.resolvedTagB64 = f.Tag.String()
	f.resolvedNonceB64 = f.Nonce.String()
	f.resolvedAADB64 = f.AdditionalData.String()

	return nil
}

func (f *v2OperationFlagsDecrypt) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.resolvedValueB64,
		Tag:                     f.resolvedTagB64,
		Nonce:                   f.resolvedNonceB64,
		AdditionalData:          f.resolvedAADB64,
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

// decryptJSONInput is the shape accepted by `decrypt --json`
// It mirrors the JSON envelope produced by `encrypt`; extra fields like state/operation/algorithm are ignored
type decryptJSONInput struct {
	Value          string `json:"value"`
	Tag            string `json:"tag"`
	Nonce          string `json:"nonce"`
	AdditionalData string `json:"additionalData"`
}

// v2OperationFlagsSign carries flags specific to the `sign` operation
// The resolved digest/header/payload fields are populated during Validate so Run can compose the inner request payload and the final emitted output
type v2OperationFlagsSign struct {
	v2OperationFlagsBase

	Input     string
	Digest    string
	JwsHeader string

	// Resolved state after Validate()
	digestB64         string // base64url-encoded 32-byte SHA-256 digest of the signing input
	jwsOutput         bool   // emit compact JWS
	jwsHeaderSegment  string // base64url header segment
	jwsPayloadSegment string // base64url payload segment
}

func (f *v2OperationFlagsSign) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)
	cmd.Flag("format").Usage = "Output format: 'json' (default: JSON envelope with base64url r||s signature), 'jws' (compact JWS string), or 'raw' (64-byte r||s signature). 'jws' requires --input"
	cmd.Flags().StringVar(&f.Input, "input", "", "Path to the message file to sign; use '-' to read from stdin")
	cmd.Flags().StringVar(&f.Digest, "digest", "", "Pre-computed SHA-256 digest (hex or base64url, 32 bytes)")
	cmd.Flags().StringVar(&f.JwsHeader, "jws-header", "", "Optional JSON fragment merged into the default protected header when building a JWS from --input")
	cmd.MarkFlagsMutuallyExclusive("input", "digest")
}

func (f *v2OperationFlagsSign) Validate() error {
	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}

	if f.Algorithm != protocolv2.SigningAlgES256 {
		return fmt.Errorf("unsupported signing algorithm %q (only %q is supported in v1)", f.Algorithm, protocolv2.SigningAlgES256)
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
	case "json", "raw":
		f.jwsOutput = false
	case "jws":
		f.jwsOutput = true
	default:
		return fmt.Errorf("invalid --format %q: sign supports 'json', 'jws', or 'raw'", f.Format)
	}

	if f.jwsOutput && f.Digest != "" {
		return errors.New("--format jws requires --input (digest alone is not enough to reconstruct the JWS signing input)")
	}

	switch {
	case f.Input != "":
		return f.resolveFromInput()
	case f.Digest != "":
		return f.resolveFromDigest()
	}
	return nil
}

// readMaybeStdin reads bytes from a file path or, when path is "-", from stdin
// Used by --input and --json on encrypt/sign so the same `-` convention works everywhere
func readMaybeStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}

	// #nosec G304 - user-supplied input path is intentional
	return os.ReadFile(path)
}

// resolveFromInput reads the message file (or stdin) and computes its SHA-256
// When the output format is JWS, a protected header is constructed so the signing input is "<header>.<payload>" in JWS compact form
func (f *v2OperationFlagsSign) resolveFromInput() error {
	data, err := readMaybeStdin(f.Input)
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
// - `json` (default) emits the indented JSON envelope produced by the browser
// - `jws` emits `<header>.<payload>.<sig>`
// - `raw` emits the 64 raw `r||s` bytes
func (f *v2OperationFlagsSign) FormatResult(state string, plain []byte, format string) ([]byte, error) {
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

	switch format {
	case "jws":
		if f.jwsHeaderSegment == "" || f.jwsPayloadSegment == "" {
			return nil, errors.New("missing JWS header/payload segments")
		}
		sigSeg := base64.RawURLEncoding.EncodeToString(sigBytes)
		out := f.jwsHeaderSegment + "." + f.jwsPayloadSegment + "." + sigSeg + "\n"
		return []byte(out), nil

	case "raw":
		return sigBytes, nil

	case "json":
		// Pretty-print the JSON envelope for stdout friendliness, preserving field order produced by the browser
		var buf bytes.Buffer
		err = json.Indent(&buf, plain, "", " ")
		if err != nil {
			return nil, fmt.Errorf("failed to indent response: %w", err)
		}
		buf.WriteByte('\n')
		return buf.Bytes(), nil

	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}
