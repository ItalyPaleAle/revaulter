package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
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

// maxInputBytes caps the plaintext bytes the CLI is willing to send through encrypt/decrypt/sign to 100KB
// The server enforces a 1 MiB limit on the outer request body (where the input is encoded as base64 in JSON, then encrypted)
const maxInputBytes = 100 << 10

// cliEnvelopeKind identifies the JSON shape produced by `encrypt` and consumed by `decrypt --json`
// Bumped only when the schema changes incompatibly so old envelopes can be rejected explicitly
const cliEnvelopeKind = "revaulter/1"

// ensureWithinInputLimit rejects oversize inputs before they hit the wire
// The reported size is the count of plaintext bytes (i.e. before base64 encoding) so the error matches the documented limit
func ensureWithinInputLimit(field string, sizeBytes int) error {
	if sizeBytes > maxInputBytes {
		return fmt.Errorf("%s exceeds the maximum allowed size of %d KB (got %.1f KB)", field, maxInputBytes>>10, (float64(sizeBytes) / 1024))
	}
	return nil
}

// decodedSizeFromBase64 returns the approximate byte length of a base64 string after decoding
// Uses base64.StdEncoding.DecodedLen, which may slightly over-report for unpadded input but is well within tolerance for size enforcement
func decodedSizeFromBase64(b64 string) int {
	return base64.StdEncoding.DecodedLen(len(b64))
}

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
	TrustStorePath      string
	NoTrustStore        bool
	YesIKnowWhatImDoing bool
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

	cmd.Flags().StringVarP(&f.RequestKey, "request-key", "k", "", "Per-user request key used to route the request")
	_ = cmd.MarkFlagRequired("request-key")
	// Each operation marks --key-label required (or accepts it from --json) in its own BindToCommand
	cmd.Flags().StringVarP(&f.KeyLabel, "key-label", "l", "", "Logical key label used for v2 key derivation")

	// Each operation marks --algorithm required (or accepts it from --json) in its own BindToCommand
	cmd.Flags().StringVarP(&f.Algorithm, "algorithm", "a", "", "algorithm identifier")

	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Timeout for the operation, as a number of seconds or Go duration")
	cmd.Flags().StringVarP(&f.Note, "note", "n", "", fmt.Sprintf("Optional message displayed alongside the request (up to %d characters)", protocolv2.MaxNoteLength))

	cmd.Flags().StringVarP(&f.Output, "output", "o", "", "Write the result to this file path instead of stdout")

	// Each operation overrides the Usage string after BindBase to spell out its allowed values
	cmd.Flags().StringVar(&f.Format, "format", "json", "Output format")

	cmd.Flags().StringVar(&f.TrustStorePath, "trust-store", "", "Path to the anchor trust store"+trustStoreDefault)
	cmd.Flags().BoolVar(&f.NoTrustStore, "no-trust-store", false, "Skip anchor pinning and hybrid bundle verification (equivalent to SSH StrictHostKeyChecking=no)")

	cmd.Flags().BoolVar(&f.YesIKnowWhatImDoing, "yes-i-know-what-im-doing", false, "Allow combining --insecure with --no-trust-store without an interactive confirmation")
	_ = cmd.Flags().MarkHidden("yes-i-know-what-im-doing")
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
func (f *v2OperationFlagsBase) GetYesIKnowWhatImDoing() bool       { return f.YesIKnowWhatImDoing }

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
	GetYesIKnowWhatImDoing() bool
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

	// --algorithm and --key-label are required for encrypt
	_ = cmd.MarkFlagRequired("algorithm")
	_ = cmd.MarkFlagRequired("key-label")

	cmd.Flag("format").Usage = "Output format: 'json'"
	cmd.Flags().StringVarP(&f.Message, "message", "m", "", "The message to encrypt as a raw string (UTF-8). Mutually exclusive with --input and --json")
	cmd.Flags().StringVarP(&f.Input, "input", "i", "", "Path to the message file to encrypt; use '-' to read from stdin. Mutually exclusive with --message and --json")
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
		rErr = json.Unmarshal(raw, &parsed)
		if rErr != nil {
			return fmt.Errorf("invalid --json: %w", rErr)
		}
		if parsed.Value == "" {
			return errors.New("--json: 'value' field is required")
		}

		// Size-check the decoded fields against the documented limit
		rErr = ensureWithinInputLimit("--json value", decodedSizeFromBase64(parsed.Value))
		if rErr != nil {
			return rErr
		}

		rErr = ensureWithinInputLimit("--json additionalData", decodedSizeFromBase64(parsed.AdditionalData))
		if rErr != nil {
			return rErr
		}

		f.resolvedValueB64 = parsed.Value
		f.resolvedAADB64 = parsed.AdditionalData

	case f.Input != "":
		raw, rErr := readMaybeStdin(f.Input)
		if rErr != nil {
			return fmt.Errorf("failed to read --input: %w", rErr)
		}

		// Reject empty input early
		// This is rarely intended and almost always a misconfigured pipe or empty file
		if len(raw) == 0 {
			return errors.New("--input is empty")
		}

		rErr = ensureWithinInputLimit("--input", len(raw))
		if rErr != nil {
			return rErr
		}
		aErr := f.checkAADSize()
		if aErr != nil {
			return aErr
		}

		f.resolvedValueB64 = base64.RawURLEncoding.EncodeToString(raw)
		f.resolvedAADB64 = f.AdditionalData.String()

	case f.Message != "":
		// --message takes a raw UTF-8 string; the browser decodes the inner Value field as base64url, so we encode here
		rErr := ensureWithinInputLimit("--message", len(f.Message))
		if rErr != nil {
			return rErr
		}
		aErr := f.checkAADSize()
		if aErr != nil {
			return aErr
		}

		f.resolvedValueB64 = base64.RawURLEncoding.EncodeToString([]byte(f.Message))
		f.resolvedAADB64 = f.AdditionalData.String()
	}

	return nil
}

// checkAADSize verifies that the (base64-encoded) --aad fits within the limit after decoding
// Empty --aad is a no-op
func (f *v2OperationFlagsEncrypt) checkAADSize() error {
	return ensureWithinInputLimit(
		"--aad",
		decodedSizeFromBase64(f.AdditionalData.String()),
	)
}

func (f *v2OperationFlagsEncrypt) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.resolvedValueB64,
		AdditionalData:          f.resolvedAADB64,
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

// v2EncryptResponsePayload is the JSON shape produced by the browser after encrypting
// `state` and `operation` are validated for binding consistency and then dropped from the user-facing output
type v2EncryptResponsePayload struct {
	State          string `json:"state"`
	Operation      string `json:"operation"`
	Algorithm      string `json:"algorithm"`
	Value          string `json:"value"`
	Nonce          string `json:"nonce"`
	Tag            string `json:"tag"`
	AdditionalData string `json:"additionalData"`
}

// encryptOutputJSON is the user-facing JSON shape produced by `encrypt`
// It mirrors what `decrypt --json` consumes, so an `encrypt | decrypt --json` pipeline needs no extra glue
type encryptOutputJSON struct {
	Kind           string `json:"kind"`
	Algorithm      string `json:"algorithm"`
	KeyLabel       string `json:"keyLabel"`
	Value          string `json:"value"`
	Nonce          string `json:"nonce"`
	Tag            string `json:"tag"`
	AdditionalData string `json:"additionalData,omitempty"`
}

// FormatResult validates the browser's response envelope against the originating request and reshapes it into the kind/keyLabel-tagged envelope `decrypt --json` expects
func (f *v2OperationFlagsEncrypt) FormatResult(state string, plain []byte, format string) ([]byte, error) {
	if format != "json" {
		return nil, fmt.Errorf("unsupported format %q", format)
	}

	var resp v2EncryptResponsePayload
	err := json.Unmarshal(plain, &resp)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypt response JSON: %w", err)
	}
	if resp.State != state {
		return nil, errors.New("encrypt response state mismatch")
	}
	if resp.Operation != protocolv2.OperationEncrypt {
		return nil, fmt.Errorf("unexpected operation in encrypt response: %q", resp.Operation)
	}
	if resp.Algorithm != f.Algorithm {
		return nil, fmt.Errorf("encrypt response algorithm %q does not match requested %q", resp.Algorithm, f.Algorithm)
	}
	if resp.Value == "" || resp.Nonce == "" || resp.Tag == "" {
		return nil, errors.New("encrypt response missing value/nonce/tag")
	}

	out := encryptOutputJSON{
		Kind:           cliEnvelopeKind,
		Algorithm:      resp.Algorithm,
		KeyLabel:       f.KeyLabel,
		Value:          resp.Value,
		Nonce:          resp.Nonce,
		Tag:            resp.Tag,
		AdditionalData: resp.AdditionalData,
	}
	body, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode encrypt output: %w", err)
	}

	return append(body, '\n'), nil
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
	cmd.Flag("algorithm").Usage = "algorithm identifier (when not using --json)"
	cmd.Flag("key-label").Usage = "Logical key label used for v2 key derivation (when not using --json)"
	cmd.Flag("format").Usage = "Output format: 'json' (default: JSON envelope) or 'raw' (write the decrypted plaintext as raw bytes)"
	cmd.Flags().VarP(&f.Value, "value", "m", "The message to decrypt, base64-encoded (when not using --json)")
	cmd.Flags().VarP(&f.Tag, "tag", "g", "Authentication tag, base64-encoded (when not using --json)")
	cmd.Flags().Var(&f.Nonce, "nonce", "Nonce/IV, base64-encoded (when not using --json)")
	cmd.Flags().Var(&f.AdditionalData, "aad", "Additional authenticated data, base64-encoded (when not using --json)")
	cmd.Flags().StringVarP(&f.JSON, "json", "j", "", `Path to a JSON file (use '-' to read from stdin) in the shape produced by "encrypt": {"kind":"`+cliEnvelopeKind+`","algorithm":"<id>","keyLabel":"<label>","value":"<base64url>","nonce":"<base64url>","tag":"<base64url>","additionalData":"<base64url>"} The 'additionalData' field is optional.. Mutually exclusive with --algorithm, --key-label, --value, --tag, --nonce, and --aad`)
	cmd.MarkFlagsMutuallyExclusive("json", "algorithm")
	cmd.MarkFlagsMutuallyExclusive("json", "key-label")
	cmd.MarkFlagsMutuallyExclusive("json", "value")
	cmd.MarkFlagsMutuallyExclusive("json", "tag")
	cmd.MarkFlagsMutuallyExclusive("json", "nonce")
	cmd.MarkFlagsMutuallyExclusive("json", "aad")
}

func (f *v2OperationFlagsDecrypt) Validate() error {
	if f.Format != "json" && f.Format != "raw" {
		return fmt.Errorf("invalid --format %q: decrypt supports 'json' or 'raw'", f.Format)
	}

	// When --json is set, the envelope supplies kind, algorithm, and keyLabel; they're populated onto the flag struct before calling base.Validate so the base normalizer sees them
	if f.JSON != "" {
		raw, rErr := readMaybeStdin(f.JSON)
		if rErr != nil {
			return fmt.Errorf("failed to read --json: %w", rErr)
		}

		var parsed decryptJSONInput
		rErr = json.Unmarshal(raw, &parsed)
		if rErr != nil {
			return fmt.Errorf("invalid --json: %w", rErr)
		}
		if parsed.Kind != cliEnvelopeKind {
			return fmt.Errorf("--json: unsupported 'kind' %q (expected %q)", parsed.Kind, cliEnvelopeKind)
		}
		if parsed.Value == "" {
			return errors.New("--json: 'value' field is required")
		}
		if parsed.Algorithm == "" {
			return errors.New("--json: 'algorithm' field is required")
		}
		if parsed.KeyLabel == "" {
			return errors.New("--json: 'keyLabel' field is required")
		}

		f.Algorithm = parsed.Algorithm
		f.KeyLabel = parsed.KeyLabel

		err := f.v2OperationFlagsBase.Validate()
		if err != nil {
			return err
		}

		rErr = checkDecryptInputSizes(parsed.Value, parsed.AdditionalData, "--json")
		if rErr != nil {
			return rErr
		}

		f.resolvedValueB64 = parsed.Value
		f.resolvedTagB64 = parsed.Tag
		f.resolvedNonceB64 = parsed.Nonce
		f.resolvedAADB64 = parsed.AdditionalData
		return nil
	}

	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}

	if f.Algorithm == "" {
		return errors.New("--algorithm is required")
	}
	if f.Value.String() == "" {
		return errors.New("either --value or --json is required")
	}

	rErr := checkDecryptInputSizes(f.Value.String(), f.AdditionalData.String(), "")
	if rErr != nil {
		return rErr
	}

	f.resolvedValueB64 = f.Value.String()
	f.resolvedTagB64 = f.Tag.String()
	f.resolvedNonceB64 = f.Nonce.String()
	f.resolvedAADB64 = f.AdditionalData.String()

	return nil
}

// checkDecryptInputSizes enforces the input ceiling on the (base64-encoded) ciphertext and AAD
// `prefix` is prepended to the field name in the error message so callers can disambiguate --json fields from individual flags
func checkDecryptInputSizes(valueB64, aadB64, prefix string) error {
	valueLabel := "--value"
	aadLabel := "--aad"
	if prefix != "" {
		valueLabel = prefix + " value"
		aadLabel = prefix + " additionalData"
	}

	err := ensureWithinInputLimit(valueLabel, decodedSizeFromBase64(valueB64))
	if err != nil {
		return err
	}

	return ensureWithinInputLimit(aadLabel, decodedSizeFromBase64(aadB64))
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

// v2DecryptResponsePayload is the JSON shape produced by the browser after decrypting
// `value` carries the base64url-encoded plaintext bytes
type v2DecryptResponsePayload struct {
	State     string `json:"state"`
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// FormatResult shapes the decrypted plaintext depending on the selected output format
// `raw` returns the plaintext bytes verbatim (no JSON wrapper), `json` indents the browser's envelope
func (f *v2OperationFlagsDecrypt) FormatResult(state string, plain []byte, format string) ([]byte, error) {
	var resp v2DecryptResponsePayload
	err := json.Unmarshal(plain, &resp)
	if err != nil {
		return nil, fmt.Errorf("invalid decrypt response JSON: %w", err)
	}
	if resp.State != state {
		return nil, errors.New("decrypt response state mismatch")
	}
	if resp.Operation != protocolv2.OperationDecrypt {
		return nil, fmt.Errorf("unexpected operation in decrypt response: %q", resp.Operation)
	}
	if resp.Algorithm != f.Algorithm {
		return nil, fmt.Errorf("decrypt response algorithm %q does not match requested %q", resp.Algorithm, f.Algorithm)
	}
	if resp.Value == "" {
		return nil, errors.New("decrypt response missing value")
	}

	switch format {
	case "raw":
		valueBytes, dErr := base64.RawURLEncoding.DecodeString(resp.Value)
		if dErr != nil {
			return nil, fmt.Errorf("invalid decrypted value: %w", dErr)
		}
		return valueBytes, nil
	case "json":
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

// decryptJSONInput is the shape accepted by `decrypt --json`
// It mirrors the JSON envelope produced by `encrypt`; `kind`, `algorithm`, and `keyLabel` are required and supply the corresponding flags
type decryptJSONInput struct {
	Kind           string `json:"kind"`
	Algorithm      string `json:"algorithm"`
	KeyLabel       string `json:"keyLabel"`
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
	resolvedValueB64  string // base64url-encoded bytes sent to the browser's signing primitive
	jwsOutput         bool   // emit compact JWS
	jwsHeaderSegment  string // base64url header segment
	jwsPayloadSegment string // base64url payload segment
}

func (f *v2OperationFlagsSign) BindToCommand(cmd *cobra.Command) {
	f.BindBase(cmd)

	// --algorithm and --key-label are required for sign
	_ = cmd.MarkFlagRequired("algorithm")
	_ = cmd.MarkFlagRequired("key-label")

	cmd.Flag("format").Usage = "Output format: 'json' (default: JSON envelope with base64url signature), 'jws' (compact JWS string), or 'raw' (raw 64-byte signature). 'jws' requires --input and is supported only for ES256 and Ed25519"
	cmd.Flags().StringVarP(&f.Input, "input", "i", "", "Path to the message file to sign; use '-' to read from stdin")
	cmd.Flags().StringVarP(&f.Digest, "digest", "d", "", "Pre-computed digest (hex or base64url): 32-byte SHA-256 for ES256, 64-byte SHA-512 for Ed25519ph")
	cmd.Flags().StringVar(&f.JwsHeader, "jws-header", "", "Optional JSON fragment merged into the default protected header when building a JWS from --input")
	cmd.MarkFlagsMutuallyExclusive("input", "digest")
}

func (f *v2OperationFlagsSign) Validate() error {
	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}

	// Accept any case, but normalize to the canonical form so the AAD the CLI computes locally matches what the browser sees after the server normalizes too
	canonical, ok := protocolv2.NormalizeSigningAlgorithm(f.Algorithm)
	if !ok {
		return fmt.Errorf("unsupported signing algorithm %q", f.Algorithm)
	}

	f.Algorithm = canonical

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

	if f.Algorithm == protocolv2.SigningAlgEd25519 && f.Digest != "" {
		return errors.New("--digest is not supported for Ed25519; use --input so the raw message bytes can be signed")
	}
	if f.jwsOutput && f.Digest != "" {
		return errors.New("--format jws requires --input (digest alone is not enough to reconstruct the JWS signing input)")
	}
	if f.jwsOutput && f.Algorithm == protocolv2.SigningAlgEd25519ph {
		return errors.New("--format jws is not supported for Ed25519ph")
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

// resolveFromInput reads the message file (or stdin) and derives the algorithm-specific bytes to sign
// When the output format is JWS, a protected header is constructed so the signing input is "<header>.<payload>" in JWS compact form
func (f *v2OperationFlagsSign) resolveFromInput() error {
	data, err := readMaybeStdin(f.Input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	err = ensureWithinInputLimit("input", len(data))
	if err != nil {
		return err
	}

	if !f.jwsOutput {
		valueB64, resolveErr := encodeSignInputValue(f.Algorithm, data)
		if resolveErr != nil {
			return resolveErr
		}
		f.resolvedValueB64 = valueB64
		return nil
	}

	// Build the JWS protected header, starting from the default and merging any user-supplied header JSON
	// The `alg` field is always forced to the JOSE algorithm that matches the selected signing algorithm
	header := map[string]any{"alg": signJWSProtectedAlg(f.Algorithm)}
	if f.JwsHeader != "" {
		var user map[string]any
		err = json.Unmarshal([]byte(f.JwsHeader), &user)
		if err != nil {
			return fmt.Errorf("invalid --jws-header JSON: %w", err)
		}
		maps.Copy(header, user)
		header["alg"] = signJWSProtectedAlg(f.Algorithm)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to serialize JWS header: %w", err)
	}

	f.jwsHeaderSegment = base64.RawURLEncoding.EncodeToString(headerJSON)
	f.jwsPayloadSegment = base64.RawURLEncoding.EncodeToString(data)

	signingInput := []byte(f.jwsHeaderSegment + "." + f.jwsPayloadSegment)
	valueB64, resolveErr := encodeSignInputValue(f.Algorithm, signingInput)
	if resolveErr != nil {
		return resolveErr
	}
	f.resolvedValueB64 = valueB64

	return nil
}

func encodeSignInputValue(algorithm string, data []byte) (string, error) {
	switch algorithm {
	case protocolv2.SigningAlgES256:
		sum := sha256.Sum256(data)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case protocolv2.SigningAlgEd25519:
		return base64.RawURLEncoding.EncodeToString(data), nil
	case protocolv2.SigningAlgEd25519ph:
		sum := sha512.Sum512(data)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
}

func signJWSProtectedAlg(algorithm string) string {
	switch algorithm {
	case protocolv2.SigningAlgEd25519:
		return "EdDSA"
	case protocolv2.SigningAlgES256:
		return protocolv2.SigningAlgES256
	default:
		panic("signJWSProtectedAlg called for unsupported JWS algorithm: " + algorithm)
	}
}

// resolveFromDigest decodes a pre-computed digest from hex or base64url
func (f *v2OperationFlagsSign) resolveFromDigest() error {
	raw, err := hex.DecodeString(f.Digest)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(f.Digest, "="))
		if err != nil {
			return errors.New("invalid --digest: not valid hex or base64url")
		}
	}

	expectedSize := 0
	switch f.Algorithm {
	case protocolv2.SigningAlgES256:
		expectedSize = sha256.Size
	case protocolv2.SigningAlgEd25519ph:
		expectedSize = sha512.Size
	default:
		return fmt.Errorf("unsupported signing algorithm %q", f.Algorithm)
	}
	if len(raw) != expectedSize {
		return fmt.Errorf("invalid --digest length: expected %d bytes, got %d", expectedSize, len(raw))
	}

	f.resolvedValueB64 = base64.RawURLEncoding.EncodeToString(raw)
	return nil
}

func (f *v2OperationFlagsSign) InnerPayload(clientTransportEcdhKey protocolv2.ECP256PublicJWK, clientTransportMlkemKey string) protocolv2.RequestPayloadInner {
	return protocolv2.RequestPayloadInner{
		Value:                   f.resolvedValueB64,
		ClientTransportEcdhKey:  clientTransportEcdhKey,
		ClientTransportMlkemKey: clientTransportMlkemKey,
	}
}

// v2SignResponsePayload is the JSON shape produced by the browser after signing
// `signature` carries the base64url-encoded raw signature bytes
type v2SignResponsePayload struct {
	State     string `json:"state"`
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	KeyLabel  string `json:"keyLabel"`
	Signature string `json:"signature"`
}

// parseAndValidateV2SignResponse validates response binding and returns the decoded raw signature
func parseAndValidateV2SignResponse(state, keyLabel, algorithm string, plain []byte) (*v2SignResponsePayload, []byte, error) {
	var resp v2SignResponsePayload
	err := json.Unmarshal(plain, &resp)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid sign response JSON: %w", err)
	}

	if resp.State != state {
		return nil, nil, errors.New("sign response state mismatch")
	}
	if resp.Operation != protocolv2.OperationSign {
		return nil, nil, fmt.Errorf("unexpected operation in sign response: %q", resp.Operation)
	}
	if resp.Algorithm != algorithm {
		return nil, nil, fmt.Errorf("unexpected algorithm in sign response: %q", resp.Algorithm)
	}
	if resp.KeyLabel != keyLabel {
		return nil, nil, fmt.Errorf("sign response keyLabel %q does not match requested %q", resp.KeyLabel, keyLabel)
	}
	if resp.Signature == "" {
		return nil, nil, errors.New("sign response missing signature")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature base64url: %w", err)
	}

	if len(sigBytes) != 64 {
		return nil, nil, fmt.Errorf("unexpected signature length: got %d bytes, want 64", len(sigBytes))
	}

	return &resp, sigBytes, nil
}

// FormatResult shapes the decrypted plaintext depending on the selected output format
// - `json` (default) emits the indented JSON envelope produced by the browser
// - `jws` emits `<header>.<payload>.<sig>`
// - `raw` emits the 64 raw signature bytes
func (f *v2OperationFlagsSign) FormatResult(state string, plain []byte, format string) ([]byte, error) {
	_, sigBytes, err := parseAndValidateV2SignResponse(state, f.KeyLabel, f.Algorithm, plain)
	if err != nil {
		return nil, err
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
