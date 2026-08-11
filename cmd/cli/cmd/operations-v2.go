package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/cliutil"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// userAgent is the User-Agent header value sent on all CLI HTTP requests
var userAgent = "RevaulterCLI/" + buildinfo.AppVersion

type v2OperationCmd struct {
	Operation string
	Short     string
	flags     v2OperationFlags
}

func newV2OperationCmd(op, short string, newFlags func() v2OperationFlags) *cobra.Command {
	impl := &v2OperationCmd{
		Operation: op,
		Short:     short,
		flags:     newFlags(),
	}
	cmd := &cobra.Command{
		Use:   op,
		Short: short,
		RunE:  impl.Run,
	}
	impl.flags.BindToCommand(cmd)
	return cmd
}

func (o *v2OperationCmd) Run(cmd *cobra.Command, args []string) error {
	log := logging.LogFromContext(cmd.Context())

	err := o.flags.Validate()
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	err = confirmNoMitmProtection(o.flags)
	if err != nil {
		return err
	}

	client, err := newCoreClient(log, o.flags, terminalAnchorConfirmer())
	if err != nil {
		return err
	}

	log.Info("Submitting request to server",
		slog.String("server", o.flags.GetServer()),
		slog.String("operation", o.Operation),
		slog.String("key_label", o.flags.GetKeyLabel()),
		slog.String("algorithm", o.flags.GetAlgorithm()),
	)

	payload := o.flags.InnerPayload()
	res, err := client.Execute(cmd.Context(), clientcore.Request{
		Operation:      o.Operation,
		KeyLabel:       o.flags.GetKeyLabel(),
		Algorithm:      o.flags.GetAlgorithm(),
		Timeout:        o.flags.GetTimeoutDuration(),
		Note:           o.flags.GetNote(),
		Value:          payload.Value,
		Nonce:          payload.Nonce,
		Tag:            payload.Tag,
		AdditionalData: payload.AdditionalData,
		OnSubmitted: func(state string) {
			log.Info("Waiting for browser confirmation", slog.String("state", state))
		},
	})
	if err != nil {
		return err
	}

	log.Info("Received response from server", slog.String("state", res.State))

	return o.writeResult(res.State, res.Payload)
}

// terminalAnchorConfirmer returns a prompt function that asks the user to accept a TOFU pin
func terminalAnchorConfirmer() clientcore.ConfirmAnchorFunc {
	if !cliutil.IsInteractiveTerminal() {
		// If the terminal is not interactive, return nil which means no confirmation
		return nil
	}

	return func(server, _, fingerprint string) (bool, error) {
		return cliutil.AnchorPrompt(server, fingerprint)
	}
}

// coreClientFlags is the minimal interface required to build a client for a Revaulter server
// It is satisfied by v2OperationFlags, *v2OperationFlagsBase, and the trust command's flags
type coreClientFlags interface {
	GetServer() string
	GetRequestKey() string
	GetConnectionOptions() (insecure bool, noh2c bool)
	GetTrustStorePath() string
	GetNoTrustStore() bool
}

// newCoreClient returns a client for the Revaulter server, configured from the command's flags
func newCoreClient(log *slog.Logger, flags coreClientFlags, confirm clientcore.ConfirmAnchorFunc) (*clientcore.Client, error) {
	insecure, noH2C := flags.GetConnectionOptions()

	return clientcore.NewClient(clientcore.Config{
		Server:         flags.GetServer(),
		RequestKey:     flags.GetRequestKey(),
		Insecure:       insecure,
		NoH2C:          noH2C,
		UserAgent:      userAgent,
		Logger:         log,
		TrustStorePath: flags.GetTrustStorePath(),
		NoTrustStore:   flags.GetNoTrustStore(),
		ConfirmAnchor:  confirm,
	})
}

type noMitmProtectionFlags interface {
	GetConnectionOptions() (insecure bool, noh2c bool)
	GetNoTrustStore() bool
	GetYesIKnowWhatImDoing() bool
}

// confirmNoMitmProtection asks the user to confirm before running an operation with every MITM protection disabled
func confirmNoMitmProtection(flags noMitmProtectionFlags) error {
	insecure, _ := flags.GetConnectionOptions()

	return cliutil.ConfirmNoMitmProtection(insecure, flags.GetNoTrustStore(), flags.GetYesIKnowWhatImDoing())
}

// v2OperationResultFormatter lets an operation override how the decrypted plaintext is shaped before being written
// Used by the sign op to emit a compact JWS or the raw signature bytes extracted from the JSON envelope
type v2OperationResultFormatter interface {
	FormatResult(state string, plain []byte, format string) ([]byte, error)
}

// writeResult emits the decrypted plaintext to either stdout or the file requested by --output
// `--format raw` writes the plaintext bytes verbatim
// `--format json` wraps them in the default JSON envelope produced by formatV2DecryptedPayload
// Operations that need richer formatting (e.g. sign emitting JWS) implement v2OperationResultFormatter and own the entire shaping
func (o *v2OperationCmd) writeResult(state string, plain []byte) error {
	format := o.flags.GetFormat()
	output := o.flags.GetOutput()

	var payload []byte
	formatter, ok := o.flags.(v2OperationResultFormatter)
	switch {
	case ok:
		var err error
		payload, err = formatter.FormatResult(state, plain, format)
		if err != nil {
			return fmt.Errorf("failed to format response: %w", err)
		}
	case format == "raw":
		payload = plain
	default:
		formatted, err := formatV2DecryptedPayload(state, plain)
		if err != nil {
			return fmt.Errorf("failed to format response: %w", err)
		}

		// Indent the JSON message
		var buf bytes.Buffer
		err = json.Indent(&buf, formatted, "", " ")
		if err != nil {
			return fmt.Errorf("failed to indent response: %w", err)
		}

		// Appended a trailing newline for shell-friendliness
		buf.WriteByte('\n')
		payload = buf.Bytes()
	}

	if output == "" {
		_, err := os.Stdout.Write(payload)
		return err
	}

	err := writeOutputFile(output, payload)
	if err != nil {
		return fmt.Errorf("failed to write output file %q: %w", output, err)
	}
	return nil
}

// formatV2DecryptedPayload returns the decrypted payload as-is when it's valid JSON, or wrapped in a JSON object with a base64-encoded "data" property otherwise
func formatV2DecryptedPayload(_ string, plain []byte) (json.RawMessage, error) {
	var v any
	err := json.Unmarshal(plain, &v)
	if err == nil && json.Valid(plain) {
		return json.RawMessage(plain), nil
	}

	// Fallback: bytes -> JSON object with base64 payload
	b, err := json.Marshal(map[string]any{
		"data": base64.RawStdEncoding.EncodeToString(plain),
	})
	if err != nil {
		return nil, err
	}

	return json.RawMessage(b), nil
}

// writeOutputFile writes payload to path with mode 0600 and refuses to follow symlinks
// On platforms that lack O_NOFOLLOW the call falls back to a Lstat pre-check (small TOCTOU window)
func writeOutputFile(path string, payload []byte) error {
	// Refuse to write through a pre-existing symlink
	// O_NOFOLLOW handles the case where the target appears between Lstat and OpenFile on platforms that support it
	st, lerr := os.Lstat(path)
	if lerr == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to write through symlink")
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC | oNoFollow
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}

	_, werr := f.Write(payload)

	cerr := f.Close()
	if werr != nil {
		return werr
	}

	return cerr
}
