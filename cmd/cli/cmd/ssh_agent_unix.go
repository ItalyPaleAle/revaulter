//go:build unix

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

type sshAgentFlags struct {
	v2OperationFlagsBase

	SocketPath string
	Comment    string
}

func newSshAgentCmd() *cobra.Command {
	f := &sshAgentFlags{}
	cmd := &cobra.Command{
		Use:   "ssh-agent",
		Short: "Run an SSH key agent that routes signing through Revaulter",
		Long: `Starts a local SSH agent that listens on a Unix socket.

SSH clients point SSH_AUTH_SOCK at the socket. When they request a signature, the agent sends a sign request to the Revaulter server. The user approves via their browser and passkey, and the resulting ECDSA signature is returned to SSH.

Note: The signing key must be published from the Revaulter web interface before the agent will advertise it. Publishing attaches an anchor-signed proof that binds the key to your pinned anchor, which is what stops a compromised server from substituting a key of its own. Run "revaulter trust" (or any other revaulter CLI command) at least once with a TTY to pin the server anchor before running the
agent in a non-interactive environment.`,
		RunE: f.Run,
	}

	f.BindBase(cmd)

	_ = cmd.MarkFlagRequired("key-label")
	defaultSocketPath := filepath.Join(defaultSSHAgentSocketDir(), "ssh-agent-<key-label>.sock")

	algFlag := cmd.Flags().Lookup("algorithm")
	if algFlag != nil {
		algFlag.DefValue = protocolv2.SigningAlgES256
		_ = algFlag.Value.Set(protocolv2.SigningAlgES256)
		algFlag.Usage = "Signing algorithm: 'ES256' (default) or 'Ed25519'"
	}

	cmd.Flags().StringVar(&f.SocketPath, "socket", "", "Path for the Unix socket (defaults to "+defaultSocketPath+")")
	cmd.Flags().StringVar(&f.Comment, "comment", "", `Comment attached to the key (default: "revaulter/<key-label>")`)

	return cmd
}

func (f *sshAgentFlags) Validate() error {
	err := f.v2OperationFlagsBase.Validate()
	if err != nil {
		return err
	}

	// Set default algorithm
	if f.Algorithm == "" {
		f.Algorithm = protocolv2.SigningAlgES256
	}

	canonical, ok := protocolv2.NormalizeSigningAlgorithm(f.Algorithm)
	switch {
	case !ok:
		return fmt.Errorf("unsupported signing algorithm %q", f.Algorithm)
	case canonical == protocolv2.SigningAlgEd25519ph:
		return errors.New("ssh-agent does not support Ed25519ph; use ES256 or Ed25519")
	default:
		f.Algorithm = canonical
	}

	// Every sign request submitted by the agent carries the prefixed note, so the prefix eats into the server's limit
	if len(sshAgentSignNote(f.Note)) > protocolv2.MaxNoteLength {
		return fmt.Errorf(
			"note cannot be longer than %d characters when used with ssh-agent (got %d): the agent prefixes it with %q",
			sshAgentMaxUserNoteLength, len(f.Note), sshAgentNotePrefix,
		)
	}

	return nil
}

func (f *sshAgentFlags) Run(cmd *cobra.Command, _ []string) error {
	log := logging.LogFromContext(cmd.Context())

	// Validate the flags
	err := f.Validate()
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	err = confirmNoMitmProtection(&f.v2OperationFlagsBase)
	if err != nil {
		return err
	}

	// Set the default values
	if f.Comment == "" {
		f.Comment = "revaulter/" + f.KeyLabel
	}
	if f.SocketPath == "" {
		f.SocketPath, err = defaultSSHAgentSocketPath(f.KeyLabel)
		if err != nil {
			return err
		}
	}

	// Get the client for the Revaulter server
	// The agent runs unattended, so it can never prompt to pin an anchor
	client, err := newCoreClient(log, &f.v2OperationFlagsBase, nil)
	if err != nil {
		return err
	}

	// Remove stale socket file if it exists
	_ = os.Remove(f.SocketPath)

	// Create a listener on the UDS
	l, err := listenAgentSocket(f.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		l.Close()
		_ = os.Remove(f.SocketPath)
	}()

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &revaulterSSHAgent{
		shutdown: ctx.Done(),
		client:   client,
		flags:    f,
		log:      log,
	}

	log.Info("SSH agent listening",
		slog.String("socket", f.SocketPath),
		slog.String("key_label", f.KeyLabel),
		slog.String("comment", f.Comment),
	)
	fmt.Fprintf(os.Stderr, "export SSH_AUTH_SOCK=%s\n", shellQuote(f.SocketPath))

	// Accept connections in a background goroutine
	go func() {
		for {
			conn, lErr := l.Accept()
			if lErr != nil {
				if shouldStopAccepting(ctx, lErr) {
					return
				}

				if isRetriableAcceptError(lErr) {
					log.Warn("Retriable SSH agent accept error", slog.Any("err", lErr))
					time.Sleep(100 * time.Millisecond)
					continue
				}

				log.Error("SSH agent accept error", slog.Any("err", lErr))
				return
			}

			go func() {
				defer conn.Close()
				rErr := agent.ServeAgent(a, conn)
				if rErr != nil && !errors.Is(rErr, net.ErrClosed) {
					log.Debug("SSH agent connection closed", slog.Any("err", rErr))
				}
			}()
		}
	}()

	// Block until the context is canceled
	<-ctx.Done()

	log.Info("SSH agent shutting down")

	return nil
}

// listenAgentSocket creates the agent's Unix socket listener with owner-only permissions
func listenAgentSocket(socketPath string) (net.Listener, error) {
	// net.Listen creates the socket with 0666&^umask, so narrowing the umask first is what keeps the socket from being briefly world-accessible between Listen and the Chmod below
	// Nothing else in the process creates files concurrently at this point, so temporarily changing the process-wide umask is safe
	oldUmask := syscall.Umask(0o077)
	l, err := net.Listen("unix", socketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		return nil, fmt.Errorf("failed to create Unix socket %s: %w", socketPath, err)
	}

	// Restrict socket to owner-only access
	// The umask above already covers this on platforms that apply it to sockets, this makes the result explicit regardless
	err = os.Chmod(socketPath, 0o600)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("failed to set socket permissions: %w", err)
	}

	return l, nil
}

// shouldStopAccepting reports whether an accept error is part of normal shutdown
func shouldStopAccepting(ctx context.Context, err error) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}

	return errors.Is(err, net.ErrClosed)
}

// isRetriableAcceptError reports whether an accept error should be retried
func isRetriableAcceptError(err error) bool {
	return errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

// defaultSSHAgentSocketPath returns a socket path under a private per-user directory
func defaultSSHAgentSocketPath(keyLabel string) (string, error) {
	dir := defaultSSHAgentSocketDir()
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH agent socket directory: %w", err)
	}

	err = os.Chmod(dir, 0o700)
	if err != nil {
		return "", fmt.Errorf("failed to restrict SSH agent socket directory: %w", err)
	}

	return filepath.Join(dir, "ssh-agent-"+keyLabel+".sock"), nil
}

// defaultSSHAgentSocketDir returns the resolved private directory for the default socket path
func defaultSSHAgentSocketDir() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("revaulter-ssh-agent-%d", os.Getuid()))
	}

	return filepath.Join(base, "revaulter")
}

// revaulterSSHAgent implements agent.Agent, routing all sign requests through Revaulter
type revaulterSSHAgent struct {
	shutdown <-chan struct{}
	client   *clientcore.Client
	flags    *sshAgentFlags
	log      *slog.Logger
}

// List returns the signing public key registered for the configured label
func (a *revaulterSSHAgent) List() ([]*agent.Key, error) {
	ctx, cancel := a.operationContext(30 * time.Second)
	defer cancel()

	advertised, err := a.fetchSigningPubkey(ctx)
	if err != nil {
		// ServeAgent only reports a generic failure to the SSH client, so without this the reason is invisible to the operator
		a.log.Error("Failed to list the signing key", slog.Any("err", err))
		return nil, err
	}

	return []*agent.Key{{
		Format:  advertised.SSHPub.Type(),
		Blob:    advertised.SSHPub.Marshal(),
		Comment: a.flags.Comment,
	}}, nil
}

// Sign submits a sign request to the Revaulter server and translates the response into SSH wire format
func (a *revaulterSSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	ctx, cancel := a.operationContext(a.signTimeout())
	defer cancel()

	advertised, err := a.validateSigningKey(ctx, key)
	if err != nil {
		// As in List, the SSH client only ever sees a generic failure
		a.log.Error("Refusing to sign", slog.Any("err", err))
		return nil, err
	}

	// Compute the value to sign
	var value string
	if a.flags.Algorithm == protocolv2.SigningAlgES256 {
		// For ES256, compute the SHA-256 digest
		digest := sha256.Sum256(data)
		value = base64.RawURLEncoding.EncodeToString(digest[:])
	} else {
		// For Ed25519, hashing is done during the signing process
		err = ensureWithinInputLimit("ssh-agent signing input", len(data))
		if err != nil {
			return nil, err
		}

		value = base64.RawURLEncoding.EncodeToString(data)
	}

	// Submit the sign request and wait for the user to approve it in the browser
	res, err := a.client.Execute(ctx, clientcore.Request{
		Operation: protocolv2.OperationSign,
		KeyLabel:  a.flags.KeyLabel,
		Algorithm: a.flags.Algorithm,
		Timeout:   a.flags.GetTimeoutDuration(),
		Note:      sshAgentSignNote(a.flags.Note),
		Value:     value,
		OnSubmitted: func(state string) {
			a.log.Info("Waiting for browser confirmation", slog.String("state", state))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}

	// Parse and validate the response
	signResp, sigBytes, err := parseAndValidateV2SignResponse(res.State, a.flags.KeyLabel, a.flags.Algorithm, res.Payload)
	if err != nil {
		return nil, err
	}

	// The browser reports which key it signed with, inside the E2EE envelope the server cannot read or forge
	// Comparing it against the advertised key catches a server that served one key to List() and relayed a signature from another
	if signResp.SigningKeyID == "" {
		err = errors.New("sign response does not report a signing key id - the server is running a version that is too old for this version of revaulter-cli")
		a.log.Error("Refusing to return the signature", slog.Any("err", err))
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(signResp.SigningKeyID), []byte(advertised.KeyID)) != 1 {
		err = fmt.Errorf("the browser signed with key %q but the server advertised key %q", signResp.SigningKeyID, advertised.KeyID)
		a.log.Error("Refusing to return the signature", slog.Any("err", err))
		return nil, err
	}

	sig := &ssh.Signature{Format: key.Type()}
	if a.flags.Algorithm == protocolv2.SigningAlgES256 {
		// Convert IEEE P1363 r||s (64 bytes) to the SSH ECDSA wire format: mpint r, mpint s
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		sig.Blob = ssh.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	} else {
		sig.Blob = sigBytes
	}
	err = key.Verify(data, sig)
	if err != nil {
		return nil, fmt.Errorf("verify SSH signature response: %w", err)
	}

	return sig, nil
}

// sshAgentNotePrefix is prepended to the user's --note on every sign request submitted by the agent
// It counts against the server's protocolv2.MaxNoteLength budget, so sshAgentFlags.Validate checks the combined length
const sshAgentNotePrefix = "SSH auth"

// sshAgentMaxUserNoteLength is how much of the server's note budget is left for the user's own --note
// Both the prefix and the space that joins it to the user's text count against protocolv2.MaxNoteLength
const sshAgentMaxUserNoteLength = protocolv2.MaxNoteLength - len(sshAgentNotePrefix) - 1

// sshAgentSignNote returns the note shown to the user for SSH auth approvals
func sshAgentSignNote(extra string) string {
	if extra == "" {
		return sshAgentNotePrefix
	}

	return sshAgentNotePrefix + " " + extra
}

// validateSigningKey rejects sign requests for keys this agent did not advertise
// Returns the advertised key so the caller can cross-check it against the key the browser reports having actually used
func (a *revaulterSSHAgent) validateSigningKey(ctx context.Context, key ssh.PublicKey) (advertisedSigningKey, error) {
	if key == nil {
		return advertisedSigningKey{}, errors.New("missing SSH public key")
	}

	advertised, err := a.fetchSigningPubkey(ctx)
	if err != nil {
		return advertisedSigningKey{}, fmt.Errorf("fetch advertised signing key: %w", err)
	}

	if !bytes.Equal(key.Marshal(), advertised.SSHPub.Marshal()) {
		return advertisedSigningKey{}, errors.New("requested SSH key is not managed by this agent")
	}

	return advertised, nil
}

// operationContext creates a per-agent-operation context that is cancelled on agent shutdown or timeout
func (a *revaulterSSHAgent) operationContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	done := make(chan struct{})

	go func() {
		select {
		case <-a.shutdown:
			cancel()
		case <-done:
		}
	}()

	return ctx, func() {
		close(done)
		cancel()
	}
}

var errSSHNotSupported = errors.New("not supported")

// Add, Remove, RemoveAll, Lock, Unlock, Signers are not supported
func (a *revaulterSSHAgent) Add(_ agent.AddedKey) error     { return errSSHNotSupported }
func (a *revaulterSSHAgent) Remove(_ ssh.PublicKey) error   { return errSSHNotSupported }
func (a *revaulterSSHAgent) RemoveAll() error               { return errSSHNotSupported }
func (a *revaulterSSHAgent) Lock(_ []byte) error            { return errSSHNotSupported }
func (a *revaulterSSHAgent) Unlock(_ []byte) error          { return errSSHNotSupported }
func (a *revaulterSSHAgent) Signers() ([]ssh.Signer, error) { return nil, errSSHNotSupported }

// advertisedSigningKey is the signing key the agent advertises to SSH clients, after it has been bound to the pinned anchor
// KeyID is the RFC 7638 JWK thumbprint, which is the same identifier the browser echoes in the E2EE sign response
type advertisedSigningKey struct {
	SSHPub ssh.PublicKey
	KeyID  string
}

// fetchSigningPubkey retrieves the stored signing public key for the configured label and algorithm
// The key is only returned after its anchor-signed publication proof has been verified against the anchor pinned in the trust store, so a compromised server cannot substitute a key of its choosing
func (a *revaulterSSHAgent) fetchSigningPubkey(parentCtx context.Context) (advertisedSigningKey, error) {
	key, err := a.client.SigningPublicKey(parentCtx, a.flags.KeyLabel, a.flags.Algorithm)
	if err != nil {
		return advertisedSigningKey{}, err
	}

	// Convert the public key into the SSH public key format
	var sshPub ssh.PublicKey
	switch pub := key.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sshPub, err = ssh.NewPublicKey(pub)
	case ed25519.PublicKey:
		sshPub, err = ssh.NewPublicKey(pub)
	default:
		return advertisedSigningKey{}, fmt.Errorf("unsupported SSH signing key type %T", key.PublicKey)
	}
	if err != nil {
		return advertisedSigningKey{}, fmt.Errorf("build SSH public key: %w", err)
	}

	return advertisedSigningKey{SSHPub: sshPub, KeyID: key.KeyID}, nil
}

// shellQuote returns a POSIX single-quoted shell literal
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// signTimeout returns the per-request sign timeout: flags timeout + grace, or a 5-minute default
func (a *revaulterSSHAgent) signTimeout() time.Duration {
	const defaultTimeout = 5 * time.Minute
	const grace = 30 * time.Second

	d := a.flags.GetTimeoutDuration()
	if d > 0 {
		return d + grace
	}

	return defaultTimeout
}
