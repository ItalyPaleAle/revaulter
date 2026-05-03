//go:build unix

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
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

Note: The signing public key is auto-registered by the server after the first sign operation with the given key label. Run "revaulter trust" (or any other revaulter CLI command) at least once with a TTY to pin the server anchor before running the
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

	if f.Algorithm == "" {
		f.Algorithm = protocolv2.SigningAlgES256
	}

	canonical, ok := protocolv2.NormalizeSigningAlgorithm(f.Algorithm)
	if !ok {
		return fmt.Errorf("unsupported signing algorithm %q", f.Algorithm)
	}
	if canonical == protocolv2.SigningAlgEd25519ph {
		return errors.New("ssh-agent does not support Ed25519ph; use ES256 or Ed25519")
	}
	f.Algorithm = canonical

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

	// Get the HTTP client
	httpClient, err := getV2HTTPClient(log, &f.v2OperationFlagsBase)
	if err != nil {
		return err
	}

	// Remove stale socket file if it exists
	_ = os.Remove(f.SocketPath)

	// Create a listener on the UDS
	l, err := net.Listen("unix", f.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket %s: %w", f.SocketPath, err)
	}
	defer func() {
		l.Close()
		_ = os.Remove(f.SocketPath)
	}()

	// Restrict socket to owner-only access
	err = os.Chmod(f.SocketPath, 0o600)
	if err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &revaulterSSHAgent{
		shutdown:   ctx.Done(),
		httpClient: httpClient,
		flags:      f,
		log:        log,
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
	shutdown   <-chan struct{}
	httpClient *http.Client
	flags      *sshAgentFlags
	log        *slog.Logger
}

// List returns the signing public key registered for the configured label
func (a *revaulterSSHAgent) List() ([]*agent.Key, error) {
	ctx, cancel := a.operationContext(30 * time.Second)
	defer cancel()

	sshPub, err := a.fetchSigningPubkey(ctx)
	if err != nil {
		return nil, err
	}

	return []*agent.Key{{
		Format:  sshPub.Type(),
		Blob:    sshPub.Marshal(),
		Comment: a.flags.Comment,
	}}, nil
}

// Sign submits a sign request to the Revaulter server and translates the response into SSH wire format
func (a *revaulterSSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	ctx, cancel := a.operationContext(a.signTimeout())
	defer cancel()

	err := a.validateSigningKey(ctx, key)
	if err != nil {
		return nil, err
	}

	// Build a sign operation reusing existing request/result helpers
	signFlags := &v2OperationFlagsSign{
		v2OperationFlagsBase: a.flags.v2OperationFlagsBase,
	}
	signFlags.Algorithm = a.flags.Algorithm
	signFlags.Note = sshAgentSignNote(a.flags.Note)
	if a.flags.Algorithm == protocolv2.SigningAlgES256 {
		digest := sha256.Sum256(data)
		signFlags.resolvedValueB64 = base64.RawURLEncoding.EncodeToString(digest[:])
	} else {
		err = ensureWithinInputLimit("ssh-agent signing input", len(data))
		if err != nil {
			return nil, err
		}
		signFlags.resolvedValueB64 = base64.RawURLEncoding.EncodeToString(data)
	}

	op := &v2OperationCmd{
		Operation: protocolv2.OperationSign,
		flags:     signFlags,
	}

	kp, err := newV2TransportKeyPair()
	if err != nil {
		return nil, fmt.Errorf("transport key pair: %w", err)
	}

	// Create the request
	state, err := op.createRequest(ctx, a.httpClient, kp)
	if err != nil {
		return nil, fmt.Errorf("submit sign request: %w", err)
	}

	// Wait for the confirmation
	a.log.Info("Waiting for browser confirmation", slog.String("state", state))
	aad := buildTransportAAD(state, protocolv2.OperationSign, a.flags.Algorithm)
	plain, err := op.getResult(ctx, a.httpClient, state, kp, aad)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}

	// Parse and validate the response
	_, sigBytes, err := parseAndValidateV2SignResponse(state, a.flags.KeyLabel, a.flags.Algorithm, plain)
	if err != nil {
		return nil, err
	}

	sig := &ssh.Signature{Format: key.Type()}
	if a.flags.Algorithm == protocolv2.SigningAlgES256 {
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

// sshAgentSignNote returns the note shown to the user for SSH auth approvals
func sshAgentSignNote(extra string) string {
	if extra == "" {
		return "SSH auth"
	}

	return "SSH auth " + extra
}

// validateSigningKey rejects sign requests for keys this agent did not advertise
func (a *revaulterSSHAgent) validateSigningKey(ctx context.Context, key ssh.PublicKey) error {
	if key == nil {
		return errors.New("missing SSH public key")
	}

	advertisedKey, err := a.fetchSigningPubkey(ctx)
	if err != nil {
		return fmt.Errorf("fetch advertised signing key: %w", err)
	}

	if !bytes.Equal(key.Marshal(), advertisedKey.Marshal()) {
		return errors.New("requested SSH key is not managed by this agent")
	}

	return nil
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

// fetchSigningPubkey retrieves the auto-stored signing public key for the configured label and algorithm
func (a *revaulterSSHAgent) fetchSigningPubkey(parentCtx context.Context) (ssh.PublicKey, error) {
	err := a.verifyAnchorTrust(parentCtx)
	if err != nil {
		return nil, err
	}

	// Create the request
	query := url.Values{}
	query.Set("label", a.flags.KeyLabel)
	query.Set("algorithm", a.flags.Algorithm)
	pathSuffix := "signing-pubkey?" + query.Encode()
	req, err := newV2RequestKeyHTTPRequest(parentCtx, http.MethodGet, a.flags.GetServer(), a.flags.GetRequestKey(), pathSuffix, nil)
	if err != nil {
		return nil, err
	}

	// Parse the response
	var resp v2RequestSigningPubkeyClientResponse
	err = doJSONRequest(a.httpClient, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("fetch signing pubkey: %w", err)
	}

	switch resp.Algorithm {
	case protocolv2.SigningAlgES256:
		var jwk protocolv2.ECP256SigningJWK
		err = json.Unmarshal(resp.JWK, &jwk)
		if err != nil {
			return nil, fmt.Errorf("parse signing key JWK: %w", err)
		}

		ecdhPub, parseErr := jwk.ToECDHPublicKey()
		if parseErr != nil {
			return nil, fmt.Errorf("invalid signing public key: %w", parseErr)
		}

		raw := ecdhPub.Bytes()
		ecdsaPub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(raw[1:33]),
			Y:     new(big.Int).SetBytes(raw[33:65]),
		}

		sshPub, parseErr := ssh.NewPublicKey(ecdsaPub)
		if parseErr != nil {
			return nil, fmt.Errorf("build SSH public key: %w", parseErr)
		}
		return sshPub, nil

	case protocolv2.SigningAlgEd25519:
		var jwk protocolv2.Ed25519SigningJWK
		err = json.Unmarshal(resp.JWK, &jwk)
		if err != nil {
			return nil, fmt.Errorf("parse signing key JWK: %w", err)
		}

		edPub, parseErr := jwk.ToPublicKey()
		if parseErr != nil {
			return nil, fmt.Errorf("invalid signing public key: %w", parseErr)
		}

		sshPub, parseErr := ssh.NewPublicKey(ed25519.PublicKey(edPub))
		if parseErr != nil {
			return nil, fmt.Errorf("build SSH public key: %w", parseErr)
		}
		return sshPub, nil

	default:
		return nil, fmt.Errorf("unsupported SSH signing algorithm %q", resp.Algorithm)
	}
}

// verifyAnchorTrust checks the pinned server anchor before trusting signing-key lookup responses
func (a *revaulterSSHAgent) verifyAnchorTrust(ctx context.Context) error {
	if a.flags.GetNoTrustStore() {
		a.log.Warn("Skipping anchor pinning and hybrid bundle verification because --no-trust-store is set")
		return nil
	}

	// Load the trust store
	ts, path, err := loadTrustStoreForFlags(a.flags)
	if err != nil {
		return err
	}

	// Request the public key
	req, err := newV2RequestKeyHTTPRequest(ctx, http.MethodGet, a.flags.GetServer(), a.flags.GetRequestKey(), "pubkey", nil)
	if err != nil {
		return err
	}

	// Parse and validate the response
	var resp v2PubkeyResponse
	err = doJSONRequest(a.httpClient, req, &resp)
	if err != nil {
		return fmt.Errorf("fetch server pubkey bundle: %w", err)
	}

	pinned, err := verifyAndPinAnchor(a.flags.GetServer(), &resp, ts, nil)
	if err != nil {
		return fmt.Errorf("anchor trust check failed: %w", err)
	}

	// Save the updated trust store if needed
	if pinned {
		err = saveTrustStore(path, ts)
		if err != nil {
			return fmt.Errorf("save trust store: %w", err)
		}
	}

	return nil
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

// v2RequestSigningPubkeyClientResponse mirrors the server's v2RequestSigningPubkeyResponse
type v2RequestSigningPubkeyClientResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	JWK       json.RawMessage `json:"jwk"`
}
