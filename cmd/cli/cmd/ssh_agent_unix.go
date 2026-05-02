//go:build unix

package cmd

import (
	"context"
	"crypto/ecdsa"
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
	"os"
	"os/signal"
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

SSH clients point SSH_AUTH_SOCK at the socket. When they request a signature,
the agent sends a sign request to the Revaulter server. The user approves via
their browser and passkey, and the resulting ECDSA signature is returned to SSH.

The signing public key is auto-registered by the server after the first sign
operation with the given key label. Run any other revaulter-cli command (e.g.
"sign") at least once with a TTY to pin the server anchor before running the
agent in a non-interactive environment.`,
		RunE: f.Run,
	}

	f.BindBase(cmd)
	_ = cmd.MarkFlagRequired("key-label")
	cmd.Flags().StringVar(&f.SocketPath, "socket", "", "Path for the Unix socket (default: /tmp/revaulter-ssh-agent-<label>.sock)")
	cmd.Flags().StringVar(&f.Comment, "comment", "", `Comment attached to the key (default: "revaulter/<key-label>")`)
	return cmd
}

func (f *sshAgentFlags) Run(cmd *cobra.Command, _ []string) error {
	log := logging.LogFromContext(cmd.Context())

	err := f.Validate()
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	if f.Comment == "" {
		f.Comment = "revaulter/" + f.KeyLabel
	}
	if f.SocketPath == "" {
		f.SocketPath = "/tmp/revaulter-ssh-agent-" + f.KeyLabel + ".sock"
	}

	httpClient, err := getV2HTTPClient(log, &f.v2OperationFlagsBase)
	if err != nil {
		return err
	}

	// Remove stale socket file if it exists
	_ = os.Remove(f.SocketPath)

	l, err := net.Listen("unix", f.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket %s: %w", f.SocketPath, err)
	}
	defer func() {
		l.Close()
		_ = os.Remove(f.SocketPath)
	}()

	// Restrict socket to owner-only access
	if err = os.Chmod(f.SocketPath, 0o600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &revaulterSSHAgent{
		httpClient: httpClient,
		flags:      f,
		log:        log,
	}

	log.Info("SSH agent listening",
		slog.String("socket", f.SocketPath),
		slog.String("key_label", f.KeyLabel),
		slog.String("comment", f.Comment),
	)
	fmt.Fprintf(os.Stderr, "export SSH_AUTH_SOCK=%s\n", f.SocketPath)

	// Accept connections until context is canceled
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Error("SSH agent accept error", slog.Any("err", err))
				}
				return
			}
			go func() {
				defer conn.Close()
				err := agent.ServeAgent(a, conn)
				if err != nil && !errors.Is(err, net.ErrClosed) {
					log.Debug("SSH agent connection closed", slog.Any("err", err))
				}
			}()
		}
	}()

	<-ctx.Done()
	log.Info("SSH agent shutting down")
	return nil
}

// revaulterSSHAgent implements agent.Agent, routing all sign requests through Revaulter
type revaulterSSHAgent struct {
	httpClient *http.Client
	flags      *sshAgentFlags
	log        *slog.Logger
}

// List returns the signing public key registered for the configured label
func (a *revaulterSSHAgent) List() ([]*agent.Key, error) {
	sshPub, err := a.fetchSigningPubkey()
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format:  sshPub.Type(),
		Blob:    sshPub.Marshal(),
		Comment: a.flags.Comment,
	}}, nil
}

// Sign hashes data with SHA-256 and submits a sign request to the Revaulter server
func (a *revaulterSSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.signTimeout())
	defer cancel()

	digest := sha256.Sum256(data)
	digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])

	// Build a sign operation reusing existing request/result helpers
	signFlags := &v2OperationFlagsSign{
		v2OperationFlagsBase: a.flags.v2OperationFlagsBase,
	}
	signFlags.Algorithm = protocolv2.SigningAlgES256
	signFlags.Note = "SSH auth"
	signFlags.digestB64 = digestB64

	op := &v2OperationCmd{
		Operation: protocolv2.OperationSign,
		flags:     signFlags,
	}

	kp, err := newV2TransportKeyPair()
	if err != nil {
		return nil, fmt.Errorf("transport key pair: %w", err)
	}

	state, err := op.createRequest(ctx, a.httpClient, kp)
	if err != nil {
		return nil, fmt.Errorf("submit sign request: %w", err)
	}

	a.log.Info("Waiting for browser confirmation", slog.String("state", state))

	aad := buildTransportAAD(state, protocolv2.OperationSign, protocolv2.SigningAlgES256)
	plain, err := op.getResult(ctx, a.httpClient, state, kp, aad)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}

	var resp v2SignResponsePayload
	if err = json.Unmarshal(plain, &resp); err != nil {
		return nil, fmt.Errorf("parse sign response: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	if err != nil || len(sigBytes) != 64 {
		return nil, fmt.Errorf("invalid signature in response")
	}

	// Convert IEEE P1363 r||s (64 bytes) to the SSH ECDSA wire format: mpint r, mpint s
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	sigBlob := ssh.Marshal(struct{ R, S *big.Int }{R: r, S: s})

	return &ssh.Signature{
		Format: key.Type(),
		Blob:   sigBlob,
	}, nil
}

// Add, Remove, RemoveAll, Lock, Unlock, Signers are not supported
func (a *revaulterSSHAgent) Add(_ agent.AddedKey) error        { return errors.New("not supported") }
func (a *revaulterSSHAgent) Remove(_ ssh.PublicKey) error      { return errors.New("not supported") }
func (a *revaulterSSHAgent) RemoveAll() error                  { return errors.New("not supported") }
func (a *revaulterSSHAgent) Lock(_ []byte) error               { return errors.New("not supported") }
func (a *revaulterSSHAgent) Unlock(_ []byte) error             { return errors.New("not supported") }
func (a *revaulterSSHAgent) Signers() ([]ssh.Signer, error)    { return nil, errors.New("not supported") }

// fetchSigningPubkey retrieves the auto-stored ES256 public key for the configured label
func (a *revaulterSSHAgent) fetchSigningPubkey() (ssh.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pathSuffix := "signing-pubkey?label=" + a.flags.KeyLabel + "&algorithm=" + protocolv2.SigningAlgES256
	req, err := newV2RequestKeyHTTPRequest(ctx, http.MethodGet, a.flags.GetServer(), a.flags.GetRequestKey(), pathSuffix, nil)
	if err != nil {
		return nil, err
	}

	var resp v2RequestSigningPubkeyClientResponse
	if err = doJSONRequest(a.httpClient, req, &resp); err != nil {
		return nil, fmt.Errorf("fetch signing pubkey: %w", err)
	}

	var jwk protocolv2.ECP256SigningJWK
	if err = json.Unmarshal(resp.JWK, &jwk); err != nil {
		return nil, fmt.Errorf("parse signing key JWK: %w", err)
	}

	ecdhPub, err := jwk.ToECDHPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid signing public key: %w", err)
	}

	// Convert raw uncompressed point (04 || x || y) to *ecdsa.PublicKey
	raw := ecdhPub.Bytes()
	ecdsaPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}

	sshPub, err := ssh.NewPublicKey(ecdsaPub)
	if err != nil {
		return nil, fmt.Errorf("build SSH public key: %w", err)
	}
	return sshPub, nil
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
