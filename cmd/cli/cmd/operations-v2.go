package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/term"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

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

	httpClient, err := getV2HTTPClient(log, o.flags)
	if err != nil {
		return err
	}

	kp, err := newV2TransportKeyPair()
	if err != nil {
		return err
	}

	state, err := o.createRequest(cmd.Context(), httpClient, kp)
	if err != nil {
		return fmt.Errorf("failed to start operation: %w", err)
	}

	aad := buildTransportAAD(state, o.Operation, o.flags.GetAlgorithm())
	plain, err := o.getResult(cmd.Context(), httpClient, state, kp, aad)
	if err != nil {
		return fmt.Errorf("failed to get response: %w", err)
	}

	return o.writeResult(state, plain)
}

// v2OperationResultFormatter lets an operation override how the decrypted plaintext is shaped before being written
// Used by the sign op to emit a compact JWS or the raw signature bytes extracted from the JSON envelope
type v2OperationResultFormatter interface {
	FormatResult(state string, plain []byte, raw bool) ([]byte, error)
}

// writeResult emits the decrypted plaintext to either stdout or the file requested by --output
// In raw mode the plaintext bytes are written verbatim; otherwise they are wrapped in the default JSON envelope produced by formatV2DecryptedPayload
func (o *v2OperationCmd) writeResult(state string, plain []byte) error {
	raw := o.flags.GetRaw()
	output := o.flags.GetOutput()

	var payload []byte
	formatter, ok := o.flags.(v2OperationResultFormatter)
	switch {
	case ok:
		var err error
		payload, err = formatter.FormatResult(state, plain, raw)
		if err != nil {
			return fmt.Errorf("failed to format response: %w", err)
		}
	case raw:
		payload = plain
	default:
		formatted, err := formatV2DecryptedPayload(state, plain)
		if err != nil {
			return fmt.Errorf("failed to format response: %w", err)
		}
		// Indent for stdout backwards compatibility
		var buf bytes.Buffer
		err = json.Indent(&buf, formatted, "", " ")
		if err != nil {
			return fmt.Errorf("failed to indent response: %w", err)
		}
		// json.Encoder.Encode appended a trailing newline; preserve that for shell-friendliness
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

func (o *v2OperationCmd) createRequest(ctx context.Context, httpClient *http.Client, kp *v2TransportKeyPair) (string, error) {
	// Fetch the user's static public keys (ECDH + ML-KEM) alongside the hybrid
	// anchor bundle so the CLI can pin the anchor on first contact and refuse
	// any subsequent pubkey substitution.
	ecdhPub, mlkemPub, err := o.fetchAndVerifyUserPubkeys(ctx, httpClient)
	if err != nil {
		return "", fmt.Errorf("failed to fetch user public keys: %w", err)
	}

	// Build the inner payload (sensitive fields)
	innerPayload := o.flags.InnerPayload(kp.EcdhPublic, kp.MlkemPublic)

	// Build AAD from plaintext metadata
	aad := buildRequestEncAAD(o.flags.GetAlgorithm(), o.flags.GetKeyLabel(), o.Operation)

	// Encrypt the inner payload with hybrid ECDH + ML-KEM
	cliEphPub, mlkemCiphertext, nonce, ciphertext, err := encryptV2RequestPayload(ecdhPub, mlkemPub, innerPayload, aad)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt request payload: %w", err)
	}

	// Build the outer request body
	outerBody := v2OperationRequest{
		KeyLabel:              o.flags.GetKeyLabel(),
		Algorithm:             o.flags.GetAlgorithm(),
		Timeout:               o.flags.GetTimeout(),
		Note:                  o.flags.GetNote(),
		RequestEncAlg:         protocolv2.TransportAlg,
		CliEphemeralPublicKey: cliEphPub,
		MlkemCiphertext:       mlkemCiphertext,
		EncryptedPayloadNonce: nonce,
		EncryptedPayload:      ciphertext,
	}

	body, err := json.Marshal(outerBody)
	if err != nil {
		return "", err
	}

	req, err := newV2RequestKeyHTTPRequest(ctx, http.MethodPost, o.flags.GetServer(), o.flags.GetRequestKey(), o.Operation, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	var res protocolv2.RequestResultResponse
	err = doJSONRequest(httpClient, req, &res)
	if err != nil {
		return "", err
	}
	if !res.Pending || res.State == "" {
		return "", errors.New("invalid create response")
	}
	return res.State, nil
}

// v2PubkeyResponse mirrors the server's /v2/request/pubkey shape.
type v2PubkeyResponse struct {
	UserID   string          `json:"userId"`
	EcdhP256 json.RawMessage `json:"ecdhP256"`
	Mlkem768 string          `json:"mlkem768"`

	AnchorEs384PublicKey         string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey       string `json:"anchorMldsa87PublicKey"`
	WrappedKeyEpoch              int64  `json:"wrappedKeyEpoch"`
	PubkeyBundleSignatureEs384   string `json:"pubkeyBundleSignatureEs384"`
	PubkeyBundleSignatureMldsa87 string `json:"pubkeyBundleSignatureMldsa87"`
}

func (o *v2OperationCmd) fetchAndVerifyUserPubkeys(ctx context.Context, httpClient *http.Client) (*ecdh.PublicKey, *mlkem.EncapsulationKey768, error) {
	log := logging.LogFromContext(ctx)

	req, err := newV2RequestKeyHTTPRequest(ctx, http.MethodGet, o.flags.GetServer(), o.flags.GetRequestKey(), "pubkey", nil)
	if err != nil {
		return nil, nil, err
	}

	var resp v2PubkeyResponse
	err = doJSONRequest(httpClient, req, &resp)
	if err != nil {
		return nil, nil, err
	}

	var ecdhJWK protocolv2.ECP256PublicJWK
	err = json.Unmarshal(resp.EcdhP256, &ecdhJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ECDH public key: %w", err)
	}
	ecdhPub, err := ecdhJWK.ToECDHPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ECDH public key: %w", err)
	}

	mlkemBytes, err := base64.RawURLEncoding.DecodeString(resp.Mlkem768)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ML-KEM public key encoding: %w", err)
	}
	mlkemPub, err := mlkem.NewEncapsulationKey768(mlkemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ML-KEM public key: %w", err)
	}

	if o.flags.GetNoTrustStore() {
		log.Warn("Skipping anchor pinning and hybrid bundle verification because --no-trust-store is set")
		return ecdhPub, mlkemPub, nil
	}

	// Validate that the server supplied the full hybrid anchor bundle.
	if len(resp.AnchorEs384PublicKey) == 0 || resp.AnchorMldsa87PublicKey == "" ||
		resp.PubkeyBundleSignatureEs384 == "" || resp.PubkeyBundleSignatureMldsa87 == "" {
		return nil, nil, errors.New("server did not return a hybrid anchor bundle; refusing to proceed (use --no-trust-store to override)")
	}

	es384Pub, mldsa87PubBytes, err := parseAnchorPubkeysFromWire(resp.AnchorEs384PublicKey, resp.AnchorMldsa87PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid anchor public key: %w", err)
	}

	if resp.UserID == "" {
		return nil, nil, errors.New("server did not return userId; refusing to proceed (use --no-trust-store to override)")
	}

	// Verify both halves of the hybrid bundle signature against the SERVER-PROVIDED
	// anchor pubkeys. The subsequent pin check catches anchor rotation; this catches
	// a server that serves a corrupt or mismatched bundle.
	es384JWK, err := protocolv2.ParseECP384PublicJWKCanonicalBody(resp.AnchorEs384PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid anchorEs384PublicKey: %w", err)
	}

	bundlePayload := &protocolv2.PubkeyBundlePayload{
		UserID:                 resp.UserID,
		RequestEncEcdhPubkey:   string(resp.EcdhP256),
		RequestEncMlkemPubkey:  resp.Mlkem768,
		AnchorEs384Crv:         es384JWK.Crv,
		AnchorEs384Kty:         es384JWK.Kty,
		AnchorEs384X:           es384JWK.X,
		AnchorEs384Y:           es384JWK.Y,
		AnchorMldsa87PublicKey: resp.AnchorMldsa87PublicKey,
		WrappedKeyEpoch:        resp.WrappedKeyEpoch,
	}
	sigEs, sigMl, err := decodeHybridSignatures(resp.PubkeyBundleSignatureEs384, resp.PubkeyBundleSignatureMldsa87)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid pubkey bundle signature: %w", err)
	}
	err = protocolv2.VerifyHybridBundle(es384Pub, mldsa87PubBytes, bundlePayload, sigEs, sigMl)
	if err != nil {
		return nil, nil, fmt.Errorf("pubkey bundle signature verification failed: %w", err)
	}

	ts, path, err := o.loadOrInitTrustStore()
	if err != nil {
		return nil, nil, err
	}

	confirm := o.terminalConfirmer()
	pinned, err := ts.checkOrPinAnchor(
		o.flags.GetServer(), resp.UserID,
		es384Pub, resp.AnchorEs384PublicKey,
		resp.AnchorMldsa87PublicKey, mldsa87PubBytes,
		confirm,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("anchor trust check failed: %w", err)
	}
	if pinned {
		err = saveTrustStore(path, ts)
		if err != nil {
			return nil, nil, fmt.Errorf("save trust store: %w", err)
		}
		log.Info("Pinned anchor on first contact", slog.String("trust_store", path))
	}

	return ecdhPub, mlkemPub, nil
}

// loadOrInitTrustStore resolves the trust store path and loads its contents.
func (o *v2OperationCmd) loadOrInitTrustStore() (*trustStore, string, error) {
	path := o.flags.GetTrustStorePath()
	if path == "" {
		p, err := defaultTrustStorePath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	ts, err := loadTrustStore(path)
	if err != nil {
		return nil, "", err
	}
	return ts, path, nil
}

// terminalConfirmer returns a prompt function that asks the user on stderr to
// accept a TOFU pin. If stdin or stderr is not a TTY, it returns nil so the
// caller fails closed.
func (o *v2OperationCmd) terminalConfirmer() func(fingerprint string) (bool, error) {
	// File descriptors on supported platforms always fit in int; the uintptr from Fd is just an OS handle representation
	stdinFd := int(os.Stdin.Fd())   // #nosec G115
	stderrFd := int(os.Stderr.Fd()) // #nosec G115
	if !term.IsTerminal(stdinFd) || !term.IsTerminal(stderrFd) {
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	return func(fingerprint string) (bool, error) {
		fmt.Fprintf(os.Stderr, "First contact with %s.\n", o.flags.GetServer())
		fmt.Fprintf(os.Stderr, "Anchor fingerprint (SHA-256 of ES384||ML-DSA-87 pubkeys):\n  %s\n", fingerprint)
		fmt.Fprint(os.Stderr, "Pin this anchor? [y/N]: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("read answer: %w", err)
		}
		line = strings.ToLower(strings.TrimSpace(line))
		return line == "y" || line == "yes", nil
	}
}

// parseAnchorPubkeysFromWire decodes the CLI-facing wire form of the hybrid anchor.
func parseAnchorPubkeysFromWire(es384JWK string, mldsa87PubB64 string) (*ecdsa.PublicKey, []byte, error) {
	jwk, err := protocolv2.ParseECP384PublicJWKCanonicalBody(es384JWK)
	if err != nil {
		return nil, nil, fmt.Errorf("ES384 JWK: %w", err)
	}

	ecdsaPub, err := jwk.ToECDSAPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ES384 pubkey: %w", err)
	}

	mldsa87PubBytes, err := base64.RawURLEncoding.DecodeString(mldsa87PubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA-87 pubkey base64: %w", err)
	}

	if len(mldsa87PubBytes) != protocolv2.MLDSA87PublicKeySize {
		return nil, nil, fmt.Errorf("ML-DSA-87 pubkey: expected %d bytes, got %d", protocolv2.MLDSA87PublicKeySize, len(mldsa87PubBytes))
	}

	return ecdsaPub, mldsa87PubBytes, nil
}

// decodeHybridSignatures decodes base64url-encoded ES384 + ML-DSA-87 signatures
// and validates their sizes.
func decodeHybridSignatures(es384B64, mldsa87B64 string) (sigEs, sigMl []byte, err error) {
	sigEs, err = protocolv2.DecodeBase64Signature(es384B64, protocolv2.ES384SignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ES384 sig: %w", err)
	}
	sigMl, err = protocolv2.DecodeBase64Signature(mldsa87B64, protocolv2.MLDSA87SignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA-87 sig: %w", err)
	}
	return sigEs, sigMl, nil
}

// getResult polls the server until the operation completes and returns the decrypted plaintext bytes
// Callers decide whether to wrap the bytes in the default JSON envelope (formatV2DecryptedPayload) or write them raw
func (o *v2OperationCmd) getResult(ctx context.Context, httpClient *http.Client, state string, kp *v2TransportKeyPair, aad []byte) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("missing transport key pair")
	}

	// Apply a local deadline so the CLI can't poll indefinitely if the server hangs, drops the state, or keeps returning pending beyond the negotiated timeout
	// Use the user-supplied --timeout plus a small grace window so the server's expiry fires first and produces a clean "failed" response; fall back to a sensible default when unset
	const defaultResultTimeout = 15 * time.Minute
	const resultTimeoutGrace = 30 * time.Second
	localTimeout := o.flags.GetTimeoutDuration()
	if localTimeout > 0 {
		localTimeout += resultTimeoutGrace
	} else {
		localTimeout = defaultResultTimeout
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, localTimeout)
	defer cancel()

	// The server long-polls and may return {pending:true} when its own subscription window elapses, when the broker is saturated, or when the subscriber slot is temporarily unavailable
	// Treat those as "keep waiting" and re-issue the request until the context is canceled (or its deadline is reached)
	// A short backoff avoids tight-spinning if the server ever returns pending immediately
	const minBackoff = 250 * time.Millisecond
	const maxBackoff = 2 * time.Second
	backoff := minBackoff

	for {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}

		req, err := newV2RequestKeyHTTPRequest(ctx, http.MethodGet, o.flags.GetServer(), o.flags.GetRequestKey(), "result/"+state, nil)
		if err != nil {
			return nil, err
		}
		var res protocolv2.RequestResultResponse
		err = doJSONRequest(httpClient, req, &res)
		if err != nil {
			return nil, err
		}
		if res.State != state {
			return nil, errors.New("response state mismatch")
		}
		if res.Pending {
			// Wait briefly before reconnecting
			// The typical server long-poll already covered the bulk of the wait time; this backoff only kicks in if the server is returning pending quickly
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		if res.Failed {
			return nil, errors.New("operation is canceled, denied, or failed")
		}
		if !res.Done || res.ResponseEnvelope == nil {
			return nil, errors.New("missing encrypted response envelope")
		}
		return decryptV2ResponseEnvelope(state, kp, res.ResponseEnvelope, aad)
	}
}

// newV2RequestKeyHTTPRequest builds an HTTP request for the v2 request endpoints
// The key is sent in the Authorization header
func newV2RequestKeyHTTPRequest(ctx context.Context, method, server, requestKey, pathSuffix string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, server+"/v2/request/"+pathSuffix, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+requestKey)
	return req, nil
}

func doJSONRequest(client *http.Client, req *http.Request, out any) error {
	// #nosec G704 -- redirects are disabled on the client and req targets are built from the validated server URL selected by the CLI flags
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&e)
		if e.Error != "" {
			return fmt.Errorf("%s (status %d)", e.Error, res.StatusCode)
		}
		return fmt.Errorf("response status code: %d", res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func getV2HTTPClient(log *slog.Logger, flags v2OperationFlags) (*http.Client, error) {
	server := flags.GetServer()
	insecure, noH2c := flags.GetConnectionOptions()

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	transport := &http2.Transport{
		IdleConnTimeout:  90 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}
	if serverURL.Scheme == "http" && !noH2c {
		if log != nil {
			log.Warn("Server URL uses the 'http://' scheme: traffic is unencrypted and integrity checks can be bypassed by a network attacker")
		}
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}
	if insecure {
		if log != nil {
			log.Warn("The '--insecure' flag is enabled: skipping TLS certificate validation")
		}
		transport.TLSClientConfig = &tls.Config{
			// #nosec G402
			InsecureSkipVerify: true,
		}
	}
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}, nil
}
