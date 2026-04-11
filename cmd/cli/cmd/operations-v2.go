package cmd

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http2"

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
	httpClient, err := getV2HTTPClient(log, o.flags)
	if err != nil {
		return err
	}

	err = o.flags.Validate()
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
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

// writeResult emits the decrypted plaintext to either stdout or the file requested by --output
// In raw mode the plaintext bytes are written verbatim; otherwise they are wrapped in the default JSON envelope produced by formatV2DecryptedPayload
func (o *v2OperationCmd) writeResult(state string, plain []byte) error {
	raw := o.flags.GetRaw()
	output := o.flags.GetOutput()

	var payload []byte
	if raw {
		payload = plain
	} else {
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
	// Fetch the user's static public keys (ECDH + ML-KEM)
	ecdhPub, mlkemPub, err := o.fetchUserPubkeys(ctx, httpClient)
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
		RequestEncAlg:         "ecdh-p256+mlkem768+a256gcm",
		CliEphemeralPublicKey: cliEphPub,
		MlkemCiphertext:       mlkemCiphertext,
		EncryptedPayloadNonce: nonce,
		EncryptedPayload:      ciphertext,
	}

	body, err := json.Marshal(outerBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.flags.GetServer()+"/v2/request/"+o.flags.GetRequestKey()+"/"+o.Operation, bytes.NewReader(body))
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

func (o *v2OperationCmd) fetchUserPubkeys(ctx context.Context, httpClient *http.Client) (*ecdh.PublicKey, *mlkem.EncapsulationKey768, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.flags.GetServer()+"/v2/request/"+o.flags.GetRequestKey()+"/pubkey", nil)
	if err != nil {
		return nil, nil, err
	}

	var resp struct {
		EcdhP256 protocolv2.ECP256PublicJWK `json:"ecdhP256"`
		Mlkem768 string                     `json:"mlkem768"`
	}
	err = doJSONRequest(httpClient, req, &resp)
	if err != nil {
		return nil, nil, err
	}

	ecdhPub, err := resp.EcdhP256.ToECDHPublicKey()
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

	return ecdhPub, mlkemPub, nil
}

// getResult polls the server until the operation completes and returns the decrypted plaintext bytes
// Callers decide whether to wrap the bytes in the default JSON envelope (formatV2DecryptedPayload) or write them raw
func (o *v2OperationCmd) getResult(ctx context.Context, httpClient *http.Client, state string, kp *v2TransportKeyPair, aad []byte) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("missing transport key pair")
	}

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

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.flags.GetServer()+"/v2/request/result/"+state, nil)
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

func doJSONRequest(client *http.Client, req *http.Request, out any) error {
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
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}
	if insecure {
		if log != nil {
			log.Warn("The '--insecure' flag is enabled: skipping TLS certificate validation")
		}
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	return &http.Client{Transport: transport}, nil
}
