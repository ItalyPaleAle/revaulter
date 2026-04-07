package cmd

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
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

	state, err := o.createRequest(cmd.Context(), httpClient, kp.Public)
	if err != nil {
		return fmt.Errorf("failed to start operation: %w", err)
	}

	aad := buildTransportAAD(state, o.Operation, o.flags.GetAlgorithm())
	res, err := o.getResult(cmd.Context(), httpClient, state, kp.Private, aad)
	if err != nil {
		return fmt.Errorf("failed to get response: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	return enc.Encode(res)
}

func (o *v2OperationCmd) createRequest(ctx context.Context, httpClient *http.Client, transportPub protocolv2.ECP256PublicJWK) (string, error) {
	// Fetch the user's static ECDH public key
	pubkey, err := o.fetchUserPubkey(ctx, httpClient)
	if err != nil {
		return "", fmt.Errorf("failed to fetch user public key: %w", err)
	}

	// Build the inner payload (sensitive fields)
	innerPayload := o.flags.InnerPayload(transportPub)

	// Build AAD from plaintext metadata
	aad := buildRequestEncAAD(o.flags.GetAlgorithm(), o.flags.GetKeyLabel(), o.Operation)

	// Encrypt the inner payload
	cliEphPub, nonce, ciphertext, err := encryptV2RequestPayload(pubkey, innerPayload, aad)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt request payload: %w", err)
	}

	// Build the outer request body
	outerBody := v2OperationRequest{
		KeyLabel:              o.flags.GetKeyLabel(),
		Algorithm:             o.flags.GetAlgorithm(),
		Timeout:               o.flags.GetTimeout(),
		Note:                  o.flags.GetNote(),
		RequestEncAlg:         "ecdh-p256+a256gcm",
		CliEphemeralPublicKey: cliEphPub,
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

func (o *v2OperationCmd) fetchUserPubkey(ctx context.Context, httpClient *http.Client) (*ecdh.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.flags.GetServer()+"/v2/request/"+o.flags.GetRequestKey()+"/pubkey", nil)
	if err != nil {
		return nil, err
	}

	var pubkeyJWK protocolv2.ECP256PublicJWK
	err = doJSONRequest(httpClient, req, &pubkeyJWK)
	if err != nil {
		return nil, err
	}

	return pubkeyJWK.ToECDHPublicKey()
}

func (o *v2OperationCmd) getResult(ctx context.Context, httpClient *http.Client, state string, priv any, aad []byte) (json.RawMessage, error) {
	clientPriv, ok := priv.(*ecdh.PrivateKey)
	if !ok || clientPriv == nil {
		return nil, errors.New("invalid client private key")
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
		return nil, errors.New("waiting for the result got interrupted")
	}
	if res.Failed {
		return nil, errors.New("operation is canceled, denied, or failed")
	}
	if !res.Done || res.ResponseEnvelope == nil {
		return nil, errors.New("missing encrypted response envelope")
	}
	plain, err := decryptV2ResponseEnvelope(state, clientPriv, res.ResponseEnvelope, aad)
	if err != nil {
		return nil, err
	}
	return formatV2DecryptedPayload(state, plain)
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
