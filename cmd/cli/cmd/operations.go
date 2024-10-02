package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http2"

	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

func init() {
	// Register all commands
	rootCmd.AddCommand(
		operationCmd{
			Operation: "wrapkey",
			Short:     "Wrap a key",
			Long:      "Wrap a key using a key stored in Azure Key Vault",
		}.GetCobraCommand(),
		operationCmd{
			Operation: "unwrapkey",
			Short:     "Unwrap a key",
			Long:      "Unwrap a key using a key stored in Azure Key Vault",
		}.GetCobraCommand(),
		operationCmd{
			Operation: "encrypt",
			Short:     "Encrypt a message",
			Long:      "Encrypt a short message using a key stored in Azure Key Vault",
		}.GetCobraCommand(),
		operationCmd{
			Operation: "decrypt",
			Short:     "Decrypt a message",
			Long:      "Decrypt a short message using a key stored in Azure Key Vault",
		}.GetCobraCommand(),
		operationCmd{
			Operation: "sign",
			Short:     "Compute a signature",
			Long:      "Compute the digital signature of a digest using a key stored in Azure Key Vault",
		}.GetCobraCommand(),
		operationCmd{
			Operation: "verify",
			Short:     "Verify a signature",
			Long:      "Verify the digital signature of a digest using a key stored in Azure Key Vault",
		}.GetCobraCommand(),
	)
}

type operationCmd struct {
	// Operation name
	Operation string
	// Short description
	Short string
	// Long description
	Long string

	flags operationFlags

	// Runtime properties
	log        *slog.Logger
	httpClient *http.Client
}

func (o operationCmd) GetCobraCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   o.Operation,
		Short: o.Short,
		Long:  o.Long,
		RunE:  o.Run,
	}

	switch o.Operation {
	case "encrypt":
		o.flags = &operationFlagsEncrypt{}
	case "decrypt":
		o.flags = &operationFlagsDecrypt{}
	case "sign":
		o.flags = &operationFlagsSign{}
	case "verify":
		o.flags = &operationFlagsVerify{}
	case "wrapkey":
		o.flags = &operationFlagsWrapKey{}
	case "unwrapkey":
		o.flags = &operationFlagsUnwrapKey{}
	default:
		// Development-time error
		panic("invalid operation: " + o.Operation)
	}

	o.flags.BindToCommand(cmd)

	return cmd
}

// Run is the main function for executing the command
func (o *operationCmd) Run(cmd *cobra.Command, args []string) (err error) {
	// Init the runtime properties
	o.log = logging.LogFromContext(cmd.Context())
	o.httpClient, err = o.getHTTPClient()
	if err != nil {
		return fmt.Errorf("failed to initialize HTTP client: %w", err)
	}

	// Validate the flags
	err = o.flags.Validate()
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	// Create the request for the operation
	state, err := o.createRequest(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to start operation: %w", err)
	}

	// Get the result
	response, err := o.getResult(cmd.Context(), state)
	if err != nil {
		return fmt.Errorf("failed to get response: %w", err)
	}

	// Print the result to stdout
	os.Stdout.Write(response)

	return nil
}

func (o operationCmd) createRequest(parentCtx context.Context) (string, error) {
	// Send request
	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
	defer cancel()

	reqBody, err := o.flags.RequestBody()
	if err != nil {
		return "", fmt.Errorf("failed to get request body: %w", err)
	}
	server := o.flags.GetServer()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/request/"+o.Operation, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Get the response
	resBody := operationResponse{}
	err = o.doRequest(req, &resBody)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}

	// Must have a state ID and the operation must be pending
	if !resBody.Pending {
		return "", errors.New("response is not valid: operation is not pending")
	}
	if resBody.State == "" {
		return "", errors.New("response is not valid: state is missing")
	}

	o.log.Debug("Operation is pending", "state", resBody.State)

	return resBody.State, nil
}

func (o operationCmd) getResult(ctx context.Context, state string) (json.RawMessage, error) {
	// Create the request
	server := o.flags.GetServer()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/request/result/"+state, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Get the response
	o.log.Debug("Waiting for result…")
	resBody := operationResponse{}
	err = o.doRequest(req, &resBody)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resBody.State != state {
		return nil, errors.New("Response state does not match the requested one")
	}

	switch {
	case resBody.Failed:
		return nil, errors.New("Operation is canceled, denied, or failed")
	case resBody.Pending:
		return nil, errors.New("Waiting for the result got interrupted")
	case !resBody.Done:
		// If the operation isn't failed or pending, then it must be done
		return nil, errors.New("Operation is in an unknown state")
	}

	o.log.Info("Operation completed successfully", "state", state)

	// Return the raw response
	return resBody.Response, nil
}

func (o operationCmd) doRequest(req *http.Request, resBody any) error {
	// Make the request
	res, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error while making the request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Handle response errors
	if res.StatusCode >= 400 {
		resContent, _ := io.ReadAll(res.Body)
		if len(resContent) > 0 {
			resBody := operationResponse{}
			// We ignore the error from the JSON unmarshaler here
			_ = json.Unmarshal(resContent, &resBody)
			switch {
			case resBody.Error != "":
				o.log.Error("The server returned an error", "status", res.StatusCode, "error", resBody.Error)
			case resBody.Failed:
				o.log.Error("The operation failed or was rejected")
			default:
				o.log.Error("The server returned an unknown error", "status", res.StatusCode, "response", string(resContent))
			}
		} else {
			o.log.Error("Request failed with no content", "status", res.StatusCode)
		}

		return fmt.Errorf("response status code: %d", res.StatusCode)
	}

	// Read the response
	err = json.NewDecoder(res.Body).Decode(&resBody)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	return nil
}

func (o operationCmd) getHTTPClient() (*http.Client, error) {
	server := o.flags.GetServer()
	insecure, noH2c := o.flags.GetConnectionOptions()

	serverUrl, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	// Force transport to use HTTP/2
	transport := &http2.Transport{
		IdleConnTimeout:  90 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}

	// If the server uses http, enable H2C with prior knowledge if configured
	if serverUrl.Scheme == "http" && !noH2c {
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	// Disable TLS certificate validation if the insecure flag is set
	if insecure {
		o.log.Warn("The '--insecure' flag is enabled: skipping TLS certificate validation")
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402
		}
	}

	return &http.Client{
		Transport: transport,
	}, nil
}
