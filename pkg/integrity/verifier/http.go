package verifier

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// Sentinel errors that callers can detect with errors.Is
var (
	ErrNoIntegrity      = errors.New("server reports hasIntegrity=false: this build does not carry a signed integrity manifest")
	ErrUnexpectedAPIVer = errors.New("unexpected apiVersion")
)

// NewHTTPClient builds an HTTP/2-capable client suitable for contacting a Revaulter server
// It optionally allows h2c (HTTP/2 Cleartext) and skipping TLS verification, to support local development
func NewHTTPClient(serverURL string, insecure, noH2C bool) (*http.Client, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	transport := &http2.Transport{
		IdleConnTimeout:  90 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}

	if parsed.Scheme == "http" && !noH2C {
		transport.AllowHTTP = true
		transport.DialTLSContext = func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	if insecure {
		transport.TLSClientConfig = &tls.Config{
			// #nosec G402
			InsecureSkipVerify: true,
		}
	}

	return &http.Client{
		// Disable following redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}, nil
}

// doJSONRequest sends req and decodes a JSON response into out
// On non-2xx responses it returns an error that tries to surface the server-side error message
func doJSONRequest(client *http.Client, req *http.Request, out any) error {
	// #nosec G704 -- redirects are disabled on the client and req targets are built from the already parsed server URL used to create the verifier client
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
	if out == nil {
		return nil
	}

	err = json.NewDecoder(res.Body).Decode(out)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}
