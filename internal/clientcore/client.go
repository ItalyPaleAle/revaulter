// Package clientcore contains the low-level implementation of a client for the Revaulter v2 protocol
package clientcore

import (
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
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/italypaleale/revaulter/internal/buildinfo"
)

// DefaultUserAgent is the User-Agent header sent by clients that do not configure one
var DefaultUserAgent = "Revaulter/" + buildinfo.AppVersion

// ConfirmAnchorFunc is invoked on first contact with a server, before its anchor is pinned in the trust store
// Implementations return true to accept the fingerprint, or an error to abort
// A nil ConfirmAnchorFunc makes the client fail closed on first contact, which is what non-interactive callers want
type ConfirmAnchorFunc func(server string, userID string, fingerprint string) (bool, error)

// Config is the configuration for a Client
type Config struct {
	// Address of the Revaulter server, including the scheme
	Server string
	// Per-user request key used to authenticate with the server
	RequestKey string

	// Optional pre-configured HTTP client
	// When nil, a client is created using the Insecure and NoH2C options
	HTTPClient *http.Client
	// Skip TLS certificate validation
	// Ignored when HTTPClient is set
	Insecure bool
	// Do not attempt connecting with HTTP/2 Cleartext when not using TLS
	// Ignored when HTTPClient is set
	NoH2C bool
	// Value of the User-Agent header, defaulting to DefaultUserAgent
	UserAgent string

	// Optional logger
	Logger *slog.Logger

	// Path to the anchor trust store, defaulting to DefaultTrustStorePath
	TrustStorePath string
	// Disable anchor pinning and all signature verification that depends on it
	NoTrustStore bool
	// Callback invoked to accept an anchor on first contact
	ConfirmAnchor ConfirmAnchorFunc
}

// Client is a low-level client for the Revaulter v2 protocol
type Client struct {
	server     string
	requestKey string
	httpClient *http.Client
	log        *slog.Logger

	trustStorePath string
	noTrustStore   bool
	confirmAnchor  ConfirmAnchorFunc
}

// NewClient creates a new Client
func NewClient(cfg Config) (*Client, error) {
	server := strings.TrimSuffix(cfg.Server, "/")
	if server == "" {
		return nil, errors.New("property Server is required")
	}
	if cfg.RequestKey == "" {
		return nil, errors.New("property RequestKey is required")
	}

	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		var err error
		httpClient, err = NewHTTPClient(log, server, cfg.Insecure, cfg.NoH2C, cfg.UserAgent)
		if err != nil {
			return nil, err
		}
	} else {
		// Callers can bring their own HTTP client, but the User-Agent is always ours
		httpClient = withUserAgent(httpClient, cfg.UserAgent)
	}

	return &Client{
		server:         server,
		requestKey:     cfg.RequestKey,
		httpClient:     httpClient,
		log:            log,
		trustStorePath: cfg.TrustStorePath,
		noTrustStore:   cfg.NoTrustStore,
		confirmAnchor:  cfg.ConfirmAnchor,
	}, nil
}

// Server returns the address of the server the client is configured to use
func (c *Client) Server() string {
	return c.server
}

// Logger returns the logger used by the client
func (c *Client) Logger() *slog.Logger {
	return c.log
}

// userAgentTransport sets the User-Agent header on every outgoing request
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request because RoundTripper must not modify the input
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(r)
}

// withUserAgent returns a copy of the HTTP client whose transport sets the User-Agent header on every request
func withUserAgent(client *http.Client, userAgent string) *http.Client {
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	res := *client
	res.Transport = &userAgentTransport{
		base:      base,
		userAgent: userAgent,
	}

	return &res
}

// NewHTTPClient returns an HTTP client configured for talking to a Revaulter server
func NewHTTPClient(log *slog.Logger, server string, insecure bool, noH2C bool, userAgent string) (*http.Client, error) {
	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	transport := &http2.Transport{
		IdleConnTimeout:  90 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}
	if serverURL.Scheme == "http" && !noH2C {
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
			log.Warn("TLS certificate validation is disabled")
		}
		transport.TLSClientConfig = &tls.Config{
			// #nosec G402 -- option explicitly set by users
			InsecureSkipVerify: true,
		}
	}

	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &userAgentTransport{
			base:      transport,
			userAgent: userAgent,
		},
	}, nil
}

// newRequestKeyHTTPRequest builds an HTTP request for the v2 request endpoints
// The key is sent in the Authorization header
func newRequestKeyHTTPRequest(ctx context.Context, method, server, requestKey, pathSuffix string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, server+"/v2/request/"+pathSuffix, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+requestKey)
	return req, nil
}

// newRequest builds an HTTP request for the v2 request endpoints, authenticated with the client's request key
func (c *Client) newRequest(ctx context.Context, method, pathSuffix string, body io.Reader) (*http.Request, error) {
	return newRequestKeyHTTPRequest(ctx, method, c.server, c.requestKey, pathSuffix, body)
}

// doJSONRequest performs an HTTP request and decodes the JSON response into out
func doJSONRequest(client *http.Client, req *http.Request, out any) error {
	// #nosec G704 -- redirects are disabled on the client and req targets are built from the validated server URL selected by the caller
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

// doJSON performs an HTTP request with the client's HTTP client and decodes the JSON response into out
func (c *Client) doJSON(req *http.Request, out any) error {
	return doJSONRequest(c.httpClient, req, out)
}
