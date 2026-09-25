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
	"github.com/italypaleale/revaulter/internal/protocolv2"
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
	// Static request key used to authenticate with the server, sent with the RequestKey authentication scheme
	// Exactly one of RequestKey, OIDCToken, and OIDCTokenProvider must be set
	RequestKey string
	// JWT signed by one of the user's trusted OIDC issuers, sent with the Bearer authentication scheme
	// Exactly one of RequestKey, OIDCToken, and OIDCTokenProvider must be set, and OIDCToken requires UserID
	OIDCToken string
	// Function that returns a JWT signed by one of the user's trusted OIDC issuers, sent with the Bearer authentication scheme
	// It's invoked every time a request needs the credential, so it can return a fresh token when the previous one expires
	// Exactly one of RequestKey, OIDCToken, and OIDCTokenProvider must be set, and OIDCTokenProvider requires UserID
	OIDCTokenProvider func(ctx context.Context) string
	// ID of the user the requests are for
	// It's required with OIDC tokens, and optional with RequestKey; when set, the server checks that it matches the user the credential belongs to
	UserID string

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
	server        string
	authorization func(ctx context.Context) (string, error)
	userID        string
	httpClient    *http.Client
	log           *slog.Logger

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

	authorization, err := credentialAuthorization(cfg)
	if err != nil {
		return nil, err
	}

	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
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
		authorization:  authorization,
		userID:         cfg.UserID,
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

// credentialAuthorization validates the credential in cfg, and returns a function that returns the value of the Authorization header that carries it
func credentialAuthorization(cfg Config) (func(ctx context.Context) (string, error), error) {
	// Exactly one credential must be set
	var set int
	if cfg.RequestKey != "" {
		set++
	}
	if cfg.OIDCToken != "" {
		set++
	}
	if cfg.OIDCTokenProvider != nil {
		set++
	}
	switch {
	case set == 0:
		return nil, errors.New("one of the properties RequestKey, OIDCToken, or OIDCTokenProvider is required")
	case set > 1:
		return nil, errors.New("properties RequestKey, OIDCToken, and OIDCTokenProvider are mutually exclusive")
	case cfg.RequestKey == "" && cfg.UserID == "":
		return nil, errors.New("property UserID is required with OIDC tokens")
	}

	switch {
	case cfg.RequestKey != "":
		if protocolv2.LooksLikeJWT(cfg.RequestKey) {
			return nil, errors.New("property RequestKey contains a JWT: pass OIDC tokens in the OIDCToken property")
		}
		authorization := protocolv2.AuthSchemeRequestKey + " " + cfg.RequestKey
		return func(context.Context) (string, error) {
			return authorization, nil
		}, nil

	case cfg.OIDCToken != "":
		if !protocolv2.LooksLikeJWT(cfg.OIDCToken) {
			return nil, errors.New("property OIDCToken does not contain a JWT")
		}
		authorization := protocolv2.AuthSchemeBearer + " " + cfg.OIDCToken
		return func(context.Context) (string, error) {
			return authorization, nil
		}, nil

	default:
		provider := cfg.OIDCTokenProvider
		return func(ctx context.Context) (string, error) {
			token := provider(ctx)
			if token == "" {
				return "", errors.New("the OIDC token provider returned an empty token")
			}
			if !protocolv2.LooksLikeJWT(token) {
				return "", errors.New("the OIDC token provider returned a value that is not a JWT")
			}
			return protocolv2.AuthSchemeBearer + " " + token, nil
		}, nil
	}
}

// newRequestWithAuthorization builds an HTTP request for the v2 request endpoints
// The authorization is sent in the Authorization header, and the user ID, when configured, in the X-Revaulter-User header
func (c *Client) newRequestWithAuthorization(ctx context.Context, method, authorization, pathSuffix string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.server+"/v2/request/"+pathSuffix, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", authorization)
	if c.userID != "" {
		req.Header.Set(protocolv2.UserIDHeader, c.userID)
	}

	return req, nil
}

// newRequest builds an HTTP request for the v2 request endpoints, authenticated with the client's credential
func (c *Client) newRequest(ctx context.Context, method, pathSuffix string, body io.Reader) (*http.Request, error) {
	authorization, err := c.authorization(ctx)
	if err != nil {
		return nil, err
	}

	return c.newRequestWithAuthorization(ctx, method, authorization, pathSuffix, body)
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
