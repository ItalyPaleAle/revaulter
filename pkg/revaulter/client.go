package revaulter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// MaxPayloadSize is the maximum size of the plaintext, ciphertext, or additional data that can be sent in a single operation
// The server enforces a 1 MiB limit on the entire request body, which the payload travels in after being encoded and encrypted
const MaxPayloadSize = 100 << 10

// DefaultUserAgent is the value of the User-Agent header sent by clients that don't configure one
var DefaultUserAgent = "RevaulterGo/" + buildinfo.AppVersion

// AnchorInfo describes the anchor a server advertises, as presented to [AnchorConfirmFunc]
type AnchorInfo struct {
	// Server is the address of the server the anchor belongs to
	Server string
	// UserID is the ID of the user the anchor belongs to
	UserID string
	// Fingerprint is the hex-encoded fingerprint of the hybrid anchor public keys
	Fingerprint string
}

// FormatFingerprint returns the anchor's fingerprint formatted for display to a human, in groups of 4 uppercase characters
// The prefixSpaces argument is the number of spaces prepended to each line
func (a AnchorInfo) FormatFingerprint(prefixSpaces int) string {
	return clientcore.FormatFingerprint(a.Fingerprint, prefixSpaces)
}

// AnchorConfirmFunc is invoked on first contact with a server, before its anchor is pinned in the trust store
// Implementations return true to accept the anchor, false to refuse it, or an error to abort the operation
type AnchorConfirmFunc func(anchor AnchorInfo) (bool, error)

// AcceptAnchorOnFirstUse is an [AnchorConfirmFunc] that accepts any anchor presented on first contact
// It makes pinning fully automatic, at the cost of trusting the network on the very first connection to a server - every subsequent connection is still verified against the pin
// Applications that can involve a human in the decision should present [AnchorInfo.Fingerprint] to the user instead
func AcceptAnchorOnFirstUse(_ AnchorInfo) (bool, error) {
	return true, nil
}

// Options is the configuration for a [Client]
type Options struct {
	// Address of the Revaulter server, including the scheme (required)
	Server string
	// Per-user request key used to authenticate with the server (required)
	// Request keys are created in the Revaulter web interface
	RequestKey string

	// Optional pre-configured HTTP client
	// When nil, a HTTP/2-enabled client is created using the Insecure and NoH2C options
	HTTPClient *http.Client
	// Skip TLS certificate validation when connecting to the server
	// This is unsafe outside of local development
	// It is ignored when HTTPClient is set
	Insecure bool
	// Do not attempt connecting with HTTP/2 Cleartext when the server URL is not using TLS
	// Ignored when HTTPClient is set
	NoH2C bool
	// Value of the User-Agent header, defaulting to DefaultUserAgent
	UserAgent string

	// Optional logger
	// When nil, the client does not emit any log
	Logger *slog.Logger

	// Path to the anchor trust store, which is shared with revaulter-cli
	// Defaults to the value of the TRUST_STORE_PATH environment variable, or "revaulter-cli/trust.json" inside the user's config directory
	TrustStorePath string
	// Disable anchor pinning entirely
	// This removes the protection against a malicious server substituting the public keys used by every operation, so it should only be used when the server is trusted through other means
	NoTrustStore bool
	// Callback invoked to accept a server's anchor on first contact
	// When nil, the client fails closed if the server's anchor is not pinned yet
	ConfirmAnchor AnchorConfirmFunc

	// Default timeout for operations that require the user's approval
	// It is sent to the server, which uses it to expire requests the user doesn't approve in time, and it also bounds how long the client waits
	// Individual requests can override this
	// When unset, operations default to 15 minutes
	Timeout time.Duration
	// Default note displayed to the user alongside every request, which individual requests can override
	// Notes are limited to MaxNoteLength characters
	Note string
}

// MaxNoteLength is the maximum length of the note displayed to the user alongside a request
const MaxNoteLength = protocolv2.MaxNoteLength

// Client is a client for a Revaulter server
// Clients are safe for concurrent use by multiple goroutines
type Client struct {
	core    *clientcore.Client
	timeout time.Duration
	note    string
}

// New creates a new [Client] with the given options
func New(opts Options) (*Client, error) {
	err := validateNote(opts.Note)
	if err != nil {
		return nil, err
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	var confirmAnchor clientcore.ConfirmAnchorFunc
	if opts.ConfirmAnchor != nil {
		confirmAnchor = func(server, userID, fingerprint string) (bool, error) {
			return opts.ConfirmAnchor(AnchorInfo{
				Server:      server,
				UserID:      userID,
				Fingerprint: fingerprint,
			})
		}
	}

	core, err := clientcore.NewClient(clientcore.Config{
		Server:         opts.Server,
		RequestKey:     opts.RequestKey,
		HTTPClient:     opts.HTTPClient,
		Insecure:       opts.Insecure,
		NoH2C:          opts.NoH2C,
		UserAgent:      userAgent,
		Logger:         opts.Logger,
		TrustStorePath: opts.TrustStorePath,
		NoTrustStore:   opts.NoTrustStore,
		ConfirmAnchor:  confirmAnchor,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		core:    core,
		timeout: opts.Timeout,
		note:    opts.Note,
	}, nil
}

// Server returns the address of the server the client is configured to use
func (c *Client) Server() string {
	return c.core.Server()
}

// requestOptions carries the per-request settings shared by all operations
type requestOptions struct {
	timeout time.Duration
	note    string
}

// resolve applies the client-level defaults to a request's timeout and note
func (c *Client) resolve(timeout time.Duration, note string) (requestOptions, error) {
	if timeout <= 0 {
		timeout = c.timeout
	}
	if note == "" {
		note = c.note
	}

	err := validateNote(note)
	if err != nil {
		return requestOptions{}, err
	}

	return requestOptions{timeout: timeout, note: note}, nil
}

// validateNote enforces the server's limit on the length of the note, client-side
func validateNote(note string) error {
	if len(note) > protocolv2.MaxNoteLength {
		return fmt.Errorf("note cannot be longer than %d characters (got %d)", protocolv2.MaxNoteLength, len(note))
	}

	return nil
}

// normalizeKeyLabel validates a key label and returns its canonical form
func normalizeKeyLabel(keyLabel string) (string, error) {
	canonical, ok := protocolv2.NormalizeAndValidateKeyLabel(keyLabel)
	if !ok {
		return "", fmt.Errorf("invalid key label: must be 1-%d bytes and contain only [A-Za-z0-9_.+-]", protocolv2.MaxKeyLabelLength)
	}

	return canonical, nil
}

// ensureWithinPayloadLimit rejects oversize inputs before they hit the wire
func ensureWithinPayloadLimit(field string, sizeBytes int) error {
	if sizeBytes > MaxPayloadSize {
		return fmt.Errorf("%s exceeds the maximum allowed size of %d KB (got %.1f KB)", field, MaxPayloadSize>>10, (float64(sizeBytes) / 1024))
	}

	return nil
}

// execute submits an operation and returns the raw payload the browser produced
func (c *Client) execute(ctx context.Context, req clientcore.Request) (*clientcore.Response, error) {
	res, err := c.core.Execute(ctx, req)
	if err != nil {
		return nil, err
	}
	if res == nil || len(res.Payload) == 0 {
		return nil, errors.New("received an empty response from the server")
	}

	return res, nil
}

// DefaultTrustStorePath returns the path of the anchor trust store used when [Options.TrustStorePath] is empty
// It is the value of the TRUST_STORE_PATH environment variable when set, or "revaulter-cli/trust.json" inside the user's config directory
func DefaultTrustStorePath() (string, error) {
	return clientcore.DefaultTrustStorePath()
}
