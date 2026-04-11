package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	kclock "k8s.io/utils/clock"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

const (
	webhookTimeout       = 20 * time.Second
	retryIntervalSeconds = 20
)

// Webhook client interface
type Webhook interface {
	// SendWebhook sends the notification
	SendWebhook(ctx context.Context, data *WebhookRequest) error
	// SetBaseURL sets the baseURL in the object
	SetBaseURL(val string)
}

// Webhook client
type webhookClient struct {
	httpClient *http.Client
	baseURL    string
	clock      kclock.Clock
}

// NewWebhook creates a new Webhook
func NewWebhook() Webhook {
	return newWebhookWithClock(kclock.RealClock{})
}

// newWebhookWithClock creates a new Webhook with the given clock
func newWebhookWithClock(clock kclock.Clock) Webhook {
	// Build an HTTP transport whose dialer refuses to connect to private or otherwise non-routable IP addresses.
	// net.Dialer.Control is invoked AFTER the OS has resolved the hostname to an IP but BEFORE the connect syscall, which means:
	//   1. it sees the actual IP that would be connected to (no TOCTOU)
	//   2. it runs for every A/AAAA candidate in a multi-address result, so a mixed-public/private DNS response cannot slip through
	//   3. it also catches redirects (we disable auto-following below for good measure, but a custom resolver round would still be blocked)
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid dial address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("dial target %q is not an IP literal", host)
			}
			if isPrivateIP(ip) {
				return fmt.Errorf("refusing to dial private/internal IP %s: SSRF protection", ip)
			}
			return nil
		},
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient := &http.Client{
		Timeout: webhookTimeout,
		// Disable automatic redirect following to prevent SSRF via redirects to internal IPs
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: otelhttp.NewTransport(transport),
	}

	return &webhookClient{
		clock:      clock,
		httpClient: httpClient,
	}
}

// validateWebhookScheme checks that the webhook URL uses an allowed scheme (http/https)
func validateWebhookScheme(webhookUrl string) error {
	parsed, err := url.Parse(webhookUrl)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	// Only allow http and https schemes
	switch parsed.Scheme {
	case "http", "https":
		// OK
		return nil
	default:
		return fmt.Errorf("webhook URL has disallowed scheme %q: only http and https are permitted", parsed.Scheme)
	}
}

// isPrivateIP returns true if the IP is in a private, loopback, link-local, or
// otherwise non-routable range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// SetBaseURL sets the baseURL in the object
func (w *webhookClient) SetBaseURL(val string) {
	w.baseURL = val
}

// SendWebhook sends the notification
func (w *webhookClient) SendWebhook(ctx context.Context, data *WebhookRequest) error {
	cfg := config.Get()
	webhookUrl := cfg.WebhookUrl

	// Validate the webhook URL scheme
	// The custom net.Dialer.Control on the HTTP transport enforces the private-IP block at connect time
	err := validateWebhookScheme(webhookUrl)
	if err != nil {
		return fmt.Errorf("webhook URL validation failed: %w", err)
	}

	// Retry up to 3 times
	const attempts = 3
	var i int
	for i = range attempts {
		var req *http.Request
		reqCtx, reqCancel := context.WithTimeout(ctx, webhookTimeout)
		switch cfg.WebhookFormat {
		case "slack":
			req, err = w.prepareSlackRequest(reqCtx, webhookUrl, data)
		case "discord":
			// Shorthand for using Slack-compatible webhooks with Discord
			if !strings.HasSuffix(webhookUrl, "/slack") {
				webhookUrl += "/slack"
			}
			req, err = w.prepareSlackRequest(reqCtx, webhookUrl, data)
		// case "plain":
		default:
			req, err = w.preparePlainRequest(reqCtx, webhookUrl, data)
		}
		if err != nil {
			reqCancel()
			// This is a permanent error
			return fmt.Errorf("failed to create request: %w", err)
		}

		var res *http.Response
		res, err = w.httpClient.Do(req)
		reqCancel()
		if err != nil {
			// Retry after 15 seconds on network failures, if we have more attempts
			if i < (attempts - 1) {
				logging.LogFromContext(ctx).WarnContext(ctx,
					"Network error sending webhook; will retry after 15 seconds",
					slog.Any("error", err),
				)
				select {
				case <-w.clock.After(15 * time.Second):
					// Nop
				case <-ctx.Done():
					err = ctx.Err()
					break
				}
				continue
			}

			// If we've exhausted the available attempts, break out of the loop right away
			break
		}

		// Drain body before closing
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()

		// Handle retries if we have more attempts
		if i < (attempts - 1) {
			// Handle throttling on 429 responses and on 5xx errors
			if res.StatusCode == http.StatusTooManyRequests {
				retryAfter, _ := strconv.Atoi(res.Header.Get("Retry-After"))
				if retryAfter < 1 || retryAfter > retryIntervalSeconds {
					retryAfter = retryIntervalSeconds
				}
				logging.LogFromContext(ctx).WarnContext(ctx,
					"Webhook throttled; will retry after delay",
					slog.Int("delaySeconds", retryAfter),
				)
				select {
				case <-w.clock.After(time.Duration(retryAfter) * time.Second):
					// Nop
				case <-ctx.Done():
					err = ctx.Err()
					break
				}
				continue
			}

			// Retry after a delay on 408 (Request Timeout) and 5xx errors, which indicate a problem with the server
			if res.StatusCode == http.StatusRequestTimeout || (res.StatusCode >= 500 && res.StatusCode < 600) {
				logging.LogFromContext(ctx).WarnContext(ctx,
					"Webhook returned an error response; will retry after delay",
					slog.Int("code", res.StatusCode),
					slog.Int("delaySeconds", retryIntervalSeconds),
				)
				select {
				case <-w.clock.After(retryIntervalSeconds * time.Second):
					// Nop
				case <-ctx.Done():
					err = ctx.Err()
					break
				}
				continue
			}
		}

		// Any other error is permanent
		if res.StatusCode < 200 || res.StatusCode > 299 {
			err = fmt.Errorf("invalid response status code: %d", res.StatusCode)
			break
		}

		// If we're here, everything is good
		break
	}

	if err != nil {
		err = fmt.Errorf("failed to send webhook after %d attempts; last error: %w", i, err)
	}
	return err
}

func (w *webhookClient) getLink() string {
	if w.baseURL != "" {
		return w.baseURL
	}
	return config.Get().BaseUrl
}

func (w *webhookClient) preparePlainRequest(ctx context.Context, webhookUrl string, data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	message := w.formatPlainMessage(data)

	// Create the request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, webhookUrl, strings.NewReader(message))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")

	webhookKey := config.Get().WebhookKey
	if webhookKey != "" {
		req.Header.Set("Authorization", webhookKey)
	}

	return req, nil
}

func (w *webhookClient) prepareSlackRequest(ctx context.Context, webhookUrl string, data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	message := w.formatSlackMessage(data)

	// Build the body
	buf := &bytes.Buffer{}
	err = json.NewEncoder(buf).Encode(struct {
		Text string `json:"text"`
	}{
		Text: message,
	})
	if err != nil {
		return nil, err
	}

	// Create the request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, webhookUrl, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	webhookKey := config.Get().WebhookKey
	if webhookKey != "" {
		req.Header.Set("Authorization", webhookKey)
	}

	return req, nil
}

type WebhookRequest struct {
	Flow string

	OperationName string
	KeyId         string
	Vault         string

	AssignedUser string
	KeyLabel     string
	Algorithm    string

	StateId   string
	Requestor string
	Note      string
}

func (w *webhookClient) formatPlainMessage(data *WebhookRequest) string {
	var note string
	if data.Note != "" {
		note = "\n\nNote: " + data.Note
	}
	return fmt.Sprintf(
		`Received a request to %s using key label **%s** for user **%s** (algorithm **%s**).

Open Revaulter: %s

(Request ID: %s - Client IP: %s)%s`,
		data.OperationName,
		data.KeyLabel,
		data.AssignedUser,
		data.Algorithm,
		w.getLink(),
		data.StateId,
		data.Requestor,
		note,
	)
}

func (w *webhookClient) formatSlackMessage(data *WebhookRequest) string {
	var note string
	if data.Note != "" {
		note = "Note: *" + data.Note + "*\n"
	}
	return fmt.Sprintf(
		"Received a request to %s using key label **%s** for user **%s** (algorithm **%s**).\n%s[Open Revaulter](%s)\n`(Request ID: %s - Client IP: %s)`",
		data.OperationName,
		data.KeyLabel,
		data.AssignedUser,
		data.Algorithm,
		note,
		w.getLink(),
		data.StateId,
		data.Requestor,
	)
}
