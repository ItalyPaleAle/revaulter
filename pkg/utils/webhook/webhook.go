package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	kclock "k8s.io/utils/clock"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/rs/zerolog"
)

const (
	webhookTimeout       = 20 * time.Second
	retryIntervalSeconds = 20
)

// Interface for webhook clients
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
	return &webhookClient{
		clock: clock,
		httpClient: &http.Client{
			Timeout: webhookTimeout,
		},
	}
}

// SetBaseURL sets the baseURL in the object
func (w *webhookClient) SetBaseURL(val string) {
	w.baseURL = val
}

// SendWebhook sends the notification
func (w *webhookClient) SendWebhook(ctx context.Context, data *WebhookRequest) (err error) {
	cfg := config.Get()

	webhookUrl := cfg.WebhookUrl

	// Retry up to 3 times
	const attempts = 3
	for i := 0; i < attempts; i++ {
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
				zerolog.Ctx(ctx).Warn().
					Err(err).
					Msg("Network error sending webhook; will retry after 15 seconds")
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
				zerolog.Ctx(ctx).Warn().Msgf("Webhook throttled; will retry after %d seconds", retryAfter)
				select {
				case <-w.clock.After(time.Duration(retryAfter) * time.Second):
					// Nop
				case <-ctx.Done():
					err = ctx.Err()
					break
				}
				continue
			}

			// Retry after a delay on 5xx errors, which indicate a problem with the server
			if res.StatusCode >= 500 && res.StatusCode < 600 {
				zerolog.Ctx(ctx).Warn().Msgf("Webhook returned an error response: %d; will retry after %d seconds", res.StatusCode, retryIntervalSeconds)
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
		err = fmt.Errorf("failed to send webhook after %d attempts; last error: %w", attempts, err)
	}
	return err
}

func (w *webhookClient) getLink(data *WebhookRequest) string {
	if w.baseURL != "" {
		return w.baseURL
	}
	return config.Get().BaseUrl
}

func (w *webhookClient) preparePlainRequest(ctx context.Context, webhookUrl string, data *WebhookRequest) (req *http.Request, err error) {
	// Format the message
	message := fmt.Sprintf(
		`Received a request to %s a key using key **%s** in vault **%s**.

Confirm request: %s

(Request ID: %s - Client IP: %s)`,
		data.OperationName,
		data.KeyId,
		data.Vault,
		w.getLink(data),
		data.StateId,
		data.Requestor,
	)

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
	var note string
	if data.Note != "" {
		note = "Note: *" + data.Note + "*\n"
	}
	message := fmt.Sprintf(
		"Received a request to %s a key using key **%s** in vault **%s**.\n%s[Confirm request](%s)\n`(Request ID: %s - Client IP: %s)`",
		data.OperationName,
		data.KeyId,
		data.Vault,
		note,
		w.getLink(data),
		data.StateId,
		data.Requestor,
	)

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
	OperationName string
	KeyId         string
	Vault         string
	StateId       string
	Requestor     string
	Note          string
}
