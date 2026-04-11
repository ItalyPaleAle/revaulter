package webhook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/testutils"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

func TestWebhook(t *testing.T) {
	// Set configurations
	t.Cleanup(config.SetTestConfig(map[string]any{
		"webhookUrl":    "http://198.51.100.10/endpoint",
		"baseUrl":       "http://198.51.100.10/app",
		"webhookKey":    "",
		"webhookFormat": "",
	}))

	ctx := logging.LogToContext(t.Context(), slog.New(slog.DiscardHandler))

	clock := clocktesting.NewFakeClock(time.Now())
	wh := newWebhookWithClock(clock).(*webhookClient) //nolint:forcetypeassert

	// Create a roundtripper that captures the requests
	rtt := &testutils.RoundTripperTest{}
	wh.httpClient.Transport = rtt

	getWebhookRequest := func() *WebhookRequest {
		return &WebhookRequest{
			OperationName: "encrypt",
			AssignedUser:  "Alice",
			KeyLabel:      "mykey",
			Algorithm:     "aes-gcm-256",
			StateId:       "mystate",
			Requestor:     "127.0.0.1",
		}
	}

	basicTestFn := func(configs map[string]any, assertFn func(t *testing.T, r *http.Request)) func(*testing.T) {
		return func(t *testing.T) {
			if len(configs) > 0 {
				t.Cleanup(config.SetTestConfig(configs))
			}

			reqCh := make(chan *http.Request, 1)
			rtt.SetReqCh(reqCh)

			err := wh.SendWebhook(ctx, getWebhookRequest())
			require.NoError(t, err)

			r := <-reqCh
			if r != nil {
				defer r.Body.Close()
				assertFn(t, r)
			}
		}
	}

	t.Run("format plain", basicTestFn(map[string]any{
		"webhookFormat": "plain",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, "Received a request to encrypt using key label **mykey** for user **Alice** (algorithm **aes-gcm-256**).\n\nOpen Revaulter: http://198.51.100.10/app\n\n(Request ID: mystate - Client IP: 127.0.0.1)")
	}))

	t.Run("empty format, fallback to plain", basicTestFn(map[string]any{
		"webhookFormat": "",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, "Received a request to encrypt using key label **mykey** for user **Alice** (algorithm **aes-gcm-256**).\n\nOpen Revaulter: http://198.51.100.10/app\n\n(Request ID: mystate - Client IP: 127.0.0.1)")
	}))

	t.Run("format slack", basicTestFn(map[string]any{
		"webhookFormat": "slack",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to encrypt using key label **mykey** for user **Alice** (algorithm **aes-gcm-256**).\n[Open Revaulter](http://198.51.100.10/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format discord appends /slack", basicTestFn(map[string]any{
		"webhookFormat": "discord",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint/slack", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to encrypt using key label **mykey** for user **Alice** (algorithm **aes-gcm-256**).\n[Open Revaulter](http://198.51.100.10/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format discord with /slack already appended", basicTestFn(map[string]any{
		"webhookUrl":    "http://203.0.113.10/endpoint/slack",
		"webhookFormat": "discord",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://203.0.113.10/endpoint/slack", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to encrypt using key label **mykey** for user **Alice** (algorithm **aes-gcm-256**).\n[Open Revaulter](http://198.51.100.10/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format slack escapes user-controlled markdown", basicTestFn(map[string]any{
		"webhookFormat": "slack",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to encrypt using key label **my\\*key\\_\\`+"`"+`demo\\~\\u0026lt;tag\\u0026gt;** for user **Alice \\u0026 Bob** (algorithm **aes\\-gcm\\-256**).\nNote: *pay\\_load \\*bold\\* \\`+"`"+`code\\`+"`"+`*\n[Open Revaulter](http://198.51.100.10/app)\n`+"`(Request ID: state\\:1 - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("plain request with authorization", basicTestFn(map[string]any{
		"webhookKey": "mykey",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint", r.URL.String())
		require.Equal(t, "mykey", r.Header.Get("Authorization"))
	}))

	t.Run("slack request with authorization", basicTestFn(map[string]any{
		"webhookKey":    "mykey",
		"webhookFormat": "slack",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://198.51.100.10/endpoint", r.URL.String())
		require.Equal(t, "mykey", r.Header.Get("Authorization"))
	}))

	t.Run("fail on 4xx status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request, 1)
		rtt.SetReqCh(reqCh)
		resCh := make(chan *http.Response, 1)
		rtt.SetResponsesCh(resCh)
		resCh <- &http.Response{
			StatusCode: http.StatusForbidden,
		}
		defer func() {
			resCh = nil
		}()

		err := wh.SendWebhook(t.Context(), getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid response status code: 403")

		r := <-reqCh
		r.Body.Close()
	})

	t.Run("retry on 429 status codes without Retry-After header", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		resCh := make(chan *http.Response, 2)
		rtt.SetResponsesCh(resCh)
		// Send a 429 status code twice
		resCh <- &http.Response{StatusCode: http.StatusTooManyRequests}
		resCh <- &http.Response{StatusCode: http.StatusTooManyRequests}
		defer func() {
			resCh = nil
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, retryIntervalSeconds*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.NoError(t, err)

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("retry on 429 status codes respects Retry-After header", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		resCh := make(chan *http.Response, 2)
		rtt.SetResponsesCh(resCh)
		makeRes := func() *http.Response {
			res := &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     make(http.Header),
			}
			res.Header.Set("Retry-After", "5")
			return res
		}
		// Send a 429 status code twice but with a Retry-After header
		resCh <- makeRes() //nolint:bodyclose
		resCh <- makeRes() //nolint:bodyclose
		defer func() {
			resCh = nil
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, 5*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.NoError(t, err)

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("retry on 5xx status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		resCh := make(chan *http.Response, 1)
		rtt.SetResponsesCh(resCh)
		// Send a 500 status code once
		resCh <- &http.Response{StatusCode: http.StatusInternalServerError}
		defer func() {
			resCh = nil
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 2, retryIntervalSeconds*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.NoError(t, err)

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("too many failed attempts with 429 status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		resCh := make(chan *http.Response, 3)
		rtt.SetResponsesCh(resCh)
		// Send a 429 status code 3 times
		resCh <- &http.Response{StatusCode: http.StatusTooManyRequests}
		resCh <- &http.Response{StatusCode: http.StatusTooManyRequests}
		resCh <- &http.Response{StatusCode: http.StatusTooManyRequests}
		defer func() {
			resCh = nil
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, retryIntervalSeconds*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid response status code: 429")

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("too many failed attempts with 5xx status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		resCh := make(chan *http.Response, 3)
		rtt.SetResponsesCh(resCh)
		// Send a 429 status code 3 times
		resCh <- &http.Response{StatusCode: http.StatusInternalServerError}
		resCh <- &http.Response{StatusCode: http.StatusBadGateway}
		resCh <- &http.Response{StatusCode: http.StatusBadGateway}
		defer func() {
			resCh = nil
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, retryIntervalSeconds*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid response status code: 502")

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("webhookUrl is invalid", func(t *testing.T) {
		defer config.SetTestConfig(map[string]any{
			"webhookUrl": "\nnotanurl",
		})()

		err := wh.SendWebhook(t.Context(), getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "webhook URL validation failed")
	})
}

func requireBodyEqual(t *testing.T, body io.ReadCloser, expect string) {
	t.Helper()

	read, err := io.ReadAll(body)
	require.NoError(t, err, "failed to read body")

	require.Equal(t, expect, string(read))
}

// Asserts that the code retries the desired number of times
func assertRetries(
	ctx context.Context, clock *clocktesting.FakeClock, reqCh <-chan *http.Request,
	expectRequests int, retryDuration time.Duration,
) <-chan error {
	// We'll return this channel that resolves with nil when everything goes well
	doneCh := make(chan error)

	// Perform the waiting in background
	go func() {
		// Expect this to receive expectRequests requests
		for i := range expectRequests {
			select {
			case r := <-reqCh:
				r.Body.Close()
			case <-ctx.Done():
				doneCh <- ctx.Err()
				return
			}

			if i < (expectRequests - 1) {
				// Sleep until we have a goroutine waiting or we wait too much (1s)
				// This is not ideal as we're depending on a wall clock but it's probably enough for now
				for range 20 {
					if !clock.HasWaiters() {
						time.Sleep(50 * time.Millisecond)
					}
				}

				// By now there should be waiters
				if !clock.HasWaiters() {
					doneCh <- errors.New("no waiters on clock")
					return
				}

				// Assert that the code sleeps for retryDuration
				start := clock.Now()
				err := stepUntilWaiters(clock, time.Second, retryDuration)
				if err != nil {
					doneCh <- err
					return
				}
				if clock.Now().Sub(start) < retryDuration {
					doneCh <- fmt.Errorf("waited less than %v", retryDuration)
					return
				}
			}
		}
		doneCh <- nil
	}()

	return doneCh
}

func stepUntilWaiters(clock *clocktesting.FakeClock, step time.Duration, max time.Duration) error {
	start := clock.Now()
	for clock.HasWaiters() {
		clock.Step(step)
		if clock.Now().Sub(start) > max {
			return fmt.Errorf("clock still has waiters after %d", clock.Now().Sub(start))
		}
	}
	return nil
}
