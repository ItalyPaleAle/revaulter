package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/italypaleale/revaulter/pkg/config"
)

func TestWebhook(t *testing.T) {
	// Set configurations
	defer SetTestConfigs(map[string]any{
		config.KeyWebhookUrl:    "http://test.local/endpoint",
		config.KeyBaseUrl:       "http://test.local/app",
		config.KeyWebhookKey:    "",
		config.KeyWebhookFormat: "",
	})()

	logger := NewAppLogger("test", io.Discard)

	clock := clocktesting.NewFakeClock(time.Now())
	wh := newWebhookWithClock(logger, clock).(*webhookClient) //nolint:forcetypeassert

	// Create a roundtripper that captures the requests
	rtt := &RoundTripperTest{}
	wh.httpClient.Transport = rtt

	getWebhookRequest := func() *WebhookRequest {
		return &WebhookRequest{
			OperationName: "wrap",
			KeyId:         "mykey",
			Vault:         "myvault",
			StateId:       "mystate",
			Requestor:     "127.0.0.1",
		}
	}

	basicTestFn := func(configs map[string]any, assertFn func(t *testing.T, r *http.Request)) func(*testing.T) {
		return func(t *testing.T) {
			if len(configs) > 0 {
				defer SetTestConfigs(configs)()
			}

			reqCh := make(chan *http.Request, 1)
			rtt.SetReqCh(reqCh)

			err := wh.SendWebhook(context.Background(), getWebhookRequest())
			require.NoError(t, err)

			r := <-reqCh
			if r != nil {
				defer r.Body.Close()
				assertFn(t, r)
			}
		}
	}

	t.Run("format plain", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "plain",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, "Received a request to wrap a key using key **mykey** in vault **myvault**.\n\nConfirm request: http://test.local/app\n\n(Request ID: mystate - Client IP: 127.0.0.1)")
	}))

	t.Run("empty format, fallback to plain", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, "Received a request to wrap a key using key **mykey** in vault **myvault**.\n\nConfirm request: http://test.local/app\n\n(Request ID: mystate - Client IP: 127.0.0.1)")
	}))

	t.Run("format slack", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "slack",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to wrap a key using key **mykey** in vault **myvault**.\n[Confirm request](http://test.local/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format discord appends /slack", basicTestFn(map[string]any{
		config.KeyWebhookFormat: "discord",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint/slack", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to wrap a key using key **mykey** in vault **myvault**.\n[Confirm request](http://test.local/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("format discord with /slack already appended", basicTestFn(map[string]any{
		config.KeyWebhookUrl:    "http://my.local/endpoint/slack",
		config.KeyWebhookFormat: "discord",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://my.local/endpoint/slack", r.URL.String())
		requireBodyEqual(t, r.Body, `{"text":"Received a request to wrap a key using key **mykey** in vault **myvault**.\n[Confirm request](http://test.local/app)\n`+"`(Request ID: mystate - Client IP: 127.0.0.1)`"+`"}`+"\n")
	}))

	t.Run("plain request with authorization", basicTestFn(map[string]any{
		config.KeyWebhookKey: "mykey",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		require.Equal(t, "mykey", r.Header.Get("authorization"))
	}))

	t.Run("slack request with authorization", basicTestFn(map[string]any{
		config.KeyWebhookKey:    "mykey",
		config.KeyWebhookFormat: "slack",
	}, func(t *testing.T, r *http.Request) {
		require.Equal(t, "http://test.local/endpoint", r.URL.String())
		require.Equal(t, "mykey", r.Header.Get("authorization"))
	}))

	t.Run("fail on 4xx status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request, 1)
		rtt.SetReqCh(reqCh)
		rtt.responses = make(chan *http.Response, 1)
		rtt.responses <- &http.Response{
			StatusCode: http.StatusForbidden,
		}
		defer func() {
			rtt.responses = nil
		}()

		err := wh.SendWebhook(context.Background(), getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid response status code: 403")

		r := <-reqCh
		r.Body.Close()
	})

	t.Run("retry on 429 status codes without Retry-After header", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		rtt.responses = make(chan *http.Response, 2)
		// Send a 429 status code twice
		rtt.responses <- &http.Response{StatusCode: http.StatusTooManyRequests}
		rtt.responses <- &http.Response{StatusCode: http.StatusTooManyRequests}
		defer func() {
			rtt.responses = nil
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, 30*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.NoError(t, err)

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("retry on 429 status codes respects Retry-After header", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		rtt.responses = make(chan *http.Response, 2)
		makeRes := func() *http.Response {
			res := &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     make(http.Header),
			}
			res.Header.Set("retry-after", "5")
			return res
		}
		// Send a 429 status code twice but with a Retry-After header
		rtt.responses <- makeRes() //nolint:bodyclose
		rtt.responses <- makeRes() //nolint:bodyclose
		defer func() {
			rtt.responses = nil
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		rtt.responses = make(chan *http.Response, 1)
		// Send a 500 status code once
		rtt.responses <- &http.Response{StatusCode: http.StatusInternalServerError}
		defer func() {
			rtt.responses = nil
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 2, 30*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.NoError(t, err)

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("too many failed attempts with 429 status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		rtt.responses = make(chan *http.Response, 3)
		// Send a 429 status code 3 times
		rtt.responses <- &http.Response{StatusCode: http.StatusTooManyRequests}
		rtt.responses <- &http.Response{StatusCode: http.StatusTooManyRequests}
		rtt.responses <- &http.Response{StatusCode: http.StatusTooManyRequests}
		defer func() {
			rtt.responses = nil
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, 30*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid response status code: 429")

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("too many failed attempts with 5xx status codes", func(t *testing.T) {
		reqCh := make(chan *http.Request)
		rtt.SetReqCh(reqCh)
		rtt.responses = make(chan *http.Response, 3)
		// Send a 429 status code 3 times
		rtt.responses <- &http.Response{StatusCode: http.StatusInternalServerError}
		rtt.responses <- &http.Response{StatusCode: http.StatusBadGateway}
		rtt.responses <- &http.Response{StatusCode: http.StatusBadGateway}
		defer func() {
			rtt.responses = nil
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		doneCh := assertRetries(ctx, clock, reqCh, 3, 30*time.Second)

		err := wh.SendWebhook(ctx, getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid response status code: 502")

		// This will receive an error after 3 requests have come in, or the context timed out
		require.NoError(t, <-doneCh)
	})

	t.Run("webhookUrl is invalid", func(t *testing.T) {
		defer SetTestConfigs(map[string]any{
			config.KeyWebhookUrl: "\nnotanurl",
		})()

		err := wh.SendWebhook(context.Background(), getWebhookRequest())
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to create request")
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
		for i := 0; i < expectRequests; i++ {
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
				for i := 0; i < 20; i++ {
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
