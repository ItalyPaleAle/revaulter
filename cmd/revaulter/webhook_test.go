package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/italypaleale/go-kit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
)

func TestWebhookOpts(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	t.Run("maps the configuration", func(t *testing.T) {
		conf := &config.Config{
			WebhookUrl:    "https://example.com/hook",
			WebhookKey:    "Bearer abc",
			WebhookFormat: "slack",
		}

		opts := webhookOpts(conf, log)
		assert.Equal(t, "https://example.com/hook", opts.URL)
		assert.Equal(t, "Bearer abc", opts.Key)
		assert.Equal(t, webhook.FormatSlack, opts.Format)
		assert.Same(t, log, opts.Logger)
		assert.False(t, opts.AllowPrivateIPs)
	})

	t.Run("allows private addresses only when enabled", func(t *testing.T) {
		conf := &config.Config{WebhookAllowPrivateAddresses: true}

		opts := webhookOpts(conf, log)
		assert.True(t, opts.AllowPrivateIPs)
	})
}

func TestWebhookPrivateDestination(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	// The test server listens on loopback, which is a private destination
	received := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	send := func(t *testing.T, allowPrivate bool) error {
		t.Helper()

		conf := &config.Config{
			WebhookUrl:                   srv.URL,
			WebhookFormat:                "plain",
			WebhookAllowPrivateAddresses: allowPrivate,
		}
		opts := webhookOpts(conf, log)

		// A single attempt keeps the refused case fast
		opts.MaxAttempts = 1

		whc, err := webhook.NewWebhook(opts)
		require.NoError(t, err)

		return whc.SendWebhook(t.Context(), webhook.StringMessage("approval required"))
	}

	t.Run("refused by default", func(t *testing.T) {
		err := send(t, false)
		require.Error(t, err)
		assert.Empty(t, received)
	})

	t.Run("delivered when allowed", func(t *testing.T) {
		err := send(t, true)
		require.NoError(t, err)
		assert.Equal(t, "approval required", <-received)
	})
}
