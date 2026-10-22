package main

import (
	"log/slog"

	"github.com/italypaleale/go-kit/webhook"

	"github.com/italypaleale/revaulter/internal/config"
)

// webhookOpts returns the options for the webhook client from the configuration
func webhookOpts(conf *config.Config, log *slog.Logger) webhook.NewWebhookOpts {
	return webhook.NewWebhookOpts{
		URL:             conf.WebhookUrl,
		Key:             conf.WebhookKey,
		Format:          webhook.WebhookFormat(conf.WebhookFormat),
		Logger:          log,
		AllowPrivateIPs: conf.WebhookAllowPrivateAddresses,
	}
}
