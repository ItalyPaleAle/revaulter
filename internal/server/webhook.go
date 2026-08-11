package server

import (
	"fmt"
	"strings"

	"github.com/italypaleale/go-kit/webhook"
)

type webhookRequest struct {
	BaseURL string

	OperationName string
	KeyId         string
	Vault         string

	AssignedUser string
	KeyLabel     string
	Algorithm    string

	Requestor string
	Note      string
}

func (wr *webhookRequest) GetPlainMessage() (string, error) {
	var note string
	if wr.Note != "" {
		note = "\n\nNote: " + wr.Note
	}
	res := fmt.Sprintf(
		`Received a request to %s using key label **%s** for user **%s**.

Open Revaulter: %s

(Client IP: %s)%s`,
		wr.OperationName,
		wr.KeyLabel,
		wr.AssignedUser,
		wr.BaseURL,
		wr.Requestor,
		note,
	)
	return res, nil
}

func (wr *webhookRequest) GetSlackMessage() (webhook.SlackMessage, error) {
	var note string
	if wr.Note != "" {
		note = "Note: *" + escapeSlackText(wr.Note) + "*\n"
	}

	text := fmt.Sprintf(
		"Received a request to %s using key label **%s** for user **%s**.\n%s[Open Revaulter](%s)\n`(Client IP: %s)`",
		escapeSlackText(wr.OperationName),
		escapeSlackText(wr.KeyLabel),
		escapeSlackText(wr.AssignedUser),
		note,
		wr.BaseURL,
		escapeSlackText(wr.Requestor),
	)
	return webhook.SlackMessage{
		Text: text,
	}, nil
}

// escapeSlackText escapes the small set of mrkdwn/meta characters we interpolate
// This prevents user-controlled fields such as key labels and notes from changing how the webhook message renders
func escapeSlackText(v string) string {
	if v == "" {
		return ""
	}

	// Slack and Discord Slack-compatible webhooks treat &, <, and > as HTML entities
	// The remaining characters are escaped so user-controlled text cannot inject emphasis, strike-through, or code spans
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"*", "\\*",
		"_", "\\_",
		"~", "\\~",
		"`", "\\`",
	)
	return replacer.Replace(v)
}
