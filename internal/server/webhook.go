package server

import (
	"fmt"
	"html"
	"strings"

	"github.com/italypaleale/go-kit/webhook"
)

// webhookTitle is the title of the notification, for the formats that support one
const webhookTitle = "Revaulter request"

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

// GetNtfyMessage returns the message for ntfy
// ntfy shows the body as plain text, so it does not include any formatting, and clicking the notification opens Revaulter
func (wr *webhookRequest) GetNtfyMessage() (webhook.NtfyMessage, error) {
	var note string
	if wr.Note != "" {
		note = "\n\nNote: " + wr.Note
	}

	msg := fmt.Sprintf(
		"Received a request to %s using key label %s for user %s.%s\n\n(Client IP: %s)",
		wr.OperationName,
		wr.KeyLabel,
		wr.AssignedUser,
		note,
		wr.Requestor,
	)
	return webhook.NtfyMessage{
		Title:   webhookTitle,
		Message: msg,
		Tags:    []string{"key"},
		Click:   wr.BaseURL,
	}, nil
}

// GetTelegramMessage returns the message for Telegram, formatted as HTML
func (wr *webhookRequest) GetTelegramMessage() (webhook.TelegramMessage, error) {
	var note string
	if wr.Note != "" {
		note = "Note: <b>" + html.EscapeString(wr.Note) + "</b>\n"
	}

	text := fmt.Sprintf(
		"Received a request to %s using key label <b>%s</b> for user <b>%s</b>.\n%s<a href=\"%s\">Open Revaulter</a>\n<code>(Client IP: %s)</code>",
		html.EscapeString(wr.OperationName),
		html.EscapeString(wr.KeyLabel),
		html.EscapeString(wr.AssignedUser),
		note,
		html.EscapeString(wr.BaseURL),
		html.EscapeString(wr.Requestor),
	)
	return webhook.TelegramMessage{
		Text:               text,
		ParseMode:          webhook.TelegramParseModeHTML,
		DisableLinkPreview: true,
	}, nil
}

// GetGoogleChatMessage returns the message for Google Chat, using the Google Chat formatting syntax
func (wr *webhookRequest) GetGoogleChatMessage() (webhook.GoogleChatMessage, error) {
	var note string
	if wr.Note != "" {
		note = "Note: *" + escapeGoogleChatText(wr.Note) + "*\n"
	}

	text := fmt.Sprintf(
		"Received a request to %s using key label *%s* for user *%s*.\n%s<%s|Open Revaulter>\n`(Client IP: %s)`",
		escapeGoogleChatText(wr.OperationName),
		escapeGoogleChatText(wr.KeyLabel),
		escapeGoogleChatText(wr.AssignedUser),
		note,
		wr.BaseURL,
		escapeGoogleChatText(wr.Requestor),
	)
	return webhook.GoogleChatMessage{
		Text: text,
	}, nil
}

// GetTeamsMessage returns the message for Microsoft Teams, using the Markdown subset supported by Adaptive Cards
func (wr *webhookRequest) GetTeamsMessage() (webhook.TeamsMessage, error) {
	var note string
	if wr.Note != "" {
		note = "\n\nNote: **" + escapeTeamsText(wr.Note) + "**"
	}

	text := fmt.Sprintf(
		"Received a request to %s using key label **%s** for user **%s**.%s\n\n[Open Revaulter](%s)\n\n(Client IP: %s)",
		escapeTeamsText(wr.OperationName),
		escapeTeamsText(wr.KeyLabel),
		escapeTeamsText(wr.AssignedUser),
		note,
		wr.BaseURL,
		escapeTeamsText(wr.Requestor),
	)
	return webhook.TeamsMessage{
		Title: webhookTitle,
		Text:  text,
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

// escapeGoogleChatText escapes the angle brackets in text we interpolate in Google Chat messages
// This prevents user-controlled fields such as display names from adding links or mentions, like "<users/all>"
func escapeGoogleChatText(v string) string {
	if v == "" {
		return ""
	}

	// Google Chat does not document how to escape characters in text messages, so angle brackets are replaced with HTML entities, which cannot start a link or a mention even if they are shown as-is
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
	)
	return replacer.Replace(v)
}

// escapeTeamsText escapes the square brackets in text we interpolate in Microsoft Teams messages
// This prevents user-controlled fields such as display names from adding links
// Other Markdown characters are not escaped because some Teams clients, such as the mobile apps, show the backslashes in front of them
func escapeTeamsText(v string) string {
	if v == "" {
		return ""
	}

	replacer := strings.NewReplacer(
		"[", "\\[",
		"]", "\\]",
	)
	return replacer.Replace(v)
}
