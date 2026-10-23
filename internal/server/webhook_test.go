package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/italypaleale/go-kit/webhook"
	"github.com/stretchr/testify/require"
)

func TestWebhookRequestFormatting(t *testing.T) {
	baseRequest := func() *webhookRequest {
		return &webhookRequest{
			BaseURL:       "http://198.51.100.10/app",
			OperationName: "encrypt",
			AssignedUser:  "Alice",
			KeyLabel:      "mykey",
			Algorithm:     "A256GCM",
			Requestor:     "127.0.0.1",
		}
	}

	t.Run("format plain", func(t *testing.T) {
		msg, err := baseRequest().GetPlainMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label **mykey** for user **Alice**.\n\nOpen Revaulter: http://198.51.100.10/app\n\n(Client IP: 127.0.0.1)", msg)
	})

	t.Run("format slack", func(t *testing.T) {
		msg, err := baseRequest().GetSlackMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label **mykey** for user **Alice**.\n[Open Revaulter](http://198.51.100.10/app)\n`(Client IP: 127.0.0.1)`", msg.Text)
		require.JSONEq(t, "{\"text\":\"Received a request to encrypt using key label **mykey** for user **Alice**.\\n[Open Revaulter](http://198.51.100.10/app)\\n`(Client IP: 127.0.0.1)`\"}\n", encodeSlackMessage(t, msg))
	})

	t.Run("format ntfy", func(t *testing.T) {
		req := baseRequest()
		req.Note = "pay_load"

		msg, err := req.GetNtfyMessage()
		require.NoError(t, err)
		require.Equal(t, webhook.NtfyMessage{
			Title:   "Revaulter request",
			Message: "Received a request to encrypt using key label mykey for user Alice.\n\nNote: pay_load\n\n(Client IP: 127.0.0.1)",
			Tags:    []string{"key"},
			Click:   "http://198.51.100.10/app",
		}, msg)
	})

	t.Run("format telegram", func(t *testing.T) {
		msg, err := baseRequest().GetTelegramMessage()
		require.NoError(t, err)
		require.Equal(t, webhook.TelegramMessage{
			Text:               "Received a request to encrypt using key label <b>mykey</b> for user <b>Alice</b>.\n<a href=\"http://198.51.100.10/app\">Open Revaulter</a>\n<code>(Client IP: 127.0.0.1)</code>",
			ParseMode:          webhook.TelegramParseModeHTML,
			DisableLinkPreview: true,
		}, msg)
	})

	t.Run("format googlechat", func(t *testing.T) {
		msg, err := baseRequest().GetGoogleChatMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label *mykey* for user *Alice*.\n<http://198.51.100.10/app|Open Revaulter>\n`(Client IP: 127.0.0.1)`", msg.Text)
		require.Empty(t, msg.ThreadKey)
	})

	t.Run("format teams", func(t *testing.T) {
		msg, err := baseRequest().GetTeamsMessage()
		require.NoError(t, err)
		require.Equal(t, webhook.TeamsMessage{
			Title: "Revaulter request",
			Text:  "Received a request to encrypt using key label **mykey** for user **Alice**.\n\n[Open Revaulter](http://198.51.100.10/app)\n\n(Client IP: 127.0.0.1)",
		}, msg)
	})

	t.Run("format slack escapes user-controlled markdown", func(t *testing.T) {
		escaped := &webhookRequest{
			BaseURL:       "http://198.51.100.10/app",
			OperationName: "encrypt",
			AssignedUser:  "Alice & Bob",
			KeyLabel:      "my*key_`demo~<tag>",
			Algorithm:     "A256GCM",
			Requestor:     "127.0.0.1",
			Note:          "pay_load *bold* `code`",
		}

		msg, err := escaped.GetSlackMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label **my\\*key\\_\\`demo\\~&lt;tag&gt;** for user **Alice &amp; Bob**.\nNote: *pay\\_load \\*bold\\* \\`code\\`*\n[Open Revaulter](http://198.51.100.10/app)\n`(Client IP: 127.0.0.1)`", msg.Text)

		var payload struct {
			Text string `json:"text"`
		}
		err = json.Unmarshal([]byte(encodeSlackMessage(t, msg)), &payload)
		require.NoError(t, err)
		require.Equal(t, msg.Text, payload.Text)
	})

	escaped := func() *webhookRequest {
		return &webhookRequest{
			BaseURL:       "http://198.51.100.10/app",
			OperationName: "encrypt",
			AssignedUser:  "<users/all> & [Bob](https://example.com)",
			KeyLabel:      "my_key",
			Algorithm:     "A256GCM",
			Requestor:     "127.0.0.1",
			Note:          "pay_load",
		}
	}

	t.Run("format telegram escapes user-controlled HTML", func(t *testing.T) {
		msg, err := escaped().GetTelegramMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label <b>my_key</b> for user <b>&lt;users/all&gt; &amp; [Bob](https://example.com)</b>.\nNote: <b>pay_load</b>\n<a href=\"http://198.51.100.10/app\">Open Revaulter</a>\n<code>(Client IP: 127.0.0.1)</code>", msg.Text)
	})

	t.Run("format googlechat escapes user-controlled links and mentions", func(t *testing.T) {
		msg, err := escaped().GetGoogleChatMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label *my_key* for user *&lt;users/all&gt; & [Bob](https://example.com)*.\nNote: *pay_load*\n<http://198.51.100.10/app|Open Revaulter>\n`(Client IP: 127.0.0.1)`", msg.Text)
	})

	t.Run("format teams escapes user-controlled links", func(t *testing.T) {
		msg, err := escaped().GetTeamsMessage()
		require.NoError(t, err)
		require.Equal(t, "Received a request to encrypt using key label **my_key** for user **<users/all> & \\[Bob\\](https://example.com)**.\n\nNote: **pay_load**\n\n[Open Revaulter](http://198.51.100.10/app)\n\n(Client IP: 127.0.0.1)", msg.Text)
	})
}

func encodeSlackMessage(t *testing.T, msg webhook.SlackMessage) string {
	t.Helper()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(msg)
	require.NoError(t, err)

	return buf.String()
}
