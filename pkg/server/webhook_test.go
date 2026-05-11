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
