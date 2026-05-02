//go:build unit && unix

package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShellQuoteEscapesSingleQuotes(t *testing.T) {
	got := shellQuote("/tmp/revaulter agent/alice's key.sock")
	require.Equal(t, "'/tmp/revaulter agent/alice'\\''s key.sock'", got)
}

func TestSSHAgentSignNote(t *testing.T) {
	require.Equal(t, "SSH auth", sshAgentSignNote(""))
	require.Equal(t, "SSH auth prod.example.com", sshAgentSignNote("prod.example.com"))
}

func TestSSHAgentOperationContextCancelsOnShutdown(t *testing.T) {
	shutdown := make(chan struct{})
	a := &revaulterSSHAgent{shutdown: shutdown}

	ctx, cancel := a.operationContext(time.Hour)
	defer cancel()

	close(shutdown)

	select {
	case <-ctx.Done():
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("operation context was not cancelled by shutdown")
	}
}
