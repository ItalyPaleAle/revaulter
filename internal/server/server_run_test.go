package server

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
)

// When the app server can't start, Run must return the error, rather than wait forever for a shutdown that was never scheduled
func TestServerRunReturnsWhenAppServerFailsToStart(t *testing.T) {
	setTestConfig(t, "v2-run-start-error.db")
	srv := newTestServer(t, nil, nil, nil)

	// Occupy a port, so the app server can't listen on it
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = busy.Close()
	})
	busyAddr, ok := busy.Addr().(*net.TCPAddr)
	require.True(t, ok)

	t.Cleanup(config.SetTestConfig(map[string]any{
		"bind": "127.0.0.1",
		"port": busyAddr.Port,
	}))
	srv.appListener = nil

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(t.Context())
	}()

	select {
	case err = <-errCh:
		require.ErrorContains(t, err, "failed to start app server")
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the app server failed to start")
	}
}
