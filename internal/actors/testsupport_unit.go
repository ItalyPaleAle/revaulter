//go:build unit

// This file is only built when the "unit" tag is set

package actors

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPeerAddress returns a loopback address with a UDP port that is currently free, for the peer server of a host in tests
func TestPeerAddress(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	err = conn.Close()
	require.NoError(t, err)

	return addr
}

// RunTestHost runs a host in background until the test ends, and returns once it accepts calls
func RunTestHost(t *testing.T, h *Host) {
	t.Helper()

	runCtx, runCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Run(runCtx, nil, nil)
	}()
	t.Cleanup(func() {
		runCancel()
		runErr := <-errCh
		require.NoError(t, runErr)
	})

	select {
	case <-h.Ready():
		// All good
	case runErr := <-errCh:
		t.Fatalf("the host stopped before becoming ready: %v", runErr)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the host to be ready")
	}
}
