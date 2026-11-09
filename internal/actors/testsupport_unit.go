//go:build unit

// This file is only built when the "unit" tag is set

package actors

import (
	"net"
	"testing"

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
