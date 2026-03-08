package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewV2TransportKeyPair(t *testing.T) {
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	require.NotNil(t, kp)
	require.NotNil(t, kp.Private)
	require.Equal(t, "EC", kp.Public.Kty)
	require.Equal(t, "P-256", kp.Public.Crv)
	require.NoError(t, kp.Public.ValidatePublic())
}
