package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewV2TransportKeyPair(t *testing.T) {
	kp, err := newV2TransportKeyPair()
	require.NoError(t, err)
	require.NotNil(t, kp)
	require.NotNil(t, kp.EcdhPrivate)
	require.Equal(t, "EC", kp.EcdhPublic.Kty)
	require.Equal(t, "P-256", kp.EcdhPublic.Crv)
	require.NoError(t, kp.EcdhPublic.ValidatePublic())
	require.NotNil(t, kp.MlkemPrivate)
	require.NotEmpty(t, kp.MlkemPublic)
}
