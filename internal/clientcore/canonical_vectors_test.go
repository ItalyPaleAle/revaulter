package clientcore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/testdata"
)

// TestCanonicalAadVectorsMatchGoImplementation asserts the shared AAD vectors against the client implementation
// The AAD builders live in this package rather than in protocolv2, so the AAD sections of the shared vectors are asserted here while the rest are asserted in internal/protocolv2/canonical_vectors_test.go
// These bytes are bound into the AES-GCM tag on both sides, so a browser/client mismatch shows up as an authentication failure at decrypt time rather than as anything that points at the real cause
func TestCanonicalAadVectorsMatchGoImplementation(t *testing.T) {
	v, err := testdata.LoadCanonicalVectors()
	require.NoError(t, err)

	t.Run("transportAad", func(t *testing.T) {
		require.NotEmpty(t, v.TransportAad)
		for _, tc := range v.TransportAad {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.Aad, string(BuildTransportAAD(tc.State, tc.Operation, tc.Algorithm)))
			})
		}
	})

	t.Run("requestEncAad", func(t *testing.T) {
		require.NotEmpty(t, v.RequestEncAad)
		for _, tc := range v.RequestEncAad {
			t.Run(tc.Name, func(t *testing.T) {
				require.Equal(t, tc.Aad, string(BuildRequestEncAAD(tc.Algorithm, tc.KeyLabel, tc.Operation)))
			})
		}
	})
}
