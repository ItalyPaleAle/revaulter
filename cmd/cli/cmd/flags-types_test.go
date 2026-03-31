package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringValueNormalizesBase64ToRawURL(t *testing.T) {
	t.Run("accepts standard base64 input", func(t *testing.T) {
		var v stringValue
		err := (&v).Set("+/8=")
		require.NoError(t, err)
		require.Equal(t, "-_8", v.String())
	})

	t.Run("accepts base64url input", func(t *testing.T) {
		var v stringValue
		err := (&v).Set("-_8")
		require.NoError(t, err)
		require.Equal(t, "-_8", v.String())
	})
}
