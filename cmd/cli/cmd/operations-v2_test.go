package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// testMitmFlags implements noMitmProtectionFlags
type testMitmFlags struct {
	insecure bool
	noTrust  bool
	yes      bool
}

func (f *testMitmFlags) GetConnectionOptions() (bool, bool) {
	return f.insecure, false
}

func (f *testMitmFlags) GetNoTrustStore() bool {
	return f.noTrust
}

func (f *testMitmFlags) GetYesIKnowWhatImDoing() bool {
	return f.yes
}

func TestV2OperationCmdConfirmNoMitmProtection(t *testing.T) {
	t.Run("allows safe flag combinations", func(t *testing.T) {
		err := confirmNoMitmProtection(&testMitmFlags{insecure: true})
		require.NoError(t, err)
	})

	t.Run("requires explicit non-interactive override", func(t *testing.T) {
		err := confirmNoMitmProtection(&testMitmFlags{insecure: true, noTrust: true})
		require.ErrorContains(t, err, "--yes-i-know-what-im-doing")
	})

	t.Run("allows explicit script override", func(t *testing.T) {
		err := confirmNoMitmProtection(&testMitmFlags{insecure: true, noTrust: true, yes: true})
		require.NoError(t, err)
	})
}

func TestFormatV2DecryptedPayload(t *testing.T) {
	t.Run("passes through valid JSON", func(t *testing.T) {
		out, err := formatV2DecryptedPayload("state-1", []byte(`{"ok":true}`))
		require.NoError(t, err)
		require.JSONEq(t, `{"ok":true}`, string(out))
	})

	t.Run("wraps non-JSON payloads", func(t *testing.T) {
		out, err := formatV2DecryptedPayload("state-1", []byte("not json"))
		require.NoError(t, err)
		require.JSONEq(t, `{"data":"bm90IGpzb24"}`, string(out))
	})
}
