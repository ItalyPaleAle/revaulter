package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPausableWriter(t *testing.T) {
	t.Run("writes through when not paused", func(t *testing.T) {
		out := &bytes.Buffer{}
		w := newPausableWriter(out)

		_, err := w.Write([]byte("first\n"))
		require.NoError(t, err)
		require.Equal(t, "first\n", out.String())
	})

	t.Run("buffers while paused, and writes out on resume", func(t *testing.T) {
		out := &bytes.Buffer{}
		w := newPausableWriter(out)

		_, err := w.Write([]byte("before\n"))
		require.NoError(t, err)

		w.Pause()
		_, err = w.Write([]byte("during 1\n"))
		require.NoError(t, err)
		_, err = w.Write([]byte("during 2\n"))
		require.NoError(t, err)
		require.Equal(t, "before\n", out.String(), "nothing must be written while paused")

		require.NoError(t, w.Resume())
		require.Equal(t, "before\nduring 1\nduring 2\n", out.String(), "the messages must be written out in order")

		// Writing goes through again after resuming
		_, err = w.Write([]byte("after\n"))
		require.NoError(t, err)
		require.Equal(t, "before\nduring 1\nduring 2\nafter\n", out.String())
	})

	t.Run("resuming without anything buffered is a no-op", func(t *testing.T) {
		out := &bytes.Buffer{}
		w := newPausableWriter(out)

		w.Pause()
		require.NoError(t, w.Resume())
		require.Empty(t, out.String())
	})
}
