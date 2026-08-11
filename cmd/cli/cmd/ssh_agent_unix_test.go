//go:build unix

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/protocolv2"
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

// newSSHAgentFlagsWithRequired builds an ssh-agent flag set with the required base flags pre-filled so Validate can focus on agent-specific behavior
func newSSHAgentFlagsWithRequired(t *testing.T) *sshAgentFlags {
	t.Helper()
	f := &sshAgentFlags{}
	f.Server = "https://example.invalid"
	f.RequestKey = "rk-test"
	f.KeyLabel = "label-test"
	return f
}

// TestSSHAgentValidateNoteLength pins the client-side note check
// The agent prefixes every note, so the usable budget is MaxNoteLength minus the prefix
func TestSSHAgentValidateNoteLength(t *testing.T) {
	// The require.Len assertion below is the independent check on this budget: it fails if the constant and the note the agent actually builds disagree
	maxUserNote := sshAgentMaxUserNoteLength

	t.Run("accepts a note that exactly fills the budget", func(t *testing.T) {
		f := newSSHAgentFlagsWithRequired(t)
		f.Note = strings.Repeat("n", maxUserNote)
		err := f.Validate()
		require.NoError(t, err)
		require.Len(t, sshAgentSignNote(f.Note), protocolv2.MaxNoteLength)
	})

	t.Run("rejects a note over the budget", func(t *testing.T) {
		f := newSSHAgentFlagsWithRequired(t)
		f.Note = strings.Repeat("n", maxUserNote+1)

		err := f.Validate()
		require.ErrorContains(t, err, "note cannot be longer than")
		require.Greater(t, len(sshAgentSignNote(f.Note)), protocolv2.MaxNoteLength, "the rejected note must actually exceed the server limit")
	})

	t.Run("accepts an empty note", func(t *testing.T) {
		f := newSSHAgentFlagsWithRequired(t)
		err := f.Validate()
		require.NoError(t, err)
	})
}

// shortTempDir returns a temporary directory with a short path
// t.TempDir() embeds the test name, which easily pushes a socket path past the ~104 byte sun_path limit on macOS
//
//nolint:usetesting // t.TempDir() is exactly what produces the over-long path this helper exists to avoid
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rv")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// TestListenAgentSocketPermissions asserts the socket is never world-accessible, even when it lives in a world-traversable directory
// The umask inside listenAgentSocket is what closes the window between net.Listen and the follow-up Chmod
func TestListenAgentSocketPermissions(t *testing.T) {
	// A 0777 parent directory is the case a custom --socket path can produce
	dir := shortTempDir(t)
	err := os.Chmod(dir, 0o777)
	require.NoError(t, err)

	socketPath := filepath.Join(dir, "agent.sock")
	l, err := listenAgentSocket(socketPath)
	require.NoError(t, err)
	defer l.Close()

	st, err := os.Stat(socketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "agent socket must be owner-only")
}

// TestListenAgentSocketRestoresUmask makes sure the temporary umask narrowing does not leak into the rest of the process
func TestListenAgentSocketRestoresUmask(t *testing.T) {
	before := syscall.Umask(0o022)
	syscall.Umask(before)

	socketPath := filepath.Join(shortTempDir(t), "agent.sock")
	l, err := listenAgentSocket(socketPath)
	require.NoError(t, err)
	defer l.Close()

	after := syscall.Umask(0o022)
	syscall.Umask(after)
	require.Equal(t, before, after, "listenAgentSocket must restore the previous umask")
}
