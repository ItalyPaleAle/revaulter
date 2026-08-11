//go:build unix

package cmd

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeFakeEditor writes a shell script that stands in for an editor, using the given file name
// The script receives the arguments the editor would receive, so the path of the temporary file is its last one
func writeFakeEditor(t *testing.T, name string, script string) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), name)
	err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+script+"\n"), 0o700) // #nosec G306 -- the script must be executable
	require.NoError(t, err)

	return scriptPath
}

// runSession runs an edit session with a shell script standing in for the editor
// The script receives the path of the temporary file as $1, exactly like a real editor would
func runSession(t *testing.T, file *encryptedFile, plaintext []byte, script string) (*editSession, error) {
	t.Helper()

	session := &editSession{
		file:   file,
		log:    testLogger(),
		editor: writeFakeEditor(t, "fake-editor.sh", script),
	}

	return session, session.run(t.Context(), plaintext)
}

func TestEditSessionSavesOnEverySave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// The editor writes twice, with a pause long enough for the watcher to notice the first write
	session, err := runSession(t, file, nil, `printf 'first draft' > "$1"; sleep 1; printf 'second draft' > "$1"; sleep 1`)
	require.NoError(t, err)
	require.GreaterOrEqual(t, session.saveCount, 2, "each save by the editor must be encrypted and written")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got, err := file.Decrypt(data)
	require.NoError(t, err)
	require.Equal(t, []byte("second draft"), got)
}

func TestEditSessionSavesContentsWrittenJustBeforeExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// The editor writes and exits immediately, before the watcher polls
	session, err := runSession(t, file, nil, `printf 'saved at exit' > "$1"`)
	require.NoError(t, err)
	require.Equal(t, 1, session.saveCount)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got, err := file.Decrypt(data)
	require.NoError(t, err)
	require.Equal(t, []byte("saved at exit"), got)
}

func TestEditSessionDoesNotWriteWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	file := newTestFile(t, path)

	session, err := runSession(t, file, nil, `true`)
	require.NoError(t, err)
	require.Equal(t, 0, session.saveCount)
	require.NoFileExists(t, path, "a file the editor never wrote must not be created")
}

func TestEditSessionKeepsExistingContentsWhenUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)
	require.NoError(t, file.Save([]byte("existing contents")))

	before, err := os.ReadFile(path)
	require.NoError(t, err)

	// The editor reads the file and exits without changing it
	session, err := runSession(t, file, []byte("existing contents"), `cat "$1" > /dev/null`)
	require.NoError(t, err)
	require.Equal(t, 0, session.saveCount)

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after, "the file must not be rewritten when the contents did not change")
}

func TestEditSessionDeletesTheTemporaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// The script records the path of the temporary file so the test can check that it is gone afterwards
	marker := filepath.Join(t.TempDir(), "temp-path")
	session, err := runSession(t, file, []byte("secret"), `printf %s "$1" > `+marker+`; printf 'changed' > "$1"`)
	require.NoError(t, err)
	require.Equal(t, 1, session.saveCount)

	tempPath, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.NotEmpty(t, tempPath)
	require.NoFileExists(t, string(tempPath))
	require.NoDirExists(t, filepath.Dir(string(tempPath)))
}

func TestEditSessionReportsEditorFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// Contents written before the failure are still saved: the user's work is not lost because the editor exited badly
	session, err := runSession(t, file, nil, `printf 'work in progress' > "$1"; exit 3`)
	require.ErrorContains(t, err, "the editor exited with an error")
	require.Equal(t, 1, session.saveCount)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got, err := file.Decrypt(data)
	require.NoError(t, err)
	require.Equal(t, []byte("work in progress"), got)
}

func TestEditSessionFailsWhenTheEditorCannotBeLaunched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	session := &editSession{
		file:   file,
		log:    testLogger(),
		editor: filepath.Join(t.TempDir(), "does-not-exist"),
	}

	err := session.run(t.Context(), nil)
	require.ErrorContains(t, err, "failed to launch the editor")
}

func TestEditSessionAddsTheWaitFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// The fake editor is named "code", and fails unless "--wait" precedes the file
	editor := writeFakeEditor(t, "code", "if [ \"$1\" != \"--wait\" ]; then exit 1; fi\nprintf 'edited' > \"$2\"")
	session := &editSession{
		file:   file,
		log:    testLogger(),
		editor: editor,
	}

	err := session.run(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, 1, session.saveCount)

	got, err := file.Decrypt(mustReadFile(t, path))
	require.NoError(t, err)
	require.Equal(t, []byte("edited"), got)
}

func TestEditSessionDoesNotAddTheWaitFlagWithNoAutoWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// The fake editor is still named "code", but this time it fails if it receives "--wait"
	editor := writeFakeEditor(t, "code", "if [ \"$1\" = \"--wait\" ]; then exit 1; fi\nprintf 'edited' > \"$1\"")
	session := &editSession{
		file:       file,
		log:        testLogger(),
		editor:     editor,
		noAutoWait: true,
	}

	err := session.run(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, 1, session.saveCount)
}

func TestEditSessionDoesNotAddTheWaitFlagTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	file := newTestFile(t, path)

	// The editor command already says to wait, so the file must still be the second argument
	editor := writeFakeEditor(t, "code", "if [ \"$1\" != \"--wait\" ] || [ \"$3\" != \"\" ]; then exit 1; fi\nprintf 'edited' > \"$2\"")
	session := &editSession{
		file:   file,
		log:    testLogger(),
		editor: editor + " --wait",
	}

	err := session.run(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, 1, session.saveCount)
}

func TestEditSessionHoldsTheLogWhileTheEditorRuns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	file := newTestFile(t, path)

	// The log goes to a file the fake editor can read, so the test can tell what was on screen while it was running
	logPath := filepath.Join(dir, "log.txt")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = logFile.Close()
	})

	// The editor saves the file, waits for the watcher to notice, then records everything the log has written so far
	snapshotPath := filepath.Join(dir, "snapshot.txt")
	editor := writeFakeEditor(t, "fake-editor.sh", "printf 'edited' > \"$1\"\nsleep 1\ncp "+logPath+" "+snapshotPath)

	out := newPausableWriter(logFile)
	session := &editSession{
		file:      file,
		log:       slog.New(slog.NewTextHandler(out, nil)),
		editor:    editor,
		logOutput: out,
	}

	err = session.run(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, 1, session.saveCount)

	// The save happened while the editor was running, and its message was held back
	snapshot := string(mustReadFile(t, snapshotPath))
	require.Contains(t, snapshot, "Launching the editor", "messages logged before the editor started are not held")
	require.NotContains(t, snapshot, "Saved the encrypted file", "messages logged while the editor is running must not reach the terminal")

	// Everything shows up once the editor has exited
	require.Contains(t, string(mustReadFile(t, logPath)), "Saved the encrypted file")
}
