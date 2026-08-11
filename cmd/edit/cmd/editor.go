package cmd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// pollInterval is how often the temporary file is checked for changes while the editor is running
// It is short enough that a save feels immediate, and long enough that watching a file costs nothing
const pollInterval = 400 * time.Millisecond

// editSession runs an editor on the decrypted contents of a file, re-encrypting them every time the editor saves
type editSession struct {
	file   *encryptedFile
	log    *slog.Logger
	editor string
	// Do not add the "--wait" flag to editors that need it
	noAutoWait bool
	// When set, the log is paused while the editor is running, and everything logged in the meantime is written out when it exits
	logOutput *pausableWriter

	// Path of the temporary file the editor works on
	tempPath string
	// Hash of the contents that are currently persisted in the encrypted file
	savedHash [32]byte
	// Modification time of the temporary file as this tool last wrote it
	tempModTime time.Time
	// Whether the encrypted file has been written at least once
	saved bool
	// Number of times the contents have been saved during this session
	saveCount int
}

// resolveEditor returns the command to launch, from the --editor flag or the usual environment variables
func resolveEditor(flag string) (string, error) {
	candidates := []string{flag, os.Getenv("VISUAL"), os.Getenv("EDITOR")}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c != "" {
			return c, nil
		}
	}

	return "", errors.New("no editor configured: set EDITOR or VISUAL, or pass --editor")
}

// editorFileName returns the name to give the temporary file the editor opens
// The name of the encrypted file is reused, minus any encryption-related extension, so editors still pick the right syntax highlighting
func editorFileName(path string) string {
	name := filepath.Base(path)
	for _, ext := range []string{".jwe", ".enc", ".encrypted"} {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			name = name[:len(name)-len(ext)]
			break
		}
	}

	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "revaulter-edit.txt"
	}

	return name
}

// run writes the plaintext to a temporary file, launches the editor on it, and saves the encrypted file every time the editor writes new contents
// The temporary file is deleted when the session ends
func (s *editSession) run(ctx context.Context, plaintext []byte) error {
	dir, err := newPrivateTempDir()
	if err != nil {
		return err
	}
	defer func() {
		// Overwrite the plaintext before deleting it, so it does not survive in a freed disk block
		_ = wipeFile(s.tempPath)
		_ = os.RemoveAll(dir)
	}()

	s.tempPath = filepath.Join(dir, editorFileName(s.file.Path))
	err = os.WriteFile(s.tempPath, plaintext, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write the temporary file: %w", err)
	}

	st, err := os.Stat(s.tempPath)
	if err != nil {
		return fmt.Errorf("failed to stat the temporary file: %w", err)
	}
	s.tempModTime = st.ModTime()
	s.savedHash = sha256.Sum256(plaintext)

	// While the editor is in the foreground, Ctrl-C belongs to it: catching the signal here keeps this process alive long enough to clean up the temporary file
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	args := s.editorArgs()
	if !s.noAutoWait && needsWaitFlag(args) {
		s.log.Info(
			"Adding the '--wait' flag to the editor, which would otherwise return before the file has been edited: pass '--no-auto-wait' to omit it",
			slog.String("editor", s.editor),
		)
		args = append(args, waitFlagName)
	}

	cmd := exec.CommandContext(ctx, args[0], append(args[1:], s.tempPath)...) // #nosec G204 -- the editor is chosen by the user, via --editor or the environment
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	s.log.Info("Launching the editor", slog.String("editor", s.editor), slog.String("file", s.file.Path))

	// Editors such as nano and vim draw over the whole terminal, so anything logged from now on would land in the middle of the file being edited
	// Hold the log until the editor has exited and the terminal is ours again
	if s.logOutput != nil {
		s.logOutput.Pause()
		defer func() {
			rErr := s.logOutput.Resume()
			if rErr != nil {
				fmt.Fprintln(os.Stderr, "Failed to write the log messages collected while the editor was running:", rErr)
			}
		}()
	}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to launch the editor %q: %w", s.editor, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var editorErr error
	for running := true; running; {
		select {
		case editorErr = <-done:
			running = false
		case <-sigCh:
			// Nothing to do: the editor received the same signal and decides what to do with it
		case <-ticker.C:
			sErr := s.saveIfChanged()
			if sErr != nil {
				// A failed save must not take the editor down: the user may still be able to fix the problem and save again
				s.log.Error("Failed to save the file", slog.Any("err", sErr))
			}
		}
	}

	// The editor may have saved between the last poll and its exit
	err = s.saveIfChanged()
	if err != nil {
		return err
	}

	if editorErr != nil {
		return fmt.Errorf("the editor exited with an error: %w", editorErr)
	}

	if s.saveCount == 0 {
		s.log.Info("No changes were saved")
	}

	return nil
}

// editorArgs splits the editor command into the program and its arguments
func (s *editSession) editorArgs() []string {
	args := splitCommand(s.editor)
	if len(args) == 0 {
		return []string{s.editor}
	}

	return args
}

// waitFlagName is the flag that tells an editor to wait until the file has been closed
const waitFlagName = "--wait"

// editorsNeedingWait are editors that open the file in an existing window and return right away, so the session would end before the user has typed anything
// They all accept "--wait", which keeps the process alive until the file is closed
var editorsNeedingWait = []string{"code", "subl"}

// waitFlagAliases are the arguments that already tell an editor to wait, so the flag is never added twice
var waitFlagAliases = []string{waitFlagName, "-w"}

// needsWaitFlag reports whether the editor must be told to wait, and has not been told already
func needsWaitFlag(args []string) bool {
	if len(args) == 0 {
		return false
	}

	// Match on the name of the executable, so a full path or a ".exe" suffix still resolves
	name := strings.ToLower(filepath.Base(args[0]))
	name = strings.TrimSuffix(name, ".exe")
	if !slices.Contains(editorsNeedingWait, name) {
		return false
	}

	for _, arg := range args[1:] {
		if slices.Contains(waitFlagAliases, arg) {
			return false
		}
	}

	return true
}

// saveIfChanged re-encrypts the temporary file when its contents changed since the last save
func (s *editSession) saveIfChanged() error {
	plaintext, err := os.ReadFile(s.tempPath) // #nosec G304 -- this is the temporary file this session created
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Some editors replace the file while saving, so it can be missing for an instant
			return nil
		}
		return fmt.Errorf("failed to read the temporary file: %w", err)
	}

	hash := sha256.Sum256(plaintext)
	if hash == s.savedHash && (s.saved || !s.tempFileTouched()) {
		return nil
	}

	err = s.file.Save(plaintext)
	if err != nil {
		return err
	}

	s.savedHash = hash
	s.saved = true
	s.saveCount++
	s.log.Info("Saved the encrypted file", slog.String("file", s.file.Path), slog.Int("bytes", len(plaintext)))

	return nil
}

// tempFileTouched reports whether the editor wrote the temporary file at least once
// It is what makes an intentionally empty new file get saved, since its contents never differ from the empty file this session created
func (s *editSession) tempFileTouched() bool {
	st, err := os.Stat(s.tempPath)
	if err != nil {
		return false
	}

	return !st.ModTime().Equal(s.tempModTime)
}

// newPrivateTempDir creates a directory only the current user can access, preferring a location that is not on disk
// os.MkdirTemp creates the directory with mode 0700
func newPrivateTempDir() (string, error) {
	// XDG_RUNTIME_DIR is usually a tmpfs, so the decrypted contents never reach a disk
	// If not set, falls back to the default temporary directory
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base != "" {
		dir, err := os.MkdirTemp(base, "revaulter-edit-")
		if err == nil {
			return dir, nil
		}
	}

	dir, err := os.MkdirTemp("", "revaulter-edit-")
	if err != nil {
		return "", fmt.Errorf("failed to create a temporary directory: %w", err)
	}

	return dir, nil
}

// wipeFile overwrites a file with zeros before it is deleted
// This is best-effort: on copy-on-write and log-structured file systems the old contents can still exist elsewhere
func wipeFile(path string) error {
	if path == "" {
		return nil
	}

	st, err := os.Stat(path)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- this is the temporary file this session created
	if err != nil {
		return err
	}
	defer f.Close()

	zeros := make([]byte, 4096)
	for written := int64(0); written < st.Size(); {
		n := int64(len(zeros))
		if remaining := st.Size() - written; remaining < n {
			n = remaining
		}

		w, err := f.Write(zeros[:n])
		if err != nil {
			return err
		}
		written += int64(w)
	}

	return f.Sync()
}

// splitCommand splits a command line into its arguments, honoring single and double quotes
// It is deliberately minimal: it covers editor commands such as `code --wait` or `"/path/with spaces/editor" -f`, without pulling in a shell
func splitCommand(cmd string) []string {
	var (
		args    []string
		current strings.Builder
		quote   rune
		hasArg  bool
	)

	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			hasArg = true
		case r == ' ' || r == '\t':
			if hasArg {
				args = append(args, current.String())
				current.Reset()
				hasArg = false
			}
		default:
			current.WriteRune(r)
			hasArg = true
		}
	}

	if hasArg {
		args = append(args, current.String())
	}

	return args
}
