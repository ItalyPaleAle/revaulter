package cliutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// MaxRequestKeyFileSize is the maximum size of a file containing a request key
// It matches the maximum size of the JWTs the server accepts, since the file can hold an OIDC token
const MaxRequestKeyFileSize = 8 << 10 // 8KB

// ReadRequestKeyFile loads a request key from the file at path
func ReadRequestKeyFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}

	// Check the path before opening it, because opening a FIFO blocks until a writer appears
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to inspect file: %w", err)
	}

	err = validateRequestKeyFileMode(info.Mode())
	if err != nil {
		return "", err
	}

	// #nosec G304 - user-supplied path is intentional
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Repeat the checks on the open file descriptor, so they describe what was actually opened even if the path was swapped in the meantime
	stat, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to inspect file: %w", err)
	}

	err = validateRequestKeyFileMode(stat.Mode())
	if err != nil {
		return "", err
	}

	// Read one byte past the limit so an oversize file is reported rather than silently truncated to a wrong key
	read, err := io.ReadAll(io.LimitReader(f, MaxRequestKeyFileSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	if len(read) > MaxRequestKeyFileSize {
		return "", fmt.Errorf("file is larger than the maximum allowed size of %d bytes", MaxRequestKeyFileSize)
	}

	requestKey := strings.TrimSpace(string(read))
	if requestKey == "" {
		return "", errors.New("file is empty")
	}

	// The key is sent verbatim in an Authorization header, so it cannot contain spaces or control characters
	// This also catches a file holding more than one line, which is never a single request key
	invalid := strings.ContainsFunc(requestKey, func(r rune) bool {
		return unicode.IsSpace(r) || !unicode.IsPrint(r)
	})
	if invalid {
		return "", errors.New("file does not contain a single request key")
	}

	return requestKey, nil
}

// OIDCTokenFileProvider returns an OIDC token provider that reads the token from the file at path again for every request
// If the file can't be read or doesn't contain a JWT, for example while it's being replaced, the provider logs a warning and returns the last token it read, starting with initial
func OIDCTokenFileProvider(log *slog.Logger, path string, initial string) func(ctx context.Context) string {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	var lock sync.Mutex
	last := initial

	return func(ctx context.Context) string {
		token, err := ReadRequestKeyFile(path)
		if err == nil && !protocolv2.LooksLikeJWT(token) {
			err = errors.New("file does not contain a JWT")
		}

		lock.Lock()
		defer lock.Unlock()

		if err != nil {
			log.WarnContext(ctx, "Failed to read the OIDC token from the request key file, using the last token that was read",
				slog.String("path", path),
				slog.Any("error", err),
			)
			return last
		}

		last = token
		return token
	}
}

// validateRequestKeyFileMode checks that mode describes a file that is allowed to hold a request key
// A directory or a device is always a mistake, and a FIFO cannot be read without blocking
func validateRequestKeyFileMode(mode fs.FileMode) error {
	if !mode.IsRegular() {
		return errors.New("not a regular file")
	}

	return nil
}
