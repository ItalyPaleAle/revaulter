package cliutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"unicode"
)

const MaxRequestKeyFileSize = 4 << 10 // 4KB

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

// validateRequestKeyFileMode checks that mode describes a file that is allowed to hold a request key
// A directory or a device is always a mistake, and a FIFO cannot be read without blocking
func validateRequestKeyFileMode(mode fs.FileMode) error {
	if !mode.IsRegular() {
		return errors.New("not a regular file")
	}

	return nil
}
