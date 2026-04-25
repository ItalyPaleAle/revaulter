package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
)

// IsTruthy returns true if a string is truthy, such as "1", "on", "yes", "true", "t", "y"
func IsTruthy(str string) bool {
	if len(str) > 4 {
		// Short-circuit to avoid processing strings that can't be true
		return false
	}
	switch strings.ToLower(str) {
	case "1", "true", "t", "on", "yes", "y":
		return true
	default:
		return false
	}
}

// FileExists returns true if a file exists on disk and is a regular file
func FileExists(path string) (bool, error) {
	s, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	return !s.IsDir(), nil
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// RandomString generates a string with random characters in base62
func RandomString(strLen int) (string, error) {
	const (
		alphabetLength   = byte(len(base62Alphabet))
		maxAcceptedValue = byte(256 - (256 % len(base62Alphabet)))
	)

	// Use rejection sampling to ensure that the string is uniformly random
	// Read a few more bytes to account for excluded ones
	buf := make([]byte, strLen)
	randomBytes := make([]byte, int(float32(strLen)*1.2))
	for i := 0; i < strLen; {
		// Read random bytes from the buffer
		_, err := io.ReadFull(rand.Reader, randomBytes)
		if err != nil {
			return "", fmt.Errorf("error reading random bytes: %w", err)
		}

		for _, b := range randomBytes {
			if b >= maxAcceptedValue {
				continue
			}
			buf[i] = base62Alphabet[b%alphabetLength]
			i++
			if i == strLen {
				break
			}
		}
	}

	return string(buf), nil
}
