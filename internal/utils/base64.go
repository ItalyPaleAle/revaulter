package utils

import (
	"encoding/base64"
	"errors"
	"strings"
)

// DecodeBase64String is a flexible base64 decoder that supports both standard and url encodings, and considers padding optional
func DecodeBase64String(in string) (out []byte, err error) {
	if in == "" {
		return nil, nil
	}

	// First, remove padding if any
	in = strings.TrimRight(in, "=")

	// Try decoding using URL encoding
	out, err = base64.RawURLEncoding.DecodeString(in)
	if err == nil {
		return out, nil
	}

	// Try standard encoding
	out, err = base64.RawStdEncoding.DecodeString(in)
	if err == nil {
		return out, nil
	}

	return nil, errors.New("string is not valid base64")
}
