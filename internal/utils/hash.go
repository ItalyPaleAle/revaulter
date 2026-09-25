package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// SHA256Hex returns the SHA-256 hash of the concatenation of data, encoded as lowercase hex
func SHA256Hex(data ...[]byte) string {
	sum := sha256Sum(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Base64URL returns the SHA-256 hash of the concatenation of data, encoded as base64url without padding
func SHA256Base64URL(data ...[]byte) string {
	sum := sha256Sum(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func sha256Sum(data [][]byte) [sha256.Size]byte {
	// A single slice doesn't need a streaming hash
	if len(data) == 1 {
		return sha256.Sum256(data[0])
	}

	h := sha256.New()
	for _, d := range data {
		_, _ = h.Write(d)
	}

	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}
