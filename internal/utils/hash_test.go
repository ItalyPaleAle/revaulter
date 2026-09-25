package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSHA256Hex(t *testing.T) {
	// Test vectors from FIPS 180-2
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256Hex())
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256Hex([]byte{}))
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", SHA256Hex([]byte("abc")))

	// Multiple slices are hashed as their concatenation
	assert.Equal(t, SHA256Hex([]byte("abc")), SHA256Hex([]byte("a"), []byte("bc")))
	assert.Equal(t, SHA256Hex([]byte("abc")), SHA256Hex([]byte("a"), nil, []byte("b"), []byte("c")))
}

func TestSHA256Base64URL(t *testing.T) {
	assert.Equal(t, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", SHA256Base64URL())
	assert.Equal(t, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", SHA256Base64URL([]byte("abc")))
	assert.Equal(t, SHA256Base64URL([]byte("abc")), SHA256Base64URL([]byte("ab"), []byte("c")))
}
