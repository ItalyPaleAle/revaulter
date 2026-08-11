package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// contentKeySize is the size of the key that encrypts the file's contents locally: 32 bytes, for AES-256-GCM
const contentKeySize = 32

// JOSE header values used by the files this tool writes
const (
	// joseAlg is "dir", meaning the content encryption key is used directly rather than being wrapped inside the JWE itself
	// The key is wrapped by Revaulter instead, and the information needed to unwrap it travels in the protected header
	joseAlg = "dir"
	// joseEnc is AES-256-GCM, the only content encryption algorithm this tool writes or reads
	joseEnc = "A256GCM"
)

// headerFormatVersion is the version of the "revaulter" protected header member
// It is bumped only when the shape changes incompatibly, so older files can be rejected with a clear message
const headerFormatVersion = 1

// jweHeader is the JWE protected header of a file written by this tool
type jweHeader struct {
	Alg       string           `json:"alg"`
	Enc       string           `json:"enc"`
	Revaulter revaulterKeyInfo `json:"revaulter"`
}

// revaulterKeyInfo describes how to recover the content encryption key from Revaulter
// It travels in the JWE protected header, which the content's authentication tag covers, so it cannot be altered without invalidating the file
type revaulterKeyInfo struct {
	// Version of this structure
	V int `json:"v"`
	// Address of the Revaulter server that holds the key
	Server string `json:"server"`
	// Logical key label the content encryption key is wrapped with
	KeyLabel string `json:"keyLabel"`
	// Algorithm the content encryption key is wrapped with
	Algorithm string `json:"algorithm"`
	// Wrapped content encryption key, base64url-encoded
	WrappedKey string `json:"wrappedKey"`
	// Nonce the content encryption key was wrapped with, base64url-encoded
	WrappedKeyNonce string `json:"wrappedKeyNonce"`
	// Authentication tag of the wrapped content encryption key, base64url-encoded
	WrappedKeyTag string `json:"wrappedKeyTag"`
}

// wrappedKey is the content encryption key as protected by Revaulter
type wrappedKey struct {
	KeyLabel   string
	Algorithm  string
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
}

// encryptedFile is a local file encrypted with a key that Revaulter holds
type encryptedFile struct {
	// Path of the file on disk
	Path string
	// Content encryption key, in cleartext, held only in memory
	contentKey []byte
	// Information about the wrapped key, written to the protected header on every save
	keyInfo revaulterKeyInfo
}

// parseHeader reads the JWE protected header of an encrypted file, without decrypting it
// This is what tells the caller which Revaulter server, key label, and algorithm are needed to unwrap the content encryption key
func parseHeader(data []byte) (*jweHeader, error) {
	segments := strings.Split(strings.TrimSpace(string(data)), ".")
	if len(segments) != 5 {
		return nil, errors.New("not a JWE in compact serialization: expected 5 segments")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, fmt.Errorf("invalid protected header encoding: %w", err)
	}

	header := &jweHeader{}
	err = json.Unmarshal(headerJSON, header)
	if err != nil {
		return nil, fmt.Errorf("invalid protected header: %w", err)
	}

	if header.Alg != joseAlg {
		return nil, fmt.Errorf("unsupported JWE 'alg': %q", header.Alg)
	}
	if header.Enc != joseEnc {
		return nil, fmt.Errorf("unsupported JWE 'enc': %q", header.Enc)
	}
	if header.Revaulter.V != headerFormatVersion {
		return nil, fmt.Errorf("unsupported Revaulter header version %d: this file was written by a newer version of revaulter-edit", header.Revaulter.V)
	}
	if header.Revaulter.KeyLabel == "" || header.Revaulter.Algorithm == "" || header.Revaulter.WrappedKey == "" {
		return nil, errors.New("protected header does not carry a wrapped key")
	}

	return header, nil
}

// WrappedKey returns the wrapped content encryption key described by the header
func (h *jweHeader) WrappedKey() (*wrappedKey, error) {
	ciphertext, err := decodeHeaderField("wrappedKey", h.Revaulter.WrappedKey)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeHeaderField("wrappedKeyNonce", h.Revaulter.WrappedKeyNonce)
	if err != nil {
		return nil, err
	}
	tag, err := decodeHeaderField("wrappedKeyTag", h.Revaulter.WrappedKeyTag)
	if err != nil {
		return nil, err
	}

	return &wrappedKey{
		KeyLabel:   h.Revaulter.KeyLabel,
		Algorithm:  h.Revaulter.Algorithm,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

func decodeHeaderField(name string, value string) ([]byte, error) {
	res, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %q in protected header: %w", name, err)
	}

	return res, nil
}

// newEncryptedFile creates the in-memory state for a file that does not exist yet, generating a random content encryption key
func newEncryptedFile(path string, server string, wrap *wrappedKey, contentKey []byte) *encryptedFile {
	return &encryptedFile{
		Path:       path,
		contentKey: contentKey,
		keyInfo: revaulterKeyInfo{
			V:               headerFormatVersion,
			Server:          server,
			KeyLabel:        wrap.KeyLabel,
			Algorithm:       wrap.Algorithm,
			WrappedKey:      base64.RawURLEncoding.EncodeToString(wrap.Ciphertext),
			WrappedKeyNonce: base64.RawURLEncoding.EncodeToString(wrap.Nonce),
			WrappedKeyTag:   base64.RawURLEncoding.EncodeToString(wrap.Tag),
		},
	}
}

// generateContentKey returns a new random content encryption key
func generateContentKey() ([]byte, error) {
	key := make([]byte, contentKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a content encryption key: %w", err)
	}

	return key, nil
}

// Decrypt decrypts the contents of an encrypted file, given its raw bytes
func (f *encryptedFile) Decrypt(data []byte) ([]byte, error) {
	segments := strings.Split(strings.TrimSpace(string(data)), ".")
	if len(segments) != 5 {
		return nil, errors.New("not a JWE in compact serialization: expected 5 segments")
	}

	// The second segment is the JWE Encrypted Key, which is always empty with "alg":"dir"
	if segments[1] != "" {
		return nil, errors.New("unexpected encrypted key segment: expected it to be empty for 'alg':'dir'")
	}

	iv, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, fmt.Errorf("invalid initialization vector: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(segments[3])
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(segments[4])
	if err != nil {
		return nil, fmt.Errorf("invalid authentication tag: %w", err)
	}

	aead, err := newContentCipher(f.contentKey)
	if err != nil {
		return nil, err
	}
	if len(iv) != aead.NonceSize() {
		return nil, errors.New("invalid initialization vector: bad size")
	}

	// RFC 7516 binds the encoded protected header into the AEAD as additional authenticated data, which is what stops the wrapped key information from being swapped out
	aad := []byte(segments[0])
	plaintext, err := aead.Open(nil, iv, append(append([]byte{}, ciphertext...), tag...), aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the file: %w", err)
	}

	return plaintext, nil
}

// Serialize encrypts the contents and returns the file as a JWE in compact serialization
func (f *encryptedFile) Serialize(plaintext []byte) ([]byte, error) {
	headerJSON, err := json.Marshal(jweHeader{
		Alg:       joseAlg,
		Enc:       joseEnc,
		Revaulter: f.keyInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize the protected header: %w", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(headerJSON)

	aead, err := newContentCipher(f.contentKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aead.NonceSize())
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a nonce: %w", err)
	}

	combined := aead.Seal(nil, iv, plaintext, []byte(headerSegment))
	ciphertext := combined[:len(combined)-aead.Overhead()]
	tag := combined[len(combined)-aead.Overhead():]

	var buf bytes.Buffer
	buf.WriteString(headerSegment)
	// The JWE Encrypted Key segment is empty, because the key is wrapped by Revaulter and described in the protected header
	buf.WriteString("..")
	buf.WriteString(base64.RawURLEncoding.EncodeToString(iv))
	buf.WriteByte('.')
	buf.WriteString(base64.RawURLEncoding.EncodeToString(ciphertext))
	buf.WriteByte('.')
	buf.WriteString(base64.RawURLEncoding.EncodeToString(tag))
	buf.WriteByte('\n')

	return buf.Bytes(), nil
}

// Save encrypts the contents and writes them to the file, atomically and with owner-only permissions
func (f *encryptedFile) Save(plaintext []byte) error {
	data, err := f.Serialize(plaintext)
	if err != nil {
		return err
	}

	return writeFileAtomic(f.Path, data)
}

// newContentCipher returns the AEAD used to encrypt the file's contents
func newContentCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// writeFileAtomic writes data to path with mode 0600, via a temporary file in the same directory
// Writing through a rename means a crash or a failed write never leaves a half-written file where the encrypted contents used to be
func writeFileAtomic(path string, data []byte) error {
	// Refuse to write through a pre-existing symlink
	st, lerr := os.Lstat(path)
	if lerr == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to write through symlink")
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("failed to create a temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	err = tmp.Chmod(0o600)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set the permissions of the temporary file: %w", err)
	}

	_, err = tmp.Write(data)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write the temporary file: %w", err)
	}

	err = tmp.Sync()
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to flush the temporary file: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("failed to close the temporary file: %w", err)
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		return fmt.Errorf("failed to save the file: %w", err)
	}

	return nil
}
