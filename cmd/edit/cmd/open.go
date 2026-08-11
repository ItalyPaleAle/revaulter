package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/italypaleale/revaulter/pkg/revaulter"
)

// keyWrapper wraps and unwraps a file's content encryption key
// The Revaulter-backed implementation requires the user to approve every call in their browser
type keyWrapper interface {
	// Wrap protects a content encryption key with the given key label and algorithm
	Wrap(ctx context.Context, keyLabel string, algorithm string, key []byte, note string) (*wrappedKey, error)
	// Unwrap recovers a content encryption key
	Unwrap(ctx context.Context, wk *wrappedKey, note string) ([]byte, error)
}

// revaulterKeyWrapper wraps content encryption keys with a Revaulter server
type revaulterKeyWrapper struct {
	client *revaulter.Client
}

func (w *revaulterKeyWrapper) Wrap(ctx context.Context, keyLabel string, algorithm string, key []byte, note string) (*wrappedKey, error) {
	res, err := w.client.Encrypt(ctx, revaulter.EncryptRequest{
		KeyLabel:  keyLabel,
		Algorithm: algorithm,
		Plaintext: key,
		Note:      note,
	})
	if err != nil {
		return nil, err
	}

	return &wrappedKey{
		KeyLabel:   res.KeyLabel,
		Algorithm:  res.Algorithm,
		Ciphertext: res.Ciphertext,
		Nonce:      res.Nonce,
		Tag:        res.Tag,
	}, nil
}

func (w *revaulterKeyWrapper) Unwrap(ctx context.Context, wk *wrappedKey, note string) ([]byte, error) {
	res, err := w.client.Decrypt(ctx, revaulter.DecryptRequest{
		KeyLabel:   wk.KeyLabel,
		Algorithm:  wk.Algorithm,
		Ciphertext: wk.Ciphertext,
		Nonce:      wk.Nonce,
		Tag:        wk.Tag,
		Note:       note,
	})
	if err != nil {
		return nil, err
	}

	return res.Plaintext, nil
}

// openOptions is the input for openFile
type openOptions struct {
	// Path of the encrypted file
	Path string
	// Address of the Revaulter server, recorded in the protected header of new files
	Server string
	// Key label used for files that do not exist yet
	KeyLabel string
	// Algorithm used to wrap the key of files that do not exist yet
	Algorithm string
	// Note displayed to the user alongside the request
	Note string
	// Create a new file, with a new content encryption key, when the path does not exist
	Create bool
}

// openFile loads an encrypted file and returns its decrypted contents
// When the file does not exist and options.Create is set, a new random content encryption key is generated and wrapped with Revaulter, and the contents are empty
// Either way, this is where the user is asked to approve the operation in their browser
func openFile(ctx context.Context, log *slog.Logger, wrapper keyWrapper, opts openOptions) (*encryptedFile, []byte, error) {
	data, err := os.ReadFile(opts.Path) // #nosec G304 -- the path is supplied by the user, which is the point of the command
	switch {
	case err == nil:
		// The file exists: unwrap its key, then decrypt it
		return openExistingFile(ctx, log, wrapper, opts, data)
	case errors.Is(err, os.ErrNotExist):
		if !opts.Create {
			return nil, nil, fmt.Errorf("file %s does not exist", opts.Path)
		}
		return createFile(ctx, log, wrapper, opts)
	default:
		return nil, nil, fmt.Errorf("failed to read %s: %w", opts.Path, err)
	}
}

// openExistingFile unwraps the content encryption key stored in the file's protected header, then decrypts the file
func openExistingFile(ctx context.Context, log *slog.Logger, wrapper keyWrapper, opts openOptions, data []byte) (*encryptedFile, []byte, error) {
	header, err := parseHeader(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse %s: %w", opts.Path, err)
	}

	// The file records which server holds its key, and which label and algorithm it was wrapped with
	// Those always win over the flags: the key cannot be unwrapped with anything else
	if header.Revaulter.Server != "" && header.Revaulter.Server != opts.Server {
		log.Warn(
			"The file was encrypted with a different server",
			slog.String("file_server", header.Revaulter.Server),
			slog.String("server", opts.Server),
		)
	}
	if opts.KeyLabel != "" && opts.KeyLabel != header.Revaulter.KeyLabel {
		log.Warn(
			"Ignoring the requested key label because the file carries its own",
			slog.String("file_key_label", header.Revaulter.KeyLabel),
			slog.String("key_label", opts.KeyLabel),
		)
	}

	wk, err := header.WrappedKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse %s: %w", opts.Path, err)
	}

	log.Info(
		"Asking Revaulter to unwrap the file's encryption key",
		slog.String("key_label", wk.KeyLabel),
		slog.String("algorithm", wk.Algorithm),
	)

	contentKey, err := wrapper.Unwrap(ctx, wk, opts.Note)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unwrap the file's encryption key: %w", err)
	}
	if len(contentKey) != contentKeySize {
		return nil, nil, fmt.Errorf("the file's encryption key is %d bytes, expected %d", len(contentKey), contentKeySize)
	}

	file := &encryptedFile{
		Path:       opts.Path,
		contentKey: contentKey,
		keyInfo:    header.Revaulter,
	}

	plaintext, err := file.Decrypt(data)
	if err != nil {
		return nil, nil, err
	}

	return file, plaintext, nil
}

// createFile generates a new content encryption key and wraps it with Revaulter, for a file that does not exist yet
func createFile(ctx context.Context, log *slog.Logger, wrapper keyWrapper, opts openOptions) (*encryptedFile, []byte, error) {
	if opts.KeyLabel == "" {
		return nil, nil, errors.New("--key-label is required to create a new file (or set " + envKeyLabel + ")")
	}

	contentKey, err := generateContentKey()
	if err != nil {
		return nil, nil, err
	}

	log.Info(
		"Asking Revaulter to wrap a new encryption key for the file",
		slog.String("key_label", opts.KeyLabel),
		slog.String("algorithm", opts.Algorithm),
	)

	wk, err := wrapper.Wrap(ctx, opts.KeyLabel, opts.Algorithm, contentKey, opts.Note)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap the file's encryption key: %w", err)
	}

	return newEncryptedFile(opts.Path, opts.Server, wk, contentKey), nil, nil
}

// requestNote returns the note displayed to the user alongside the approval request
// The server only accepts a limited set of characters in notes, and caps their length, so the file name is sanitized to fit
func requestNote(userNote string, path string) string {
	if userNote != "" {
		return userNote
	}

	const prefix = "revaulter-edit "
	name := sanitizeNote(filepath.Base(path))
	if name == "" {
		return strings.TrimSpace(prefix)
	}

	budget := revaulter.MaxNoteLength - len(prefix)
	if len(name) > budget {
		name = name[len(name)-budget:]
	}

	return prefix + name
}

// sanitizeNote replaces every character the server does not allow in a note with a dash
func sanitizeNote(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z',
			ch >= 'a' && ch <= 'z',
			ch >= '0' && ch <= '9',
			ch == ' ', ch == '.', ch == '/', ch == '_', ch == '-':
			out = append(out, ch)
		default:
			out = append(out, '-')
		}
	}

	return string(out)
}
