package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/italypaleale/go-sql-utils/adapter"
)

// ErrKVNotFound is returned by KVStore.Get when the key does not exist
var ErrKVNotFound = errors.New("key not found")

const etagSize = 16

// KVStore is a generic key/value store backed by the v2_kv table
type KVStore struct {
	db adapter.Querier
}

func NewKVStore(db adapter.Querier) (*KVStore, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &KVStore{
		db: db,
	}, nil
}

// KVStore returns an instance of KVStore
func (db *DB) KVStore() *KVStore {
	kv, err := NewKVStore(db)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return kv
}

// KVStore returns an instance of KVStore for the transaction
func (tx *DbTx) KVStore() *KVStore {
	kv, err := NewKVStore(tx)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return kv
}

// Get returns the value stored under key, along with the etag guarding it
// Returns ErrKVNotFound if the key does not exist
func (s *KVStore) Get(ctx context.Context, key string) (value string, etag string, err error) {
	err = s.db.
		QueryRow(ctx, `SELECT value, etag FROM v2_kv WHERE key = $1`, key).
		Scan(&value, &etag)
	if s.db.IsNoRowsError(err) {
		return "", "", ErrKVNotFound
	} else if err != nil {
		return "", "", err
	}

	return value, etag, nil
}

// SetIfAbsent writes the value only when the key does not exist yet
// Returns the etag of the row it wrote and true, or an empty etag and false when the key already had a value
func (s *KVStore) SetIfAbsent(ctx context.Context, key string, value string) (etag string, ok bool, err error) {
	etag, err = generateEtag()
	if err != nil {
		return "", false, err
	}

	affected, err := s.db.Exec(ctx,
		`INSERT INTO v2_kv (key, value, etag) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING`,
		key, value, etag,
	)
	if err != nil {
		return "", false, err
	}
	if affected == 0 {
		return "", false, nil
	}

	return etag, true, nil
}

// CompareAndSwap replaces the value under key only when its etag still matches the one the caller last read
// It returns the etag now guarding the row
// It returns false, with no error, when the etag no longer matches
func (s *KVStore) CompareAndSwap(ctx context.Context, key string, etag string, value string) (newEtag string, ok bool, err error) {
	if etag == "" {
		return "", false, nil
	}

	newEtag, err = generateEtag()
	if err != nil {
		return "", false, err
	}

	affected, err := s.db.Exec(ctx,
		`UPDATE v2_kv SET value = $1, etag = $2 WHERE key = $3 AND etag = $4`,
		value, newEtag, key, etag,
	)
	if err != nil {
		return "", false, err
	}
	if affected == 0 {
		return "", false, nil
	}

	return newEtag, true, nil
}

// Delete removes a key
// Returns true when a row was removed
func (s *KVStore) Delete(ctx context.Context, key string) (bool, error) {
	affected, err := s.db.Exec(ctx, `DELETE FROM v2_kv WHERE key = $1`, key)
	if err != nil {
		return false, err
	}

	return affected > 0, nil
}

// generateEtag returns a fresh random token
// It is generated in Go rather than by the database so that both backends behave identically
func generateEtag() (string, error) {
	buf := make([]byte, etagSize)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("failed to generate etag: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
