package db

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKVStore(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		kv := conn.KVStore()

		t.Run("Get returns ErrKVNotFound for a missing key", func(t *testing.T) {
			_, _, err := kv.Get(ctx, "missing")

			require.ErrorIs(t, err, ErrKVNotFound)
		})

		t.Run("SetIfAbsent writes once and returns an etag", func(t *testing.T) {
			etag, written, err := kv.SetIfAbsent(ctx, "k1", "first")
			require.NoError(t, err)
			require.True(t, written)
			require.NotEmpty(t, etag)

			otherEtag, written, err := kv.SetIfAbsent(ctx, "k1", "second")
			require.NoError(t, err)
			require.False(t, written)
			require.Empty(t, otherEtag)

			val, got, err := kv.Get(ctx, "k1")
			require.NoError(t, err)
			require.Equal(t, "first", val)
			require.Equal(t, etag, got)
		})

		t.Run("CompareAndSwap only replaces a matching etag", func(t *testing.T) {
			etag, _, err := kv.SetIfAbsent(ctx, "k2", "a")
			require.NoError(t, err)

			swappedEtag, ok, err := kv.CompareAndSwap(ctx, "k2", "not-the-etag", "b")
			require.NoError(t, err)
			require.False(t, ok)
			require.Empty(t, swappedEtag)

			val, _, err := kv.Get(ctx, "k2")
			require.NoError(t, err)
			require.Equal(t, "a", val)

			swappedEtag, ok, err = kv.CompareAndSwap(ctx, "k2", etag, "b")
			require.NoError(t, err)
			require.True(t, ok)
			require.NotEmpty(t, swappedEtag)

			val, got, err := kv.Get(ctx, "k2")
			require.NoError(t, err)
			require.Equal(t, "b", val)
			require.Equal(t, swappedEtag, got)

			// The etag the caller started from is now stale, so replaying the same write does nothing
			_, ok, err = kv.CompareAndSwap(ctx, "k2", etag, "c")
			require.NoError(t, err)
			require.False(t, ok)
		})

		t.Run("CompareAndSwap rotates the etag on every write", func(t *testing.T) {
			etag, _, err := kv.SetIfAbsent(ctx, "k3", "0")
			require.NoError(t, err)

			seen := map[string]struct{}{etag: {}}
			for i := range 5 {
				etag, _, err = kv.CompareAndSwap(ctx, "k3", etag, strconv.Itoa(i))
				require.NoError(t, err)

				_, dup := seen[etag]
				require.False(t, dup, "etag %q was reused", etag)
				seen[etag] = struct{}{}
			}
		})

		t.Run("CompareAndSwap without an etag never writes", func(t *testing.T) {
			// A caller that has not read the row has nothing to compare against, and must not be able to clobber it
			_, _, err := kv.SetIfAbsent(ctx, "k4", "a")
			require.NoError(t, err)

			_, ok, err := kv.CompareAndSwap(ctx, "k4", "", "b")
			require.NoError(t, err)
			require.False(t, ok)

			val, _, err := kv.Get(ctx, "k4")
			require.NoError(t, err)
			require.Equal(t, "a", val)
		})

		t.Run("CompareAndSwap on a missing key does nothing", func(t *testing.T) {
			_, ok, err := kv.CompareAndSwap(ctx, "missing", "some-etag", "b")

			require.NoError(t, err)
			require.False(t, ok)
		})

		t.Run("Delete removes the key", func(t *testing.T) {
			_, _, err := kv.SetIfAbsent(ctx, "k5", "v")
			require.NoError(t, err)

			deleted, err := kv.Delete(ctx, "k5")
			require.NoError(t, err)
			require.True(t, deleted)

			_, _, err = kv.Get(ctx, "k5")
			require.ErrorIs(t, err, ErrKVNotFound)

			deleted, err = kv.Delete(ctx, "k5")
			require.NoError(t, err)
			require.False(t, deleted)
		})
	})
}

func TestKVStoreSetIfAbsentUnderConcurrentCallers(t *testing.T) {
	runDBTest(t, func(t *testing.T, conn *DB) {
		require.NoError(t, RunMigrations(t.Context(), conn, nil))

		ctx := t.Context()
		kv := conn.KVStore()

		const callers = 8
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			winners int
		)

		wg.Add(callers)
		for i := range callers {
			go func() {
				defer wg.Done()

				_, written, err := kv.SetIfAbsent(ctx, "race", "caller-"+strconv.Itoa(i))
				if err != nil {
					return
				}

				if written {
					mu.Lock()
					winners++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		// Exactly one caller may win, which is what keeps a racing caller from double-seeding the audit stream cursor
		require.Equal(t, 1, winners)
	})
}
