package broker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBroker(t *testing.T) {
	broker := NewBroker[int]()

	// Subscribe 3 times
	var (
		subs [3]chan int
		err  error
	)
	subs[0], err = broker.Subscribe()
	require.NoError(t, err)
	subs[1], err = broker.Subscribe()
	require.NoError(t, err)
	subs[2], err = broker.Subscribe()
	require.NoError(t, err)

	// Send a message
	go func() {
		// Publish in a background goroutine
		broker.Publish(42)
	}()
	var count int
	to := time.After(time.Second)
	for count < 3 {
		var n int
		select {
		case n = <-subs[0]:
			// nop
		case n = <-subs[1]:
			// nop
		case n = <-subs[2]:
			// nop
		case <-to:
			t.Fatalf("timed out while waiting for messages; got %d of 3", count)
		}
		require.Equal(t, 42, n)
		count++
	}
	require.Equal(t, 3, count)

	// Remove one sub
	broker.Unsubscribe(subs[2])

	// Ensure the channel is closed
	assertChanClosed(t, subs[2])

	// Send another message
	go func() {
		// Publish in a background goroutine
		broker.Publish(1)
	}()
	to = time.After(time.Second)
	count = 0
	for count < 2 {
		var n int
		select {
		case n = <-subs[0]:
			// nop
		case n = <-subs[1]:
			// nop
		case <-to:
			t.Fatalf("timed out while waiting for messages; got %d of 3", count)
		}
		require.Equal(t, 1, n)
		count++
	}
	require.Equal(t, 2, count)

	// Close the broker
	broker.Shutdown()

	// Assert all subscriptions are closed
	for _, s := range subs {
		assertChanClosed(t, s)
	}

	// Subscribing should fail
	sub, err := broker.Subscribe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrBrokerStopped)
	require.Nil(t, sub)
}

// TestBrokerPublishNonBlocking verifies that Publish never blocks on a slow or hung subscribe
// A single slow subscriber must not prevent Publish from returning promptly, and Unsubscribe/Shutdown must remain responsive.
func TestBrokerPublishNonBlocking(t *testing.T) {
	b := NewBroker[int]()

	slow, err := b.Subscribe()
	require.NoError(t, err)
	fast, err := b.Subscribe()
	require.NoError(t, err)

	// Fill the slow subscriber's buffer so additional publishes must drop
	for range cap(slow) {
		b.Publish(1)
	}

	// Drain the fast one so we don't confuse the two subscribers' buffers
	for len(fast) > 0 {
		<-fast
	}

	// This publish must NOT block, even though slow's buffer is full
	done := make(chan struct{})
	go func() {
		b.Publish(99)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked when subscriber buffer was full")
	}

	// The fast subscriber should still receive the new message
	select {
	case n := <-fast:
		require.Equal(t, 99, n)
	case <-time.After(time.Second):
		t.Fatal("fast subscriber did not receive message after dropped slow delivery")
	}

	// Unsubscribe must still be responsive while slow's buffer is full
	unsubDone := make(chan struct{})
	go func() {
		b.Unsubscribe(slow)
		close(unsubDone)
	}()
	select {
	case <-unsubDone:
	case <-time.After(time.Second):
		t.Fatal("Unsubscribe blocked by full subscriber buffer")
	}

	b.Shutdown()
}

func assertChanClosed[T any](t *testing.T, ch chan T) {
	t.Helper()
	select {
	case _, ok := <-ch:
		require.False(t, ok)
	default:
		t.Fatal("channel 2 should have been closed")
	}
}
